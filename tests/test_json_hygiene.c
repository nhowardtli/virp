/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — JSON ingress hygiene.
 *
 * HAM review 2026-09-06, items 9, 10, 12 and 16. Four different ways a
 * request could be silently RESHAPED between the wire and the chain,
 * with the reshaped form being what got recorded:
 *
 *   9   a nanosecond timestamp through an IEEE-754 double. cJSON stores
 *       every number as a double, and 1788722800424766173 comes back as
 *       1788722800424766208 -- off by 35, measured on the real parse
 *       path before this fix.
 *   10  a string one byte over its fixed buffer, snprintf'd in and
 *       reported as success. Two distinct ids became one internal
 *       string.
 *   12  a canonical string carrying a character the canonicalizer
 *       cannot escape. Producer and verifier then built the SAME
 *       malformed bytes and agreed, which is not verification.
 *   16  the canonicalization buffer's snprintf return hashed without a
 *       clamp: an out-of-bounds read the day any field widens.
 *
 * onode_parse_request_fuzz() is the real parse_request(), so nothing
 * here opens a socket.
 */

#include "virp.h"
#include "virp_onode.h"
#include "virp_chain.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int tests_run = 0, tests_passed = 0, tests_failed = 0;

#define TEST(name) do { tests_run++; \
        printf("  [%2d] %-62s ", tests_run, name); fflush(stdout); } while (0)
#define OK()   do { printf("PASS\n"); tests_passed++; } while (0)
#define BAD(m) do { printf("FAIL: %s\n", m); tests_failed++; } while (0)
#define WANT(cond, m) do { if (cond) OK(); else BAD(m); } while (0)

static bool parse(const char *json)
{
    return onode_parse_request_fuzz((const uint8_t *)json, strlen(json));
}

/* ---------------------------------------------------------------- 9 -- */

static void item9(void)
{
    TEST("9: a ns value past 2^53 as a JSON NUMBER is refused");
    WANT(!parse("{\"action\":\"intent_store\",\"intent_id\":\"i1\","
                "\"expires_at_ns\":1788722800424766173}"),
         "a value the parser cannot represent exactly was accepted");

    TEST("9: the same value as a DECIMAL STRING is accepted");
    WANT(parse("{\"action\":\"intent_store\",\"intent_id\":\"i1\","
               "\"expires_at_ns\":\"1788722800424766173\"}"),
         "the exact wire form was refused");

    TEST("9: a number inside the safe range is still accepted");
    WANT(parse("{\"action\":\"intent_store\",\"intent_id\":\"i1\","
               "\"expires_at_ns\":9007199254740991}"),
         "2^53-1 must be accepted");

    TEST("9: 2^53+1, which DECODES to 2^53, is refused");
    /* The one literal a `<=` bound would have let through: it rounds to
     * exactly 2^53 and would have looked safe. The bound is strict for
     * this reason, which costs the single value 2^53 itself. */
    WANT(!parse("{\"action\":\"intent_store\",\"intent_id\":\"i1\","
                "\"expires_at_ns\":9007199254740993}"),
         "a lossy literal that rounds into the safe range was accepted");

    TEST("9: 2^53 itself is refused as a number, accepted as a string");
    WANT(!parse("{\"action\":\"intent_store\",\"intent_id\":\"i1\","
                "\"expires_at_ns\":9007199254740992}")
         && parse("{\"action\":\"intent_store\",\"intent_id\":\"i1\","
                  "\"expires_at_ns\":\"9007199254740992\"}"),
         "the boundary value is not handled as documented");

    TEST("9: a non-integral number is refused");
    WANT(!parse("{\"action\":\"intent_store\",\"intent_id\":\"i1\","
                "\"expires_at_ns\":1.5}"),
         "a fractional nanosecond was accepted");

    TEST("9: a non-numeric string is refused, not read as zero");
    WANT(!parse("{\"action\":\"intent_store\",\"intent_id\":\"i1\","
                "\"expires_at_ns\":\"tomorrow\"}"),
         "garbage was accepted");

    TEST("9: a huge from_sequence as a number is refused");
    WANT(!parse("{\"action\":\"chain_verify\",\"session_id\":\"s\","
                "\"from_sequence\":1788722800424766173}"),
         "a lossy sequence literal was accepted");
}

/* --------------------------------------------------------------- 10 -- */

/* session_id is char[64]: 63 usable characters. */
#define S63 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define S64 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"

static void item10(void)
{
    TEST("10: a session_id that exactly fills the buffer is accepted");
    WANT(parse("{\"action\":\"chain_append\",\"session_id\":\"" S63 "\","
               "\"artifact_type\":\"observation\",\"artifact_id\":\"a\","
               "\"artifact_hash\":\"" S63 "a\"}"),
         "the longest legal id was refused");

    TEST("10: one byte over is REFUSED, not truncated to the same string");
    WANT(!parse("{\"action\":\"chain_append\",\"session_id\":\"" S64 "\","
                "\"artifact_type\":\"observation\",\"artifact_id\":\"a\","
                "\"artifact_hash\":\"" S63 "a\"}"),
         "an over-length session_id was accepted (and truncated)");

    TEST("10: an over-length artifact_type is REFUSED");
    WANT(!parse("{\"action\":\"chain_append\",\"session_id\":\"s\","
                "\"artifact_type\":\"comparator_verdict\","
                "\"artifact_id\":\"a\",\"artifact_hash\":\"" S63 "a\"}"),
         "an 18-character artifact_type was accepted into a char[16]");

    TEST("10: the truncated alias production stores is still accepted");
    WANT(parse("{\"action\":\"chain_append\",\"session_id\":\"s\","
               "\"artifact_type\":\"comparator_verd\","
               "\"artifact_id\":\"a\",\"artifact_hash\":\"" S63 "a\"}"),
         "the legacy spelling was refused; existing entries carry it");

    TEST("10: the chainwalk alias is still accepted");
    WANT(parse("{\"action\":\"chain_append\",\"session_id\":\"s\","
               "\"artifact_type\":\"chainwalk_summa\","
               "\"artifact_id\":\"a\",\"artifact_hash\":\"" S63 "a\"}"),
         "the legacy spelling was refused");
}

/* --------------------------------------------------------------- 12 -- */

static void item12(void)
{
    TEST("12: the validator accepts an ordinary id");
    WANT(virp_chain_canonical_string_ok("gate-enforce:R1"), "rejected");

    TEST("12: a double quote is refused");
    WANT(!virp_chain_canonical_string_ok("a\"b"), "quote accepted");

    TEST("12: a backslash is refused");
    WANT(!virp_chain_canonical_string_ok("a\\b"), "backslash accepted");

    TEST("12: a control byte is refused");
    WANT(!virp_chain_canonical_string_ok("a\nb"), "newline accepted");

    TEST("12: DEL (0x7F) is refused");
    WANT(!virp_chain_canonical_string_ok("a\x7f" "b"), "DEL accepted");

    TEST("12: well-formed UTF-8 is accepted");
    WANT(virp_chain_canonical_string_ok("R\xc3\xa9seau"), "UTF-8 rejected");

    TEST("12: a truncated UTF-8 sequence is refused");
    WANT(!virp_chain_canonical_string_ok("a\xc3"), "bad UTF-8 accepted");

    TEST("12: an over-long UTF-8 encoding is refused");
    WANT(!virp_chain_canonical_string_ok("\xc0\xaf"), "over-long accepted");

    TEST("12: a UTF-16 surrogate encoded in UTF-8 is refused");
    WANT(!virp_chain_canonical_string_ok("\xed\xa0\x80"),
         "surrogate accepted");

    TEST("12: a lone continuation byte is refused");
    WANT(!virp_chain_canonical_string_ok("\x80"), "continuation accepted");

    /* The ingress, not just the predicate. */
    TEST("12: a quoted session_id is refused at the ingress");
    WANT(!parse("{\"action\":\"chain_append\",\"session_id\":\"a\\\"b\","
                "\"artifact_type\":\"observation\",\"artifact_id\":\"a\","
                "\"artifact_hash\":\"" S63 "a\"}"),
         "a session_id the canonical form cannot carry was accepted");

    TEST("12: a quoted artifact_id is refused at the ingress");
    WANT(!parse("{\"action\":\"chain_append\",\"session_id\":\"s\","
                "\"artifact_type\":\"observation\","
                "\"artifact_id\":\"a\\\"b\","
                "\"artifact_hash\":\"" S63 "a\"}"),
         "a quoted artifact_id was accepted");

    TEST("12: a backslash in artifact_type is refused at the ingress");
    WANT(!parse("{\"action\":\"chain_append\",\"session_id\":\"s\","
                "\"artifact_type\":\"obs\\\\x\",\"artifact_id\":\"a\","
                "\"artifact_hash\":\"" S63 "a\"}"),
         "a backslash in artifact_type was accepted");
}

/* --------------------------------------------------------------- 12 -- */
/* The append path, which is where the malformed canonical form was built. */

static const char *DB = "/tmp/virp_test_jsonhygiene.db";
static const char *CK = "/tmp/virp_test_jsonhygiene.key";

static void item12_append(void)
{
    unlink(DB);
    unlink("/tmp/virp_test_jsonhygiene.db-wal");
    unlink("/tmp/virp_test_jsonhygiene.db-shm");
    unlink(CK);

    virp_signing_key_t k;
    virp_key_generate(&k, VIRP_KEY_TYPE_CHAIN);
    virp_key_save_file(&k, CK);
    virp_key_destroy(&k);

    virp_chain_state_t st;
    if (virp_chain_init(&st, DB, CK, 1, "local") != VIRP_OK) {
        TEST("12: append refuses a non-conformant session_id");
        BAD("chain init failed");
        return;
    }

    virp_chain_entry_t e;
    const char *H =
        "1111111111111111111111111111111111111111111111111111111111111111";

    TEST("12: append refuses a session_id carrying a quote");
    WANT(virp_chain_append(&st, "sess\"ion", "observation", "a-0", H, &e)
             != VIRP_OK,
         "a quoted session_id reached the canonical object");

    TEST("12: append refuses an artifact_id carrying a backslash");
    WANT(virp_chain_append(&st, "sess", "observation", "a\\0", H, &e)
             != VIRP_OK,
         "a backslashed artifact_id reached the canonical object");

    TEST("12: a conformant append still succeeds");
    WANT(virp_chain_append(&st, "sess", "observation", "a-0", H, &e)
             == VIRP_OK,
         "the validator refused a legitimate append");

    TEST("12: an org_id carrying a quote is refused at init");
    {
        virp_chain_state_t bad;
        WANT(virp_chain_init(&bad, "/tmp/virp_test_jsonhygiene2.db", CK, 1,
                             "or\"g") != VIRP_OK,
             "a non-conformant org_id would taint every entry this node writes");
    }

    virp_chain_destroy(&st);
    unlink(DB);
    unlink("/tmp/virp_test_jsonhygiene.db-wal");
    unlink("/tmp/virp_test_jsonhygiene.db-shm");
    unlink("/tmp/virp_test_jsonhygiene2.db");
    unlink(CK);
}

int main(void)
{
    printf("\n=== JSON ingress hygiene (HAM 2026-09-06) ===\n");
    item9();
    item10();
    item12();
    item12_append();
    printf("\n=== Results: %d passed, %d failed (of %d) ===\n",
           tests_passed, tests_failed, tests_run);
    return tests_failed ? 1 : 0;
}
