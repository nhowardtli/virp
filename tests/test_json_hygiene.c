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

int main(void)
{
    printf("\n=== JSON ingress hygiene (HAM 2026-09-06) ===\n");
    item9();
    printf("\n=== Results: %d passed, %d failed (of %d) ===\n",
           tests_passed, tests_failed, tests_run);
    return tests_failed ? 1 : 0;
}
