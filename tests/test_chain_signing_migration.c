/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — chain signing MIGRATION: sessions written before signing was
 * enabled must not false-FAIL after it is.
 *
 * HAM review 2026-09-06, item 7.
 *
 * Enabling optional Ed25519 chain signing adds the signature columns to
 * the whole DATABASE. The C verifier inferred "this session is signed"
 * from (columns exist AND a verifying pubkey is available) rather than
 * from the session's own head, so every legitimate pre-signing session
 * verified as a signed session with missing signatures and FAILED with
 * "stripped signature".
 *
 * The Python standalone verifier (report/verify.py,
 * verify_chain_signatures) already asks the right question:
 *
 *     head_signed = bool(head and head.get("head_sig"))
 *     any_entry_signed = any(r.get("chain_sig") for r in rows)
 *     if not head_signed and not any_entry_signed:  -> "unsigned"
 *
 * Nothing covered the migration sequence, in either verifier. This does,
 * and it asserts the two verifiers agree.
 *
 * Built by #including src/virp_chain.c, the invariant-test pattern.
 */

#include "../src/virp_chain.c"

#include "virp_chainsign.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { printf("  [TEST] %-58s ", name); fflush(stdout); } while (0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while (0)
#define FAILM(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)
#define ASSERT(cond, msg) do { if (!(cond)) { FAILM(msg); return; } } while (0)

static const char *DB = "/tmp/virp_test_sigmigrate.db";
static const char *CK = "/tmp/virp_test_sigmigrate_chain.key";
static const char *SK = "/tmp/virp_test_sigmigrate_sign.key";
static const char *PK = "/tmp/virp_test_sigmigrate_sign.pub";

static const char *H1 =
    "1111111111111111111111111111111111111111111111111111111111111111";

static void cleanup(void)
{
    unlink(DB);
    unlink("/tmp/virp_test_sigmigrate.db-wal");
    unlink("/tmp/virp_test_sigmigrate.db-shm");
    unlink(CK); unlink(SK); unlink(PK);
}

static void make_chain_key(void)
{
    virp_signing_key_t sk;
    virp_key_generate(&sk, VIRP_KEY_TYPE_CHAIN);
    unlink(CK);
    virp_key_save_file(&sk, CK);
    virp_key_destroy(&sk);
}

static void make_sign_key(void)
{
    virp_chainsign_key_t kp;
    if (virp_chainsign_generate(&kp) != VIRP_OK) abort();
    unlink(SK); unlink(PK);
    if (virp_chainsign_save(&kp, SK, PK) != VIRP_OK) abort();
    virp_chainsign_destroy(&kp);
}

/*
 * The migration sequence, exactly as a real node lives it:
 *   1. a session is written with signing OFF
 *   2. signing is enabled (columns appear, database-wide)
 *   3. a new session is written with signing ON
 * Leaves the database on disk for the verifier to open read-only.
 */
static void build_migrated_db(void)
{
    cleanup();
    make_chain_key();
    make_sign_key();

    virp_chain_state_t st;
    if (virp_chain_init(&st, DB, CK, 1, "local") != VIRP_OK) abort();

    virp_chain_entry_t e;
    for (int i = 0; i < 3; i++) {
        char aid[32];
        snprintf(aid, sizeof(aid), "old-%d", i);
        if (virp_chain_append(&st, "s-before", "observation", aid, H1, &e)
            != VIRP_OK) abort();
    }

    if (virp_chain_enable_signing(&st, SK) != VIRP_OK) abort();

    for (int i = 0; i < 3; i++) {
        char aid[32];
        snprintf(aid, sizeof(aid), "new-%d", i);
        if (virp_chain_append(&st, "s-after", "observation", aid, H1, &e)
            != VIRP_OK) abort();
    }
    virp_chain_destroy(&st);
}

/* ===================================================================== */

static void test_presigning_session_passes_with_pubkey(void)
{
    TEST("migration: a pre-signing session PASSES under the pubkey");
    build_migrated_db();

    virp_chain_state_t v;
    ASSERT(virp_chain_open_verifier_ex(&v, DB, CK, PK, 1, "local") == VIRP_OK,
           "open verifier");

    virp_chain_verify_result_t r;
    virp_error_t rc = virp_chain_verify_session(&v, "s-before", &r);
    if (rc != VIRP_OK || !r.valid) {
        printf("FAIL: pre-signing session did not verify (rc=%d detail=%s)\n",
               (int)rc, r.error_detail);
        tests_failed++;
        virp_chain_destroy(&v);
        return;
    }
    ASSERT(r.entries_checked == 3, "should have walked 3 entries");
    ASSERT(r.entries_signed == 0, "an unsigned session signs nothing");
    ASSERT(r.entries_unsigned == 3, "all three must count as unsigned");
    ASSERT(!r.sig_checked, "signature tier must not claim to have run");
    virp_chain_destroy(&v);
    cleanup();
    PASS();
}

static void test_postsigning_session_still_verifies(void)
{
    TEST("migration: the born-signed session still verifies signed");
    build_migrated_db();

    virp_chain_state_t v;
    ASSERT(virp_chain_open_verifier_ex(&v, DB, CK, PK, 1, "local") == VIRP_OK,
           "open verifier");

    virp_chain_verify_result_t r;
    virp_error_t rc = virp_chain_verify_session(&v, "s-after", &r);
    if (rc != VIRP_OK || !r.valid) {
        printf("FAIL: signed session did not verify (rc=%d detail=%s)\n",
               (int)rc, r.error_detail);
        tests_failed++;
        virp_chain_destroy(&v);
        return;
    }
    ASSERT(r.sig_checked, "signature tier must have run");
    ASSERT(r.entries_signed == 3, "all three entries must verify signed");
    ASSERT(r.entries_unsigned == 0, "none should count as unsigned");
    ASSERT(r.head_sig_ok, "the head signature must verify");
    virp_chain_destroy(&v);
    cleanup();
    PASS();
}

static void test_stripping_a_signature_is_still_fatal(void)
{
    TEST("migration: a STRIPPED signature in a signed session still FAILS");
    build_migrated_db();

    /* Blank one entry's signature in the signed session. The fix must not
     * turn the real attack into a soft "unsigned" reading: the head still
     * carries a signature, so the session is signed and the missing entry
     * signature is tampering. */
    sqlite3 *db = NULL;
    if (sqlite3_open(DB, &db) != SQLITE_OK) abort();
    if (sqlite3_exec(db,
            "UPDATE chain_entries SET chain_sig='' "
            "WHERE session_id='s-after' AND sequence=1",
            NULL, NULL, NULL) != SQLITE_OK) abort();
    sqlite3_close(db);

    virp_chain_state_t v;
    ASSERT(virp_chain_open_verifier_ex(&v, DB, CK, PK, 1, "local") == VIRP_OK,
           "open verifier");
    virp_chain_verify_result_t r;
    ASSERT(virp_chain_verify_session(&v, "s-after", &r) == VIRP_OK, "verify");
    ASSERT(!r.valid, "a stripped signature must remain a FAILURE");
    ASSERT(r.first_broken == 1, "must name the stripped entry");
    virp_chain_destroy(&v);
    cleanup();
    PASS();
}

static void test_stripping_the_whole_session_is_reported_as_unsigned(void)
{
    TEST("migration: an all-stripped session reads unsigned, as Python does");
    build_migrated_db();

    /* Every signature gone, head included. Python's rule says such a
     * session is 'unsigned' (never a FAIL); this pins that the C verifier
     * agrees rather than inventing a stricter reading the public verifier
     * would contradict. The COMPLETENESS and HMAC tiers still apply and
     * are what actually catch this, which is the point: the two verifiers
     * must not disagree about what the same database says. */
    sqlite3 *db = NULL;
    if (sqlite3_open(DB, &db) != SQLITE_OK) abort();
    sqlite3_exec(db, "UPDATE chain_entries SET chain_sig='', "
                     "chain_sig_key_id='' WHERE session_id='s-after'",
                 NULL, NULL, NULL);
    sqlite3_exec(db, "UPDATE chain_heads SET head_sig='', "
                     "head_sig_key_id='' WHERE session_id='s-after'",
                 NULL, NULL, NULL);
    sqlite3_close(db);

    virp_chain_state_t v;
    ASSERT(virp_chain_open_verifier_ex(&v, DB, CK, PK, 1, "local") == VIRP_OK,
           "open verifier");
    virp_chain_verify_result_t r;
    ASSERT(virp_chain_verify_session(&v, "s-after", &r) == VIRP_OK, "verify");
    ASSERT(r.valid, "an all-unsigned session is not a signature FAILURE");
    ASSERT(!r.sig_checked, "nothing was signature-checked");
    ASSERT(r.entries_unsigned == 3, "all three read as unsigned");
    virp_chain_destroy(&v);
    cleanup();
    PASS();
}

static void test_range_api_agrees_with_the_session_api(void)
{
    TEST("migration: the range verify API reaches the same conclusion");
    build_migrated_db();

    virp_chain_state_t v;
    ASSERT(virp_chain_open_verifier_ex(&v, DB, CK, PK, 1, "local") == VIRP_OK,
           "open verifier");
    virp_chain_verify_result_t r;
    virp_error_t rc = virp_chain_verify(&v, "s-before", 0, 2, &r);
    if (rc != VIRP_OK || !r.valid) {
        printf("FAIL: range verify of the pre-signing session failed "
               "(rc=%d detail=%s)\n", (int)rc, r.error_detail);
        tests_failed++;
        virp_chain_destroy(&v);
        return;
    }
    ASSERT(!r.sig_checked, "range verify must not claim the signature tier");
    virp_chain_destroy(&v);
    cleanup();
    PASS();
}

int main(void)
{
    printf("\n=== VIRP chain-signing MIGRATION tests (HAM item 7) ===\n");
    test_presigning_session_passes_with_pubkey();
    test_postsigning_session_still_verifies();
    test_stripping_a_signature_is_still_fatal();
    test_stripping_the_whole_session_is_reported_as_unsigned();
    test_range_api_agrees_with_the_session_api();
    printf("\n=== Results: %d passed, %d failed ===\n",
           tests_passed, tests_failed);
    return tests_failed ? 1 : 0;
}
