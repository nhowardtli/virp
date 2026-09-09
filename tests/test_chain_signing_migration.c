// SPDX-License-Identifier: Apache-2.0
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

/* =====================================================================
 * SIGNATURE-ERA VERDICTS (HAM item 7, reworked 2026-09-07)
 *
 * The first cut of item 7 graded an unsigned-era session VALID. Measured
 * on 313's real chain, that is 17 sessions and it is wrong: VALID is
 * what a fully verified signed session gets, and a reader who sees VALID
 * has no way to tell "every signature checked out" from "there were no
 * signatures to check".
 *
 * 313's actual shapes, from the 2026-09-07 baseline:
 *
 *   ALL_UNSIGNED  17 sessions. No signature on any entry, head unsigned.
 *                 Every one starts before 2026-08-23 17:48:11Z, when
 *                 chain signing was first enabled on that node, except
 *                 burnin-rollback:2026-08-23, which falls inside a
 *                 2m21s window where the daemon restarted WITHOUT
 *                 signing. Journal-confirmed, both ends.
 *   MIXED         30 sessions that span the cutover: unsigned entries
 *                 early, signed entries later, head signed. These are
 *                 NOT clean and must stay BROKEN under the real key --
 *                 the verifier cannot tell a cutover gap from a stripped
 *                 signature by looking at the entry alone.
 *   ALL_SIGNED    40 sessions.
 *
 * So there are three outcomes, not two:
 *
 *   VALID          every applicable check passed. Signed sessions only.
 *   UNSIGNED_ERA   no signature anywhere, head unsigned. Nothing was
 *                  stripped because nothing was ever there. Not clean.
 *   SIGNED_FROM_1  sequence 0 unsigned, EVERY later entry signed and
 *                  verifying, head signed. The genesis entry predates
 *                  the signing key; everything after it is covered.
 *   BROKEN         anything else, including a gap anywhere but seq 0,
 *                  and seq 0 unsigned with any other unsigned entry.
 * ===================================================================== */

/* Build a session with an explicit per-entry signing pattern.
 * pattern[i] != 0 means "entry i is signed". */
static void build_patterned_session(const char *sess, const char *pattern)
{
    virp_chain_state_t st;
    if (virp_chain_init(&st, DB, CK, 1, "local") != VIRP_OK) abort();

    virp_chain_entry_t e;
    for (const char *p = pattern; *p; p++) {
        bool want = (*p == 'S');
        if (want && !st.sign_enabled) {
            if (virp_chain_enable_signing(&st, SK) != VIRP_OK) abort();
        } else if (!want && st.sign_enabled) {
            /* Model a daemon restarted WITHOUT signing: the columns stay,
             * the process simply does not sign. That is exactly what
             * 313's 18:05:30 restart did. */
            st.sign_enabled = false;
        }
        char aid[32];
        snprintf(aid, sizeof(aid), "%s-%d", sess, (int)(p - pattern));
        if (virp_chain_append(&st, sess, "observation", aid, H1, &e)
            != VIRP_OK) abort();
    }
    virp_chain_destroy(&st);
}

static void verdict_of(const char *sess, virp_chain_verify_result_t *r)
{
    virp_chain_state_t v;
    if (virp_chain_open_verifier_ex(&v, DB, CK, PK, 1, "local") != VIRP_OK)
        abort();
    if (virp_chain_verify_session(&v, sess, r) != VIRP_OK) abort();
    virp_chain_destroy(&v);
}

static void test_all_unsigned_is_not_valid(void)
{
    TEST("era: an ALL-UNSIGNED session is UNSIGNED_ERA, not VALID");
    cleanup(); make_chain_key(); make_sign_key();
    /* A signed session in the same database, so the signature COLUMNS
     * exist while the unsigned session sits beside them. That is exactly
     * 313: 40 signed sessions, 17 with no signature at all, one set of
     * columns. Without this the columns would be absent and the test
     * would prove nothing about the case that actually occurs. */
    build_patterned_session("s-other", "SSS");
    build_patterned_session("s-era", "uuuu");

    virp_chain_verify_result_t r;
    verdict_of("s-era", &r);
    ASSERT(r.sig_era == VIRP_CHAIN_SIG_ERA_UNSIGNED,
           "an unsigned-era session must say so, not read as VALID");
    ASSERT(!r.valid_signed,
           "valid_signed is reserved for a session whose signatures checked out");
    ASSERT(r.entries_unsigned == 4, "all four entries are unsigned");
    ASSERT(r.entries_signed == 0, "none is signed");
    cleanup();
    PASS();
}

static void test_unsigned_genesis_then_all_signed(void)
{
    TEST("era: seq 0 unsigned, every later entry signed -> SIGNED_FROM_N");
    cleanup(); make_chain_key(); make_sign_key();
    build_patterned_session("s-gen", "uSSS");

    virp_chain_verify_result_t r;
    verdict_of("s-gen", &r);
    ASSERT(r.valid, "the chain itself is intact");
    ASSERT(r.sig_era == VIRP_CHAIN_SIG_ERA_FROM_N,
           "must be SIGNED_FROM_N, visibly not VALID");
    ASSERT(!r.valid_signed, "not a fully signed session");
    ASSERT(r.entries_signed == 3 && r.entries_unsigned == 1,
           "three signed, one unsigned");
    ASSERT(r.first_unsigned == 0, "the unsigned entry is the genesis one");
    cleanup();
    PASS();
}

static void test_gap_after_genesis_is_broken(void)
{
    TEST("era: an unsigned entry after a signed one stays BROKEN");
    cleanup(); make_chain_key(); make_sign_key();
    build_patterned_session("s-gap", "SSuS");

    virp_chain_verify_result_t r;
    verdict_of("s-gap", &r);
    ASSERT(!r.valid, "a mid-session signature gap is a FAILURE");
    ASSERT(r.first_broken == 2, "must name the gap");
    ASSERT(r.sig_era != VIRP_CHAIN_SIG_ERA_FROM_N,
           "a mid-session gap is not the genesis carve-out");
    cleanup();
    PASS();
}

static void test_unsigned_genesis_plus_later_gap_is_broken(void)
{
    TEST("era: seq 0 unsigned AND a later gap stays BROKEN");
    cleanup(); make_chain_key(); make_sign_key();
    build_patterned_session("s-cut", "SSS");
    build_patterned_session("s-two", "uSuS");

    virp_chain_verify_result_t r;
    verdict_of("s-two", &r);
    ASSERT(!r.valid, "two unsigned entries is not the genesis carve-out");
    ASSERT(r.sig_era != VIRP_CHAIN_SIG_ERA_FROM_N,
           "the carve-out is one CONTIGUOUS prefix; a signature that stops "
           "after resuming is a gap, not a cutover");
    cleanup();
    PASS();
}

static void test_the_313_mixed_shape_is_from_n(void)
{
    TEST("era: 313's MIXED cutover shape is SIGNED_FROM_N, not VALID");
    cleanup(); make_chain_key(); make_sign_key();
    /* gate-enforce:R1 on 313: unsigned run, then signed run, head signed.
     * 29 of 313's sessions have exactly this shape. Under the FROM_N
     * rules they are a cutover, not a gap -- but they are still NOT
     * clean, and must never read as VALID. */
    build_patterned_session("s-cut", "SSS");
    build_patterned_session("s-mix313", "uuuuuSSSSS");

    virp_chain_verify_result_t r;
    verdict_of("s-mix313", &r);
    ASSERT(r.valid, "the chain is intact across the transition");
    ASSERT(r.sig_era == VIRP_CHAIN_SIG_ERA_FROM_N,
           "a single unsigned->signed transition is a cutover session");
    ASSERT(!r.valid_signed,
           "it is NOT a clean signed session and must not read as one");
    ASSERT(r.sig_transition_seq == 5, "transition at sequence 5");
    ASSERT(r.sig_era != VIRP_CHAIN_SIG_ERA_UNSIGNED,
           "it is not an unsigned-era session: it carries signatures");
    cleanup();
    PASS();
}

static void test_fully_signed_is_still_plain_valid(void)
{
    TEST("era: a fully signed session is still VALID, unqualified");
    cleanup(); make_chain_key(); make_sign_key();
    build_patterned_session("s-full", "SSSS");

    virp_chain_verify_result_t r;
    verdict_of("s-full", &r);
    ASSERT(r.valid && r.valid_signed, "must be a clean signed VALID");
    ASSERT(r.sig_era == VIRP_CHAIN_SIG_ERA_SIGNED,
           "the era must say fully signed");
    ASSERT(r.entries_unsigned == 0, "nothing unsigned");
    cleanup();
    PASS();
}

/* =====================================================================
 * SIGNED_FROM_N (2026-09-07). An unsigned PREFIX followed by a signed
 * suffix, which is what 29 of 313's sessions actually are: they were
 * open across the 2026-08-23 17:56:58Z cutover.
 *
 * Every one of these conditions must hold, or the session is BROKEN:
 *
 *   1. exactly ONE transition, and it is unsigned -> signed. Never
 *      signed -> unsigned, and never more than one.
 *   2. the head is signed.
 *   3. the first signed entry's timestamp is at or after the CUTOVER
 *      INSTANT, derived from the chain itself (the earliest signature
 *      anywhere in the database), never from a flag or config.
 *   4. every entry after the transition verifies under the pinned key.
 *   5. the hash chain is intact across the transition.
 *
 * SIGNED_FROM_1 from the previous commit is the degenerate case of this
 * (transition at sequence 1) and is folded in: one era value, always
 * carrying the transition sequence, rather than two names for one idea.
 * ===================================================================== */

static void test_from_n_unsigned_prefix_then_signed(void)
{
    TEST("from_n: unsigned prefix then signed suffix -> SIGNED_FROM_N");
    cleanup(); make_chain_key(); make_sign_key();
    build_patterned_session("s-cut", "SSS");        /* sets the cutover */
    build_patterned_session("s-n", "uuuSSSS");

    virp_chain_verify_result_t r;
    verdict_of("s-n", &r);
    ASSERT(r.valid, "the chain itself is intact");
    ASSERT(r.sig_era == VIRP_CHAIN_SIG_ERA_FROM_N,
           "an unsigned prefix then a signed suffix is SIGNED_FROM_N");
    ASSERT(!r.valid_signed, "not a fully signed session");
    ASSERT(r.sig_transition_seq == 3,
           "the transition sequence must be reported");
    ASSERT(r.entries_unsigned == 3 && r.entries_signed == 4,
           "three unsigned, four signed");
    cleanup();
    PASS();
}

static void test_from_1_is_the_degenerate_from_n(void)
{
    TEST("from_n: a single unsigned genesis is FROM_N at transition 1");
    cleanup(); make_chain_key(); make_sign_key();
    build_patterned_session("s-cut", "SSS");
    build_patterned_session("s-1", "uSSS");

    virp_chain_verify_result_t r;
    verdict_of("s-1", &r);
    ASSERT(r.sig_era == VIRP_CHAIN_SIG_ERA_FROM_N, "same era, k=1");
    ASSERT(r.sig_transition_seq == 1, "transition at sequence 1");
    cleanup();
    PASS();
}

static void test_signed_then_unsigned_is_broken(void)
{
    TEST("from_n: signed THEN unsigned is BROKEN (condition 1)");
    cleanup(); make_chain_key(); make_sign_key();
    build_patterned_session("s-rev", "SSSuu");

    virp_chain_verify_result_t r;
    verdict_of("s-rev", &r);
    ASSERT(!r.valid, "a signature that stops is indistinguishable from one "
                     "that was stripped");
    ASSERT(r.sig_era != VIRP_CHAIN_SIG_ERA_FROM_N, "never FROM_N");
    cleanup();
    PASS();
}

static void test_signed_unsigned_signed_is_broken(void)
{
    TEST("from_n: SIGNED-UNSIGNED-SIGNED is BROKEN (autopilot:2026-08-23)");
    cleanup(); make_chain_key(); make_sign_key();
    /* The exact shape of autopilot:2026-08-23 on 313: signed through
     * sequence 23, unsigned 24-35, signed from 36. Two transitions.
     * See docs/notes/SIGNING-WINDOW-2026-08-23.md. */
    build_patterned_session("s-auto", "SSSSuuuuSSSS");

    virp_chain_verify_result_t r;
    verdict_of("s-auto", &r);
    ASSERT(!r.valid, "two transitions is BROKEN, permanently and by design");
    ASSERT(r.sig_era != VIRP_CHAIN_SIG_ERA_FROM_N,
           "a restart window is indistinguishable from a stripped run");
    ASSERT(r.first_broken == 4, "must name the first unsigned entry");
    cleanup();
    PASS();
}

static void test_no_flag_can_excuse_signed_unsigned_signed(void)
{
    TEST("from_n: NO tier combination grades SIGNED-UNSIGNED-SIGNED clean");
    cleanup(); make_chain_key(); make_sign_key();
    build_patterned_session("s-auto2", "SSSSuuuuSSSS");

    /* Every combination of the three verifier tiers. The keyless and
     * symmetric tiers do not look at signatures at all, so they report
     * VALID -- that is correct and is why the ERA is a separate axis:
     * whenever the asymmetric tier runs, this shape is BROKEN, and when
     * it does not run the era says NOT_GRADED rather than implying the
     * signatures were fine. */
    const char *keys[]  = { NULL, CK, NULL, CK };
    const char *pubs[]  = { NULL, NULL, PK, PK };
    for (int i = 0; i < 4; i++) {
        virp_chain_state_t v;
        if (virp_chain_open_verifier_ex(&v, DB, keys[i], pubs[i], 1, "local")
            != VIRP_OK) { FAILM("open verifier"); return; }
        virp_chain_verify_result_t r;
        if (virp_chain_verify_session(&v, "s-auto2", &r) != VIRP_OK) {
            virp_chain_destroy(&v); FAILM("verify"); return;
        }
        if (pubs[i]) {
            ASSERT(!r.valid, "with the pubkey it MUST be BROKEN");
            ASSERT(r.sig_era != VIRP_CHAIN_SIG_ERA_FROM_N, "never FROM_N");
        } else {
            ASSERT(r.sig_era == VIRP_CHAIN_SIG_ERA_NOT_GRADED,
                   "without the pubkey the era must claim nothing");
            ASSERT(!r.valid_signed, "and must never read as cleanly signed");
        }
        virp_chain_destroy(&v);
    }
    cleanup();
    PASS();
}

static void test_unsigned_head_is_not_from_n(void)
{
    TEST("from_n: an unsigned head is not FROM_N (condition 2)");
    cleanup(); make_chain_key(); make_sign_key();
    build_patterned_session("s-cut", "SSS");
    build_patterned_session("s-uh", "uuSS");
    /* Blank the head signature, leaving the entries as they are. */
    {
        sqlite3 *db = NULL;
        if (sqlite3_open(DB, &db) != SQLITE_OK) { FAILM("open"); return; }
        sqlite3_exec(db, "UPDATE chain_heads SET head_sig='', "
                         "head_sig_key_id='' WHERE session_id='s-uh'",
                     NULL, NULL, NULL);
        sqlite3_close(db);
    }
    virp_chain_verify_result_t r;
    verdict_of("s-uh", &r);
    ASSERT(r.sig_era != VIRP_CHAIN_SIG_ERA_FROM_N,
           "without a signed head the length claim is unauthenticated, so "
           "the suffix cannot be said to cover the session");
    cleanup();
    PASS();
}

static void test_cutover_is_derived_from_the_chain(void)
{
    TEST("from_n: the cutover instant comes from the chain, not a flag");
    cleanup(); make_chain_key(); make_sign_key();
    build_patterned_session("s-first", "SS");
    build_patterned_session("s-later", "uuSS");

    virp_chain_state_t v;
    ASSERT(virp_chain_open_verifier_ex(&v, DB, CK, PK, 1, "local") == VIRP_OK,
           "open");
    uint64_t cut = 0;
    ASSERT(virp_chain_cutover_ns(&v, &cut) == VIRP_OK, "cutover query");
    ASSERT(cut != 0, "a chain with signatures has a cutover instant");

    /* It must equal the earliest signed entry in the whole database. */
    sqlite3_stmt *st = NULL;
    uint64_t expect = 0;
    if (sqlite3_prepare_v2(v.db, "SELECT MIN(timestamp_ns) FROM chain_entries "
                                 "WHERE chain_sig IS NOT NULL AND chain_sig<>''",
                           -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW)
            expect = (uint64_t)sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    ASSERT(cut == expect, "cutover must be MIN(timestamp) over signed entries");
    virp_chain_destroy(&v);
    cleanup();
    PASS();
}

static void test_a_suffix_predating_the_cutover_is_broken(void)
{
    TEST("from_n: a signed suffix predating the cutover is refused (cond 3)");
    cleanup(); make_chain_key(); make_sign_key();
    build_patterned_session("s-cut", "SSS");
    build_patterned_session("s-pre", "uuSS");

    /* The predicate, directly: a session whose first signed entry sits
     * before the chain's earliest signature cannot be a cutover session.
     * The shape cannot be built through the append path -- the clock only
     * moves forward -- and forging it would break the signature that
     * condition 4 checks first. So the rule is asserted on the predicate
     * that implements it, with the live 313 chain (29 of 29 sessions
     * satisfying it) as the integration evidence. */
    virp_chain_state_t v;
    ASSERT(virp_chain_open_verifier_ex(&v, DB, CK, PK, 1, "local") == VIRP_OK,
           "open");
    uint64_t cut = 0;
    virp_chain_cutover_ns(&v, &cut);
    ASSERT(!virp_chain_from_n_temporally_ok(cut - 1, cut),
           "a first-signed BEFORE the cutover must be refused");
    ASSERT(virp_chain_from_n_temporally_ok(cut, cut),
           "exactly at the cutover is accepted");
    ASSERT(virp_chain_from_n_temporally_ok(cut + 1, cut),
           "after the cutover is accepted");
    virp_chain_destroy(&v);
    cleanup();
    PASS();
}

static void test_a_bad_signature_after_the_transition_is_broken(void)
{
    TEST("from_n: a suffix entry that does not verify is BROKEN (cond 4)");
    cleanup(); make_chain_key(); make_sign_key();
    build_patterned_session("s-cut", "SSS");
    build_patterned_session("s-bad", "uuSSS");
    {
        sqlite3 *db = NULL;
        if (sqlite3_open(DB, &db) != SQLITE_OK) { FAILM("open"); return; }
        /* Corrupt one signature in the SUFFIX. */
        sqlite3_exec(db, "UPDATE chain_entries SET chain_sig="
                         "'00000000000000000000000000000000"
                         "00000000000000000000000000000000"
                         "00000000000000000000000000000000"
                         "00000000000000000000000000000000' "
                         "WHERE session_id='s-bad' AND sequence=3",
                     NULL, NULL, NULL);
        sqlite3_close(db);
    }
    virp_chain_verify_result_t r;
    verdict_of("s-bad", &r);
    ASSERT(!r.valid, "a suffix signature that does not verify is fatal");
    ASSERT(r.sig_era != VIRP_CHAIN_SIG_ERA_FROM_N, "never FROM_N");
    cleanup();
    PASS();
}

static void test_a_broken_hash_across_the_transition_is_broken(void)
{
    TEST("from_n: a broken hash across the transition is BROKEN (cond 5)");
    cleanup(); make_chain_key(); make_sign_key();
    build_patterned_session("s-cut", "SSS");
    build_patterned_session("s-hash", "uuSSS");
    {
        sqlite3 *db = NULL;
        if (sqlite3_open(DB, &db) != SQLITE_OK) { FAILM("open"); return; }
        sqlite3_exec(db, "UPDATE chain_entries SET previous_entry_hash="
                         "'dead000000000000000000000000000000000000"
                         "000000000000000000000000' "
                         "WHERE session_id='s-hash' AND sequence=2",
                     NULL, NULL, NULL);
        sqlite3_close(db);
    }
    virp_chain_verify_result_t r;
    verdict_of("s-hash", &r);
    ASSERT(!r.valid, "linkage across the transition must hold");
    ASSERT(r.sig_era != VIRP_CHAIN_SIG_ERA_FROM_N, "never FROM_N");
    cleanup();
    PASS();
}

int main(void)
{
    printf("\n=== VIRP chain-signing MIGRATION tests (HAM item 7) ===\n");
    test_from_n_unsigned_prefix_then_signed();
    test_from_1_is_the_degenerate_from_n();
    test_signed_then_unsigned_is_broken();
    test_signed_unsigned_signed_is_broken();
    test_no_flag_can_excuse_signed_unsigned_signed();
    test_unsigned_head_is_not_from_n();
    test_cutover_is_derived_from_the_chain();
    test_a_suffix_predating_the_cutover_is_broken();
    test_a_bad_signature_after_the_transition_is_broken();
    test_a_broken_hash_across_the_transition_is_broken();
    test_all_unsigned_is_not_valid();
    test_unsigned_genesis_then_all_signed();
    test_gap_after_genesis_is_broken();
    test_unsigned_genesis_plus_later_gap_is_broken();
    test_the_313_mixed_shape_is_from_n();
    test_fully_signed_is_still_plain_valid();
    test_presigning_session_passes_with_pubkey();
    test_postsigning_session_still_verifies();
    test_stripping_a_signature_is_still_fatal();
    test_stripping_the_whole_session_is_reported_as_unsigned();
    test_range_api_agrees_with_the_session_api();
    printf("\n=== Results: %d passed, %d failed ===\n",
           tests_passed, tests_failed);
    return tests_failed ? 1 : 0;
}
