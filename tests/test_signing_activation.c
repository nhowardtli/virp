/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — D-1 signing ACTIVATION: what may turn -S on, and on what (V39 item 2)
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The Sep 1 Docket run graded 18 organic sessions on 313 FAILED. Nothing
 * was tampered with. `-S` was enabled on a database that already held open
 * per-device chain sessions, so every session that straddled the cutover
 * ended up with unsigned entries under a signed head — which the verifier
 * calls a stripped signature, correctly and fatally.
 *
 * A chain session is signed or unsigned AS A WHOLE. The daemon's sessions
 * are keyed by device, not by process lifetime, so they outlive restarts
 * and simply continue at the next sequence. "Add -S to the unit and
 * restart" therefore cannot be a safe cutover, and never was.
 *
 * WHAT IS PINNED HERE
 *   Passing, describing today's shipped behaviour:
 *     - a fresh database born signed: every entry and the head carry a
 *       signature under ONE key_id, and the session verifies;
 *     - reopening with the SAME key continues the session under the same
 *       key_id and still verifies;
 *     - THE 313 SHAPE, reproduced: unsigned entries, then activation, then
 *       more entries — the session now FAILS verification. This is the
 *       evidence for the rule, and it must keep failing.
 *
 *   PENDING (known-failing by design), stating the acceptance criteria for
 *   OPTION A — "signing may only be enabled on an empty database":
 *     - activation on a NONEMPTY database must be refused, and must leave
 *       the database file byte-identical (it does not today: the four
 *       ALTER TABLE ADD COLUMN statements run before anything could
 *       refuse, so the attempt itself mutates the file);
 *     - reopening a signed database with a DIFFERENT signing key must be
 *       refused at startup, naming the database and both key_ids (it is
 *       not today: the daemon signs new entries under the new key_id and
 *       the disagreement surfaces later, at read time, on somebody else's
 *       screen).
 *
 * NO DAEMON CODE CHANGE ACCOMPANIES THIS FILE. Item 2 was launched with no
 * rule ticked, which the work order defines as option C: tests and runbook
 * only, against option A as the provisional choice. The runbook is
 * docs/SIGNING-CUTOVER.md. When a rule is ruled and implemented, the two
 * PENDING markers below must be removed in the same commit that makes them
 * pass — a pending marker that silently becomes correct is how stale
 * markers accumulate.
 *
 * The D-0 Appendix A fixtures and the D-1 golden vectors are NOT duplicated
 * here; they are already locked by `make test-chain-invariant` and
 * `make test-chainsign-vectors`, and nothing in this file writes to them.
 */
#define _POSIX_C_SOURCE 200809L

#include "virp.h"
#include "virp_chain.h"
#include "virp_chainsign.h"
#include "virp_crypto.h"

#include <openssl/evp.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int tests_passed, tests_failed, tests_pending, pending_unexpected;
static int current_failed;

#define TEST(name) do { printf("  [TEST] %-58s ", name); fflush(stdout); \
                        current_failed = 0; } while (0)
#define FAILM(msg) do { printf("FAIL: %s (line %d)\n", msg, __LINE__); \
                        current_failed = 1; } while (0)
#define ASSERT(c, m) do { if (!(c)) { FAILM(m); return; } } while (0)

/* Same discipline as tests/test_onode.c: a known-failing-by-design test is
 * counted in its own bucket, never as a pass, and an unexpected PASS is a
 * hard failure because the marker has become a lie. */
#define RUN(fn) do { fn(); if (current_failed) tests_failed++; \
                     else { tests_passed++; printf("PASS\n"); } } while (0)
#define RUN_PENDING(fn, criterion) do { \
    fn(); \
    if (current_failed) { \
        tests_pending++; \
        printf("    ^^ [PENDING] known-failing by design; NOT a pass\n"); \
        printf("       acceptance criterion: %s\n", (criterion)); \
    } else { \
        tests_failed++; pending_unexpected++; \
        printf("[PENDING BUT PASSED]\n"); \
        printf("    The acceptance criterion is met — remove the marker\n"); \
        printf("    in the same commit that made it pass.\n"); \
    } \
} while (0)

static const char *DB  = "/tmp/virp-sigact.db";
static const char *WAL = "/tmp/virp-sigact.db-wal";
static const char *SHM = "/tmp/virp-sigact.db-shm";
static const char *CK  = "/tmp/virp-sigact-chain.key";
static const char *SK1 = "/tmp/virp-sigact-sign1.key";
static const char *PK1 = "/tmp/virp-sigact-sign1.pub";
static const char *SK2 = "/tmp/virp-sigact-sign2.key";
static const char *PK2 = "/tmp/virp-sigact-sign2.pub";
static const char *SESSION = "gate-enforce:SIGACT-DEV";

static void cleanup(void)
{
    unlink(DB); unlink(WAL); unlink(SHM);
    unlink(CK); unlink(SK1); unlink(PK1); unlink(SK2); unlink(PK2);
}

static void make_chain_key(void)
{
    virp_signing_key_t k;
    virp_key_generate(&k, VIRP_KEY_TYPE_CHAIN);
    unlink(CK);
    virp_key_save_file(&k, CK);
    virp_key_destroy(&k);
}

static void make_sign_key(const char *sk, const char *pk, char key_id_out[33])
{
    virp_chainsign_key_t kp;
    if (virp_chainsign_generate(&kp) != VIRP_OK) abort();
    unlink(sk); unlink(pk);
    if (virp_chainsign_save(&kp, sk, pk) != VIRP_OK) abort();
    if (key_id_out) memcpy(key_id_out, kp.key_id_hex, 33);
    virp_chainsign_destroy(&kp);
}

/* sha256 of a whole file, hex. The byte-identity check for option A. */
static int file_sha256(const char *path, char out[65])
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c, EVP_sha256(), NULL);
    unsigned char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        EVP_DigestUpdate(c, buf, n);
    fclose(f);
    unsigned char md[32]; unsigned int mdl = 0;
    EVP_DigestFinal_ex(c, md, &mdl);
    EVP_MD_CTX_free(c);
    for (int i = 0; i < 32; i++) snprintf(out + i * 2, 3, "%02x", md[i]);
    return 0;
}

static int append_n(virp_chain_state_t *st, const char *prefix, int n)
{
    for (int i = 0; i < n; i++) {
        char id[64], h[65];
        snprintf(id, sizeof(id), "%s-%d", prefix, i);
        memset(h, (char)('a' + (i % 6)), 64); h[64] = '\0';
        virp_chain_entry_t e;
        if (virp_chain_append(st, SESSION, "observation", id, h, &e) != VIRP_OK)
            return -1;
    }
    return 0;
}

/* Read one text column from the chain database through a SEPARATE
 * connection, so nothing here depends on the writer's cached statements. */
static int col(const char *sql, char *out, size_t cap)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(DB, &db) != SQLITE_OK) return -1;
    sqlite3_stmt *s = NULL;
    int rc = -1;
    out[0] = '\0';
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW) {
        const unsigned char *t = sqlite3_column_text(s, 0);
        snprintf(out, cap, "%s", t ? (const char *)t : "");
        rc = 0;
    }
    if (s) sqlite3_finalize(s);
    sqlite3_close(db);
    return rc;
}

static int count_int(const char *sql)
{
    char buf[64];
    if (col(sql, buf, sizeof(buf)) != 0) return -1;
    return atoi(buf);
}

/* ═════════════════════ passing: today's behaviour ═════════════════════ */

static void test_fresh_db_born_signed(void)
{
    TEST("fresh DB + -S: every entry and the head signed, one key_id");
    cleanup();
    make_chain_key();
    char kid[33];
    make_sign_key(SK1, PK1, kid);

    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 0x51ACA000, "local") == VIRP_OK, "init");
    ASSERT(virp_chain_enable_signing(&st, SK1) == VIRP_OK,
           "enable_signing on an EMPTY database must succeed");
    ASSERT(append_n(&st, "born", 4) == 0, "append");

    virp_chain_verify_result_t r;
    memset(&r, 0, sizeof(r));
    ASSERT(virp_chain_verify_session(&st, SESSION, &r) == VIRP_OK, "verify rc");
    ASSERT(r.valid, "a born-signed session must verify");
    ASSERT(r.entries_checked == 4, "four entries");
    ASSERT(r.entries_unsigned == 0 || !r.sig_key_unavailable,
           "no unsigned entries in a born-signed session");
    virp_chain_destroy(&st);

    /* Session key binding: one key_id across every entry AND the head. */
    ASSERT(count_int("SELECT COUNT(*) FROM chain_entries "
                     "WHERE chain_sig IS NULL OR chain_sig = ''") == 0,
           "every entry carries a signature");
    ASSERT(count_int("SELECT COUNT(DISTINCT chain_sig_key_id) "
                     "FROM chain_entries") == 1,
           "exactly one signing key_id across the session");
    char got[64];
    ASSERT(col("SELECT DISTINCT chain_sig_key_id FROM chain_entries",
               got, sizeof(got)) == 0 && strcmp(got, kid) == 0,
           "entries carry THIS key_id");
    ASSERT(col("SELECT head_sig_key_id FROM chain_heads", got,
               sizeof(got)) == 0 && strcmp(got, kid) == 0,
           "the head carries the same key_id as the entries");
    ASSERT(col("SELECT head_sig FROM chain_heads", got, sizeof(got)) == 0 &&
           got[0], "the head is signed");
    cleanup();
}

static void test_restart_same_key_continues(void)
{
    TEST("restart with the SAME key: continues, same key_id, verifies");
    cleanup();
    make_chain_key();
    char kid[33];
    make_sign_key(SK1, PK1, kid);

    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 0x51ACA000, "local") == VIRP_OK, "init 1");
    ASSERT(virp_chain_enable_signing(&st, SK1) == VIRP_OK, "enable 1");
    ASSERT(append_n(&st, "pre", 3) == 0, "append 1");
    virp_chain_destroy(&st);

    /* The restart. Same database, same K_chain, same signing secret. */
    ASSERT(virp_chain_init(&st, DB, CK, 0x51ACA000, "local") == VIRP_OK, "init 2");
    ASSERT(virp_chain_enable_signing(&st, SK1) == VIRP_OK,
           "re-enabling with the same key is idempotent");
    ASSERT(append_n(&st, "post", 3) == 0, "append 2");

    virp_chain_verify_result_t r;
    memset(&r, 0, sizeof(r));
    ASSERT(virp_chain_verify_session(&st, SESSION, &r) == VIRP_OK, "verify rc");
    ASSERT(r.valid, "the session must still verify across the restart");
    ASSERT(r.entries_checked == 6, "six entries");
    virp_chain_destroy(&st);

    ASSERT(count_int("SELECT COUNT(DISTINCT chain_sig_key_id) "
                     "FROM chain_entries") == 1,
           "still exactly one key_id after the restart");
    cleanup();
}

static void test_straddled_session_fails_verification(void)
{
    TEST("THE 313 SHAPE: unsigned entries then -S = session FAILS");
    cleanup();
    make_chain_key();
    char kid[33];
    make_sign_key(SK1, PK1, kid);

    /* Phase 1 — the daemon runs WITHOUT -S. The session opens unsigned. */
    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 0x51ACA000, "local") == VIRP_OK, "init 1");
    ASSERT(append_n(&st, "unsigned", 2) == 0, "unsigned appends");
    virp_chain_destroy(&st);

    /* Phase 2 — the cutover, done the WRONG way: -S added to the running
     * database. The per-device session is keyed by device and outlives the
     * restart, so it simply continues — now signed. */
    ASSERT(virp_chain_init(&st, DB, CK, 0x51ACA000, "local") == VIRP_OK, "init 2");
    ASSERT(virp_chain_enable_signing(&st, SK1) == VIRP_OK,
           "today nothing refuses this — that is the whole finding");
    ASSERT(append_n(&st, "signed", 2) == 0, "signed appends");

    /* The head is now signed while sequence 0 is not. */
    ASSERT(count_int("SELECT COUNT(*) FROM chain_entries "
                     "WHERE chain_sig IS NULL OR chain_sig = ''") == 2,
           "the two pre-cutover entries are unsigned");
    char hs[200];
    ASSERT(col("SELECT head_sig FROM chain_heads", hs, sizeof(hs)) == 0 &&
           hs[0], "the head IS signed");

    /* And that is what Docket graded FAILED on 313, eighteen times. The C
     * verifier must keep saying so: an unsigned entry under a signed head
     * is a stripped signature, not a benign pre-D-1 session. */
    virp_chain_state_t v;
    ASSERT(virp_chain_open_verifier_ex(&v, DB, CK, PK1, 0x51ACA000, "local") == VIRP_OK,
           "open verifier with the public key");
    virp_chain_verify_result_t r;
    memset(&r, 0, sizeof(r));
    virp_chain_verify_session(&v, SESSION, &r);
    ASSERT(!r.valid,
           "a straddled session MUST fail — this is the 313 verdict");
    ASSERT(r.first_broken >= 0, "the verdict must name where it broke");
    printf("\n         [313 verdict reproduced] first_broken=%lld detail=\"%s\"\n"
           "         %-58s ",
           (long long)r.first_broken, r.error_detail, "");
    virp_chain_destroy(&v);
    virp_chain_destroy(&st);
    cleanup();
}

/* ═════════════════ PENDING: option A acceptance criteria ═══════════════ */

static void test_activation_on_nonempty_db_is_refused(void)
{
    TEST("OPTION A: -S on a NONEMPTY database is refused, DB untouched");
    cleanup();
    make_chain_key();
    char kid[33];
    make_sign_key(SK1, PK1, kid);

    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 0x51ACA000, "local") == VIRP_OK, "init 1");
    ASSERT(append_n(&st, "existing", 2) == 0, "seed the database");
    virp_chain_destroy(&st);          /* checkpoints and closes cleanly */

    char before[65], after[65];
    ASSERT(file_sha256(DB, before) == 0, "hash before");

    ASSERT(virp_chain_init(&st, DB, CK, 0x51ACA000, "local") == VIRP_OK, "init 2");
    virp_error_t rc = virp_chain_enable_signing(&st, SK1);
    virp_chain_destroy(&st);

    /* Criterion 1: it must be refused at all. */
    ASSERT(rc != VIRP_OK,
           "enable_signing on a nonempty database must be REFUSED");

    /* Criterion 2: a refused activation must not have touched the file.
     * Today the four ALTER TABLE ADD COLUMN statements run before anything
     * could refuse, so even a hypothetical late refusal would leave a
     * migrated database behind. The refusal has to come FIRST. */
    ASSERT(file_sha256(DB, after) == 0, "hash after");
    ASSERT(strcmp(before, after) == 0,
           "a refused activation must leave the database byte-identical");
    cleanup();
}

static void test_restart_with_a_different_key_is_refused(void)
{
    TEST("OPTION A: reopening a signed DB with a DIFFERENT key is refused");
    cleanup();
    make_chain_key();
    char kid1[33], kid2[33];
    make_sign_key(SK1, PK1, kid1);
    make_sign_key(SK2, PK2, kid2);
    ASSERT(strcmp(kid1, kid2) != 0, "the two keys must differ");

    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 0x51ACA000, "local") == VIRP_OK, "init 1");
    ASSERT(virp_chain_enable_signing(&st, SK1) == VIRP_OK, "enable key 1");
    ASSERT(append_n(&st, "k1", 2) == 0, "append under key 1");
    virp_chain_destroy(&st);

    ASSERT(virp_chain_init(&st, DB, CK, 0x51ACA000, "local") == VIRP_OK, "init 2");
    virp_error_t rc = virp_chain_enable_signing(&st, SK2);
    if (rc == VIRP_OK) {
        /* Show the damage the missing refusal causes, so the criterion is
         * not abstract: new entries land under a second key_id and the
         * session becomes unverifiable under either public key alone. */
        (void)append_n(&st, "k2", 2);
    }
    virp_chain_destroy(&st);

    ASSERT(rc != VIRP_OK,
           "a signing key different from the one the database already "
           "carries must be refused at startup, naming both key_ids");
    cleanup();
}

int main(void)
{
    printf("\n=== VIRP D-1 signing activation (V39 item 2) ===\n");
    printf("  NOTE: no daemon code change accompanies this suite. Item 2 was\n"
           "        launched with no rule ticked (option C). The two PENDING\n"
           "        tests state option A's acceptance criteria.\n"
           "        Runbook: docs/SIGNING-CUTOVER.md\n\n");

    RUN(test_fresh_db_born_signed);
    RUN(test_restart_same_key_continues);
    RUN(test_straddled_session_fails_verification);

    printf("\n  -- option A, not implemented --\n");
    RUN_PENDING(test_activation_on_nonempty_db_is_refused,
        "virp_chain_enable_signing() refuses when the database holds any "
        "entry, BEFORE the schema ALTERs, so a refused activation leaves "
        "the file byte-identical");
    RUN_PENDING(test_restart_with_a_different_key_is_refused,
        "a chain-signing key whose key_id differs from the one already in "
        "the database is refused at startup, naming the database and both "
        "key_ids — never signed silently alongside the old one");

    printf("\n=== Results: %d passed, %d failed", tests_passed, tests_failed);
    if (tests_pending) printf(", %d PENDING", tests_pending);
    printf(" ===\n");
    if (tests_pending)
        printf("\n  ****  SUITE IS NOT CLEAN: %d PENDING test(s)  ****\n"
               "  Known-failing by design. They are NOT counted as passes\n"
               "  and they are NOT skipped — they ran and they failed.\n"
               "  Each names its acceptance criterion above.\n\n",
               tests_pending);
    if (pending_unexpected)
        printf("  ****  %d PENDING test(s) UNEXPECTEDLY PASSED  ****\n",
               pending_unexpected);
    return tests_failed == 0 ? 0 : 1;
}
