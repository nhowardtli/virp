/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — the apply-time replay guard: correctness contract, and a
 * head-to-head between the two approaches proposed for it.
 *
 * THE GUARD. Before appending a gate_intent for an approved apply, the
 * daemon asks the chain whether this approval has already been spent on
 * a committed intent. The chain is the authority because it closes the
 * crash window between the intent commit and the consumed.list write.
 *
 * TWO APPROACHES have been proposed, and they are not the same thing:
 *
 *   (A) docs/PERF-REPLAY-GUARD.md (2026-09-02): the guard scans and
 *       JSON-parses every gate_intent body ever written. Measured 0.074 s
 *       per approved apply at ~21,000 intents, growing without bound. The
 *       proposal is a MATERIALISED CITATION: an indexed table written
 *       inside the same transaction as the intent append, turning the
 *       guard into an O(log n) lookup. Not implemented when written.
 *
 *   (B) perf/verify-closer-map (2026-09-07): a per-verify in-memory map,
 *       built to kill a 2.3-hour whole-chain VERIFY. It does not make the
 *       apply path faster -- it deliberately invalidates on every append
 *       so the guard keeps scanning, because a cached count is a WRONG
 *       count the moment the next intent lands.
 *
 * (B) is a correctness fix for a problem (A) does not have, and (A) is a
 * performance fix for a path (B) leaves exactly as slow as it found it.
 * They are complementary, not alternatives, and this file pins the
 * contract that BOTH must satisfy so neither can regress the other.
 *
 * THE CONTRACT, in order of how badly a violation ends:
 *   1. A count is never LOW. Under-reporting is approval reuse.
 *   2. The count is correct immediately after an append, with no
 *      intervening verify to flush anything.
 *   3. The count survives a close and reopen (it is chain state, not
 *      process state).
 *   4. A fast path that cannot answer falls back to the authority; it
 *      never reads absence as "not spent".
 */

#include "../src/virp_chain.c"

#include "virp_chainsign.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int tests_passed = 0, tests_failed = 0;

#define TEST(name) do { printf("  [TEST] %-62s ", name); fflush(stdout); } while (0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while (0)
#define FAILM(m) do { printf("FAIL: %s\n", m); tests_failed++; } while (0)
#define ASSERT(c, m) do { if (!(c)) { FAILM(m); return; } } while (0)

static const char *DB = "/tmp/virp_test_replayguard.db";
static const char *CK = "/tmp/virp_test_replayguard.key";

static void cleanup(void)
{
    unlink(DB);
    unlink("/tmp/virp_test_replayguard.db-wal");
    unlink("/tmp/virp_test_replayguard.db-shm");
    unlink(CK);
}

static void make_chain_key(void)
{
    virp_signing_key_t sk;
    virp_key_generate(&sk, VIRP_KEY_TYPE_CHAIN);
    unlink(CK);
    virp_key_save_file(&sk, CK);
    virp_key_destroy(&sk);
}

/* Append a gate_intent whose body cites `aeh`, exactly as the daemon's
 * gate_emit_intent does. */
static void append_intent(virp_chain_state_t *st, const char *sess,
                          const char *aid, const char *aeh)
{
    char body[512];
    snprintf(body, sizeof(body),
             "{\"schema\":\"gate_intent/1\",\"device\":\"R1\","
             "\"command\":\"show version\",\"approval_entry_hash\":\"%s\"}",
             aeh);
    char hash[65];
    virp_chain_artifact_digest(body, hash);
    virp_chain_entry_t e;
    if (virp_chain_append_with_artifact(st, sess, "gate_intent", aid,
                                        hash, body, &e) != VIRP_OK)
        abort();
}

static const char *AEH_A =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char *AEH_B =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/* ── contract 1 + 2: correct immediately after an append ───────────── */

static void test_count_is_correct_immediately_after_append(void)
{
    TEST("guard: the count is correct with no intervening verify");
    cleanup(); make_chain_key();
    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "init");

    int n = -1;
    ASSERT(virp_chain_count_intents_for_approval(&st, AEH_A, &n) == VIRP_OK,
           "query");
    ASSERT(n == 0, "an unspent approval must count 0");

    append_intent(&st, "gate-enforce:R1", "i-1", AEH_A);

    /* THE CASE THAT BROKE. A cached map, built by the first query and
     * not invalidated by the append, answers 0 here -- and 0 means "not
     * spent", so the apply proceeds and the approval is spent twice. */
    ASSERT(virp_chain_count_intents_for_approval(&st, AEH_A, &n) == VIRP_OK,
           "query 2");
    ASSERT(n == 1, "the approval is spent and the guard must say so");

    append_intent(&st, "gate-enforce:R1", "i-2", AEH_A);
    ASSERT(virp_chain_count_intents_for_approval(&st, AEH_A, &n) == VIRP_OK,
           "query 3");
    ASSERT(n == 2, "two intents cite it now");

    /* A different approval is unaffected. */
    ASSERT(virp_chain_count_intents_for_approval(&st, AEH_B, &n) == VIRP_OK,
           "query 4");
    ASSERT(n == 0, "an unrelated approval must still count 0");

    virp_chain_destroy(&st);
    cleanup();
    PASS();
}

/* ── contract 3: it is chain state, not process state ──────────────── */

static void test_count_survives_close_and_reopen(void)
{
    TEST("guard: the count survives a close and reopen");
    cleanup(); make_chain_key();
    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "init");
    append_intent(&st, "gate-enforce:R1", "i-1", AEH_A);
    virp_chain_destroy(&st);

    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "reinit");
    int n = -1;
    ASSERT(virp_chain_count_intents_for_approval(&st, AEH_A, &n) == VIRP_OK,
           "query");
    ASSERT(n == 1, "a daemon restart must not forget a spent approval");
    virp_chain_destroy(&st);
    cleanup();
    PASS();
}

/* ── the two approaches, head to head ──────────────────────────────── */

static void test_verify_map_does_not_leak_into_the_guard(void)
{
    TEST("guard: a verify's cached map never answers the guard");
    cleanup(); make_chain_key();
    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "init");
    append_intent(&st, "gate-enforce:R1", "i-1", AEH_A);

    /* Run a verify, which builds and frees the verify-scoped maps. */
    virp_chain_verify_result_t r;
    ASSERT(virp_chain_verify_session(&st, "gate-enforce:R1", &r) == VIRP_OK,
           "verify");

    /* Then spend the approval again and ask. Approach (B)'s map must not
     * be holding a pre-append snapshot. */
    append_intent(&st, "gate-enforce:R1", "i-2", AEH_A);
    int n = -1;
    ASSERT(virp_chain_count_intents_for_approval(&st, AEH_A, &n) == VIRP_OK,
           "query");
    ASSERT(n == 2, "the guard must see both intents after a verify ran");

    virp_chain_destroy(&st);
    cleanup();
    PASS();
}

static void test_the_oracle_and_the_fast_path_agree(void)
{
    TEST("guard: fast path == authoritative scan, entry for entry");
    cleanup(); make_chain_key();
    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "init");

    /* A populated chain: several approvals, varying spend counts, plus
     * intents citing nothing at all. */
    char aeh[8][65];
    for (int k = 0; k < 8; k++) {
        memset(aeh[k], (char)('0' + k), 64);
        aeh[k][64] = '\0';
        for (int j = 0; j <= k % 3; j++) {
            char id[32];
            snprintf(id, sizeof(id), "i-%d-%d", k, j);
            append_intent(&st, "gate-enforce:R1", id, aeh[k]);
        }
    }

    /* The authority: the scan-and-parse the guard has always done,
     * recomputed here independently of whatever the guard now uses. */
    for (int k = 0; k < 8; k++) {
        int expect = 0;
        sqlite3_stmt *q = NULL;
        if (sqlite3_prepare_v2(st.db,
                "SELECT a.artifact_content FROM chain_entries c "
                "JOIN artifacts a ON a.artifact_id = c.artifact_id "
                "               AND a.artifact_hash = c.artifact_hash "
                "WHERE c.artifact_type = 'gate_intent'", -1, &q, NULL)
            == SQLITE_OK) {
            while (sqlite3_step(q) == SQLITE_ROW) {
                const unsigned char *b = sqlite3_column_text(q, 0);
                if (!b) continue;
                cJSON *o = cJSON_Parse((const char *)b);
                if (!o) continue;
                char got[65];
                if (cj_str(o, "approval_entry_hash", got, sizeof(got)) &&
                    strcmp(got, aeh[k]) == 0)
                    expect++;
                cJSON_Delete(o);
            }
            sqlite3_finalize(q);
        }
        int got = -1;
        if (virp_chain_count_intents_for_approval(&st, aeh[k], &got)
            != VIRP_OK) { FAILM("query"); virp_chain_destroy(&st); return; }
        if (got != expect) {
            char m[160];
            snprintf(m, sizeof(m), "approval %d: guard says %d, the chain "
                     "says %d", k, got, expect);
            FAILM(m); virp_chain_destroy(&st); return;
        }
    }
    virp_chain_destroy(&st);
    cleanup();
    PASS();
}

static void test_an_unknown_approval_never_reads_as_spent_or_unspent_wrongly(void)
{
    TEST("guard: absence of a citation is 0, presence is never missed");
    cleanup(); make_chain_key();
    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "init");

    /* An intent whose body carries NO approval_entry_hash at all must
     * not be counted against any approval. */
    char body[256];
    snprintf(body, sizeof(body),
             "{\"schema\":\"gate_intent/1\",\"device\":\"R1\","
             "\"command\":\"show version\"}");
    char hash[65];
    virp_chain_artifact_digest(body, hash);
    virp_chain_entry_t e;
    ASSERT(virp_chain_append_with_artifact(&st, "gate-enforce:R1",
                                           "gate_intent", "i-none", hash,
                                           body, &e) == VIRP_OK, "append");
    int n = -1;
    ASSERT(virp_chain_count_intents_for_approval(&st, AEH_A, &n) == VIRP_OK,
           "query");
    ASSERT(n == 0, "an intent citing nothing counts against nothing");

    /* And an empty hash is a no-op query, not a scan that matches "". */
    ASSERT(virp_chain_count_intents_for_approval(&st, "", &n) == VIRP_OK,
           "empty query");
    ASSERT(n == 0, "an empty approval hash counts 0");

    virp_chain_destroy(&st);
    cleanup();
    PASS();
}

/* ── the measurement, so the finding is not lost ───────────────────── */

static void test_report_apply_path_cost(void)
{
    TEST("guard: report the apply-path cost at 2000 intents");
    cleanup(); make_chain_key();
    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "init");
    for (int i = 0; i < 2000; i++) {
        char id[32], a[65];
        snprintf(id, sizeof(id), "i-%d", i);
        memset(a, 'c', 64); a[64] = '\0';
        snprintf(a, 5, "%04d", i % 500);
        a[4] = 'c';
        append_intent(&st, "gate-enforce:R1", id, a);
    }
    /* Force the AUTHORITY, so this keeps reporting the cost the finding
     * is about even now that the fast path exists. This is also the cost
     * every apply pays whenever the citation index is not trusted. */
    sqlite3_exec(st.db, "DELETE FROM chain_meta WHERE k='citation_backfill';",
                 NULL, NULL, NULL);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int n = 0;
    for (int i = 0; i < 20; i++)
        virp_chain_count_intents_for_approval(&st, AEH_A, &n);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double per = ((t1.tv_sec - t0.tv_sec) +
                  (t1.tv_nsec - t0.tv_nsec) / 1e9) / 20.0;
    printf("\n         %.4f s per guard query at 2000 intents, "
           "SCAN-AND-PARSE (the fallback).\n"
           "         docs/PERF-REPLAY-GUARD.md measured 0.074 s at ~21000; "
           "the cost is linear in the intent count.\n         ", per);
    virp_chain_destroy(&st);
    cleanup();
    PASS();
}

/* ── the materialised citation (docs/PERF-REPLAY-GUARD.md) ─────────── */
/*
 * Its five stated constraints, each as a test. The proposal was explicit
 * that this path is the one place where getting it wrong means an
 * approval can be spent twice, so every constraint is pinned rather than
 * assumed.
 */

static int count_rows(virp_chain_state_t *st, const char *sql)
{
    sqlite3_stmt *q = NULL; int n = -1;
    if (sqlite3_prepare_v2(st->db, sql, -1, &q, NULL) == SQLITE_OK) {
        if (sqlite3_step(q) == SQLITE_ROW) n = sqlite3_column_int(q, 0);
        sqlite3_finalize(q);
    }
    return n;
}

static void test_citation_written_atomically_with_the_intent(void)
{
    TEST("citation: a row lands in the same transaction as the intent");
    cleanup(); make_chain_key();
    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "init");

    ASSERT(count_rows(&st, "SELECT count(*) FROM intent_approval_citation")
           == 0, "no citations before any intent");
    append_intent(&st, "gate-enforce:R1", "i-1", AEH_A);
    ASSERT(count_rows(&st, "SELECT count(*) FROM intent_approval_citation")
           == 1, "the append must have written its citation");

    /* Constraint 2: a citation that can be lost independently
     * reintroduces the crash window the guard exists to close. Force the
     * append to fail after the entry would have been written and assert
     * NOTHING landed -- not the entry, not the citation. */
    sqlite3_exec(st.db, "DROP TABLE artifacts;", NULL, NULL, NULL);
    char body[256];
    snprintf(body, sizeof(body),
             "{\"schema\":\"gate_intent/1\",\"approval_entry_hash\":\"%s\"}",
             AEH_B);
    char hash[65];
    virp_chain_artifact_digest(body, hash);
    virp_chain_entry_t e;
    ASSERT(virp_chain_append_with_artifact(&st, "gate-enforce:R1",
                                           "gate_intent", "i-doomed", hash,
                                           body, &e) != VIRP_OK,
           "the append must fail with the store gone");
    ASSERT(count_rows(&st, "SELECT count(*) FROM intent_approval_citation")
           == 1, "a rolled-back append must leave NO citation behind");

    virp_chain_destroy(&st);
    cleanup();
    PASS();
}

static void test_backfill_is_verified_against_the_scan(void)
{
    TEST("citation: existing intents are backfilled and checked");
    cleanup(); make_chain_key();

    /* Build a chain the way a pre-citation daemon would have: entries and
     * bodies, but no citation table at all. */
    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "init");
    for (int i = 0; i < 12; i++) {
        char id[32];
        snprintf(id, sizeof(id), "i-%d", i);
        append_intent(&st, "gate-enforce:R1", id, (i % 2) ? AEH_A : AEH_B);
    }
    int intents = count_rows(&st,
        "SELECT count(*) FROM chain_entries WHERE artifact_type='gate_intent'");
    ASSERT(intents == 12, "12 intents written");
    /* Erase the citations, simulating a chain written before this change. */
    sqlite3_exec(st.db, "DELETE FROM intent_approval_citation;",
                 NULL, NULL, NULL);
    sqlite3_exec(st.db, "DELETE FROM chain_meta WHERE k='citation_backfill';",
                 NULL, NULL, NULL);
    virp_chain_destroy(&st);

    /* Reopen: the backfill runs, and must be VERIFIED before the fast
     * path is trusted (constraint 3). */
    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "reopen");
    ASSERT(count_rows(&st, "SELECT count(*) FROM intent_approval_citation")
           == 12, "every pre-existing intent must be backfilled");
    ASSERT(count_rows(&st,
           "SELECT count(*) FROM chain_meta WHERE k='citation_backfill'")
           == 1, "the backfill must record that it completed");

    int n = -1;
    ASSERT(virp_chain_count_intents_for_approval(&st, AEH_A, &n) == VIRP_OK,
           "query");
    ASSERT(n == 6, "six intents cite A");
    ASSERT(virp_chain_count_intents_for_approval(&st, AEH_B, &n) == VIRP_OK,
           "query");
    ASSERT(n == 6, "six intents cite B");

    virp_chain_destroy(&st);
    cleanup();
    PASS();
}

static void test_a_missing_citation_falls_back_never_reads_unspent(void)
{
    TEST("citation: a missing row falls back; absence is never 'not spent'");
    cleanup(); make_chain_key();
    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "init");
    append_intent(&st, "gate-enforce:R1", "i-1", AEH_A);

    /* Constraint 5. Delete the citation but leave the intent, and leave
     * the backfill marker in place so nothing re-runs. The guard must
     * still say SPENT: the chain is the authority, and a fast path that
     * cannot answer defers to it rather than answering 0. */
    sqlite3_exec(st.db, "DELETE FROM intent_approval_citation;",
                 NULL, NULL, NULL);
    int n = -1;
    ASSERT(virp_chain_count_intents_for_approval(&st, AEH_A, &n) == VIRP_OK,
           "query");
    ASSERT(n == 1, "a lost citation must NEVER read as an unspent approval");

    virp_chain_destroy(&st);
    cleanup();
    PASS();
}

static void test_the_chain_wins_when_they_disagree(void)
{
    TEST("citation: the chain is the authority when the two disagree");
    cleanup(); make_chain_key();
    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "init");
    append_intent(&st, "gate-enforce:R1", "i-1", AEH_A);

    /* Constraint 1. Forge an EXTRA citation for an approval no intent
     * cites. The derived table says 1; the chain says 0. The chain wins,
     * and the disagreement is a fault, not a verdict: the guard must not
     * refuse an apply on the strength of a row nothing backs. */
    sqlite3_exec(st.db,
        "INSERT INTO intent_approval_citation(chain_entry_id, "
        "approval_entry_hash) VALUES (999999, '"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');",
        NULL, NULL, NULL);
    int n = -1;
    ASSERT(virp_chain_count_intents_for_approval(&st, AEH_B, &n) == VIRP_OK,
           "query");
    ASSERT(n == 0, "a citation with no chain entry behind it counts 0");

    virp_chain_destroy(&st);
    cleanup();
    PASS();
}

static void test_the_fast_path_is_actually_fast(void)
{
    TEST("citation: the guard is a lookup, not a scan-and-parse");
    cleanup(); make_chain_key();
    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "init");
    for (int i = 0; i < 2000; i++) {
        char id[32], a[65];
        snprintf(id, sizeof(id), "i-%d", i);
        memset(a, 'c', 64); a[64] = '\0';
        snprintf(a, 5, "%04d", i % 500);
        a[4] = 'c';
        append_intent(&st, "gate-enforce:R1", id, a);
    }
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int n = 0;
    for (int i = 0; i < 200; i++)
        virp_chain_count_intents_for_approval(&st, AEH_A, &n);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double per = ((t1.tv_sec - t0.tv_sec) +
                  (t1.tv_nsec - t0.tv_nsec) / 1e9) / 200.0;
    printf("\n         %.6f s per guard query at 2000 intents\n         ",
           per);
    ASSERT(per < 0.0005,
           "the indexed lookup must be flat, not linear in the intent count");
    virp_chain_destroy(&st);
    cleanup();
    PASS();
}

int main(void)
{
    printf("\n=== VIRP apply-time replay guard — contract + approaches ===\n");
    test_count_is_correct_immediately_after_append();
    test_count_survives_close_and_reopen();
    test_verify_map_does_not_leak_into_the_guard();
    test_the_oracle_and_the_fast_path_agree();
    test_an_unknown_approval_never_reads_as_spent_or_unspent_wrongly();
    test_report_apply_path_cost();
    test_citation_written_atomically_with_the_intent();
    test_backfill_is_verified_against_the_scan();
    test_a_missing_citation_falls_back_never_reads_unspent();
    test_the_chain_wins_when_they_disagree();
    test_the_fast_path_is_actually_fast();
    printf("\n=== Results: %d passed, %d failed ===\n",
           tests_passed, tests_failed);
    return tests_failed ? 1 : 0;
}
