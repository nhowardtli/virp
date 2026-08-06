/*
 * virp-chain-verify.c — a minimal auditor's verifier.
 *
 * WHY THIS FILE EXISTS
 * The chain verification logic is present and good: virp_chain_verify_session()
 * checks per-entry HMACs, prev-hash linkage, and (since 2026-08-01) completeness
 * against a signed head record. But it is a LIBRARY function. The shipped CLI
 * offers only `virp chain tail`, which prints entries and verifies nothing. An
 * auditor handed a chain.db and told "verify this" therefore has no command to
 * run. This is that missing command, written for test #2 so the transcript can
 * state what a verifier actually reports about a crash-damaged chain.
 *
 * It also answers a question `virp_chain_verify_session` deliberately does not:
 * for every chain entry, is the artifact BODY it commits to actually present in
 * the artifacts table? A chain can be cryptographically perfect while committing
 * to objects that were never stored.
 *
 * Usage: virp-chain-verify <chain.db> <chain.key> [session]
 *        with no session, every session in the DB is verified.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>
#include "virp_chain.h"

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <chain.db> <chain.key> [session]\n", argv[0]);
        return 2;
    }
    const char *db_path = argv[1], *key_path = argv[2];
    const char *only    = (argc > 3) ? argv[3] : NULL;

    virp_chain_state_t chain;
    if (virp_chain_init(&chain, db_path, key_path, 1, "local") != VIRP_OK) {
        fprintf(stderr, "FATAL: cannot open chain %s with key %s\n",
                db_path, key_path);
        return 2;
    }

    /* Enumerate sessions directly; the public API has no session iterator. */
    sqlite3 *raw = NULL;
    if (sqlite3_open_v2(db_path, &raw, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        fprintf(stderr, "FATAL: cannot reopen db read-only\n");
        return 2;
    }

    int bad = 0, sessions = 0;
    sqlite3_stmt *st = NULL;
    const char *q = "SELECT DISTINCT session_id FROM chain_entries ORDER BY session_id";
    sqlite3_prepare_v2(raw, q, -1, &st, NULL);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *sess = (const char *)sqlite3_column_text(st, 0);
        if (only && strcmp(only, sess) != 0) continue;
        sessions++;
        virp_chain_verify_result_t r;
        memset(&r, 0, sizeof(r));
        virp_error_t e = virp_chain_verify_session(&chain, sess, &r);
        printf("%-46s %-6s entries=%-5lld to_seq=%-5lld %s\n",
               sess, (e == VIRP_OK && r.valid) ? "VALID" : "BROKEN",
               (long long)r.entries_checked, (long long)r.to_sequence,
               (e == VIRP_OK && r.valid) ? "" : r.error_detail);
        if (!(e == VIRP_OK && r.valid)) bad++;
    }
    sqlite3_finalize(st);

    /* The question the crypto does not ask: is the committed body present?
     *
     * CORRECTED 2026-08-04: the join must be on (artifact_id, artifact_hash)
     * — the pair the entry commits to — not artifact_id alone. The id-only
     * join produced test #2's near-miss: a second-resolution id collision
     * (obs:pbs-lab:1785538992) stored only the second observation's body,
     * and this check found *a* body under the first entry's id and called
     * it present. An entry whose committed hash has no matching stored
     * body is orphaned even when some other entry's body shares its id. */
    printf("\n-- entries committing to an artifact body that is NOT stored --\n");
    const char *q2 =
        "SELECT e.session_id, e.sequence, e.artifact_id, substr(e.artifact_hash,1,16) "
        "FROM chain_entries e LEFT JOIN artifacts a "
        "  ON a.artifact_id = e.artifact_id AND a.artifact_hash = e.artifact_hash "
        "WHERE a.artifact_id IS NULL ORDER BY e.session_id, e.sequence";
    sqlite3_prepare_v2(raw, q2, -1, &st, NULL);
    int missing = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        printf("   %s seq=%lld %s commits to %s... (body absent)\n",
               sqlite3_column_text(st, 0), (long long)sqlite3_column_int64(st, 1),
               sqlite3_column_text(st, 2), sqlite3_column_text(st, 3));
        missing++;
    }
    sqlite3_finalize(st);
    if (!missing) printf("   (none)\n");
    sqlite3_close(raw);

    printf("\nsessions verified=%d broken=%d  entries-with-missing-body=%d\n",
           sessions, bad, missing);
    virp_chain_destroy(&chain);
    return (bad || missing) ? 1 : 0;
}
