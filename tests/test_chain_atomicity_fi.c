/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — chain_append crash-atomicity regression (LAB-ONLY, fault-injected)
 *
 * WHAT THIS PINS
 * --------------
 * chain_append_locked() writes the entry, the head row AND the artifact body
 * inside ONE transaction that commits at the very end. The adversarial program
 * (test #2) named the window this closes: if the body store sat past the
 * COMMIT, a daemon killed between the two would leave a chain entry committing
 * to a body that does not exist — a "recorded-happened-once" record with no
 * evidence behind it. The fix moved the body store inside the transaction, so a
 * crash before COMMIT must lose the entry too, not just the body.
 *
 * This is distinct from test_chain.c's `append_with_artifact body failure rolls
 * back entry`, which exercises the EXPLICIT ROLLBACK branch (the store call
 * returns an error and the code runs ROLLBACK). That branch cannot prove the
 * crash case: a SIGKILL never gets to run ROLLBACK. Here we actually kill the
 * process mid-transaction (VIRP_FI("mid_outcome"), SIGKILL — uncatchable, no
 * atexit, no clean DB close) and rely on SQLite's own crash recovery when the
 * database is reopened. What survives is exactly what was durable at the kill.
 *
 * THE INVARIANT CHECKED
 * ---------------------
 * After the crash and reopen: entry_present == body_present. The two must be in
 * the same state — both gone (shipped: killed before COMMIT) or, in a broken
 * build, entry present with body absent (a dangling commitment). Any inequality
 * is a dangling commitment and fails the test.
 *
 * RED PROOF (harness build only — never the shipped source):
 *   Move chain_artifact_store_locked() to AFTER the COMMIT in src/virp_chain.c,
 *   rebuild with -DVIRP_FAULT_INJECT, and run this test. The entry then commits
 *   before the kill and the body never lands: entry_present=1, body_present=0,
 *   and this test FAILS with "DANGLING COMMITMENT". Revert the source; the
 *   shipped in-transaction store passes.
 *
 * SAFETY: built only by `make test-chain-atomicity-fi` (sets
 * -DVIRP_FAULT_INJECT, links build-fi/). Operates on a private /tmp database;
 * touches no production socket, chain, or spool. See include/virp_fault_inject.h.
 */

#define _POSIX_C_SOURCE 200809L

#include "virp_chain.h"
#include "virp_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdbool.h>

static const char *DB   = "/tmp/virp_fi_atomicity.db";
static const char *WAL  = "/tmp/virp_fi_atomicity.db-wal";
static const char *SHM  = "/tmp/virp_fi_atomicity.db-shm";
static const char *KEY  = "/tmp/virp_fi_atomicity.key";

/* A body-carrying append hits the mid_outcome point (it fires only when
 * artifact_content is non-empty). "outcome" is a known body-carrying type,
 * the same one test_chain.c's rollback test appends directly. The hash is a
 * commitment, not sha256(body) — the library does not require equality, and
 * the body is stored and looked up keyed by this hash. */
static const char *SESSION     = "atomicity-fi";
static const char *ARTIFACT_ID = "outcome:fi-crash-1";
static const char *ARTIFACT_HASH =
    "aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900";
static const char *BODY = "crash-window body — must land with the entry or not at all";

static void fresh_paths(void)
{
    unlink(DB); unlink(WAL); unlink(SHM); unlink(KEY);
}

static void create_key(void)
{
    virp_signing_key_t sk;
    virp_key_generate(&sk, VIRP_KEY_TYPE_CHAIN);
    virp_key_save_file(&sk, KEY);
    virp_key_destroy(&sk);
}

int main(void)
{
    printf("=== chain_append crash-atomicity (mid_outcome SIGKILL) ===\n");
    fresh_paths();
    create_key();

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 2; }

    if (pid == 0) {
        /* CHILD: arm the crash point, then perform the body-carrying append.
         * VIRP_FI("mid_outcome") fires inside chain_append_locked's
         * transaction, before COMMIT, and SIGKILLs this process. */
        setenv("VIRP_FI_POINT", "mid_outcome", 1);

        virp_chain_state_t st;
        if (virp_chain_init(&st, DB, KEY, 1, "fi-org") != VIRP_OK) {
            fprintf(stderr, "child: chain init failed\n");
            _exit(70);
        }
        virp_chain_entry_t e;
        virp_chain_append_with_artifact(&st, SESSION, "outcome",
                                        ARTIFACT_ID, ARTIFACT_HASH, BODY, &e);
        /* Reaching here means the crash point never fired. Either the binary
         * was not built with -DVIRP_FAULT_INJECT or the point name drifted. */
        fprintf(stderr, "child: append returned — mid_outcome did NOT fire\n");
        _exit(71);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) { perror("waitpid"); return 2; }

    /* The child must have died BY SIGKILL at mid_outcome. Anything else means
     * the harness is not measuring the crash path. */
    if (!(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)) {
        if (WIFEXITED(status) && WEXITSTATUS(status) == 71) {
            fprintf(stderr,
                "SETUP FAIL: mid_outcome never fired — build with "
                "-DVIRP_FAULT_INJECT (make test-chain-atomicity-fi).\n");
        } else {
            fprintf(stderr, "SETUP FAIL: child did not SIGKILL "
                "(status=0x%x)\n", (unsigned)status);
        }
        return 2;
    }
    printf("  child SIGKILLed at mid_outcome (mid-transaction), as designed.\n");

    /* Reopen the crashed database. SQLite runs crash recovery on open. */
    virp_chain_state_t st2;
    if (virp_chain_init(&st2, DB, KEY, 1, "fi-org") != VIRP_OK) {
        fprintf(stderr, "FAIL: reopen after crash failed\n");
        return 1;
    }

    bool entry_present = false, body_present = false;
    virp_chain_artifact_exists(&st2, ARTIFACT_ID, &entry_present);
    virp_chain_artifact_body_exists(&st2, ARTIFACT_HASH, &body_present);
    printf("  after recovery: entry_present=%d body_present=%d\n",
           (int)entry_present, (int)body_present);

    int rc = 0;

    /* CORE INVARIANT: entry and body land or vanish together. Inequality in
     * either direction is a dangling commitment. */
    if (entry_present != body_present) {
        fprintf(stderr,
            "FAIL: DANGLING COMMITMENT — entry_present=%d body_present=%d. "
            "A crash left the chain committing to a body it cannot produce "
            "(or vice versa). The body store is not inside the append "
            "transaction.\n",
            (int)entry_present, (int)body_present);
        rc = 1;
    }

    /* SHIPPED BEHAVIOR: mid_outcome sits before COMMIT, so a kill there must
     * lose the WHOLE append. Surviving state here means the entry committed
     * before the crash point — the exact regression this guards. */
    if (entry_present) {
        fprintf(stderr,
            "FAIL: the append survived a SIGKILL at mid_outcome — the entry "
            "was committed before the crash point. The store/commit boundary "
            "regressed outside the transaction.\n");
        rc = 1;
    }

    virp_chain_destroy(&st2);
    fresh_paths();

    if (rc == 0)
        printf("PASS: crash mid-append left no entry and no body — atomic.\n");
    return rc;
}
