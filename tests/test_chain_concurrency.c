/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — chain.db concurrency test (Item 3 hardening).
 *
 * Snow's cage operator drives concurrent traffic; the rejection-persistence
 * path and every other chain writer share the same sqlite3 db handle and
 * prepared statements. This test hammers those shared statements from many
 * threads at once (append + get_last + artifact_store, same- and cross-
 * session) and asserts chain.db stays consistent: no dropped rows, correct
 * per-session count, contiguous sequences, and chain_verify valid across
 * ALL entries. Without a serializing lock the shared sqlite3_stmt use is
 * undefined behavior -> UNIQUE violations / corruption / crash.
 *
 * Mirrors tests/test_onode_concurrency.c's thread structure.
 */

#include "virp.h"
#include "virp_chain.h"
#include "virp_crypto.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#define NUM_APPENDERS   16
#define APPENDS_EACH    50
#define NUM_SESSIONS     4
#define NUM_READERS      4
#define NUM_ARTIFACT     4
#define ARTIFACT_EACH   50

static const char *SESSIONS[NUM_SESSIONS] = { "sess-A", "sess-B", "sess-C", "sess-D" };
static const char *DB  = "/tmp/virp_test_chain_conc.db";
static const char *KEY = "/tmp/virp_test_chain_conc.key";

static virp_chain_state_t g_chain;
static volatile int g_appends_running = 1;

typedef struct { int tid; } warg_t;

static void fill_hash(char h[65], int a, int b)
{
    static const char hx[] = "0123456789abcdef";
    for (int k = 0; k < 64; k++) h[k] = hx[(a * 7 + b * 13 + k) & 15];
    h[64] = '\0';
}

static void *append_worker(void *p)
{
    warg_t *a = (warg_t *)p;
    const char *sess = SESSIONS[a->tid % NUM_SESSIONS];
    for (int i = 0; i < APPENDS_EACH; i++) {
        char id[128], hash[65];
        snprintf(id, sizeof(id), "art-%d-%d", a->tid, i);
        fill_hash(hash, a->tid, i);
        virp_chain_entry_t e;
        virp_error_t err = virp_chain_append(&g_chain, sess, "observation",
                                             id, hash, &e);
        if (err != VIRP_OK) {
            /* Any failure under concurrency is the race we guard against
             * (e.g. two threads racing get_last -> duplicate sequence). */
            fprintf(stderr, "  APPEND FAILED tid=%d i=%d err=%d\n",
                    a->tid, i, err);
            _exit(2);
        }
    }
    return NULL;
}

/* Concurrent readers: hammer stmt_get_last while appends use it too. */
static void *reader_worker(void *p)
{
    (void)p;
    while (g_appends_running) {
        for (int s = 0; s < NUM_SESSIONS; s++) {
            virp_chain_entry_t e;
            virp_chain_get_last(&g_chain, SESSIONS[s], &e);
        }
    }
    return NULL;
}

/* Concurrent artifact writers: hammer stmt_artifact_insert. */
static void *artifact_worker(void *p)
{
    warg_t *a = (warg_t *)p;
    for (int i = 0; i < ARTIFACT_EACH; i++) {
        char id[128], hash[65];
        snprintf(id, sizeof(id), "blob-%d-%d", a->tid, i);
        fill_hash(hash, a->tid + 100, i);
        virp_chain_artifact_store(&g_chain, id, "observation",
                                  "content-bytes", hash,
                                  SESSIONS[a->tid % NUM_SESSIONS]);
    }
    return NULL;
}

int main(void)
{
    unlink(DB); unlink(KEY);
    virp_signing_key_t sk;
    virp_key_generate(&sk, VIRP_KEY_TYPE_CHAIN);
    virp_key_save_file(&sk, KEY);

    if (virp_chain_init(&g_chain, DB, KEY, 1, "test-org") != VIRP_OK) {
        fprintf(stderr, "chain init failed\n");
        return 1;
    }

    printf("Firing %d appenders x %d + %d readers + %d artifact-writers x %d "
           "(concurrent)...\n",
           NUM_APPENDERS, APPENDS_EACH, NUM_READERS, NUM_ARTIFACT, ARTIFACT_EACH);

    pthread_t app[NUM_APPENDERS];   warg_t app_a[NUM_APPENDERS];
    pthread_t art[NUM_ARTIFACT];    warg_t art_a[NUM_ARTIFACT];
    pthread_t rd[NUM_READERS];

    for (int i = 0; i < NUM_READERS; i++)  pthread_create(&rd[i], NULL, reader_worker, NULL);
    for (int i = 0; i < NUM_ARTIFACT; i++) { art_a[i].tid = i; pthread_create(&art[i], NULL, artifact_worker, &art_a[i]); }
    for (int i = 0; i < NUM_APPENDERS; i++) { app_a[i].tid = i; pthread_create(&app[i], NULL, append_worker, &app_a[i]); }

    for (int i = 0; i < NUM_APPENDERS; i++) pthread_join(app[i], NULL);
    for (int i = 0; i < NUM_ARTIFACT; i++)  pthread_join(art[i], NULL);
    g_appends_running = 0;
    for (int i = 0; i < NUM_READERS; i++)   pthread_join(rd[i], NULL);

    /* Post-run consistency: each session got exactly (threads-per-session *
     * APPENDS_EACH) rows, sequences 0..N-1 contiguous, chain_verify valid. */
    int per_session_threads  = NUM_APPENDERS / NUM_SESSIONS;   /* 4 */
    int expected_per_session = per_session_threads * APPENDS_EACH; /* 200 */
    int fails = 0;

    for (int s = 0; s < NUM_SESSIONS; s++) {
        virp_chain_verify_result_t r;
        memset(&r, 0, sizeof(r));
        virp_error_t err = virp_chain_verify(&g_chain, SESSIONS[s],
                                             0, expected_per_session - 1, &r);
        int ok = (err == VIRP_OK && r.valid && r.first_broken == -1 &&
                  r.entries_checked == expected_per_session);
        printf("  session %s: err=%d valid=%d entries_checked=%lld first_broken=%lld "
               "(expected %d) -> %s\n",
               SESSIONS[s], (int)err, (int)r.valid,
               (long long)r.entries_checked, (long long)r.first_broken,
               expected_per_session, ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    virp_chain_destroy(&g_chain);
    unlink(DB); unlink(KEY);

    printf("\nResults: %s  (%d concurrent chain writes across %d sessions, "
           "no dropped/corrupt rows, all sequences verify)\n",
           fails == 0 ? "PASS" : "FAIL",
           NUM_APPENDERS * APPENDS_EACH, NUM_SESSIONS);
    return fails == 0 ? 0 : 1;
}
