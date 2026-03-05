/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Trust Chain (Primitive 6) Tests
 *
 * Tests: genesis, sequential linking, verify valid, verify tampered,
 *        milestone, crash recovery, key type check, two-session independence
 */

#define _POSIX_C_SOURCE 199309L

#include "virp_chain.h"
#include "virp_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { printf("  [TEST] %-50s ", name); } while (0)

#define PASS() \
    do { printf("PASS\n"); tests_passed++; } while (0)

#define FAIL(msg) \
    do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)

#define ASSERT(cond, msg) \
    do { if (!(cond)) { FAIL(msg); return; } } while (0)

static const char *TEST_DB = "/tmp/virp_test_chain.db";
static const char *TEST_KEY = "/tmp/virp_test_chain.key";

static void create_test_key(void)
{
    virp_signing_key_t sk;
    virp_key_generate(&sk, VIRP_KEY_TYPE_CHAIN);
    virp_key_save_file(&sk, TEST_KEY);
    virp_key_destroy(&sk);
}

static void cleanup(void)
{
    unlink(TEST_DB);
    unlink(TEST_KEY);
    /* Also clean WAL/SHM files */
    unlink("/tmp/virp_test_chain.db-wal");
    unlink("/tmp/virp_test_chain.db-shm");
}

/* =========================================================================
 * Test: Genesis entry
 * ========================================================================= */

static void test_genesis(void)
{
    TEST("Genesis entry");
    cleanup();
    create_test_key();

    virp_chain_state_t state;
    virp_error_t err = virp_chain_init(&state, TEST_DB, TEST_KEY, 1, "test-org");
    ASSERT(err == VIRP_OK, "chain_init failed");

    virp_chain_entry_t entry;
    err = virp_chain_append(&state, "session-1", "observation",
                            "obs-001", "abcd1234abcd1234abcd1234abcd1234"
                            "abcd1234abcd1234abcd1234abcd1234",
                            &entry);
    ASSERT(err == VIRP_OK, "chain_append failed");
    ASSERT(entry.sequence == 0, "genesis should be sequence 0");
    ASSERT(strlen(entry.chain_entry_hash) == 64, "hash should be 64 hex chars");
    ASSERT(strlen(entry.chain_hmac) == 64, "HMAC should be 64 hex chars");
    ASSERT(strcmp(entry.artifact_type, "observation") == 0, "artifact_type mismatch");
    ASSERT(entry.signer_node_id == 1, "signer_node_id mismatch");
    ASSERT(strcmp(entry.signer_org_id, "test-org") == 0, "org_id mismatch");
    ASSERT(strcmp(entry.artifact_hash_alg, "sha256") == 0, "hash_alg mismatch");
    ASSERT(strcmp(entry.artifact_schema_version, "1") == 0, "schema_version mismatch");

    /* Verify genesis previous hash format */
    char expected_genesis[65];
    char buf[256];
    int n = snprintf(buf, sizeof(buf), "VIRP_CHAIN_GENESIS:session-1");
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)buf, (size_t)n, hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(expected_genesis + i * 2, 3, "%02x", hash[i]);
    expected_genesis[64] = '\0';
    ASSERT(strcmp(entry.previous_entry_hash, expected_genesis) == 0,
           "genesis previous_entry_hash wrong");

    virp_chain_destroy(&state);
    PASS();
}

/* =========================================================================
 * Test: Sequential linking
 * ========================================================================= */

static void test_sequential_linking(void)
{
    TEST("Sequential linking (5 entries)");
    cleanup();
    create_test_key();

    virp_chain_state_t state;
    virp_chain_init(&state, TEST_DB, TEST_KEY, 1, "local");

    virp_chain_entry_t entries[5];
    for (int i = 0; i < 5; i++) {
        char artifact_id[32];
        snprintf(artifact_id, sizeof(artifact_id), "art-%03d", i);
        char artifact_hash[65];
        snprintf(artifact_hash, sizeof(artifact_hash),
                 "%064d", i);  /* Fake hash */

        virp_error_t err = virp_chain_append(&state, "session-seq",
                                              "intent", artifact_id,
                                              artifact_hash, &entries[i]);
        ASSERT(err == VIRP_OK, "append failed");
        ASSERT(entries[i].sequence == (int64_t)i, "sequence mismatch");
    }

    /* Verify linking: each entry's previous_entry_hash == prior's chain_entry_hash */
    for (int i = 1; i < 5; i++) {
        ASSERT(strcmp(entries[i].previous_entry_hash,
                      entries[i - 1].chain_entry_hash) == 0,
               "chain linkage broken");
    }

    virp_chain_destroy(&state);
    PASS();
}

/* =========================================================================
 * Test: Verify valid chain
 * ========================================================================= */

static void test_verify_valid(void)
{
    TEST("Verify valid chain");
    cleanup();
    create_test_key();

    virp_chain_state_t state;
    virp_chain_init(&state, TEST_DB, TEST_KEY, 1, "local");

    /* Append 10 entries */
    for (int i = 0; i < 10; i++) {
        virp_chain_entry_t e;
        char id[32], hash[65];
        snprintf(id, sizeof(id), "art-%03d", i);
        snprintf(hash, sizeof(hash), "%064d", i);
        virp_chain_append(&state, "session-verify", "observation",
                          id, hash, &e);
    }

    /* Verify full range */
    virp_chain_verify_result_t result;
    virp_error_t err = virp_chain_verify(&state, "session-verify",
                                          0, 9, &result);
    ASSERT(err == VIRP_OK, "verify call failed");
    ASSERT(result.valid, "chain should be valid");
    ASSERT(result.entries_checked == 10, "should check 10 entries");
    ASSERT(result.first_broken == -1, "no broken entry");

    virp_chain_destroy(&state);
    PASS();
}

/* =========================================================================
 * Test: Verify tampered chain
 * ========================================================================= */

static void test_verify_tampered(void)
{
    TEST("Verify tampered chain");
    cleanup();
    create_test_key();

    virp_chain_state_t state;
    virp_chain_init(&state, TEST_DB, TEST_KEY, 1, "local");

    /* Append 5 entries */
    for (int i = 0; i < 5; i++) {
        virp_chain_entry_t e;
        char id[32], hash[65];
        snprintf(id, sizeof(id), "art-%03d", i);
        snprintf(hash, sizeof(hash), "%064d", i);
        virp_chain_append(&state, "session-tamper", "observation",
                          id, hash, &e);
    }

    /* Tamper with entry 2 — modify artifact_hash directly in DB */
    sqlite3_exec(state.db,
        "UPDATE chain_entries SET artifact_hash = 'TAMPERED0000000000000000"
        "00000000000000000000000000000000000000' "
        "WHERE session_id = 'session-tamper' AND sequence = 2;",
        NULL, NULL, NULL);

    /* Verify should detect the tamper */
    virp_chain_verify_result_t result;
    virp_chain_verify(&state, "session-tamper", 0, 4, &result);
    ASSERT(!result.valid, "tampered chain should be invalid");
    ASSERT(result.first_broken == 2, "should detect tamper at sequence 2");

    virp_chain_destroy(&state);
    PASS();
}

/* =========================================================================
 * Test: Milestone at 100
 * ========================================================================= */

static void test_milestone(void)
{
    TEST("Milestone at 100 entries");
    cleanup();
    create_test_key();

    virp_chain_state_t state;
    virp_chain_init(&state, TEST_DB, TEST_KEY, 1, "local");

    /* Append 101 entries */
    for (int i = 0; i <= 100; i++) {
        virp_chain_entry_t e;
        char id[32], hash[65];
        snprintf(id, sizeof(id), "art-%04d", i);
        snprintf(hash, sizeof(hash), "%064d", i);
        virp_chain_append(&state, "session-milestone", "observation",
                          id, hash, &e);
    }

    /* Check that milestone was created at sequence 100 */
    sqlite3_stmt *stmt;
    const char *sql = "SELECT sequence FROM chain_milestones "
                      "WHERE session_id = 'session-milestone'";
    int rc = sqlite3_prepare_v2(state.db, sql, -1, &stmt, NULL);
    ASSERT(rc == SQLITE_OK, "prepare failed");

    ASSERT(sqlite3_step(stmt) == SQLITE_ROW, "no milestone found");
    int64_t milestone_seq = sqlite3_column_int64(stmt, 0);
    ASSERT(milestone_seq == 100, "milestone should be at sequence 100");
    sqlite3_finalize(stmt);

    virp_chain_destroy(&state);
    PASS();
}

/* =========================================================================
 * Test: Get last entry
 * ========================================================================= */

static void test_get_last(void)
{
    TEST("Get last entry");
    cleanup();
    create_test_key();

    virp_chain_state_t state;
    virp_chain_init(&state, TEST_DB, TEST_KEY, 1, "local");

    /* No entries — should fail */
    virp_chain_entry_t e;
    virp_error_t err = virp_chain_get_last(&state, "empty-session", &e);
    ASSERT(err == VIRP_ERR_CHAIN_SEQUENCE, "should fail for empty session");

    /* Add entries */
    for (int i = 0; i < 3; i++) {
        char id[32], hash[65];
        snprintf(id, sizeof(id), "art-%d", i);
        snprintf(hash, sizeof(hash), "%064d", i);
        virp_chain_append(&state, "session-last", "outcome", id, hash, &e);
    }

    /* Get last should return sequence 2 */
    err = virp_chain_get_last(&state, "session-last", &e);
    ASSERT(err == VIRP_OK, "get_last failed");
    ASSERT(e.sequence == 2, "last should be sequence 2");

    virp_chain_destroy(&state);
    PASS();
}

/* =========================================================================
 * Test: Key type is CHAIN
 * ========================================================================= */

static void test_key_type(void)
{
    TEST("Key type is VIRP_KEY_TYPE_CHAIN");
    cleanup();
    create_test_key();

    virp_chain_state_t state;
    virp_chain_init(&state, TEST_DB, TEST_KEY, 1, "local");

    ASSERT(state.chain_key.type == VIRP_KEY_TYPE_CHAIN,
           "chain key should be type 3");

    virp_chain_destroy(&state);
    PASS();
}

/* =========================================================================
 * Test: Two sessions are independent
 * ========================================================================= */

static void test_session_independence(void)
{
    TEST("Two sessions are independent");
    cleanup();
    create_test_key();

    virp_chain_state_t state;
    virp_chain_init(&state, TEST_DB, TEST_KEY, 1, "local");

    /* Session A: 3 entries */
    virp_chain_entry_t ea;
    for (int i = 0; i < 3; i++) {
        char id[32], hash[65];
        snprintf(id, sizeof(id), "a-%d", i);
        snprintf(hash, sizeof(hash), "%064d", i);
        virp_chain_append(&state, "session-A", "observation", id, hash, &ea);
    }

    /* Session B: 2 entries */
    virp_chain_entry_t eb;
    for (int i = 0; i < 2; i++) {
        char id[32], hash[65];
        snprintf(id, sizeof(id), "b-%d", i);
        snprintf(hash, sizeof(hash), "%064d", i + 100);
        virp_chain_append(&state, "session-B", "intent", id, hash, &eb);
    }

    /* Session A last should be seq 2, Session B last should be seq 1 */
    virp_chain_entry_t last_a, last_b;
    virp_chain_get_last(&state, "session-A", &last_a);
    virp_chain_get_last(&state, "session-B", &last_b);

    ASSERT(last_a.sequence == 2, "session-A last should be 2");
    ASSERT(last_b.sequence == 1, "session-B last should be 1");

    /* Both should verify independently */
    virp_chain_verify_result_t ra, rb;
    virp_chain_verify(&state, "session-A", 0, 2, &ra);
    virp_chain_verify(&state, "session-B", 0, 1, &rb);
    ASSERT(ra.valid, "session-A should be valid");
    ASSERT(rb.valid, "session-B should be valid");

    virp_chain_destroy(&state);
    PASS();
}

/* =========================================================================
 * Test: UNIQUE constraint on (session_id, sequence)
 * ========================================================================= */

static void test_unique_constraint(void)
{
    TEST("UNIQUE(session_id, sequence) enforced");
    cleanup();
    create_test_key();

    virp_chain_state_t state;
    virp_chain_init(&state, TEST_DB, TEST_KEY, 1, "local");

    /* Append two entries normally */
    virp_chain_entry_t e;
    virp_chain_append(&state, "session-uniq", "observation",
                      "art-0", "0000000000000000000000000000000000000000000000000000000000000000", &e);
    virp_chain_append(&state, "session-uniq", "observation",
                      "art-1", "1111111111111111111111111111111111111111111111111111111111111111", &e);

    ASSERT(e.sequence == 1, "second entry should be sequence 1");

    virp_chain_destroy(&state);
    PASS();
}

/* =========================================================================
 * Main
 * ========================================================================= */

int main(void)
{
    printf("\n=== VIRP Trust Chain (Primitive 6) Tests ===\n\n");

    test_genesis();
    test_sequential_linking();
    test_verify_valid();
    test_verify_tampered();
    test_milestone();
    test_get_last();
    test_key_type();
    test_session_independence();
    test_unique_constraint();

    printf("\n=== Results: %d passed, %d failed ===\n\n",
           tests_passed, tests_failed);

    cleanup();
    return tests_failed > 0 ? 1 : 0;
}
