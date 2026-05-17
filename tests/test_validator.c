/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Response Validator tests
 *
 * Exercises the real chain.db path, not mocks. Mirrors test_chain.c
 * style: TEST/PASS/FAIL/ASSERT macros, /tmp/virp_test_validator.* files,
 * cleanup in each test.
 */

#define _POSIX_C_SOURCE 199309L

#include "virp_validator.h"
#include "virp_chain.h"
#include "virp_crypto.h"

#include <openssl/sha.h>
#include <sqlite3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { printf("  [TEST] %-60s ", name); } while (0)

#define PASS() \
    do { printf("PASS\n"); tests_passed++; } while (0)

#define FAIL(msg) \
    do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)

#define ASSERT(cond, msg) \
    do { if (!(cond)) { FAIL(msg); return; } } while (0)

static const char *TEST_DB  = "/tmp/virp_test_validator.db";
static const char *TEST_KEY = "/tmp/virp_test_validator.key";

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
    unlink("/tmp/virp_test_validator.db-wal");
    unlink("/tmp/virp_test_validator.db-shm");
}

static void sha256_hex(const unsigned char *data, size_t len, char out[65])
{
    unsigned char d[SHA256_DIGEST_LENGTH];
    SHA256(data, len, d);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(out + i * 2, 3, "%02x", d[i]);
    }
    out[64] = '\0';
}

/*
 * Seed an "observation" artifact on the given session. Returns the hex hash
 * of the fake artifact content via *hash_out. Use this hex as evidence_ref.
 */
static void seed_artifact(virp_chain_state_t *st, const char *session,
                          const char *artifact_id, const char *content,
                          char hash_out[65])
{
    sha256_hex((const unsigned char *)content, strlen(content), hash_out);
    virp_chain_entry_t e;
    virp_chain_append(st, session, "observation", artifact_id, hash_out, &e);
}

/* Phase 4 helper: seed an artifact whose artifact_id follows the
 * "obs:<device>:<ts_ns>" shape that virp-bridge.py:389 produces in
 * production. Required for tests that exercise the entity-binding
 * check (which only fires on obs:device:ts shapes). */
static void seed_obs_artifact(virp_chain_state_t *st, const char *session,
                              const char *device, const char *content,
                              char hash_out[65])
{
    sha256_hex((const unsigned char *)content, strlen(content), hash_out);
    char aid[128];
    snprintf(aid, sizeof(aid), "obs:%s:%lld", device,
             (long long)( ((long long)1778979300LL * 1000000000LL)
                          + (long long)(rand() & 0xfffff) ));
    virp_chain_entry_t e;
    virp_chain_append(st, session, "observation", aid, hash_out, &e);
}

/* =========================================================================
 * Test 1: PASS — evidence in turn AND in chain, prose hash matches
 * ========================================================================= */

static void test_pass_full(void)
{
    TEST("PASS: evidence in turn and chain, prose hash matches");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local") == VIRP_OK, "chain_init");

    char ev[65];
    seed_artifact(&st, "sess-pass", "obs-1", "bgp peer 10.0.0.1 up", ev);

    const char *prose = "BGP peer 10.0.0.1 is established.";
    char ph[65];
    sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    char json[1024];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"sess-pass\","
        "\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[\"%s\"],"
        "\"assertions\":[{\"device\":\"r1\",\"claim_type\":\"state_observation\","
        "\"evidence_ref\":\"%s\"}]}",
        ph, ev, ev);
    ASSERT(n > 0 && n < (int)sizeof(json), "snprintf");

    validator_manifest_t m;
    validator_violation_code_t reason;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &reason) == VIRP_OK, "parse");

    validator_result_t r;
    ASSERT(validator_evaluate(&st, &m, prose, strlen(prose), &r) == VIRP_OK, "evaluate");
    ASSERT(r.decision == VALIDATOR_DECISION_PASS, "decision not PASS");
    ASSERT(r.turn_violation == VALIDATOR_VIOLATION_NONE, "turn_violation not NONE");
    ASSERT(r.per_assertion_count == 1, "assertion count");
    ASSERT(r.per_assertion[0].decision == VALIDATOR_DECISION_PASS, "per[0] not PASS");

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 2: WARN — state_read with null evidence
 * ========================================================================= */

static void test_warn_state_read_null(void)
{
    TEST("WARN: state_read with null evidence_ref");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    const char *prose = "observations pending";
    char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    char json[512];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s2\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[],"
        "\"assertions\":[{\"device\":\"r2\",\"claim_type\":\"state_observation\","
        "\"evidence_ref\":null}]}", ph);

    validator_manifest_t m;
    validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse");
    ASSERT(!m.assertions[0].has_evidence, "has_evidence should be false");

    validator_result_t r;
    validator_evaluate(&st, &m, prose, strlen(prose), &r);
    ASSERT(r.decision == VALIDATOR_DECISION_WARN, "decision not WARN");
    ASSERT(r.per_assertion[0].violation == VALIDATOR_VIOLATION_NO_EVIDENCE_STATE_READ, "violation code");
    ASSERT(r.per_assertion[0].error_class == VALIDATOR_ERROR_CLASS_PROVENANCE, "class should be provenance");
    ASSERT(r.per_assertion[0].remediation_hint == VALIDATOR_HINT_RERUN_WITH_TOOLS, "hint should be rerun_with_tools");

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 3: BLOCK — state_change with null evidence
 * ========================================================================= */

static void test_block_state_change_null(void)
{
    TEST("BLOCK: state_change with null evidence_ref");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    const char *prose = "interface toggled";
    char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    char json[512];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s3\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[],"
        "\"assertions\":[{\"device\":\"r3\",\"claim_type\":\"state_change\","
        "\"evidence_ref\":null}]}", ph);

    validator_manifest_t m;
    validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse");

    validator_result_t r;
    validator_evaluate(&st, &m, prose, strlen(prose), &r);
    ASSERT(r.decision == VALIDATOR_DECISION_BLOCK, "decision not BLOCK");
    ASSERT(r.per_assertion[0].violation == VALIDATOR_VIOLATION_NO_EVIDENCE_STATE_CHANGE, "violation");

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 4: BLOCK — evidence_ref not in tool_call_refs
 * ========================================================================= */

static void test_block_evidence_not_in_turn(void)
{
    TEST("BLOCK: evidence_ref not present in tool_call_refs");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    char ev[65];
    seed_artifact(&st, "s4", "obs-1", "some output", ev);

    const char *prose = "claiming something";
    char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    /* Note: tool_call_refs is empty; evidence_ref exists in chain but not in refs. */
    char json[1024];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s4\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[],"
        "\"assertions\":[{\"device\":\"r4\",\"claim_type\":\"state_observation\","
        "\"evidence_ref\":\"%s\"}]}", ph, ev);

    validator_manifest_t m; validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse");

    validator_result_t r;
    validator_evaluate(&st, &m, prose, strlen(prose), &r);
    ASSERT(r.decision == VALIDATOR_DECISION_BLOCK, "decision not BLOCK");
    ASSERT(r.per_assertion[0].violation == VALIDATOR_VIOLATION_EVIDENCE_NOT_IN_TURN, "violation");

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 5: BLOCK — evidence in tool_call_refs but not in chain.db
 * ========================================================================= */

static void test_block_evidence_not_in_chain(void)
{
    TEST("BLOCK: evidence in tool_call_refs but not in chain");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    /* Fabricated hash — never written to chain.db. */
    const char *fake = "deadbeef00000000deadbeef00000000"
                       "deadbeef00000000deadbeef00000000";

    const char *prose = "fabricated claim";
    char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    char json[1024];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s5\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[\"%s\"],"
        "\"assertions\":[{\"device\":\"r5\",\"claim_type\":\"state_observation\","
        "\"evidence_ref\":\"%s\"}]}", ph, fake, fake);

    validator_manifest_t m; validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse");

    validator_result_t r;
    validator_evaluate(&st, &m, prose, strlen(prose), &r);
    ASSERT(r.decision == VALIDATOR_DECISION_BLOCK, "decision not BLOCK");
    ASSERT(r.per_assertion[0].violation == VALIDATOR_VIOLATION_EVIDENCE_NOT_IN_CHAIN, "violation");
    ASSERT(r.per_assertion[0].error_class == VALIDATOR_ERROR_CLASS_CONTENT, "class should be content");
    ASSERT(r.per_assertion[0].remediation_hint == VALIDATOR_HINT_FABRICATION_DETECTED, "hint should be fabrication_detected");

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 6: BLOCK — prose_hash mismatch
 * ========================================================================= */

static void test_block_prose_hash_mismatch(void)
{
    TEST("BLOCK: prose_hash does not match re-hashed prose");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    const char *prose = "the real prose";
    /* Declare a different hash than what the prose will hash to. */
    const char *wrong = "1111111111111111111111111111111111111111111111111111111111111111";

    char json[512];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s6\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[],\"assertions\":[]}", wrong);

    validator_manifest_t m; validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse");

    validator_result_t r;
    validator_evaluate(&st, &m, prose, strlen(prose), &r);
    ASSERT(r.decision == VALIDATOR_DECISION_BLOCK, "decision not BLOCK");
    ASSERT(r.turn_violation == VALIDATOR_VIOLATION_PROSE_HASH_MISMATCH, "turn_violation");

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 7: Parser rejects manifest with >MAX_ASSERTIONS
 * ========================================================================= */

static void test_manifest_too_large(void)
{
    TEST("Parser rejects > VALIDATOR_MAX_ASSERTIONS entries");
    cleanup();
    create_test_key();

    /* MAX_ASSERTIONS+1 entries × ~70 B each + envelope. 96 KB is
     * comfortable; the prior 16 KB sizing relied on stack layout
     * tolerating the OOB write that snprintf-loop accumulation
     * triggered when off exceeded sizeof(json). Sized for honesty,
     * not luck. */
    char *json = (char *)malloc(96 * 1024);
    ASSERT(json != NULL, "alloc");
    size_t cap = 96 * 1024;
    const char *ph = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    int off = snprintf(json, cap,
        "{\"session_id\":\"s7\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[],\"assertions\":[", ph);

    for (int i = 0; i < VALIDATOR_MAX_ASSERTIONS + 1; i++) {
        int w = snprintf(json + off, cap - (size_t)off,
            "%s{\"device\":\"r%d\",\"claim_type\":\"state_observation\",\"evidence_ref\":null}",
            (i == 0) ? "" : ",", i);
        off += w;
    }
    off += snprintf(json + off, cap - (size_t)off, "]}");

    validator_manifest_t m;
    validator_violation_code_t reason;
    virp_error_t err = validator_parse_manifest(json, (size_t)off, &m, &reason);
    free(json);
    ASSERT(err != VIRP_OK, "parser should reject");
    ASSERT(reason == VALIDATOR_VIOLATION_MANIFEST_TOO_LARGE, "reason code");
    PASS();
}

/* =========================================================================
 * Test 8: Unknown claim_type — parses to UNKNOWN then evaluates to BLOCK
 * ========================================================================= */

static void test_unknown_claim_type(void)
{
    TEST("BLOCK: unknown claim_type parses to UNKNOWN, evaluates BLOCK");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    const char *prose = "whatever";
    char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    char json[512];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s8\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[],"
        "\"assertions\":[{\"device\":\"r8\",\"claim_type\":\"vibes_check\","
        "\"evidence_ref\":null}]}", ph);

    validator_manifest_t m; validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse should succeed");
    ASSERT(m.assertions[0].claim_type == VALIDATOR_CLAIM_UNKNOWN, "claim_type UNKNOWN");

    validator_result_t r;
    validator_evaluate(&st, &m, prose, strlen(prose), &r);
    ASSERT(r.decision == VALIDATOR_DECISION_BLOCK, "decision not BLOCK");
    ASSERT(r.per_assertion[0].violation == VALIDATOR_VIOLATION_UNKNOWN_CLAIM_TYPE, "violation");

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 9: Parser edge cases
 *   - rejects non-hex evidence_ref
 *   - rejects non-string device
 *   - accepts explicit JSON null
 *   - accepts missing evidence_ref key (forward-compat)
 * ========================================================================= */

static void test_parser_edge_cases(void)
{
    TEST("Parser: non-hex/non-string rejected; null and missing accepted");

    const char *ph = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    validator_manifest_t m;
    validator_violation_code_t reason;

    /* Non-hex evidence_ref. */
    char json1[512];
    int n1 = snprintf(json1, sizeof(json1),
        "{\"session_id\":\"s9a\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[],"
        "\"assertions\":[{\"device\":\"r9\",\"claim_type\":\"state_observation\","
        "\"evidence_ref\":\"not-hex\"}]}", ph);
    ASSERT(validator_parse_manifest(json1, (size_t)n1, &m, &reason) != VIRP_OK, "non-hex should fail");
    ASSERT(reason == VALIDATOR_VIOLATION_MANIFEST_MALFORMED, "reason code non-hex");

    /* Non-string device. */
    char json2[512];
    int n2 = snprintf(json2, sizeof(json2),
        "{\"session_id\":\"s9b\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[],"
        "\"assertions\":[{\"device\":12345,\"claim_type\":\"state_observation\","
        "\"evidence_ref\":null}]}", ph);
    ASSERT(validator_parse_manifest(json2, (size_t)n2, &m, &reason) != VIRP_OK, "non-string should fail");
    ASSERT(reason == VALIDATOR_VIOLATION_MANIFEST_MALFORMED, "reason code non-string");

    /* Explicit null. */
    char json3[512];
    int n3 = snprintf(json3, sizeof(json3),
        "{\"session_id\":\"s9c\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[],"
        "\"assertions\":[{\"device\":\"r9\",\"claim_type\":\"state_observation\","
        "\"evidence_ref\":null}]}", ph);
    ASSERT(validator_parse_manifest(json3, (size_t)n3, &m, &reason) == VIRP_OK, "null should parse");
    ASSERT(!m.assertions[0].has_evidence, "null has_evidence=false");

    /* Missing evidence_ref key. */
    char json4[512];
    int n4 = snprintf(json4, sizeof(json4),
        "{\"session_id\":\"s9d\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[],"
        "\"assertions\":[{\"device\":\"r9\",\"claim_type\":\"state_observation\"}]}", ph);
    ASSERT(validator_parse_manifest(json4, (size_t)n4, &m, &reason) == VIRP_OK, "missing should parse");
    ASSERT(!m.assertions[0].has_evidence, "missing has_evidence=false");

    PASS();
}

/* =========================================================================
 * Test 10: commit_decision writes artifact_type="validation" to chain
 * ========================================================================= */

static void test_commit_decision(void)
{
    TEST("commit_decision writes artifact_type=validation to chain");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    char ev[65];
    seed_artifact(&st, "s10", "obs-1", "content10", ev);

    const char *prose = "state is good";
    char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    char json[1024];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s10\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[\"%s\"],"
        "\"assertions\":[{\"device\":\"r10\",\"claim_type\":\"state_observation\","
        "\"evidence_ref\":\"%s\"}]}", ph, ev, ev);

    validator_manifest_t m; validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse");
    validator_result_t r;
    ASSERT(validator_evaluate(&st, &m, prose, strlen(prose), &r) == VIRP_OK, "evaluate");
    ASSERT(r.decision == VALIDATOR_DECISION_PASS, "expected PASS before commit");

    ASSERT(validator_commit_decision(&st, &m, &r) == VIRP_OK, "commit");
    ASSERT(strlen(r.chain_entry_hash) == 64, "chain_entry_hash populated");
    ASSERT(r.chain_sequence >= 0, "chain_sequence populated");
    ASSERT(strlen(r.artifact_hash) == 64, "artifact_hash populated");

    /* Confirm row exists with artifact_type="validation". */
    sqlite3_stmt *stmt;
    const char *q = "SELECT COUNT(*) FROM chain_entries "
                    "WHERE session_id='s10' AND artifact_type='validation'";
    ASSERT(sqlite3_prepare_v2(st.db, q, -1, &stmt, NULL) == SQLITE_OK, "prepare");
    ASSERT(sqlite3_step(stmt) == SQLITE_ROW, "step");
    int count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    ASSERT(count == 1, "should be exactly one validation row");

    /* Phase 2: the canonical decision body must also be persisted to
     * artifacts so post-hoc forensic comparison is possible. Prior to
     * Phase 2 the artifacts table had 0 validation rows; now it has 1. */
    const char *qa = "SELECT artifact_content FROM artifacts "
                     "WHERE session_id='s10' AND artifact_type='validation'";
    ASSERT(sqlite3_prepare_v2(st.db, qa, -1, &stmt, NULL) == SQLITE_OK, "prepare artifacts");
    ASSERT(sqlite3_step(stmt) == SQLITE_ROW, "artifacts row should exist");
    const unsigned char *body = sqlite3_column_text(stmt, 0);
    ASSERT(body != NULL, "artifact_content non-null");
    /* Spot-check the body contains the new turn_error_class field. */
    ASSERT(strstr((const char *)body, "\"turn_error_class\":\"none\"") != NULL,
           "canonical JSON should embed turn_error_class=none for PASS");
    sqlite3_finalize(stmt);

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 11: Decision precedence
 *   - WARN + PASS  → WARN
 *   - WARN + BLOCK → BLOCK
 * ========================================================================= */

static void test_precedence(void)
{
    TEST("Precedence: WARN+PASS=WARN, WARN+BLOCK=BLOCK");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    char ev[65];
    seed_artifact(&st, "s11", "obs-1", "evidence-content", ev);

    /* (a) WARN + PASS → WARN */
    {
        const char *prose = "two claims, one warned";
        char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

        char json[2048];
        int n = snprintf(json, sizeof(json),
            "{\"session_id\":\"s11\",\"prose_hash\":\"%s\","
            "\"tool_call_refs\":[\"%s\"],"
            "\"assertions\":["
              "{\"device\":\"r11\",\"claim_type\":\"state_observation\",\"evidence_ref\":null},"
              "{\"device\":\"r11\",\"claim_type\":\"state_observation\",\"evidence_ref\":\"%s\"}"
            "]}", ph, ev, ev);

        validator_manifest_t m; validator_violation_code_t rr;
        ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse a");
        validator_result_t r;
        validator_evaluate(&st, &m, prose, strlen(prose), &r);
        ASSERT(r.decision == VALIDATOR_DECISION_WARN, "WARN+PASS should roll up to WARN");
    }

    /* (b) WARN + BLOCK → BLOCK */
    {
        const char *prose = "warn plus block";
        char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

        char json[2048];
        int n = snprintf(json, sizeof(json),
            "{\"session_id\":\"s11\",\"prose_hash\":\"%s\","
            "\"tool_call_refs\":[],"
            "\"assertions\":["
              "{\"device\":\"r11\",\"claim_type\":\"state_observation\",\"evidence_ref\":null},"
              "{\"device\":\"r11\",\"claim_type\":\"state_change\",\"evidence_ref\":null}"
            "]}", ph);

        validator_manifest_t m; validator_violation_code_t rr;
        ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse b");
        validator_result_t r;
        validator_evaluate(&st, &m, prose, strlen(prose), &r);
        ASSERT(r.decision == VALIDATOR_DECISION_BLOCK, "WARN+BLOCK should roll up to BLOCK");
        ASSERT(r.per_assertion[0].decision == VALIDATOR_DECISION_WARN, "per[0] WARN");
        ASSERT(r.per_assertion[1].decision == VALIDATOR_DECISION_BLOCK, "per[1] BLOCK");
    }

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 12: violation → error_class + remediation_hint mapping (full table)
 *
 * Walks every violation code and checks the mapping function returns
 * the locked class+hint. This is the truth table for the wire format.
 * ========================================================================= */

static void test_class_hint_mapping(void)
{
    TEST("Mapping: every violation code maps to expected class + hint");

    struct {
        validator_violation_code_t   v;
        validator_error_class_t      expect_class;
        validator_remediation_hint_t expect_hint;
    } cases[] = {
        { VALIDATOR_VIOLATION_NONE,                       VALIDATOR_ERROR_CLASS_NONE,       VALIDATOR_HINT_NONE                 },
        { VALIDATOR_VIOLATION_NO_EVIDENCE_STATE_READ,     VALIDATOR_ERROR_CLASS_PROVENANCE, VALIDATOR_HINT_RERUN_WITH_TOOLS     },
        { VALIDATOR_VIOLATION_NO_EVIDENCE_STATE_CHANGE,   VALIDATOR_ERROR_CLASS_PROVENANCE, VALIDATOR_HINT_RERUN_WITH_TOOLS     },
        { VALIDATOR_VIOLATION_EVIDENCE_NOT_IN_TURN,       VALIDATOR_ERROR_CLASS_PROVENANCE, VALIDATOR_HINT_RERUN_WITH_TOOLS     },
        { VALIDATOR_VIOLATION_EVIDENCE_NOT_IN_CHAIN,      VALIDATOR_ERROR_CLASS_CONTENT,    VALIDATOR_HINT_FABRICATION_DETECTED },
        { VALIDATOR_VIOLATION_UNKNOWN_CLAIM_TYPE,         VALIDATOR_ERROR_CLASS_SCHEMA,     VALIDATOR_HINT_REPORT_SCHEMA_GAP    },
        { VALIDATOR_VIOLATION_PROSE_HASH_MISMATCH,        VALIDATOR_ERROR_CLASS_CONTENT,    VALIDATOR_HINT_FABRICATION_DETECTED },
        { VALIDATOR_VIOLATION_MANIFEST_MALFORMED,         VALIDATOR_ERROR_CLASS_FORMAT,     VALIDATOR_HINT_REGENERATE_MANIFEST  },
        { VALIDATOR_VIOLATION_MANIFEST_TOO_LARGE,         VALIDATOR_ERROR_CLASS_FORMAT,     VALIDATOR_HINT_REGENERATE_MANIFEST  },
        { VALIDATOR_VIOLATION_MANIFEST_MISSING,           VALIDATOR_ERROR_CLASS_PROVENANCE, VALIDATOR_HINT_RERUN_WITH_TOOLS     },
        /* Phase 3 mappings */
        { VALIDATOR_VIOLATION_EVIDENCE_REFS_MISSING,      VALIDATOR_ERROR_CLASS_PROVENANCE, VALIDATOR_HINT_RERUN_WITH_TOOLS     },
        { VALIDATOR_VIOLATION_DERIVED_FROM_MISSING,       VALIDATOR_ERROR_CLASS_PROVENANCE, VALIDATOR_HINT_RERUN_WITH_TOOLS     },
        { VALIDATOR_VIOLATION_ACTION_REF_MISSING,         VALIDATOR_ERROR_CLASS_PROVENANCE, VALIDATOR_HINT_RERUN_WITH_TOOLS     },
        { VALIDATOR_VIOLATION_ACTION_REF_NOT_IN_CHAIN,    VALIDATOR_ERROR_CLASS_CONTENT,    VALIDATOR_HINT_FABRICATION_DETECTED },
        { VALIDATOR_VIOLATION_DERIVED_FROM_NOT_IN_CHAIN,  VALIDATOR_ERROR_CLASS_CONTENT,    VALIDATOR_HINT_FABRICATION_DETECTED },
        { VALIDATOR_VIOLATION_OUTCOME_NOT_AFTER_ACTION,   VALIDATOR_ERROR_CLASS_CONTENT,    VALIDATOR_HINT_FABRICATION_DETECTED },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        validator_error_class_t gc      = validator_violation_class(cases[i].v);
        validator_remediation_hint_t gh = validator_violation_hint(cases[i].v);
        if (gc != cases[i].expect_class) {
            char msg[160];
            snprintf(msg, sizeof(msg),
                     "violation %d: class %s, expected %s",
                     (int)cases[i].v,
                     validator_error_class_str(gc),
                     validator_error_class_str(cases[i].expect_class));
            FAIL(msg);
            return;
        }
        if (gh != cases[i].expect_hint) {
            char msg[160];
            snprintf(msg, sizeof(msg),
                     "violation %d: hint %s, expected %s",
                     (int)cases[i].v,
                     validator_remediation_hint_str(gh),
                     validator_remediation_hint_str(cases[i].expect_hint));
            FAIL(msg);
            return;
        }
    }
    PASS();
}

/* =========================================================================
 * Test 13: MANIFEST_MISSING (NULL/0-len input) classes as provenance
 *
 * Belt-and-suspenders for the locked taxonomy decision: the AI layer
 * failing to emit any manifest is a provenance failure (no inputs
 * supplied), not a format failure (nothing to be malformed about).
 * ========================================================================= */

static void test_manifest_missing_provenance(void)
{
    TEST("validator_run_turn: MISSING manifest classes as provenance");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    validator_result_t r;
    virp_error_t err = validator_run_turn(&st,
                                          NULL, 0,
                                          NULL, 0,
                                          "sess-missing",
                                          &r);
    ASSERT(err == VIRP_OK, "run_turn should succeed (commit-on-fail path)");
    ASSERT(r.decision == VALIDATOR_DECISION_BLOCK, "decision BLOCK");
    ASSERT(r.turn_violation == VALIDATOR_VIOLATION_MANIFEST_MISSING, "turn_violation MISSING");
    ASSERT(r.turn_error_class == VALIDATOR_ERROR_CLASS_PROVENANCE, "class provenance");
    ASSERT(r.turn_remediation_hint == VALIDATOR_HINT_RERUN_WITH_TOOLS, "hint rerun_with_tools");

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 14: comparison PASS — evidence_refs with 2 entries, both seeded
 * ========================================================================= */

static void test_comparison_pass(void)
{
    TEST("PASS: comparison with 2 evidence_refs, both in chain+turn");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    char ev1[65], ev2[65];
    seed_artifact(&st, "s-cmp", "obs-1", "before reading", ev1);
    seed_artifact(&st, "s-cmp", "obs-2", "after reading",  ev2);

    const char *prose = "BGP table grew from 17 to 19 routes between snapshots.";
    char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    char json[2048];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s-cmp\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[\"%s\",\"%s\"],"
        "\"assertions\":[{\"device\":\"r1\",\"claim_type\":\"comparison\","
        "\"evidence_refs\":[\"%s\",\"%s\"]}]}", ph, ev1, ev2, ev1, ev2);

    validator_manifest_t m; validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse");
    ASSERT(m.assertions[0].evidence_refs_count == 2, "parsed 2 refs");

    validator_result_t r;
    validator_evaluate(&st, &m, prose, strlen(prose), &r);
    ASSERT(r.decision == VALIDATOR_DECISION_PASS, "comparison should PASS");

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 15: comparison BLOCK — only 1 evidence_ref (needs ≥2)
 * ========================================================================= */

static void test_comparison_block_too_few(void)
{
    TEST("BLOCK: comparison with <2 evidence_refs → EVIDENCE_REFS_MISSING");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    char ev1[65];
    seed_artifact(&st, "s-cmp2", "obs-1", "only one obs", ev1);

    const char *prose = "Comparing one thing to itself.";
    char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    char json[1024];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s-cmp2\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[\"%s\"],"
        "\"assertions\":[{\"device\":\"r1\",\"claim_type\":\"comparison\","
        "\"evidence_refs\":[\"%s\"]}]}", ph, ev1, ev1);

    validator_manifest_t m; validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse");

    validator_result_t r;
    validator_evaluate(&st, &m, prose, strlen(prose), &r);
    ASSERT(r.decision == VALIDATOR_DECISION_BLOCK, "BLOCK");
    ASSERT(r.per_assertion[0].violation == VALIDATOR_VIOLATION_EVIDENCE_REFS_MISSING, "violation");
    ASSERT(r.per_assertion[0].error_class == VALIDATOR_ERROR_CLASS_PROVENANCE, "class provenance");

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 16: recommendation PASS — derived_from in chain (no turn req)
 * ========================================================================= */

static void test_recommendation_pass(void)
{
    TEST("PASS: recommendation with derived_from in chain");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    char ev1[65];
    seed_artifact(&st, "s-rec", "obs-1", "high cpu observation", ev1);

    const char *prose = "Consider rebalancing the BGP best-path computation; recent CPU spikes suggest churn.";
    char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    /* Note: tool_call_refs is empty — recommendation doesn't need turn ref. */
    char json[1024];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s-rec\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[],"
        "\"assertions\":[{\"device\":\"r1\",\"claim_type\":\"recommendation\","
        "\"derived_from\":[\"%s\"]}]}", ph, ev1);

    validator_manifest_t m; validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse");
    ASSERT(m.assertions[0].derived_from_count == 1, "parsed 1 derived_from");

    validator_result_t r;
    validator_evaluate(&st, &m, prose, strlen(prose), &r);
    ASSERT(r.decision == VALIDATOR_DECISION_PASS, "recommendation should PASS");

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 17: recommendation BLOCK — derived_from missing
 * ========================================================================= */

static void test_recommendation_block_no_derived(void)
{
    TEST("BLOCK: recommendation without derived_from → DERIVED_FROM_MISSING");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    const char *prose = "Suggest doing the thing.";
    char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    char json[512];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s-rec2\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[],"
        "\"assertions\":[{\"device\":\"r1\",\"claim_type\":\"recommendation\","
        "\"evidence_ref\":null}]}", ph);

    validator_manifest_t m; validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse");

    validator_result_t r;
    validator_evaluate(&st, &m, prose, strlen(prose), &r);
    ASSERT(r.decision == VALIDATOR_DECISION_BLOCK, "BLOCK");
    ASSERT(r.per_assertion[0].violation == VALIDATOR_VIOLATION_DERIVED_FROM_MISSING, "violation");
    ASSERT(r.per_assertion[0].error_class == VALIDATOR_ERROR_CLASS_PROVENANCE, "class provenance");

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 18: synthesis PASS — 3 evidence_refs, all seeded
 * ========================================================================= */

static void test_synthesis_pass(void)
{
    TEST("PASS: synthesis across 3 evidence_refs");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    char ev1[65], ev2[65], ev3[65];
    seed_artifact(&st, "s-syn", "obs-1", "r1 bgp", ev1);
    seed_artifact(&st, "s-syn", "obs-2", "r2 bgp", ev2);
    seed_artifact(&st, "s-syn", "obs-3", "r3 bgp", ev3);

    const char *prose = "Across r1, r2, r3 the BGP session count is stable at 4 peers each.";
    char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    char json[2048];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s-syn\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[\"%s\",\"%s\",\"%s\"],"
        "\"assertions\":[{\"device\":\"fabric\",\"claim_type\":\"synthesis\","
        "\"evidence_refs\":[\"%s\",\"%s\",\"%s\"]}]}",
        ph, ev1, ev2, ev3, ev1, ev2, ev3);

    validator_manifest_t m; validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse");
    ASSERT(m.assertions[0].evidence_refs_count == 3, "parsed 3 refs");

    validator_result_t r;
    validator_evaluate(&st, &m, prose, strlen(prose), &r);
    ASSERT(r.decision == VALIDATOR_DECISION_PASS, "synthesis should PASS");

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 19: outcome_verification PASS — post-action observation later than action
 * ========================================================================= */

static void test_outcome_verification_pass(void)
{
    TEST("PASS: outcome_verification with evidence ts > action ts");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    char action_h[65];
    seed_artifact(&st, "s-out", "action-1", "config change applied", action_h);
    /* Tiny sleep ensures monotonic timestamp delta; chain_append uses
     * get_wall_ns() which has ns resolution but sub-µs ordering of
     * back-to-back inserts is not formally guaranteed without a sleep. */
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 2000000 };  /* 2ms */
    nanosleep(&ts, NULL);
    char post_h[65];
    seed_artifact(&st, "s-out", "post-1", "device state after change", post_h);

    const char *prose = "The interface is now up after the no shutdown.";
    char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    char json[1536];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s-out\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[\"%s\",\"%s\"],"
        "\"assertions\":[{\"device\":\"r1\",\"claim_type\":\"outcome_verification\","
        "\"evidence_ref\":\"%s\",\"action_ref\":\"%s\"}]}",
        ph, action_h, post_h, post_h, action_h);

    validator_manifest_t m; validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse");
    ASSERT(m.assertions[0].has_action_ref, "parsed action_ref");

    validator_result_t r;
    validator_evaluate(&st, &m, prose, strlen(prose), &r);
    if (r.decision != VALIDATOR_DECISION_PASS) {
        char msg[200];
        snprintf(msg, sizeof(msg),
                 "outcome_verification PASS expected, got %s (%s)",
                 validator_decision_str(r.decision),
                 validator_violation_str(r.per_assertion[0].violation));
        FAIL(msg);
        virp_chain_destroy(&st);
        return;
    }

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 20: outcome_verification BLOCK — observation precedes action
 *
 * This is the protocol-significant regression: the FortiGate-style
 * "I made the change" overclaim where the AI cites a pre-action
 * observation as proof of post-action state. Without this check,
 * the AI's manifest looks structurally valid; the timestamp
 * comparison is the only structural property that catches it.
 * ========================================================================= */

static void test_outcome_verification_block_pre_action(void)
{
    TEST("BLOCK: outcome_verification with evidence ts ≤ action ts");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    /* Seed observation FIRST, then action. AI claims the observation
     * proves the post-action state, but the observation is older
     * than the action — exactly the overclaim shape. */
    char pre_h[65];
    seed_artifact(&st, "s-pre", "pre-obs", "device state before change", pre_h);
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 2000000 };
    nanosleep(&ts, NULL);
    char action_h[65];
    seed_artifact(&st, "s-pre", "action-1", "the action", action_h);

    const char *prose = "Interface is up after the change [fabricated re-pull].";
    char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    char json[1536];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s-pre\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[\"%s\",\"%s\"],"
        "\"assertions\":[{\"device\":\"r1\",\"claim_type\":\"outcome_verification\","
        "\"evidence_ref\":\"%s\",\"action_ref\":\"%s\"}]}",
        ph, pre_h, action_h, pre_h, action_h);

    validator_manifest_t m; validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse");

    validator_result_t r;
    validator_evaluate(&st, &m, prose, strlen(prose), &r);
    ASSERT(r.decision == VALIDATOR_DECISION_BLOCK, "BLOCK");
    ASSERT(r.per_assertion[0].violation == VALIDATOR_VIOLATION_OUTCOME_NOT_AFTER_ACTION, "violation");
    ASSERT(r.per_assertion[0].error_class == VALIDATOR_ERROR_CLASS_CONTENT, "class CONTENT");
    ASSERT(r.per_assertion[0].remediation_hint == VALIDATOR_HINT_FABRICATION_DETECTED, "hint fabrication_detected");

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 21: outcome_verification BLOCK — action_ref missing entirely
 * ========================================================================= */

static void test_outcome_verification_block_no_action_ref(void)
{
    TEST("BLOCK: outcome_verification without action_ref → ACTION_REF_MISSING");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    char ev[65];
    seed_artifact(&st, "s-noac", "obs-1", "post obs but no action ref", ev);

    const char *prose = "Outcome verified but I forgot to cite the action.";
    char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    char json[1024];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s-noac\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[\"%s\"],"
        "\"assertions\":[{\"device\":\"r1\",\"claim_type\":\"outcome_verification\","
        "\"evidence_ref\":\"%s\"}]}", ph, ev, ev);

    validator_manifest_t m; validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse");

    validator_result_t r;
    validator_evaluate(&st, &m, prose, strlen(prose), &r);
    ASSERT(r.decision == VALIDATOR_DECISION_BLOCK, "BLOCK");
    ASSERT(r.per_assertion[0].violation == VALIDATOR_VIOLATION_ACTION_REF_MISSING, "violation");
    ASSERT(r.per_assertion[0].error_class == VALIDATOR_ERROR_CLASS_PROVENANCE, "class provenance");

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 22: resolver — exact match (case-insensitive) RESOLVED
 * ========================================================================= */

static void test_resolver_exact_match(void)
{
    TEST("Resolver: exact match (case-insensitive) → RESOLVED");
    const char *fleet[] = {"SW-3850", "fortigate-200g", "R1", "Wazuh"};
    validator_resolve_result_t r;

    /* Same case */
    validator_resolve_device("SW-3850", fleet, 4, &r);
    ASSERT(r.status == VALIDATOR_RESOLVE_RESOLVED, "SW-3850 → RESOLVED");
    ASSERT(strcmp(r.canonical, "SW-3850") == 0, "canonical SW-3850");

    /* Different case still resolves and preserves registry casing */
    validator_resolve_device("sw-3850", fleet, 4, &r);
    ASSERT(r.status == VALIDATOR_RESOLVE_RESOLVED, "sw-3850 → RESOLVED");
    ASSERT(strcmp(r.canonical, "SW-3850") == 0, "canonical preserves SW-3850 case");

    validator_resolve_device("WAZUH", fleet, 4, &r);
    ASSERT(r.status == VALIDATOR_RESOLVE_RESOLVED, "WAZUH → RESOLVED");
    ASSERT(strcmp(r.canonical, "Wazuh") == 0, "canonical preserves Wazuh case");

    PASS();
}

/* =========================================================================
 * Test 23: resolver — hyphen-token prefix RESOLVED
 * ========================================================================= */

static void test_resolver_token_prefix(void)
{
    TEST("Resolver: hyphen-token prefix → RESOLVED");
    const char *fleet[] = {"fortigate-200g", "SW-3850", "pa-850", "R1"};
    validator_resolve_result_t r;

    validator_resolve_device("fortigate", fleet, 4, &r);
    ASSERT(r.status == VALIDATOR_RESOLVE_RESOLVED, "fortigate → RESOLVED");
    ASSERT(strcmp(r.canonical, "fortigate-200g") == 0, "canonical fortigate-200g");

    /* Case-insensitive */
    validator_resolve_device("FORTIGATE", fleet, 4, &r);
    ASSERT(r.status == VALIDATOR_RESOLVE_RESOLVED, "FORTIGATE → RESOLVED");
    ASSERT(strcmp(r.canonical, "fortigate-200g") == 0, "canonical preserves case");

    PASS();
}

/* =========================================================================
 * Test 24: resolver — prefix too short / mid-token UNRESOLVED
 * ========================================================================= */

static void test_resolver_prefix_rejects_too_short_and_midtoken(void)
{
    TEST("Resolver: <4 char prefix and mid-token prefix → UNRESOLVED");
    const char *fleet[] = {"fortigate-200g"};
    validator_resolve_result_t r;

    /* Too short: "fort" is <4 chars... actually it's 4 chars. Test with 3. */
    validator_resolve_device("for", fleet, 1, &r);
    ASSERT(r.status == VALIDATOR_RESOLVE_UNRESOLVED, "for → UNRESOLVED (too short)");

    /* 4-char "fort" is the minimum length but doesn't end at a hyphen boundary */
    validator_resolve_device("fort", fleet, 1, &r);
    ASSERT(r.status == VALIDATOR_RESOLVE_UNRESOLVED, "fort → UNRESOLVED (mid-token)");

    /* Mid-second-token, not at boundary */
    validator_resolve_device("fortigate-20", fleet, 1, &r);
    ASSERT(r.status == VALIDATOR_RESOLVE_UNRESOLVED, "fortigate-20 → UNRESOLVED (mid-token)");

    PASS();
}

/* =========================================================================
 * Test 25: resolver — no-hyphen canonicals: exact match only
 * ========================================================================= */

static void test_resolver_no_hyphen_exact_only(void)
{
    TEST("Resolver: no-hyphen canonical requires exact match");
    const char *fleet[] = {"R1", "R12", "Wazuh"};
    validator_resolve_result_t r;

    validator_resolve_device("R1", fleet, 3, &r);
    ASSERT(r.status == VALIDATOR_RESOLVE_RESOLVED, "R1 → RESOLVED (exact)");
    ASSERT(strcmp(r.canonical, "R1") == 0, "canonical R1");

    /* R1 is a prefix of R12 lexicographically, but no-hyphen rule says
     * prefix matching only applies to hyphenated canonicals → no fuzzy
     * match. R1 must match R1 exactly even though R12 starts with R1. */
    /* (The above is covered by the exact match above resolving to R1
     *  uniquely. Now verify "R" alone doesn't resolve.) */
    validator_resolve_device("R", fleet, 3, &r);
    ASSERT(r.status == VALIDATOR_RESOLVE_UNRESOLVED, "R → UNRESOLVED");

    /* "router" doesn't match R1 even though semantically related */
    validator_resolve_device("router", fleet, 3, &r);
    ASSERT(r.status == VALIDATOR_RESOLVE_UNRESOLVED, "router → UNRESOLVED");

    /* Wazuh exact case-insensitive */
    validator_resolve_device("wazuh", fleet, 3, &r);
    ASSERT(r.status == VALIDATOR_RESOLVE_RESOLVED, "wazuh → RESOLVED");
    ASSERT(strcmp(r.canonical, "Wazuh") == 0, "canonical Wazuh");

    PASS();
}

/* =========================================================================
 * Test 26: resolver — AMBIGUOUS when two canonicals match by prefix
 * ========================================================================= */

static void test_resolver_ambiguous(void)
{
    TEST("Resolver: prefix matching ≥2 canonicals → AMBIGUOUS");
    const char *fleet[] = {"fortigate-200g", "fortigate-100f", "fortiwifi-60f"};
    validator_resolve_result_t r;

    validator_resolve_device("fortigate", fleet, 3, &r);
    ASSERT(r.status == VALIDATOR_RESOLVE_AMBIGUOUS, "fortigate → AMBIGUOUS");
    ASSERT(r.candidate_count == 2, "2 candidates");
    /* candidate order: appearance in input list */
    ASSERT(strcmp(r.candidates[0], "fortigate-200g") == 0, "candidate 0");
    ASSERT(strcmp(r.candidates[1], "fortigate-100f") == 0, "candidate 1");

    /* "forti" matches fortigate-200g, fortigate-100f, fortiwifi-60f
     * — all three because "forti" is ≥4 chars and is a prefix that
     * ends at... wait, "forti" doesn't end at a hyphen in any of these.
     * Let's check: "fortigate-200g"[5] = 'g', not '-'. So "forti" does
     * NOT match by token prefix. Should be UNRESOLVED. */
    validator_resolve_device("forti", fleet, 3, &r);
    ASSERT(r.status == VALIDATOR_RESOLVE_UNRESOLVED, "forti → UNRESOLVED (mid-token)");

    PASS();
}

/* =========================================================================
 * Test 27: resolver — exact takes priority over prefix
 *
 * If claim_ref matches one canonical exactly AND another by prefix
 * (hypothetical because of devices.json being a flat list), exact
 * wins. Construct: ["fortigate", "fortigate-200g"] + claim "fortigate"
 * → RESOLVED to "fortigate" exact, not AMBIGUOUS.
 * ========================================================================= */

static void test_resolver_exact_priority_over_prefix(void)
{
    TEST("Resolver: exact match wins over prefix match");
    const char *fleet[] = {"fortigate", "fortigate-200g"};
    validator_resolve_result_t r;
    validator_resolve_device("fortigate", fleet, 2, &r);
    ASSERT(r.status == VALIDATOR_RESOLVE_RESOLVED, "RESOLVED (not AMBIGUOUS)");
    ASSERT(strcmp(r.canonical, "fortigate") == 0, "canonical exact match");
    PASS();
}

/* =========================================================================
 * Test 28: resolver — no match
 * ========================================================================= */

static void test_resolver_no_match(void)
{
    TEST("Resolver: unrelated claim_ref → UNRESOLVED");
    const char *fleet[] = {"fortigate-200g", "SW-3850"};
    validator_resolve_result_t r;

    validator_resolve_device("the firewall", fleet, 2, &r);
    ASSERT(r.status == VALIDATOR_RESOLVE_UNRESOLVED, "the firewall → UNRESOLVED");

    validator_resolve_device("", fleet, 2, &r);
    ASSERT(r.status == VALIDATOR_RESOLVE_UNRESOLVED, "empty string → UNRESOLVED");

    validator_resolve_device("nonexistent-device-99", fleet, 2, &r);
    ASSERT(r.status == VALIDATOR_RESOLVE_UNRESOLVED, "nonexistent → UNRESOLVED");

    PASS();
}

/* =========================================================================
 * Test 29: entity binding — exact match PASS
 * ========================================================================= */

static void test_entity_binding_exact_pass(void)
{
    TEST("Entity binding: assertion.device exact match → PASS");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    char ev[65];
    seed_obs_artifact(&st, "s-eb1", "fortigate-200g",
                      "fortigate bgp state", ev);

    const char *prose = "fortigate-200g BGP peer is established.";
    char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    char json[1024];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s-eb1\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[\"%s\"],"
        "\"assertions\":[{\"device\":\"fortigate-200g\","
        "\"claim_type\":\"state_observation\","
        "\"evidence_ref\":\"%s\"}]}", ph, ev, ev);

    validator_manifest_t m; validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse");

    validator_result_t r;
    validator_evaluate(&st, &m, prose, strlen(prose), &r);
    ASSERT(r.decision == VALIDATOR_DECISION_PASS, "PASS");

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 30: entity binding — canonical resolution PASS
 *
 * The case the original brief described: assertion says "fortigate",
 * chain entry's device segment is "fortigate-200g". Pre-Phase-4 this
 * was a hypothetical false negative; the validator didn't check device
 * at all. Post-Phase-4 the check binds and resolves.
 * ========================================================================= */

static void test_entity_binding_canonical_pass(void)
{
    TEST("Entity binding: 'fortigate' → 'fortigate-200g' canonical → PASS");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    char ev[65];
    seed_obs_artifact(&st, "s-eb2", "fortigate-200g", "config diff", ev);

    const char *prose = "fortigate config changed; rule 17 added.";
    char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    char json[1024];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s-eb2\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[\"%s\"],"
        "\"assertions\":[{\"device\":\"fortigate\","
        "\"claim_type\":\"config_change\","
        "\"evidence_ref\":\"%s\"}]}", ph, ev, ev);

    validator_manifest_t m; validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse");

    validator_result_t r;
    validator_evaluate(&st, &m, prose, strlen(prose), &r);
    if (r.decision != VALIDATOR_DECISION_PASS) {
        char msg[160];
        snprintf(msg, sizeof(msg), "expected PASS, got %s/%s",
                 validator_decision_str(r.decision),
                 validator_violation_str(r.per_assertion[0].violation));
        FAIL(msg);
        virp_chain_destroy(&st);
        return;
    }

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 31: entity binding — device mismatch BLOCK
 *
 * Assertion claims device="r1" but evidence_ref points at a chain entry
 * for fortigate-200g. AI mislabeling — class=content,
 * hint=fabrication_detected.
 * ========================================================================= */

static void test_entity_binding_mismatch_block(void)
{
    TEST("Entity binding: device mismatch → BLOCK with ENTITY_DEVICE_MISMATCH");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    char ev[65];
    seed_obs_artifact(&st, "s-eb3", "fortigate-200g", "actually fg state", ev);

    const char *prose = "R1 routing table looks normal.";
    char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    char json[1024];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s-eb3\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[\"%s\"],"
        "\"assertions\":[{\"device\":\"r1\","
        "\"claim_type\":\"state_observation\","
        "\"evidence_ref\":\"%s\"}]}", ph, ev, ev);

    validator_manifest_t m; validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse");

    validator_result_t r;
    validator_evaluate(&st, &m, prose, strlen(prose), &r);
    ASSERT(r.decision == VALIDATOR_DECISION_BLOCK, "BLOCK");
    ASSERT(r.per_assertion[0].violation == VALIDATOR_VIOLATION_ENTITY_DEVICE_MISMATCH,
           "ENTITY_DEVICE_MISMATCH");
    ASSERT(r.per_assertion[0].error_class == VALIDATOR_ERROR_CLASS_CONTENT,
           "class=content");
    ASSERT(r.per_assertion[0].remediation_hint == VALIDATOR_HINT_FABRICATION_DETECTED,
           "hint=fabrication_detected");

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Test 32: entity binding — legacy artifact_id (no obs:device:ts)
 *                          skipped silently
 *
 * Chain entries from before the obs:device:ts convention (or from
 * external test seeders) won't have a parseable device segment.
 * Binding skips silently — provenance is still verified via hash,
 * but the device cross-check can't run. Assertion PASSes if hash
 * provenance is good.
 * ========================================================================= */

static void test_entity_binding_legacy_artifact_skip(void)
{
    TEST("Entity binding: non-obs: artifact_id → binding skipped, PASS");
    cleanup();
    create_test_key();

    virp_chain_state_t st;
    virp_chain_init(&st, TEST_DB, TEST_KEY, 1, "local");

    /* seed_artifact (NOT seed_obs_artifact) writes artifact_id as
     * the literal "obs-legacy-1" — starts with "obs-" not "obs:". */
    char ev[65];
    seed_artifact(&st, "s-eb4", "obs-legacy-1", "old style content", ev);

    const char *prose = "Anything goes here, device unverifiable.";
    char ph[65]; sha256_hex((const unsigned char *)prose, strlen(prose), ph);

    char json[1024];
    int n = snprintf(json, sizeof(json),
        "{\"session_id\":\"s-eb4\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[\"%s\"],"
        "\"assertions\":[{\"device\":\"anything\","
        "\"claim_type\":\"state_observation\","
        "\"evidence_ref\":\"%s\"}]}", ph, ev, ev);

    validator_manifest_t m; validator_violation_code_t rr;
    ASSERT(validator_parse_manifest(json, (size_t)n, &m, &rr) == VIRP_OK, "parse");

    validator_result_t r;
    validator_evaluate(&st, &m, prose, strlen(prose), &r);
    ASSERT(r.decision == VALIDATOR_DECISION_PASS, "PASS (binding skipped)");

    virp_chain_destroy(&st);
    PASS();
}

/* =========================================================================
 * Main
 * ========================================================================= */

int main(void)
{
    printf("\n=== VIRP Response Validator Tests ===\n\n");

    test_pass_full();
    test_warn_state_read_null();
    test_block_state_change_null();
    test_block_evidence_not_in_turn();
    test_block_evidence_not_in_chain();
    test_block_prose_hash_mismatch();
    test_manifest_too_large();
    test_unknown_claim_type();
    test_parser_edge_cases();
    test_commit_decision();
    test_precedence();
    test_class_hint_mapping();
    test_manifest_missing_provenance();
    /* Phase 3 — new claim types */
    test_comparison_pass();
    test_comparison_block_too_few();
    test_recommendation_pass();
    test_recommendation_block_no_derived();
    test_synthesis_pass();
    test_outcome_verification_pass();
    test_outcome_verification_block_pre_action();
    test_outcome_verification_block_no_action_ref();
    /* Phase 4 — canonical resolver + entity binding */
    test_resolver_exact_match();
    test_resolver_token_prefix();
    test_resolver_prefix_rejects_too_short_and_midtoken();
    test_resolver_no_hyphen_exact_only();
    test_resolver_ambiguous();
    test_resolver_exact_priority_over_prefix();
    test_resolver_no_match();
    test_entity_binding_exact_pass();
    test_entity_binding_canonical_pass();
    test_entity_binding_mismatch_block();
    test_entity_binding_legacy_artifact_skip();

    printf("\n=== Results: %d passed, %d failed ===\n\n",
           tests_passed, tests_failed);

    cleanup();
    return tests_failed > 0 ? 1 : 0;
}
