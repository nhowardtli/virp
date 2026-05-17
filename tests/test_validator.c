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
        "\"assertions\":[{\"device\":\"r1\",\"claim_type\":\"state_read\","
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
        "\"assertions\":[{\"device\":\"r2\",\"claim_type\":\"state_read\","
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
        "\"assertions\":[{\"device\":\"r4\",\"claim_type\":\"state_read\","
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
        "\"assertions\":[{\"device\":\"r5\",\"claim_type\":\"state_read\","
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
            "%s{\"device\":\"r%d\",\"claim_type\":\"state_read\",\"evidence_ref\":null}",
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
        "\"assertions\":[{\"device\":\"r9\",\"claim_type\":\"state_read\","
        "\"evidence_ref\":\"not-hex\"}]}", ph);
    ASSERT(validator_parse_manifest(json1, (size_t)n1, &m, &reason) != VIRP_OK, "non-hex should fail");
    ASSERT(reason == VALIDATOR_VIOLATION_MANIFEST_MALFORMED, "reason code non-hex");

    /* Non-string device. */
    char json2[512];
    int n2 = snprintf(json2, sizeof(json2),
        "{\"session_id\":\"s9b\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[],"
        "\"assertions\":[{\"device\":12345,\"claim_type\":\"state_read\","
        "\"evidence_ref\":null}]}", ph);
    ASSERT(validator_parse_manifest(json2, (size_t)n2, &m, &reason) != VIRP_OK, "non-string should fail");
    ASSERT(reason == VALIDATOR_VIOLATION_MANIFEST_MALFORMED, "reason code non-string");

    /* Explicit null. */
    char json3[512];
    int n3 = snprintf(json3, sizeof(json3),
        "{\"session_id\":\"s9c\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[],"
        "\"assertions\":[{\"device\":\"r9\",\"claim_type\":\"state_read\","
        "\"evidence_ref\":null}]}", ph);
    ASSERT(validator_parse_manifest(json3, (size_t)n3, &m, &reason) == VIRP_OK, "null should parse");
    ASSERT(!m.assertions[0].has_evidence, "null has_evidence=false");

    /* Missing evidence_ref key. */
    char json4[512];
    int n4 = snprintf(json4, sizeof(json4),
        "{\"session_id\":\"s9d\",\"prose_hash\":\"%s\","
        "\"tool_call_refs\":[],"
        "\"assertions\":[{\"device\":\"r9\",\"claim_type\":\"state_read\"}]}", ph);
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
        "\"assertions\":[{\"device\":\"r10\",\"claim_type\":\"state_read\","
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
              "{\"device\":\"r11\",\"claim_type\":\"state_read\",\"evidence_ref\":null},"
              "{\"device\":\"r11\",\"claim_type\":\"state_read\",\"evidence_ref\":\"%s\"}"
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
              "{\"device\":\"r11\",\"claim_type\":\"state_read\",\"evidence_ref\":null},"
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
        { VALIDATOR_VIOLATION_NONE,                     VALIDATOR_ERROR_CLASS_NONE,       VALIDATOR_HINT_NONE                 },
        { VALIDATOR_VIOLATION_NO_EVIDENCE_STATE_READ,   VALIDATOR_ERROR_CLASS_PROVENANCE, VALIDATOR_HINT_RERUN_WITH_TOOLS     },
        { VALIDATOR_VIOLATION_NO_EVIDENCE_STATE_CHANGE, VALIDATOR_ERROR_CLASS_PROVENANCE, VALIDATOR_HINT_RERUN_WITH_TOOLS     },
        { VALIDATOR_VIOLATION_EVIDENCE_NOT_IN_TURN,     VALIDATOR_ERROR_CLASS_PROVENANCE, VALIDATOR_HINT_RERUN_WITH_TOOLS     },
        { VALIDATOR_VIOLATION_EVIDENCE_NOT_IN_CHAIN,    VALIDATOR_ERROR_CLASS_CONTENT,    VALIDATOR_HINT_FABRICATION_DETECTED },
        { VALIDATOR_VIOLATION_UNKNOWN_CLAIM_TYPE,       VALIDATOR_ERROR_CLASS_SCHEMA,     VALIDATOR_HINT_REPORT_SCHEMA_GAP    },
        { VALIDATOR_VIOLATION_PROSE_HASH_MISMATCH,      VALIDATOR_ERROR_CLASS_CONTENT,    VALIDATOR_HINT_FABRICATION_DETECTED },
        { VALIDATOR_VIOLATION_MANIFEST_MALFORMED,       VALIDATOR_ERROR_CLASS_FORMAT,     VALIDATOR_HINT_REGENERATE_MANIFEST  },
        { VALIDATOR_VIOLATION_MANIFEST_TOO_LARGE,       VALIDATOR_ERROR_CLASS_FORMAT,     VALIDATOR_HINT_REGENERATE_MANIFEST  },
        { VALIDATOR_VIOLATION_MANIFEST_MISSING,         VALIDATOR_ERROR_CLASS_PROVENANCE, VALIDATOR_HINT_RERUN_WITH_TOOLS     },
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

    printf("\n=== Results: %d passed, %d failed ===\n\n",
           tests_passed, tests_failed);

    cleanup();
    return tests_failed > 0 ? 1 : 0;
}
