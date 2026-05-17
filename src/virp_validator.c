/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Response Validator implementation
 *
 * Fails closed on every ambiguous input. No fallbacks.
 */

#define _POSIX_C_SOURCE 199309L

#include "virp_validator.h"

#include "cJSON.h"

#include <openssl/sha.h>

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

static bool is_hex64(const char *s)
{
    if (s == NULL) return false;
    for (size_t i = 0; i < VALIDATOR_HASH_HEX_LEN; i++) {
        char c = s[i];
        if (c == '\0') return false;
        bool ok = (c >= '0' && c <= '9') ||
                  (c >= 'a' && c <= 'f');
        if (!ok) return false;
    }
    return s[VALIDATOR_HASH_HEX_LEN] == '\0';
}

/* Device names and session IDs are restricted to a printable ASCII
 * subset that is safe to embed in JSON without escaping. This is a
 * policy choice; VIRP device identifiers already satisfy it. */
static bool is_safe_token(const char *s, size_t max_len)
{
    if (s == NULL || s[0] == '\0') return false;
    size_t i;
    for (i = 0; i < max_len; i++) {
        char c = s[i];
        if (c == '\0') return true;
        bool ok = (c >= 'A' && c <= 'Z') ||
                  (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') ||
                  c == '.' || c == '_' || c == '-';
        if (!ok) return false;
    }
    return false; /* not NUL-terminated within max_len */
}

static void sha256_hex(const unsigned char *data, size_t len, char out[VALIDATOR_HASH_HEX_LEN + 1])
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(data, len, digest);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        (void)snprintf(out + i * 2, 3, "%02x", digest[i]);
    }
    out[VALIDATOR_HASH_HEX_LEN] = '\0';
}

static validator_claim_type_t parse_claim_type(const char *s)
{
    if (s == NULL) return VALIDATOR_CLAIM_UNKNOWN;
    if (strcmp(s, "state_read") == 0)    return VALIDATOR_CLAIM_STATE_READ;
    if (strcmp(s, "state_change") == 0)  return VALIDATOR_CLAIM_STATE_CHANGE;
    if (strcmp(s, "config_change") == 0) return VALIDATOR_CLAIM_CONFIG_CHANGE;
    return VALIDATOR_CLAIM_UNKNOWN;
}

/* BLOCK > WARN > PASS */
static validator_decision_t decision_max(validator_decision_t a, validator_decision_t b)
{
    return (a > b) ? a : b;
}

/* =========================================================================
 * Human-readable helpers
 * ========================================================================= */

const char *validator_decision_str(validator_decision_t d)
{
    switch (d) {
        case VALIDATOR_DECISION_PASS:  return "pass";
        case VALIDATOR_DECISION_WARN:  return "warn";
        case VALIDATOR_DECISION_BLOCK: return "block";
    }
    return "unknown";
}

const char *validator_violation_str(validator_violation_code_t v)
{
    switch (v) {
        case VALIDATOR_VIOLATION_NONE:                     return "none";
        case VALIDATOR_VIOLATION_NO_EVIDENCE_STATE_READ:   return "no_evidence_state_read";
        case VALIDATOR_VIOLATION_NO_EVIDENCE_STATE_CHANGE: return "no_evidence_state_change";
        case VALIDATOR_VIOLATION_EVIDENCE_NOT_IN_TURN:     return "evidence_not_in_turn";
        case VALIDATOR_VIOLATION_EVIDENCE_NOT_IN_CHAIN:    return "evidence_not_in_chain";
        case VALIDATOR_VIOLATION_UNKNOWN_CLAIM_TYPE:       return "unknown_claim_type";
        case VALIDATOR_VIOLATION_PROSE_HASH_MISMATCH:      return "prose_hash_mismatch";
        case VALIDATOR_VIOLATION_MANIFEST_MALFORMED:       return "manifest_malformed";
        case VALIDATOR_VIOLATION_MANIFEST_TOO_LARGE:       return "manifest_too_large";
        case VALIDATOR_VIOLATION_MANIFEST_MISSING:         return "manifest_missing";
    }
    return "unknown";
}

const char *validator_claim_type_str(validator_claim_type_t t)
{
    switch (t) {
        case VALIDATOR_CLAIM_STATE_READ:    return "state_read";
        case VALIDATOR_CLAIM_STATE_CHANGE:  return "state_change";
        case VALIDATOR_CLAIM_CONFIG_CHANGE: return "config_change";
        case VALIDATOR_CLAIM_UNKNOWN:       return "unknown";
    }
    return "unknown";
}

const char *validator_error_class_str(validator_error_class_t c)
{
    switch (c) {
        case VALIDATOR_ERROR_CLASS_NONE:       return "none";
        case VALIDATOR_ERROR_CLASS_FORMAT:     return "format";
        case VALIDATOR_ERROR_CLASS_SCHEMA:     return "schema";
        case VALIDATOR_ERROR_CLASS_PROVENANCE: return "provenance";
        case VALIDATOR_ERROR_CLASS_CONTENT:    return "content";
    }
    return "none";
}

const char *validator_remediation_hint_str(validator_remediation_hint_t h)
{
    switch (h) {
        case VALIDATOR_HINT_NONE:                 return "none";
        case VALIDATOR_HINT_REGENERATE_MANIFEST:  return "regenerate_manifest";
        case VALIDATOR_HINT_REPORT_SCHEMA_GAP:    return "report_schema_gap";
        case VALIDATOR_HINT_RERUN_WITH_TOOLS:     return "rerun_with_tools";
        case VALIDATOR_HINT_FABRICATION_DETECTED: return "fabrication_detected";
    }
    return "none";
}

validator_error_class_t validator_violation_class(validator_violation_code_t v)
{
    switch (v) {
        case VALIDATOR_VIOLATION_NONE:
            return VALIDATOR_ERROR_CLASS_NONE;
        case VALIDATOR_VIOLATION_MANIFEST_MALFORMED:
        case VALIDATOR_VIOLATION_MANIFEST_TOO_LARGE:
            return VALIDATOR_ERROR_CLASS_FORMAT;
        case VALIDATOR_VIOLATION_UNKNOWN_CLAIM_TYPE:
            return VALIDATOR_ERROR_CLASS_SCHEMA;
        case VALIDATOR_VIOLATION_NO_EVIDENCE_STATE_READ:
        case VALIDATOR_VIOLATION_NO_EVIDENCE_STATE_CHANGE:
        case VALIDATOR_VIOLATION_EVIDENCE_NOT_IN_TURN:
        case VALIDATOR_VIOLATION_MANIFEST_MISSING:
            return VALIDATOR_ERROR_CLASS_PROVENANCE;
        case VALIDATOR_VIOLATION_EVIDENCE_NOT_IN_CHAIN:
        case VALIDATOR_VIOLATION_PROSE_HASH_MISMATCH:
            return VALIDATOR_ERROR_CLASS_CONTENT;
    }
    return VALIDATOR_ERROR_CLASS_NONE;
}

validator_remediation_hint_t validator_violation_hint(validator_violation_code_t v)
{
    switch (validator_violation_class(v)) {
        case VALIDATOR_ERROR_CLASS_NONE:       return VALIDATOR_HINT_NONE;
        case VALIDATOR_ERROR_CLASS_FORMAT:     return VALIDATOR_HINT_REGENERATE_MANIFEST;
        case VALIDATOR_ERROR_CLASS_SCHEMA:     return VALIDATOR_HINT_REPORT_SCHEMA_GAP;
        case VALIDATOR_ERROR_CLASS_PROVENANCE: return VALIDATOR_HINT_RERUN_WITH_TOOLS;
        case VALIDATOR_ERROR_CLASS_CONTENT:    return VALIDATOR_HINT_FABRICATION_DETECTED;
    }
    return VALIDATOR_HINT_NONE;
}

/* =========================================================================
 * Manifest parser
 * ========================================================================= */

static virp_error_t parse_tool_call_refs(const cJSON *arr, validator_manifest_t *m,
                                         validator_violation_code_t *reason_out)
{
    if (!cJSON_IsArray(arr)) {
        *reason_out = VALIDATOR_VIOLATION_MANIFEST_MALFORMED;
        return VIRP_ERR_INVALID_LENGTH;
    }
    size_t n = 0;
    const cJSON *item;
    cJSON_ArrayForEach(item, arr) {
        if (n >= VALIDATOR_MAX_TOOL_CALL_REFS) {
            *reason_out = VALIDATOR_VIOLATION_MANIFEST_TOO_LARGE;
            return VIRP_ERR_INVALID_LENGTH;
        }
        if (!cJSON_IsString(item) || !is_hex64(item->valuestring)) {
            *reason_out = VALIDATOR_VIOLATION_MANIFEST_MALFORMED;
            return VIRP_ERR_INVALID_LENGTH;
        }
        memcpy(m->tool_call_refs[n], item->valuestring, VALIDATOR_HASH_HEX_LEN + 1);
        n++;
    }
    m->tool_call_ref_count = n;
    return VIRP_OK;
}

static virp_error_t parse_one_assertion(const cJSON *obj, validator_assertion_t *a,
                                        validator_violation_code_t *reason_out)
{
    if (!cJSON_IsObject(obj)) {
        *reason_out = VALIDATOR_VIOLATION_MANIFEST_MALFORMED;
        return VIRP_ERR_INVALID_LENGTH;
    }

    const cJSON *dev = cJSON_GetObjectItemCaseSensitive(obj, "device");
    if (!cJSON_IsString(dev) || !is_safe_token(dev->valuestring, VALIDATOR_DEVICE_MAX)) {
        *reason_out = VALIDATOR_VIOLATION_MANIFEST_MALFORMED;
        return VIRP_ERR_INVALID_LENGTH;
    }
    (void)snprintf(a->device, sizeof(a->device), "%s", dev->valuestring);

    const cJSON *ct = cJSON_GetObjectItemCaseSensitive(obj, "claim_type");
    if (!cJSON_IsString(ct)) {
        *reason_out = VALIDATOR_VIOLATION_MANIFEST_MALFORMED;
        return VIRP_ERR_INVALID_LENGTH;
    }
    a->claim_type = parse_claim_type(ct->valuestring);
    /* UNKNOWN is not a parse error — it is evaluated to BLOCK later. */

    /* evidence_ref: missing key OR explicit null → has_evidence=false.
     * Any other type, or a non-hex string, is a parse error. */
    const cJSON *ev = cJSON_GetObjectItemCaseSensitive(obj, "evidence_ref");
    if (ev == NULL || cJSON_IsNull(ev)) {
        a->has_evidence = false;
        a->evidence_ref[0] = '\0';
    } else if (cJSON_IsString(ev)) {
        if (!is_hex64(ev->valuestring)) {
            *reason_out = VALIDATOR_VIOLATION_MANIFEST_MALFORMED;
            return VIRP_ERR_INVALID_LENGTH;
        }
        a->has_evidence = true;
        memcpy(a->evidence_ref, ev->valuestring, VALIDATOR_HASH_HEX_LEN + 1);
    } else {
        *reason_out = VALIDATOR_VIOLATION_MANIFEST_MALFORMED;
        return VIRP_ERR_INVALID_LENGTH;
    }

    return VIRP_OK;
}

virp_error_t validator_parse_manifest(const char *json,
                                      size_t json_len,
                                      validator_manifest_t *manifest,
                                      validator_violation_code_t *reason_out)
{
    if (manifest == NULL || reason_out == NULL) return VIRP_ERR_NULL_PTR;
    memset(manifest, 0, sizeof(*manifest));
    *reason_out = VALIDATOR_VIOLATION_NONE;

    if (json == NULL || json_len == 0) {
        *reason_out = VALIDATOR_VIOLATION_MANIFEST_MISSING;
        return VIRP_ERR_NULL_PTR;
    }

    cJSON *root = cJSON_ParseWithLength(json, json_len);
    if (root == NULL) {
        *reason_out = VALIDATOR_VIOLATION_MANIFEST_MALFORMED;
        return VIRP_ERR_INVALID_LENGTH;
    }

    virp_error_t err = VIRP_OK;

    const cJSON *sid = cJSON_GetObjectItemCaseSensitive(root, "session_id");
    if (!cJSON_IsString(sid) || !is_safe_token(sid->valuestring, VALIDATOR_SESSION_ID_MAX)) {
        *reason_out = VALIDATOR_VIOLATION_MANIFEST_MALFORMED;
        err = VIRP_ERR_INVALID_LENGTH;
        goto out;
    }
    (void)snprintf(manifest->session_id, sizeof(manifest->session_id),
                   "%s", sid->valuestring);

    const cJSON *ph = cJSON_GetObjectItemCaseSensitive(root, "prose_hash");
    if (!cJSON_IsString(ph) || !is_hex64(ph->valuestring)) {
        *reason_out = VALIDATOR_VIOLATION_MANIFEST_MALFORMED;
        err = VIRP_ERR_INVALID_LENGTH;
        goto out;
    }
    memcpy(manifest->prose_hash, ph->valuestring, VALIDATOR_HASH_HEX_LEN + 1);

    const cJSON *refs = cJSON_GetObjectItemCaseSensitive(root, "tool_call_refs");
    if (refs == NULL) {
        manifest->tool_call_ref_count = 0;
    } else {
        err = parse_tool_call_refs(refs, manifest, reason_out);
        if (err != VIRP_OK) goto out;
    }

    const cJSON *asserts = cJSON_GetObjectItemCaseSensitive(root, "assertions");
    if (!cJSON_IsArray(asserts)) {
        *reason_out = VALIDATOR_VIOLATION_MANIFEST_MALFORMED;
        err = VIRP_ERR_INVALID_LENGTH;
        goto out;
    }

    size_t n = 0;
    const cJSON *it;
    cJSON_ArrayForEach(it, asserts) {
        if (n >= VALIDATOR_MAX_ASSERTIONS) {
            *reason_out = VALIDATOR_VIOLATION_MANIFEST_TOO_LARGE;
            err = VIRP_ERR_INVALID_LENGTH;
            goto out;
        }
        err = parse_one_assertion(it, &manifest->assertions[n], reason_out);
        if (err != VIRP_OK) goto out;
        n++;
    }
    manifest->assertion_count = n;

out:
    cJSON_Delete(root);
    return err;
}

/* =========================================================================
 * Evaluation
 * ========================================================================= */

static bool ref_in_turn(const validator_manifest_t *m, const char *hex)
{
    for (size_t i = 0; i < m->tool_call_ref_count; i++) {
        if (memcmp(m->tool_call_refs[i], hex, VALIDATOR_HASH_HEX_LEN + 1) == 0) {
            return true;
        }
    }
    return false;
}

static virp_error_t ref_in_chain(virp_chain_state_t *chain,
                                 const char *session_id,
                                 const char *artifact_hash_hex,
                                 bool *found)
{
    *found = false;
    const char *sql =
        "SELECT 1 FROM chain_entries "
        "WHERE session_id = ? AND artifact_hash = ? LIMIT 1";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(chain->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return VIRP_ERR_CHAIN_DB;

    rc = sqlite3_bind_text(stmt, 1, session_id, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) { sqlite3_finalize(stmt); return VIRP_ERR_CHAIN_DB; }
    rc = sqlite3_bind_text(stmt, 2, artifact_hash_hex, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) { sqlite3_finalize(stmt); return VIRP_ERR_CHAIN_DB; }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *found = true;
    } else if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return VIRP_ERR_CHAIN_DB;
    }
    sqlite3_finalize(stmt);
    return VIRP_OK;
}

static void evaluate_assertion(virp_chain_state_t *chain,
                               const validator_manifest_t *m,
                               const validator_assertion_t *a,
                               validator_assertion_result_t *r)
{
    r->decision  = VALIDATOR_DECISION_PASS;
    r->violation = VALIDATOR_VIOLATION_NONE;

    if (a->claim_type == VALIDATOR_CLAIM_UNKNOWN) {
        r->decision  = VALIDATOR_DECISION_BLOCK;
        r->violation = VALIDATOR_VIOLATION_UNKNOWN_CLAIM_TYPE;
        return;
    }

    if (!a->has_evidence) {
        if (a->claim_type == VALIDATOR_CLAIM_STATE_READ) {
            r->decision  = VALIDATOR_DECISION_WARN;
            r->violation = VALIDATOR_VIOLATION_NO_EVIDENCE_STATE_READ;
        } else {
            r->decision  = VALIDATOR_DECISION_BLOCK;
            r->violation = VALIDATOR_VIOLATION_NO_EVIDENCE_STATE_CHANGE;
        }
        return;
    }

    if (!ref_in_turn(m, a->evidence_ref)) {
        r->decision  = VALIDATOR_DECISION_BLOCK;
        r->violation = VALIDATOR_VIOLATION_EVIDENCE_NOT_IN_TURN;
        return;
    }

    bool in_chain = false;
    virp_error_t err = ref_in_chain(chain, m->session_id, a->evidence_ref, &in_chain);
    if (err != VIRP_OK || !in_chain) {
        r->decision  = VALIDATOR_DECISION_BLOCK;
        r->violation = VALIDATOR_VIOLATION_EVIDENCE_NOT_IN_CHAIN;
        return;
    }
}

virp_error_t validator_evaluate(virp_chain_state_t *chain,
                                const validator_manifest_t *manifest,
                                const char *prose,
                                size_t prose_len,
                                validator_result_t *result)
{
    if (chain == NULL || manifest == NULL || result == NULL) return VIRP_ERR_NULL_PTR;
    if (prose == NULL && prose_len != 0) return VIRP_ERR_NULL_PTR;

    memset(result, 0, sizeof(*result));
    result->chain_sequence = -1;

    validator_decision_t roll = VALIDATOR_DECISION_PASS;

    /* Prose hash check — turn-wide. */
    char computed[VALIDATOR_HASH_HEX_LEN + 1];
    sha256_hex((const unsigned char *)(prose ? prose : ""), prose_len, computed);
    if (memcmp(computed, manifest->prose_hash, VALIDATOR_HASH_HEX_LEN + 1) != 0) {
        result->turn_violation = VALIDATOR_VIOLATION_PROSE_HASH_MISMATCH;
        roll = decision_max(roll, VALIDATOR_DECISION_BLOCK);
    }

    /* Per-assertion. */
    result->per_assertion_count = manifest->assertion_count;
    for (size_t i = 0; i < manifest->assertion_count; i++) {
        evaluate_assertion(chain, manifest, &manifest->assertions[i],
                           &result->per_assertion[i]);
        roll = decision_max(roll, result->per_assertion[i].decision);
    }

    result->decision = roll;

    /* Derive error_class and remediation_hint from violation codes.
     * Pure function of violation; never touches emit sites. */
    result->turn_error_class      = validator_violation_class(result->turn_violation);
    result->turn_remediation_hint = validator_violation_hint(result->turn_violation);
    for (size_t i = 0; i < result->per_assertion_count; i++) {
        result->per_assertion[i].error_class =
            validator_violation_class(result->per_assertion[i].violation);
        result->per_assertion[i].remediation_hint =
            validator_violation_hint(result->per_assertion[i].violation);
    }

    return VIRP_OK;
}

/* =========================================================================
 * Commit
 * ========================================================================= */

/*
 * Build canonical JSON describing the decision. Deterministic byte-for-byte
 * given the same inputs — this is what gets SHA-256'd to produce the
 * artifact_hash that lands in chain.db. Assertion order is the order
 * the AI layer declared them, which is also the order we evaluated them.
 */
static int build_canonical_decision(const validator_manifest_t *m,
                                    const validator_result_t *r,
                                    char *buf, size_t buf_len)
{
    int off = 0;
    int w = snprintf(buf, buf_len,
        "{\"session_id\":\"%s\","
        "\"decision\":\"%s\","
        "\"turn_violation\":%d,"
        "\"turn_error_class\":\"%s\","
        "\"turn_remediation_hint\":\"%s\","
        "\"prose_hash\":\"%s\","
        "\"assertions\":[",
        m->session_id,
        validator_decision_str(r->decision),
        (int)r->turn_violation,
        validator_error_class_str(r->turn_error_class),
        validator_remediation_hint_str(r->turn_remediation_hint),
        m->prose_hash);
    if (w < 0 || (size_t)w >= buf_len) return -1;
    off = w;

    for (size_t i = 0; i < r->per_assertion_count; i++) {
        const validator_assertion_t *a = &m->assertions[i];
        const validator_assertion_result_t *ar = &r->per_assertion[i];
        w = snprintf(buf + off, buf_len - (size_t)off,
            "%s{\"device\":\"%s\","
            "\"claim_type\":\"%s\","
            "\"decision\":\"%s\","
            "\"violation\":%d,"
            "\"error_class\":\"%s\","
            "\"remediation_hint\":\"%s\"}",
            (i == 0) ? "" : ",",
            a->device,
            validator_claim_type_str(a->claim_type),
            validator_decision_str(ar->decision),
            (int)ar->violation,
            validator_error_class_str(ar->error_class),
            validator_remediation_hint_str(ar->remediation_hint));
        if (w < 0 || (size_t)w >= buf_len - (size_t)off) return -1;
        off += w;
    }

    w = snprintf(buf + off, buf_len - (size_t)off, "]}");
    if (w < 0 || (size_t)w >= buf_len - (size_t)off) return -1;
    off += w;
    return off;
}

virp_error_t validator_commit_decision(virp_chain_state_t *chain,
                                       const validator_manifest_t *manifest,
                                       validator_result_t *result)
{
    if (chain == NULL || manifest == NULL || result == NULL) return VIRP_ERR_NULL_PTR;

    /* Canonical JSON buffer: big enough for MAX_ASSERTIONS plus preamble. */
    char canonical[8192];
    int n = build_canonical_decision(manifest, result, canonical, sizeof(canonical));
    if (n < 0) return VIRP_ERR_BUFFER_TOO_SMALL;

    sha256_hex((const unsigned char *)canonical, (size_t)n, result->artifact_hash);

    char artifact_id[64];
    (void)snprintf(artifact_id, sizeof(artifact_id),
                   "val-%.16s", result->artifact_hash);

    virp_chain_entry_t entry;
    virp_error_t err = virp_chain_append(chain,
                                         manifest->session_id,
                                         "validation",
                                         artifact_id,
                                         result->artifact_hash,
                                         &entry);
    if (err != VIRP_OK) return err;

    memcpy(result->chain_entry_hash, entry.chain_entry_hash,
           sizeof(result->chain_entry_hash));
    result->chain_sequence = entry.sequence;

    /* Persist the canonical decision body to artifacts.
     * Best-effort: chain_entries is the canonical record; an
     * orphan-headers-only failure mode is current behavior for
     * pre-Phase-2 entries, so we don't fail the whole call here.
     * A warning to stderr is captured by the systemd journal for
     * post-hoc inspection. */
    virp_error_t aerr = virp_chain_artifact_store(chain,
                                                   artifact_id,
                                                   "validation",
                                                   canonical,
                                                   result->artifact_hash,
                                                   manifest->session_id);
    if (aerr != VIRP_OK) {
        fprintf(stderr,
                "validator_commit_decision: artifact_store failed "
                "(err=%d) for session=%s artifact_id=%s — chain entry "
                "written but body not persisted\n",
                (int)aerr, manifest->session_id, artifact_id);
    }
    return VIRP_OK;
}

/* =========================================================================
 * Fail-closed convenience wrapper
 * ========================================================================= */

virp_error_t validator_run_turn(virp_chain_state_t *chain,
                                const char *manifest_json,
                                size_t manifest_json_len,
                                const char *prose,
                                size_t prose_len,
                                const char *fallback_session_id,
                                validator_result_t *result)
{
    if (chain == NULL || result == NULL || fallback_session_id == NULL) {
        return VIRP_ERR_NULL_PTR;
    }

    validator_manifest_t manifest;
    validator_violation_code_t reason = VALIDATOR_VIOLATION_NONE;
    virp_error_t perr = validator_parse_manifest(manifest_json, manifest_json_len,
                                                  &manifest, &reason);
    if (perr != VIRP_OK) {
        memset(result, 0, sizeof(*result));
        result->chain_sequence  = -1;
        result->decision        = VALIDATOR_DECISION_BLOCK;
        result->turn_violation  = (reason != VALIDATOR_VIOLATION_NONE)
                                  ? reason
                                  : VALIDATOR_VIOLATION_MANIFEST_MALFORMED;
        result->turn_error_class      = validator_violation_class(result->turn_violation);
        result->turn_remediation_hint = validator_violation_hint(result->turn_violation);

        /* Manifest may not have given us a session_id. Fall back. */
        (void)snprintf(manifest.session_id, sizeof(manifest.session_id),
                       "%s", fallback_session_id);
        (void)snprintf(manifest.prose_hash, sizeof(manifest.prose_hash),
                       "%064d", 0);
        manifest.assertion_count     = 0;
        manifest.tool_call_ref_count = 0;
        return validator_commit_decision(chain, &manifest, result);
    }

    virp_error_t eerr = validator_evaluate(chain, &manifest, prose, prose_len, result);
    if (eerr != VIRP_OK) return eerr;

    return validator_commit_decision(chain, &manifest, result);
}
