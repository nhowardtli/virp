/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Response Validator
 *
 * Out-of-band verification of AI-layer prose against chain.db.
 * Runs on CT 211 (O-Node side). The AI layer on CT 210 cannot write
 * chain.db or forge artifact_hash values, which is the only trust
 * boundary this component relies on.
 *
 * Inputs per turn:
 *   - Manifest JSON sidecar (assertions + tool_call_refs + prose_hash)
 *   - The prose bytes the AI layer is about to emit
 *
 * Outputs:
 *   - A decision (PASS / WARN / BLOCK) plus per-assertion reasons
 *   - A "validation" artifact committed to chain.db so the check is
 *     itself tamper-evident
 *
 * A missing or malformed manifest fails closed to BLOCK. This is not
 * a suggestion — callers must not treat it as recoverable.
 *
 * See docs/VALIDATOR-MANIFEST-CONTRACT.md for the manifest schema
 * and the AI-layer-side obligations.
 */

#ifndef VIRP_VALIDATOR_H
#define VIRP_VALIDATOR_H

#include "virp.h"
#include "virp_chain.h"

/* =========================================================================
 * Limits
 *
 * Caps bound the worst-case manifest. At the values below the manifest
 * struct is ~180KB, so validator_run_turn heap-allocates it; the
 * validator_result_t (~8KB) and per-call canonical/response buffers
 * follow the same pattern. Increase the caps freely — adjust the heap
 * sizing in validator_commit_decision and the onode handler if the
 * per-assertion canonical format grows.
 * ========================================================================= */

#define VALIDATOR_MAX_ASSERTIONS        1024
#define VALIDATOR_MAX_TOOL_CALL_REFS    512
#define VALIDATOR_DEVICE_MAX            64
#define VALIDATOR_HASH_HEX_LEN          64      /* SHA-256 hex, no NUL */
#define VALIDATOR_CLAIM_TYPE_MAX        32
#define VALIDATOR_SESSION_ID_MAX        64      /* mirrors virp_chain_entry_t */

/* =========================================================================
 * Claim types
 *
 * state_read    — AI asserts current device state (BGP peer up, route X,
 *                 interface counter Y). Missing evidence is a WARN.
 * state_change  — AI asserts a runtime change occurred (interface toggled,
 *                 adjacency flapped). Missing evidence is a BLOCK.
 * config_change — AI asserts configuration was modified. Missing evidence
 *                 is a BLOCK.
 * unknown       — parser could not map the string. Always BLOCK.
 * ========================================================================= */

typedef enum {
    VALIDATOR_CLAIM_UNKNOWN       = 0,
    VALIDATOR_CLAIM_STATE_READ    = 1,
    VALIDATOR_CLAIM_STATE_CHANGE  = 2,
    VALIDATOR_CLAIM_CONFIG_CHANGE = 3
} validator_claim_type_t;

/* =========================================================================
 * Decision and violation codes
 *
 * Decision precedence: BLOCK > WARN > PASS. A turn's rollup is the
 * strongest decision seen across all assertions and any turn-wide
 * violation (prose hash, manifest malformed).
 * ========================================================================= */

typedef enum {
    VALIDATOR_DECISION_PASS  = 0,
    VALIDATOR_DECISION_WARN  = 1,
    VALIDATOR_DECISION_BLOCK = 2
} validator_decision_t;

typedef enum {
    VALIDATOR_VIOLATION_NONE                    = 0,
    VALIDATOR_VIOLATION_NO_EVIDENCE_STATE_READ  = 1,  /* → WARN  */
    VALIDATOR_VIOLATION_NO_EVIDENCE_STATE_CHANGE= 2,  /* → BLOCK */
    VALIDATOR_VIOLATION_EVIDENCE_NOT_IN_TURN    = 3,  /* → BLOCK */
    VALIDATOR_VIOLATION_EVIDENCE_NOT_IN_CHAIN   = 4,  /* → BLOCK */
    VALIDATOR_VIOLATION_UNKNOWN_CLAIM_TYPE      = 5,  /* → BLOCK */
    VALIDATOR_VIOLATION_PROSE_HASH_MISMATCH     = 6,  /* → BLOCK (turn) */
    VALIDATOR_VIOLATION_MANIFEST_MALFORMED      = 7,  /* → BLOCK (turn) */
    VALIDATOR_VIOLATION_MANIFEST_TOO_LARGE      = 8,  /* → BLOCK (turn) */
    VALIDATOR_VIOLATION_MANIFEST_MISSING        = 9   /* → BLOCK (turn) */
} validator_violation_code_t;

/* =========================================================================
 * Manifest — parsed form of the JSON sidecar
 * ========================================================================= */

typedef struct {
    char                     device[VALIDATOR_DEVICE_MAX];
    validator_claim_type_t   claim_type;
    bool                     has_evidence;                       /* false if JSON null or omitted */
    char                     evidence_ref[VALIDATOR_HASH_HEX_LEN + 1];
} validator_assertion_t;

typedef struct {
    char                   session_id[VALIDATOR_SESSION_ID_MAX];
    char                   prose_hash[VALIDATOR_HASH_HEX_LEN + 1];
    char                   tool_call_refs[VALIDATOR_MAX_TOOL_CALL_REFS]
                                          [VALIDATOR_HASH_HEX_LEN + 1];
    size_t                 tool_call_ref_count;
    validator_assertion_t  assertions[VALIDATOR_MAX_ASSERTIONS];
    size_t                 assertion_count;
} validator_manifest_t;

/* =========================================================================
 * Evaluation result
 * ========================================================================= */

typedef struct {
    validator_decision_t          decision;
    validator_violation_code_t    violation;
} validator_assertion_result_t;

typedef struct {
    validator_decision_t          decision;               /* rollup */
    validator_violation_code_t    turn_violation;         /* non-assertion-scoped */
    validator_assertion_result_t  per_assertion[VALIDATOR_MAX_ASSERTIONS];
    size_t                        per_assertion_count;

    /* Populated by validator_commit_decision(); zeroed until then. */
    char                          chain_entry_hash[VALIDATOR_HASH_HEX_LEN + 1];
    int64_t                       chain_sequence;
    char                          artifact_hash[VALIDATOR_HASH_HEX_LEN + 1];
} validator_result_t;

/* =========================================================================
 * API
 * ========================================================================= */

/*
 * Parse a manifest JSON document.
 *
 * On success, *manifest is populated and VIRP_OK is returned.
 * On failure, *reason_out carries a VALIDATOR_VIOLATION_* code suitable
 * for constructing a fail-closed BLOCK decision upstream, and the
 * return value is a virp_error_t describing the structural problem.
 *
 * Accepts explicit `evidence_ref: null` and a missing evidence_ref key
 * (forward compat) — both set has_evidence=false.
 * Rejects non-hex evidence_ref, non-string device, >MAX_ASSERTIONS,
 * missing session_id, missing prose_hash, prose_hash not 64 hex chars.
 */
virp_error_t validator_parse_manifest(const char *json,
                                      size_t json_len,
                                      validator_manifest_t *manifest,
                                      validator_violation_code_t *reason_out);

/*
 * Evaluate a parsed manifest against chain.db plus the prose bytes.
 *
 * Recomputes SHA-256(prose) and compares to manifest->prose_hash.
 * For each assertion: checks evidence presence rules, membership in
 * tool_call_refs, and existence in chain.db for manifest->session_id.
 *
 * Does NOT write to chain.db. Use validator_commit_decision to persist.
 */
virp_error_t validator_evaluate(virp_chain_state_t *chain,
                                const validator_manifest_t *manifest,
                                const char *prose,
                                size_t prose_len,
                                validator_result_t *result);

/*
 * Commit the decision as artifact_type="validation" on chain.db for
 * manifest->session_id. Populates result->chain_entry_hash,
 * result->chain_sequence, and result->artifact_hash.
 */
virp_error_t validator_commit_decision(virp_chain_state_t *chain,
                                       const validator_manifest_t *manifest,
                                       validator_result_t *result);

/*
 * Fail-closed convenience wrapper.
 *
 * Parses, evaluates, and commits in one call. If parsing fails, an
 * empty-manifest BLOCK decision with turn_violation set to the parse
 * reason is committed (with session_id = "unknown" if not recoverable).
 *
 * Callers that have no manifest at all should pass manifest_json = NULL
 * and manifest_json_len = 0; this records a MANIFEST_MISSING BLOCK.
 *
 * Requires a fallback_session_id for the case where the manifest is
 * unparseable — normally the on-wire session context. Must be non-NULL.
 */
virp_error_t validator_run_turn(virp_chain_state_t *chain,
                                const char *manifest_json,
                                size_t manifest_json_len,
                                const char *prose,
                                size_t prose_len,
                                const char *fallback_session_id,
                                validator_result_t *result);

/* Human-readable helpers for logging and banners. */
const char *validator_decision_str(validator_decision_t d);
const char *validator_violation_str(validator_violation_code_t v);
const char *validator_claim_type_str(validator_claim_type_t t);

#endif /* VIRP_VALIDATOR_H */
