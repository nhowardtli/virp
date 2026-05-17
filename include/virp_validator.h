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
 * All sized for stack allocation. No dynamic allocation in the hot path.
 * ========================================================================= */

#define VALIDATOR_MAX_ASSERTIONS        1024
#define VALIDATOR_MAX_TOOL_CALL_REFS    512
#define VALIDATOR_DEVICE_MAX            64
#define VALIDATOR_HASH_HEX_LEN          64      /* SHA-256 hex, no NUL */
#define VALIDATOR_CLAIM_TYPE_MAX        32
#define VALIDATOR_SESSION_ID_MAX        64      /* mirrors virp_chain_entry_t */
/* Phase 3: per-assertion multi-evidence + analytical claim types */
#define VALIDATOR_MAX_EVIDENCE_REFS     8       /* comparison, synthesis */
#define VALIDATOR_MAX_DERIVED_FROM      8       /* recommendation */

/* =========================================================================
 * Claim types
 *
 * state_observation     — AI asserts current device state (BGP peer up,
 *                         route X, interface counter Y). Missing evidence
 *                         is a WARN. Renamed from state_read in Phase 3.
 * state_change          — AI asserts a runtime change occurred (interface
 *                         toggled, adjacency flapped). Missing evidence
 *                         is a BLOCK.
 * config_change         — AI asserts configuration was modified. Missing
 *                         evidence is a BLOCK.
 * comparison            — AI is contrasting 2+ observations. Requires
 *                         evidence_refs[] with ≥2 entries, all in chain.
 * recommendation        — AI is suggesting an action based on observations.
 *                         Requires derived_from[] with ≥1 entry pointing
 *                         at observations that triggered the suggestion.
 *                         No evidence_ref required (recommendation is
 *                         analysis, not a state read).
 * synthesis             — AI is summarizing across observations. Requires
 *                         evidence_refs[] with ≥2 entries, all in chain.
 * outcome_verification  — AI claims a prior action succeeded. Requires
 *                         BOTH evidence_ref (the post-action observation)
 *                         AND action_ref (the action that was taken).
 *                         Validator checks both in chain AND timestamp
 *                         ordering: evidence_ref.ts > action_ref.ts. The
 *                         protocol-significant claim type added to catch
 *                         "I made the change" overclaims without a
 *                         re-pulled state observation.
 * unknown               — parser could not map the string. Always BLOCK.
 * ========================================================================= */

typedef enum {
    VALIDATOR_CLAIM_UNKNOWN              = 0,
    VALIDATOR_CLAIM_STATE_OBSERVATION    = 1,  /* renamed from STATE_READ */
    VALIDATOR_CLAIM_STATE_CHANGE         = 2,
    VALIDATOR_CLAIM_CONFIG_CHANGE        = 3,
    VALIDATOR_CLAIM_COMPARISON           = 4,
    VALIDATOR_CLAIM_RECOMMENDATION       = 5,
    VALIDATOR_CLAIM_SYNTHESIS            = 6,
    VALIDATOR_CLAIM_OUTCOME_VERIFICATION = 7
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
    VALIDATOR_VIOLATION_NONE                       = 0,
    VALIDATOR_VIOLATION_NO_EVIDENCE_STATE_READ     = 1,  /* → WARN  (state_observation/no evidence) */
    VALIDATOR_VIOLATION_NO_EVIDENCE_STATE_CHANGE   = 2,  /* → BLOCK */
    VALIDATOR_VIOLATION_EVIDENCE_NOT_IN_TURN       = 3,  /* → BLOCK */
    VALIDATOR_VIOLATION_EVIDENCE_NOT_IN_CHAIN      = 4,  /* → BLOCK */
    VALIDATOR_VIOLATION_UNKNOWN_CLAIM_TYPE         = 5,  /* → BLOCK */
    VALIDATOR_VIOLATION_PROSE_HASH_MISMATCH        = 6,  /* → BLOCK (turn) */
    VALIDATOR_VIOLATION_MANIFEST_MALFORMED         = 7,  /* → BLOCK (turn) */
    VALIDATOR_VIOLATION_MANIFEST_TOO_LARGE         = 8,  /* → BLOCK (turn) */
    VALIDATOR_VIOLATION_MANIFEST_MISSING           = 9,  /* → BLOCK (turn) */
    /* Phase 3: analytical claim types */
    VALIDATOR_VIOLATION_EVIDENCE_REFS_MISSING      = 10, /* → BLOCK (comparison/synthesis need ≥2) */
    VALIDATOR_VIOLATION_DERIVED_FROM_MISSING       = 11, /* → BLOCK (recommendation needs ≥1) */
    VALIDATOR_VIOLATION_ACTION_REF_MISSING         = 12, /* → BLOCK (outcome_verification needs it) */
    VALIDATOR_VIOLATION_ACTION_REF_NOT_IN_CHAIN    = 13, /* → BLOCK */
    VALIDATOR_VIOLATION_DERIVED_FROM_NOT_IN_CHAIN  = 14, /* → BLOCK */
    VALIDATOR_VIOLATION_OUTCOME_NOT_AFTER_ACTION   = 15, /* → BLOCK (timestamp ordering) */
    /* Phase 4: entity normalization (assertion.device ↔ chain-entry device) */
    VALIDATOR_VIOLATION_ENTITY_DEVICE_MISMATCH     = 16, /* → BLOCK (content — AI mislabeled) */
    VALIDATOR_VIOLATION_ENTITY_AMBIGUOUS           = 17  /* → BLOCK (schema — ambiguous claim_ref) */
} validator_violation_code_t;

/* =========================================================================
 * Error class and remediation hint (Phase 2 — typed error surface)
 *
 * Maps each violation code to a class (format / schema / provenance /
 * content) and a remediation hint string. The model receiving a BLOCK
 * verdict reads these to route its response: format/schema errors are
 * validator-side gaps (regenerate or report); provenance errors mean
 * the AI layer needs to rerun tools; content errors are the only
 * class that warrants self-correction.
 *
 * Mapping (locked 2026-05-17, validator-typing pass):
 *   NONE                       → none / none
 *   MANIFEST_MALFORMED         → format / regenerate_manifest
 *   MANIFEST_TOO_LARGE         → format / regenerate_manifest
 *   MANIFEST_MISSING           → provenance / rerun_with_tools
 *   UNKNOWN_CLAIM_TYPE         → schema / report_schema_gap
 *   NO_EVIDENCE_STATE_READ     → provenance / rerun_with_tools
 *   NO_EVIDENCE_STATE_CHANGE   → provenance / rerun_with_tools
 *   EVIDENCE_NOT_IN_TURN       → provenance / rerun_with_tools
 *   EVIDENCE_NOT_IN_CHAIN      → content / fabrication_detected
 *   PROSE_HASH_MISMATCH        → content / fabrication_detected
 * ========================================================================= */

typedef enum {
    VALIDATOR_ERROR_CLASS_NONE       = 0,
    VALIDATOR_ERROR_CLASS_FORMAT     = 1,
    VALIDATOR_ERROR_CLASS_SCHEMA     = 2,
    VALIDATOR_ERROR_CLASS_PROVENANCE = 3,
    VALIDATOR_ERROR_CLASS_CONTENT    = 4
} validator_error_class_t;

typedef enum {
    VALIDATOR_HINT_NONE                 = 0,
    VALIDATOR_HINT_REGENERATE_MANIFEST  = 1,
    VALIDATOR_HINT_REPORT_SCHEMA_GAP    = 2,
    VALIDATOR_HINT_RERUN_WITH_TOOLS     = 3,
    VALIDATOR_HINT_FABRICATION_DETECTED = 4
} validator_remediation_hint_t;

/* =========================================================================
 * Manifest — parsed form of the JSON sidecar
 * ========================================================================= */

typedef struct {
    char                     device[VALIDATOR_DEVICE_MAX];
    validator_claim_type_t   claim_type;
    bool                     has_evidence;                       /* false if JSON null or omitted */
    char                     evidence_ref[VALIDATOR_HASH_HEX_LEN + 1];

    /* Phase 3: multi-evidence and analytical-claim fields. All optional;
     * required-by-type rules enforced at evaluate time. */
    char                     evidence_refs[VALIDATOR_MAX_EVIDENCE_REFS]
                                          [VALIDATOR_HASH_HEX_LEN + 1];
    size_t                   evidence_refs_count;
    char                     derived_from[VALIDATOR_MAX_DERIVED_FROM]
                                          [VALIDATOR_HASH_HEX_LEN + 1];
    size_t                   derived_from_count;
    bool                     has_action_ref;
    char                     action_ref[VALIDATOR_HASH_HEX_LEN + 1];
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
    validator_error_class_t       error_class;        /* derived from violation */
    validator_remediation_hint_t  remediation_hint;   /* derived from violation */
} validator_assertion_result_t;

typedef struct {
    validator_decision_t          decision;               /* rollup */
    validator_violation_code_t    turn_violation;         /* non-assertion-scoped */
    validator_error_class_t       turn_error_class;       /* derived from turn_violation */
    validator_remediation_hint_t  turn_remediation_hint;  /* derived from turn_violation */
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
const char *validator_error_class_str(validator_error_class_t c);
const char *validator_remediation_hint_str(validator_remediation_hint_t h);

/* Mapping: violation code → error class / remediation hint. Pure functions. */
validator_error_class_t      validator_violation_class(validator_violation_code_t v);
validator_remediation_hint_t validator_violation_hint(validator_violation_code_t v);

/* =========================================================================
 * Phase 4 — Canonical device-id resolver
 *
 * Resolves a claim_ref (the AI's free-form device reference in an
 * assertion's `device` field) against a candidate set of canonical
 * device_ids. Three outcomes:
 *
 *   RESOLVED   — exactly one canonical matches; result->canonical is filled
 *   AMBIGUOUS  — multiple canonicals match; result->candidates[..count] listed
 *   UNRESOLVED — no canonical matches; both fields empty
 *
 * Matching rules, in priority order:
 *   1. Exact match (case-insensitive) → RESOLVED if unique
 *   2. Hyphen-token prefix: claim_ref equals a complete prefix of the
 *      canonical's hyphen-token sequence AND is ≥4 characters.
 *      "fortigate" matches "fortigate-200g" (1-token prefix of [fortigate,
 *      200g]). "fort" does not (too short). "fortigate-200" does not
 *      (mid-token, not a complete token prefix).
 *   3. No-hyphen canonicals: exact match only.
 *
 * Case-insensitive throughout. The canonical name returned preserves the
 * case from the candidate list (e.g., "sw-3850" resolves to "SW-3850" if
 * that's how it appears in the registry).
 *
 * Used by:
 *   - validator_evaluate (binding check): claim_ref vs single chain-entry
 *     device. Single-candidate context — AMBIGUOUS not reachable.
 *   - api/validator/__init__.py exposure (Phase 4 commit 2): claim_ref
 *     vs full /run/virp/devices.json registry. AMBIGUOUS reachable.
 * ========================================================================= */

#define VALIDATOR_RESOLVE_MAX_CANDIDATES 16

typedef enum {
    VALIDATOR_RESOLVE_RESOLVED   = 0,
    VALIDATOR_RESOLVE_AMBIGUOUS  = 1,
    VALIDATOR_RESOLVE_UNRESOLVED = 2
} validator_resolve_status_t;

typedef struct {
    validator_resolve_status_t status;
    char canonical[VALIDATOR_DEVICE_MAX];  /* populated when RESOLVED */
    char candidates[VALIDATOR_RESOLVE_MAX_CANDIDATES][VALIDATOR_DEVICE_MAX];
    size_t candidate_count;                /* populated when AMBIGUOUS */
} validator_resolve_result_t;

/* Resolve claim_ref against a set of canonical device_ids.
 *
 * canonicals: array of NUL-terminated strings (max VALIDATOR_DEVICE_MAX
 *             chars each); use a char ** for ergonomic stack init.
 * canonical_count: number of entries in canonicals.
 *
 * On AMBIGUOUS, up to VALIDATOR_RESOLVE_MAX_CANDIDATES candidates are
 * copied; the rest are truncated (the candidate_count reflects the
 * truncated value). */
void validator_resolve_device(const char *claim_ref,
                              const char *const *canonicals,
                              size_t canonical_count,
                              validator_resolve_result_t *out);

#endif /* VIRP_VALIDATOR_H */
