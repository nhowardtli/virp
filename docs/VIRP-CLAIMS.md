# VIRP-CLAIMS: Claim Verification Layer

### Companion Specification to draft-howard-virp-01

**Status:** Informational Draft  
**Author:** Nate Howard, Third Level IT LLC  
**Date:** 2026-03-08  
**Repository:** github.com/nhowardtli/virp

-----

## Abstract

VIRP (Verified Infrastructure Response Protocol) establishes cryptographic authenticity for infrastructure observations. This companion specification defines a Claim Verification Layer (CVL) that binds AI-generated operational assertions to specific signed observations, enabling auditability and contradiction detection.

VIRP-CLAIMS does not guarantee that AI reasoning is correct. It guarantees that AI reasoning is **traceable, bounded, and auditable**. These are distinct and achievable properties. Correctness of interpretation remains outside protocol scope and is explicitly acknowledged as such.

-----

## 1. Motivation

A signed observation proves that telemetry was collected from a specific device at a specific time and has not been modified. It does not constrain what an AI agent may subsequently assert about that telemetry.

Without a binding layer, the following failure mode exists:

```
O-Node collects: show ip bgp summary
Signature: VALID
AI asserts:      "All BGP peers are healthy"
Reality:         One peer is in Idle state
Protocol result: No violation detected
```

The observation is authentic. The conclusion is wrong. VIRP v1 cannot detect this because the conclusion is never checked against the evidence.

VIRP-CLAIMS addresses this by requiring that operational assertions reference specific observations, declare the evidence chain used to derive them, and expose that chain to deterministic verification.

-----

## 2. Scope and Non-Goals

**In scope:**

- Defining the Claim object and its required fields
- Defining the Verdict enumeration and semantics
- Specifying how a verifier checks a Claim against its referenced Observations
- Defining collection metadata that exposes observation quality

**Explicitly out of scope:**

- Whether the AI reasoned correctly about valid evidence
- Natural language interpretation of CLI output
- Parser correctness guarantees
- Model behavior constraints

The protocol can verify that a claim is **grounded**. It cannot verify that a grounded claim is **true**. Operators must understand this distinction. The CVL makes the distinction visible and auditable rather than hidden inside model confidence.

-----

## 3. Data Model

### 3.1 Observation (VIRP v1, reproduced for reference)

```
Observation {
    obs_id:        uint64          // monotonic, unique per O-Node
    node_id:       string          // device identifier
    command:       string          // exact command executed
    timestamp:     uint64          // Unix epoch, seconds
    sequence:      uint64          // per-node monotonic counter
    raw_output:    bytes           // verbatim device response
    signature:     bytes[32]       // HMAC-SHA256 over canonical fields
    trust_tier:    enum            // GREEN | YELLOW | RED | BLACK
}
```

### 3.2 CollectionMetadata (new in CVL)

Attached to every Observation at collection time. Exposes completeness signals that affect whether an Observation is safe to reason from.

```
CollectionMetadata {
    collection_status:  enum        // COMPLETE | TRUNCATED | TIMEOUT | PARTIAL | ERROR
    payload_bytes:      uint32      // byte count of raw_output
    payload_hash:       bytes[32]   // SHA-256 of raw_output, independent of HMAC
    truncation_flag:    bool        // explicit truncation detected in output
    timeout_flag:       bool        // collection terminated by timeout
    parser_name:        string      // identifier of parser applied, if any
    parser_version:     string      // semver of parser
    parser_confidence:  float       // [0.0, 1.0] parser extraction confidence, 0 if not parsed
    collection_latency_ms: uint32   // time from command send to response complete
}
```

A verifier MUST treat any Observation with `collection_status != COMPLETE` as insufficient for strong Claims. Verdicts derived from incomplete Observations MUST be downgraded to `INCOMPLETE`.

### 3.3 Claim

A Claim is a structured, machine-verifiable assertion derived from one or more Observations. Free-form natural language summaries are permitted as supplemental fields but are not verifiable and MUST NOT be used as the basis for Verdict determination.

```
Claim {
    claim_id:       string          // UUID v4
    claim_type:     string          // namespaced type, e.g. "bgp.neighbor.state"
    agent_id:       string          // identifier of AI agent producing the claim
    timestamp:      uint64          // Unix epoch, claim production time
    
    assertion:      Assertion       // the structured claim (see 3.3.1)
    evidence:       []EvidenceRef   // one or more observation bindings
    
    natural_language: string        // optional, non-verifiable summary
    confidence:     float           // agent self-reported confidence [0.0, 1.0]
}
```

#### 3.3.1 Assertion

```
Assertion {
    subject:    string      // e.g. "bgp.neighbor[10.0.0.2]"
    predicate:  string      // e.g. "state"
    operator:   enum        // EQ | NEQ | GT | LT | GTE | LTE | EXISTS | NOT_EXISTS
    value:      string      // expected value as string, e.g. "Established"
}
```

#### 3.3.2 EvidenceRef

```
EvidenceRef {
    obs_id:         uint64      // references Observation.obs_id
    node_id:        string      // must match Observation.node_id
    extracted_path: string      // JSONPath or field descriptor into parsed output
    extracted_value: string     // value actually extracted from that path
}
```

The `extracted_path` and `extracted_value` fields expose exactly how the Claim was derived from the raw observation. A skeptic can take `obs_id`, retrieve the raw output, apply the same extraction path, and confirm or contradict the extracted value independently.

-----

## 4. Verdict Enumeration

```
enum Verdict {
    VERIFIED        // claim assertion matches extracted evidence from valid, complete observations
    CONTRADICTED    // claim assertion directly contradicts extracted evidence
    UNVERIFIABLE    // no signed observation exists that covers the claim subject
    INCOMPLETE      // supporting observations exist but are marked TRUNCATED, TIMEOUT, or PARTIAL
    STALE           // observations exist but fall outside the configured freshness window
    SCHEMA_ERROR    // claim is malformed or references nonexistent observation IDs
}
```

### 4.1 Verdict Precedence

When multiple evidence references are present, the most conservative Verdict applies:

```
CONTRADICTED > INCOMPLETE > STALE > UNVERIFIABLE > VERIFIED
```

A single CONTRADICTED evidence reference makes the Claim CONTRADICTED regardless of other evidence.

-----

## 5. Verifier Behavior

A conforming verifier MUST implement the following checks in order:

**Step 1 — Schema validation**  
Confirm Claim is well-formed. All required fields present. `claim_type` is a recognized namespace. If malformed: return `SCHEMA_ERROR`.

**Step 2 — Observation retrieval**  
For each `EvidenceRef`, retrieve the referenced Observation by `obs_id`. If any referenced Observation cannot be found in the signed corpus: return `UNVERIFIABLE`.

**Step 3 — Signature verification**  
Verify HMAC-SHA256 signature on each referenced Observation. If any signature fails: treat that Observation as invalid and return `UNVERIFIABLE` for claims depending on it.

**Step 4 — Freshness check**  
Confirm each Observation timestamp falls within the configured freshness window (default: 300 seconds). If any observation is outside the window: flag for `STALE`. Apply precedence rules.

**Step 5 — Completeness check**  
Inspect `CollectionMetadata.collection_status` for each Observation. If any is not `COMPLETE`: return `INCOMPLETE`. Apply precedence rules.

**Step 6 — Extraction verification**  
For each `EvidenceRef`, apply `extracted_path` to the Observation’s `raw_output` and confirm the result matches `extracted_value`. If extraction produces a different value than claimed: return `CONTRADICTED`.

**Step 7 — Assertion check**  
Evaluate `Assertion.operator` against the extracted values. If the assertion evaluates false: return `CONTRADICTED`. If it evaluates true: return `VERIFIED`.

-----

## 6. Trust Tier Inheritance

Claims inherit the trust tier of their lowest-tier referenced Observation.

```
Claim references obs GREEN + obs YELLOW → Claim tier: YELLOW
Claim references obs RED               → Claim tier: RED (regardless of others)
```

A VERIFIED claim at tier RED means: the evidence supports the claim, but the evidence itself comes from a node with degraded trust posture. Operators MUST be presented with tier alongside Verdict.

-----

## 7. Example: BGP State Claim

### 7.1 Observation

```json
{
  "obs_id": 37807,
  "node_id": "R1",
  "command": "show ip bgp summary",
  "timestamp": 1741478201,
  "sequence": 412,
  "raw_output": "...<verbatim output>...",
  "signature": "a3f92e...",
  "trust_tier": "GREEN",
  "collection_metadata": {
    "collection_status": "COMPLETE",
    "payload_bytes": 1842,
    "payload_hash": "9d4c1a...",
    "truncation_flag": false,
    "timeout_flag": false,
    "parser_name": "cisco-bgp-summary",
    "parser_version": "1.2.0",
    "parser_confidence": 0.97,
    "collection_latency_ms": 312
  }
}
```

### 7.2 Claim (VERIFIED case)

```json
{
  "claim_id": "f81d4fa-e29a-4f9b-8c3e-1234abcd5678",
  "claim_type": "bgp.neighbor.state",
  "agent_id": "ironclaw-agent-v1",
  "timestamp": 1741478209,
  "assertion": {
    "subject": "bgp.neighbor[10.0.0.2]",
    "predicate": "state",
    "operator": "EQ",
    "value": "Established"
  },
  "evidence": [
    {
      "obs_id": 37807,
      "node_id": "R1",
      "extracted_path": "$.neighbors[?(@.address=='10.0.0.2')].state",
      "extracted_value": "Established"
    }
  ],
  "natural_language": "BGP neighbor 10.0.0.2 on R1 is in Established state.",
  "confidence": 0.97
}
```

**Verifier output:**

```
Claim:     bgp.neighbor[10.0.0.2].state == Established
Evidence:  obs_id 37807 (R1, 2026-03-08T14:16:41Z)
Signature: VALID
Freshness: WITHIN WINDOW (8s)
Complete:  YES
Extracted: Established
Verdict:   VERIFIED  [GREEN]
```

### 7.3 Claim (UNVERIFIABLE case — fabricated)

```json
{
  "claim_id": "a99c3fd1-...",
  "claim_type": "firewall.policy.exists",
  "assertion": {
    "subject": "firewall.policy[873a]",
    "predicate": "exists",
    "operator": "EQ",
    "value": "true"
  },
  "evidence": []
}
```

**Verifier output:**

```
Claim:     firewall.policy[873a].exists == true
Evidence:  NONE
Verdict:   UNVERIFIABLE
Reason:    No signed observation covers this subject.
           Claim cannot be evaluated against the VIRP corpus.
```

-----

## 8. What This Does Not Solve

This section is included deliberately to prevent scope creep and misrepresentation.

**Parser correctness:** If `cisco-bgp-summary` v1.2.0 misparses a neighbor state, the Claim will be VERIFIED and incorrect. CVL exposes the parser name and version so this is detectable and attributable, but does not prevent it.

**Model hallucination on valid evidence:** A model may see `state: Established` and conclude “the network is healthy” when other peers are down. CVL bounds Claims to specific assertions about specific subjects. Broad health summaries should be decomposed into individual Claims or flagged as non-verifiable natural language.

**Adversarial observation injection:** If the O-Node itself is compromised, signed observations may be fabricated at source. CVL inherits VIRP’s trust tier model for this. A compromised node produces RED-tier observations.

**Completeness of coverage:** A signed observation corpus covers only what was collected. Absence of a signed observation does not prove absence of a network condition.

**Recorded-happened-once, not happened-was-recorded:** VIRP proves that a *recorded* execution happened **at most once** (single-use approvals + hash-linked OUTCOME). It does **not** prove that everything that *happened* was recorded. An approved apply consumes its authorization, contacts the device, then records an OUTCOME; a crash after the device executed but before the OUTCOME commits leaves "approved, no outcome" — the device changed, yet the chain cannot say so, and that state is indistinguishable from "never contacted". The `chain_append` atomicity fix does not close this (the missing record is *between* appends, across device I/O). See `SECURITY.md` §Execution Durability and the EXECUTION_INTENT proposal in `docs/virp-audit-design-proposals.md`, which is what would let VIRP say "attempted, disposition unknown".

**Crash-safety is SIGKILL, not power loss:** Where crash-safety is claimed, it was established against a `SIGKILL` of the daemon process (fault-injection harness `tests/adversarial/fi-run.sh`), which models a process crash — not a power loss or disk failure. Durability under power loss depends on fsync/WAL and the storage honouring flushes, which `SIGKILL` does not exercise.

-----

## 9. Relationship to VIRP Core

```
VIRP Core (draft-howard-virp-01)
└── Observation authenticity
└── O-Node signing
└── Trust tiers
└── Freshness / TTL
└── Two-channel separation (Observation vs Intent)

VIRP-CLAIMS (this document)
└── Claim binding to Observations
└── Structured assertion schema
└── Verifier algorithm
└── Verdict enumeration
└── Collection metadata / completeness signals
└── Trust tier inheritance for Claims
```

VIRP-CLAIMS depends on VIRP Core. VIRP Core is complete and useful without VIRP-CLAIMS. CVL is a companion layer, not a revision.

-----

## 10. Implementation Notes

A minimal CVL verifier requires:

- Read access to a signed Observation corpus (flat file, SQLite, or API)
- HMAC-SHA256 verification (reuses VIRP Core logic)
- A JSONPath or equivalent extraction library
- Configurable freshness window (default: 300s)

A reference implementation will be published at `github.com/nhowardtli/virp` alongside the core library. The verifier will expose a `virp verify <claim_file>` CLI interface suitable for demonstration and integration testing.

-----

## 11. The One Sentence

> VIRP does not claim a model cannot reason incorrectly. It ensures that incorrect reasoning is detectable, attributable, and bounded — because every Claim is traceable to the exact signed evidence it was derived from.

-----

## Appendix A. Security Claim Status (implementation review inventory)

Status of the July 2026 cold-review security-claim inventory for the
protocol properties this layer inherits from VIRP Core. DEMONSTRATED
means a negative test or checked-in machine proof in this repository
exercises the property; every pointer below is a file in this tree.

| Claim | Property | Status | Evidence |
|---|---|---|---|
| C5 | Replay of a captured observation is rejected | DEMONSTRATED | `tests/test_obs_v2.c`: `test_replay_same_sequence_rejected`, `test_non_monotonic_sequence_rejected`, `test_replay_rejected_across_store_restart`; injective agreement in `proofs/virp_obs_v2.pv` |
| C6 | Stale observations (outside the freshness window) are rejected | DEMONSTRATED | `tests/test_obs_v2.c`: `test_stale_observation_rejected` (injected verifier clock, both directions, signed-timestamp tamper) |
| C7 | A signed observation for command/device A cannot satisfy a request for command/device B | DEMONSTRATED | `tests/test_obs_v2.c`: `test_command_substitution_rejected`, `test_device_substitution_rejected`; end-to-end in `tests/test_onode.c`: `test_execute_v2_session_bound_roundtrip` |
| C8 | Observations are bound to the session that produced them | DEMONSTRATED | `tests/test_obs_v2.c`: `test_cross_session_replay_rejected`; ProVerif session-key secrecy query in `proofs/virp_obs_v2.out` |
| C16 | The signed v2 header bytes are an explicit, padding-free wire encoding | DEMONSTRATED | `virp_obs_header_v2_serialize()` in `src/virp_message.c`; golden-offset test `test_serialization_roundtrip_and_layout` in `tests/test_obs_v2.c` |
| C17 | Error observations are typed `VIRP_OBS_ERROR` (0x0f) and carry the command's true classified tier — never the executed-output type or a blanket GREEN | DEMONSTRATED (live + suite) | Negative tests `test_error_obs_connect_failure_is_error_with_true_tier`, `test_error_obs_driver_refusal_is_error_not_output`, `test_error_obs_gate_block_logs_as_error_not_change` in `tests/test_onode.c`; live rejections 2026-07-23 (`docs/LIVE-PROOF-2026-07-23.md` §T2–T4, T6–T7) |
| C18 | A tier-gate block files a signed PROPOSAL (chain entry + proposal_id in the rejection) and executes nothing | DEMONSTRATED (live + suite) | `tests/test_approval.c`: `test_block_files_proposal`; live: `docs/LIVE-PROOF-2026-07-23.md` §T2 |
| C19 | An approval binds command_hash + device + 300 s TTL, signed by a dedicated Ed25519 key the daemon can verify but never sign with | DEMONSTRATED (live + suite) | `tests/test_approval.c`: `test_e2e_propose_approve_apply`, `test_wrong_key_rejected`, `test_daemon_refuses_secret_key`; live: `docs/LIVE-PROOF-2026-07-23.md` §T5, T8 |
| C20 | An approved apply executes exactly once; reuse, expiry, hash/device mismatch, and missing approval are rejected with distinct codes (-36…-41), reuse surviving daemon restart | DEMONSTRATED (live + suite) | `tests/test_approval.c`: `test_reused_approval_rejected`, `test_expired_approval_rejected`, `test_hash_mismatch_rejected`, `test_device_mismatch_rejected`, `test_no_approval_plain_block`, `test_reuse_survives_restart`; live: `docs/LIVE-PROOF-2026-07-23.md` §T4–T7 |
| C21 | PROPOSAL → APPROVAL → OUTCOME are hash-linked on the trust chain | DEMONSTRATED (live + suite) | `tests/test_approval.c`: `test_e2e_propose_approve_apply`, `test_cli_chain_tail_format`; live: `docs/LIVE-PROOF-2026-07-23.md` §T8 |
| C22 | The gate rejects every known multi-command injection vector, on every driver | DEMONSTRATED (suite only) | Daemon boundary: `tests/test_onode.c` `test_multicommand_newline_is_blocked`, `..._batch`, `test_multicommand_batch_rejects_per_item_not_whole_batch`, `test_separator_policy_rejects_every_class`, and both SHADOW cases. Per-driver classifiers: `test_adversarial_separators` in `tests/test_driver_cisco_gate.c`, `test_driver_asa.c`, `test_driver_panos.c`, `test_driver_juniper.c`, `test_driver_fortigate_black.c` — newline, CR, CRLF, `;`, `\|`, `&`, `&&`, backtick, `$(`, `${`, tab, leading/trailing newline, each built on a real GREEN entry from that driver's own table |
| C23 | An unrecognized command fails closed (RED) on all five drivers | DEMONSTRATED (suite only) | `test_no_match_fails_closed` in `tests/test_driver_asa.c`, `test_driver_panos.c`, `test_driver_juniper.c`, `test_driver_fortigate_black.c`; Cisco's fail-closed default in `tests/test_driver_cisco_gate.c` `test_fail_closed`. Both no-match paths per driver (NULL early return and table fallback) are covered |
| C24 | Every classification table entry is reachable and returns the tier it declares | DEMONSTRATED (suite only) | `test_table_driven_all_entries` in all five driver suites, iterating each driver's own table (257 entries). Proves reachability — an entry shadowed by a broader or earlier entry would silently never fire — under both matching disciplines: PAN-OS is first-match (order load-bearing), the other four longest-match |
| C25 | A prefix-flagged table entry cannot absorb a second command | DEMONSTRATED (suite only) | `tests/test_driver_panos.c`: `test_prefix_entries_positive_and_negative` (separator forms all RED), `test_prefix_flag_lint` (fails the suite if `prefix=true` sits on a GREEN/YELLOW entry that shadows a stricter one) |

**Body-integrity caveat (added 2026-07-29).** C5–C8 and C16 attest the
*verification layer*: they bind the signed header — command hash,
device, session, sequence, timestamp — and reject substitution and
replay at verify time. None of them attest that the observation *body*
is the device's response to the header's command. The 2026-07-29 static
review found three SSH-driver mechanisms by which foreign bytes (stale
buffered output, concurrent watchdog probes, wrapper echoes) can enter
the body before signing, and one live occurrence was observed on
2026-07-29 (a signed `show system resources` observation on pa-850
carrying `show system info` output). C7 in particular remains
DEMONSTRATED for what it states — verify-time substitution rejection —
but should not be read as a body-to-command correspondence guarantee.
See `SECURITY.md` §Observation-Body Integrity.

**Reference-verifier caveat (added 2026-07-29).** The shipped
`api/virp_verify.py:verify_evidence` diverges from the §6 procedure: it
HMAC-verifies `obs["raw_message"]` when present, but takes freshness,
completeness and the extracted value from unsigned sibling fields of
the corpus entry, and when `raw_message` is absent it falls back to the
plaintext `obs["verified"]` boolean with no cryptographic check. Until
that is fixed, §6's guarantees hold for the specified procedure, not
for the shipped implementation. See `SECURITY.md` §Verifier
Limitations.

**Scope of the live evidence.** C17–C21 carry live results from
2026-07-23. Those runs submitted **single commands only**, against a
**single driver** (Cisco IOS). They say nothing about multi-command
injection, about the no-match default, or about the other four drivers —
all of which were found defective afterwards and are covered here by
suite evidence alone. C22–C25 are marked DEMONSTRATED (suite only) for
that reason: no live device has exercised them. See
`docs/LIVE-PROOF-2026-07-23.md` §Scope for what that run did and did not
establish.

**Two open questions, unresolved.**

0. *(Settled 2026-07-28)* The production chain's integrity question is
   no longer open. The `valid:false first_broken:2` result was a verifier
   bug — `virp-bridge.py:chain_verify()` walks globally over a
   per-session chain. Verified per-session and read-only: 162/169 live
   sessions fully hash-linked, the 7 failures all writer-convention
   mismatches (five with an all-zero genesis from a second writer), and
   all three `approval:*` sessions valid, including `approval:R1` from
   the 2026-07-23 live proof. Narrowed 2026-07-29: the per-session C
   verifier accepts a truncated tail (deleting the newest K entries
   still verifies valid, as does a zero-row session), so "fully
   hash-linked" establishes internal link consistency, not
   completeness; and the bridge verifier never checks the keyed
   `chain_hmac` at all. Follow-ups now: the bridge verifier is unfixed
   (global walk + no HMAC check; consumer-side repo) and the
   two-writer genesis divergence. The C verifier's tail-completeness
   gap is FIXED 2026-08-01 (range completeness + signed per-session
   head record; see SECURITY.md §Verifier Limitations). See the README
   chain-integrity section and `SECURITY.md` §Verifier Limitations.

1. *Config-dumping reads at YELLOW.* `show full-configuration`
   (FortiGate), `show system ha` (FortiGate) and `show running-config`
   (ASA/Cisco) are classified YELLOW as "config reads", but their output
   contains every encrypted secret on the box — PSKs, HA passwords, admin
   hashes. YELLOW clears the default gate threshold, so these execute
   without approval. Whether a config dump is a config *read* or a
   credential read is unsettled; the current tiering treats it as the
   former.
2. *Wiring the Wazuh table.* `WZ_ROUTE_TABLE` now fails closed to RED but
   is attached to no `route_command` hook, so `gate_classify` returns
   UNCLASSIFIED for that driver. Wiring it would make BLACK endpoints
   (`/active-response`, `/manager/restart`) auditable immediately and
   blocking the moment wazuh leaves SHADOW. It also needs a REST-shaped
   separator grammar first (see the scope limits in `SECURITY.md`).

Statuses above apply to the v2 observation path
(`virp_verify_observation_v2`, `src/virp_crypto.c`) for C5–C16, and to
the approval/error-observation paths (`src/virp_approval.c`,
`onode_execute_obs_ex`) for C17–C21. The legacy v1 message path
performs none of the C5–C16 checks at verify time; C17–C21 live
evidence was collected over the v1 bridge path (see the caveats in
`docs/LIVE-PROOF-2026-07-23.md`). The approval flow has no ProVerif
model yet (deferred).

-----

*This document is an informational draft. Feedback and critique welcome at nhoward@thirdlevelit.com.*