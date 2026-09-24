# Security review remediation — 2026-09-24

Baseline: `13994c5da6136cd90d3aea0d5ff389b9152c63e0` in `nhowardtli/virp`.
Inputs: the owner's supplied `gaps-and-security.md` (81 entries, including
independent duplicates) and `final-report.md` (G01–G54 terminology).
The latter also references `virp-verify@c38c4f8`; that repository is outside
this patch. This ledger records source changes and local verification,
not production deployment or closure of the entire review.

## Implemented in this branch

| Finding | Change | Regression evidence |
| --- | --- | --- |
| G16/G17: formatted lengths exceed stored buffers | Reject oversized signed handler JSON; bound JunOS, PAN-OS and REST output lengths and mark truncation; reject invalid driver lengths before filtering, including retries; guard the scrub boundary. | `test-security-bounds`, `test-security-handlers`, JunOS/PAN-OS refusal tests under ASan/UBSan |
| G22: v1 frame length wraps | Reject frames beyond `UINT16_MAX`; maximum observation data is 65,475 bytes. Account for capture truncation before recording the execution digest. No wire format change. | Five boundary cases in `test-security-bounds` |
| G21: unchecked artifact hash/body ingress | Require exactly 64 lowercase hexadecimal hash characters at ingress and every chain append. Reject an oversized supplied body instead of silently dropping it. | `test-json-hygiene`, including malformed hashes and oversized body |
| HAM 10: batch truncates or skips bad commands | Reject the whole batch for overlong fields, malformed items or excess commands, before dispatch. | Direct parser and socket-handler regressions |
| G02: Cisco/FortiGate gate misses literal BLACK commands | Apply each driver's existing denylist at its gate hook as well as its execution backstop. The explicit BLACK passthrough policy still applies. | Table-driven literal-denylist checks in both refusal suites |
| G05: UID policy parsing can weaken policy | Reject malformed, nonnumeric, negative, overflowing or empty allowlists. Reject malformed ceiling maps, duplicate normalized UID keys and maps omitting an allowed UID. Absent optional maps retain the existing default. | `test-security-handlers`, template policy tests |
| G12: client artifact can preempt approval outcome | Match both artifact ID and reserved `outcome` type when checking consumption. | `test_client_artifact_cannot_preempt_outcome` |
| G13, custody subset | Refuse symlink, nonregular, foreign-owned and group/world-writable approver registries; detect read errors. | `test-approvers` |
| G15, evidence type subset | Gate 3 and the Python report reject v1 intent/management subtypes masquerading as device observations. The claim API accepts only DEVICE_OUTPUT, including refusal of signed ERROR as factual claim evidence. | Direct gate tests and signed API/report fixtures |
| G28, stripped-head subset | C and Python refuse a session that retains signed entries but has no signed head, including a deleted tail with a rewritten unsigned head. | C signing migration and Python cross-language vectors, using public verification keys |
| G30, range-walk subset | An operational SQLite range-walk error returns a database error and sets `verifier_error`, rather than grading it as truncation. | Existing chain/verifier-error regression suites; no dedicated mid-walk fault injection in this patch |
| G34/G42, session subset | Check session timeouts under the session mutex at daemon access points; protect Gate 3 v2 session/key reads with that mutex. | Direct expired ACTIVE/NEGOTIATED session tests; session and v2 suites |
| G36, fuzz coverage subset | Add a hostile device-output harness through the real scrubber, REST body filter and shared prompt reader; instrument the library as well as the harness in CI. | ASan/UBSan standalone run of 2,004 deterministic inputs; libFuzzer smoke job added |
| G37: shared seats can read rendered credentials | Atomically publish credentials as `0600 virp:virp`; publish only four authorization fields to `devices.policy.json` as `0640`; shell and wrapper read the policy projection. | 23 renderer checks including modes and absence of device credentials |
| Undeclared failure-with-body becomes execution evidence | Treat failed results without a declared disposition/non-dispatch proof as UNKNOWN, regardless of body text. Execution receipt schema `/2` represents uncertain execution as `null`. | Five direct execution regressions, including the formerly pending refusal-with-body cases |
| G51, documentation subset | Correct the current-policy description and the already-fixed commitment-only roll-up claim; distinguish source verification from historical deployment assertions. | Source reconciliation; commitment-only grading and report suites |

## Compatibility and rollout requirements

* `gate_execution/2` changes `executed` to a nullable boolean. Consumers
  must preserve `null` as unknown; `executed_reported=false` accompanies
  uncertainty. The TACACS reconciler accepts both receipt versions and
  requires the reserved `gate_execution` artifact type. The receipt digest covers scrubbed bytes retained for the
  observation, with `output_truncated` also covering the wire-size cap.
* Existing malformed UID policies now stop startup. Review the rendered
  allowlist and ceiling coverage before restarting a node.
* Install the renderer, shell and wrapper together, then render the policy
  projection. The shell no longer falls back to a potentially stale template.
  Confirm the service can read the new owner-only credentials and shell
  seats cannot. Existing leaked credentials are not rotated by this patch.
* Legacy malformed artifact hashes can no longer be appended. Existing
  historical rows are not rewritten. Signed sessions with missing signed
  heads now fail verification; this must not be remedied by inventing a head.
* Registry files must have a trusted owner and no group/world write bit.
  This does not move an approval private key off the daemon host.
* No wire-version migration, live host change, key rotation, merge or
  deployment is included.

## Verification performed

The local build used GCC with the repository's warnings-as-errors flags.
The changed C driver library compiled with Cisco, FortiGate, ASA, JunOS,
PAN-OS, Wazuh, LibreNMS and Zammad enabled. All five refusal suites passed.

Passing checks include chain (35), JSON hygiene (42), signing migration
(22), Python signing vectors (19), approver registry (10), direct O-Node
execution (5), API/observation report verification (22), renderer (23),
template UID policy (25), commitment-only grading (3), and verifier-error
handling (11), TACACS accounting/reconciliation (54), plus the session, v2, scrub, body-filter, chain-invariant,
wire-boundary and handler suites. The report suite ran 48 tests with seven
existing skips; it is not described as 48 exercised checks.

ASan and UBSan passed for wire bounds, direct handlers, direct execution,
JSON hygiene and chain verification, as well as JunOS/PAN-OS formatting.
Leak detection was disabled locally because LeakSanitizer cannot operate
in this runtime. CI retains leak detection. The new libFuzzer CI command
was not run locally; the same harness ran standalone with ASan/UBSan.

**Local environment limits:** Unix socket creation is denied, so the full
O-Node, shell and approval CLI suites cannot pass here. The approval suite
ran 27 passing tests with seven socket-dependent failures. The core suite
ran 61/62; the remaining test requires `chown` to another UID, which this
runtime also denies. These failures are not suppressed or relabeled as
passes. CI on a normal Linux runner is still required before merge.

## Findings still open

All supplied findings not explicitly addressed above remain open; a
subset mitigation is not closure of its broader finding. In particular:

* G01: measured vendor abbreviation grammars and default-deny canonical
  command classification. Literal denylist coverage does not establish
  equivalence to every abbreviation a device accepts.
* G03/G04: the explicit privileged-seat policy and proof of human presence.
  `13994c5` deliberately permits per-UID ceilings to raise privileges and
  BLACK passthrough. This branch documents that behavior without reversing
  the recorded policy decision.
* G09–G11 and related approval findings: versioned canonical approval
  binding of device, semantic tables and typed operation profiles.
* G12–G15 remaining scope: appender namespaces, off-host approval keys,
  broker caller authentication, removal/domain separation of intent signing
  APIs and isolation of caller-authored artifact storage.
* G20 and remaining input semantics: binary/NUL-safe device bodies and
  terminal escape handling. The input length fixes do not solve those.
* G24–G34 remaining verifier scope: canonical encoding/number precision,
  complete closer-field comparison, C/Python/Rust era and Ed25519 agreement,
  database error propagation in intent grading, filtered-selection evidence
  grading, chain-pointer races and large production database verification.
* G28 completeness beyond stripped heads: deletion of all signature metadata,
  entire sessions or rollback of a whole database needs an independently
  retained checkpoint/witness. Local signatures alone do not establish it.
* G35/G36: signer/parser process isolation, vendor transcript fuzz corpora,
  sustained fuzz campaigns and differential verifier fuzzing.
* G38–G41: transport identity, TLS/host-key deployment, insecure environment
  switches and the complete deployment-unit lint inventory.
* G43/G44: per-caller sessions, default v2 production observations and a
  reachable v3 producer/key lifecycle. This patch does not turn v1 into v2.
* G45–G50: live prompt/AAA behavior, the PAN-OS body mismatch, framed device
  transports, FortiGate PTY coverage and proof of deployed state.
* G51–G54 remaining scope: full claims-ledger reconciliation, Go-tree scope,
  external MCP/consumer bridges and audit scope cleanup.

The report's dependency/CVE and product-version claims were not verified
as part of this patch and are not adopted as release guidance. This tree
uses both vendored cJSON and json-c; neither parser is removed here.
