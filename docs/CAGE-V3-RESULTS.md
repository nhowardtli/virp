# Cage execute-v3 helper qualification — October 15–16, 2026

Historical stop below was resolved by the dedicated VM103 qualification.
See [TLI rollout phase one](TLI-ROLLOUT-PHASE1.md) for current status.

## Outcome and stop condition

An initial model-driven VM227 → canary → FRR GREEN read and RED refusal passed.
Both immutable v3 frames were stored and verified with the public key alone.
The **final integrated build is not yet qualified end to end**: the canary was
concurrently reconfigured, first blocking VM227 ingress, then at 03:57 UTC
restricting SSH to `AllowUsers lab-bridge`. The latter rejects both the owner
and `virp-cage-test`; qualification stopped without overriding it.

Production runbook is written but **not released**. .211 was not accessed.

## Implementation and tests

Commit `a935cfd`, branch `feat/v3-execute-path`:

- Strict v3 decoding and Ed25519 verification; pinned session/node/device/command,
  sequence, freshness, typed payload, length and UTF-8 checks; no v1 fallback.
- HELLO/BIND before execution; bind failure prevents dispatch. One execute attempt,
  no automatic session takeover or execution retry after ambiguous failure.
- Exact bytes fsynced locally, appended as observation, and append acknowledgement
  checked before returning output. Failed storage retains original bytes.
- Hash-pinned offline production helper migration preserves existing fixed OPS,
  Duo grant, interface preflight, expiry, request uniqueness and lock checks.
- Candidate Cisco auth/denial safeguards preserved from `1c63e91`/`52562b4`.
- Production key is neither generated nor read by staging; only metadata checked.

Test-first logs capture missing consumer, wrong-session append acknowledgement,
and missing execute wrapper failures. Final `all-tests` passed with all production
drivers: C core 61/61, O-Node 169/169, 589 Python unittest cases (including 13 new
helper cases), 87 API pytest cases, and remaining C/security suites. Focused Cisco
auth/description/reconnect tests passed. Offline migration check preserved OPS
and all grant/preflight checks and refused changed baseline bytes.

Two intermediate suite failures were repaired: the registry test fixture was
created group-writable under umask 0002 (fixture now explicitly 0600); a commit
made during a build left stale embedded provenance (rebuilt and full clean suite
rerun passed). No enforcement checks were loosened.

## Evidence

Initial successful model: existing configured `gpt-4.1-mini-2025-04-14` on VM227.
Trusted root runner holds transport/API credentials; model tool arguments never
contain credentials. This does not claim security against cage-root compromise.

Chain session `cage-v3-20261015`, two observations:

- GREEN wire session `3b1853016f4c5c4c4889a0ca0d2123d4`, request
  `efa8420df404aa2ded2d0dea1d9b870e`, type 7, FRRouting 8.4.4 output.
- RED wire session `8c2b551f79cee1dd946b3f7343c8b62c`, request
  `cd404da6f18bffbbfe3a8d5f1089e82b`, type 15, tier RED / max GREEN refusal,
  proposal `7e1c15406008c43c4f1faa947977befd`. No approval or apply.
- Head `a9321a62144f2d74a4b41a48b807c009ed30c1b273a886cdb5f833916b7ab94c`.

Independent export verification: 75 chain entries, 7 heads and 22 v3 observations
(including earlier canary history) verified with only the canary public key.
Native chain_verify covered explicit complete ranges, with zero open executions.
Canary key_id `e75d7ee71aa7a4caa5db94b565d3777e`; never use it as .211's identity.
No witness receipt or virp-verify 0.1.3 acceptance is claimed.

The first successful proof used daemon `ecb2051` and the initial decoder/storage
helper. The final shared consumer and integrated daemon `a935cfd` have local test
coverage but their live model rerun failed before execution. Do not conflate them.
Current canary binary SHA256:
`91de8a773ce73e3ccdd80720a46473607a9756fbafe1c2433ffc0a22a605690b`.

## Recovery and remaining work

Snapshots: VM100 and VM227 `before-cage-v3`; VM100
`before-cage-v3-ingress` preserves concurrent changes. Temporary FortiGate rule
62710/address CAGE-CANARY-V3 and exact PVE100/PVE227 exceptions were removed;
all other policies retained. New helper STOP marker set. Existing production
runner, grants and .211 untouched. Canary retained; no snapshot rollback.

First unblock: establish a nonconflicting canary access/ownership window, then
repeat the final integrated model proof. Separately reconcile production candidate
baseline `140f6f9` health/readiness/watchdog delta before releasing the runbook.
Do not remove the runbook release gate merely because unit tests pass.

Private audit: `/home/nhoward/audits/virp-cage-v3-20261015/`.
Only explicit public artifacts were exported; no signing/device/API secret was
added to the repository. See model-proof-2.json, public-verification.json,
evidence/chain-verify.json, full-tests-clean.log and cleanup.json.
