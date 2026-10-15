# v3 execute-path unattended block: stopped at contract preflight

**Historical:** the owner subsequently resolved the chain-format and canary-creation blockers. See `V3-REFUSAL-TYPING-GAP-2026-10-15.md` for the current, narrower code-level gap.

## Scope and status
Owner authorized Task 1 (C v3 execute path and VM212 canary), Task 2 (signed replay refusal), and Task 3 only after the first two finish. Hard constraints: no install-prod on .211, no SW-3850 commands, no FortiGate/PVE firewall changes, no AWS changes; snapshot before VM changes; stop at contract gaps instead of guessing.

Branch `feat/v3-execute-path` was created in `/home/nhoward/virp-wt/v3-execute-path` from freshly fetched `origin/main`, commit `3238863ffd944b1502d42eb723052e26d3b5d8f6`. No implementation changes have been made. This commit records blockers, not completed functionality.

## Blocker 1: the designated canary is absent
Fresh read-only `qm list` on colo pve1 (10.0.10.10) has no VM212. The September20 owner-authorized retirement report records colo VM212 `virp-node2` as deleted, including its owned disks/snapshots. The home CT212 `frr-router` was explicitly excluded from that retirement and is a different host/type/site.

No substitution, VM recreation, restore, startup, snapshot, guest login, installation or canary execution was attempted. Snapshot-before-change cannot be satisfied for a nonexistent VM. Resolve by identifying an existing replacement canary by site, VMID and identity, or explicitly specifying recreation/recovery of VM212 and the intended FRR containerlab placement. Merely reusing ID212 would not establish target identity.

## Blocker 2: “every new entry v3” is not a defined existing chain contract
The task requests proposal, approval, apply outcome, observation and gate_rejection entries “signed v3 with the node's chain-sign key”, and “every new entry v3”. Current main defines two separate formats:

1. **Observation wire v3**, `include/virp.h`: version byte 3, 88-byte session-bound header, payload, 32-byte HMAC, 64-byte Ed25519 signature. The Ed25519 signed span is header + payload + HMAC. Execute currently accepts only versions1/2 (`src/virp_onode.c`, request parser around519 and execute around2363).
2. **Detached chain signing**, `include/virp_chain.h`, `src/virp_chain.c`: existing canonical JSON plus detached signatures domain-separated by `VIRP-CHAIN-ENTRY-SIG-v1` and `VIRP-CHAIN-HEAD-SIG-v1`. `artifact_schema_version` is currently `1`. Proposal, approval, outcome and gate-rejection artifacts are JSON bodies, not v3 observation frames. Existing chain signatures deliberately leave canonical bytes unchanged.

A possible resolution is: emit v3 observations (including error/refusal responses), sign all new chain entries/heads using the existing detached Ed25519 contract and the requested node chain key, while preserving legacy canonical schemas and verification. This would be **v3 observations plus Ed25519-signed chain entries**, not literally “every chain entry v3”. This interpretation has NOT been silently adopted. Alternatively, a new v3 artifact/chain envelope needs an explicit canonical schema, version semantics, domain tags and verifier compatibility contract. Do not change artifact_schema_version to3 as a cosmetic label.

The requested same node key can be implemented under explicit domain separation; key custody must remain on the node. This does not by itself define the missing envelope semantics.

## Task 2 follow-up contract
After resolving the above, write the replay regression first. Pin precisely what “approval id” and “original outcome id” mean in the existing API: approval proposal_id vs approval chain-entry hash, and the original stored outcome artifact_id/hash. The test must demonstrate a signed refusal referring to the actual earlier committed outcome, unchanged earlier apply bytes, and clean chain verification. Do not synthesize an original outcome when an intent was consumed but execution/outcome remains indeterminate; that case needs an explicit representation. No Task2 test or implementation was written during this stopped preflight.

## Results and counts
- Implementation commits: 0; this is a documentation-only blocker commit.
- C tests run: 0. Python tests run: 0. No batteries claimed green.
- Canary sessions: none; VM212 absent.
- VM snapshots/changes: none. Only read-only hypervisor inventory used.
- .211 actions: none; no install-prod, restart, key operation or device command.
- SW-3850 commands: none.
- Firewall/AWS changes: none.
- Historical evidence: unchanged.

## Deploy instructions status
Task3's prerequisite (Tasks1/2 complete with time remaining) was not met. No .211 enrollment line or executable install-prod sequence is supplied: there is no qualified build, no observed .211 chain public key for this task, and no canary acceptance to anchor exact commands. Supplying placeholders as runnable deployment instructions would contradict the stop-at-gap requirement. The future runbook must pin snapshot identity, signed artifact hash, service/config paths and rollback, then install/restart/verify and update DEPLOYED.md; none of those deployment actions were run here.

## Resume inputs
1. Confirm the format interpretation: v3 observation wire plus unchanged canonical chain entries with existing detached Ed25519 signatures, or provide the new canonical contract.
2. Pin the canary that replaces retired colo VM212 (or define its recovery/recreation scope) and its FRR containerlab targets.
3. Define replay linkage for consumed-intent/no-outcome cases alongside the normal original-outcome case.

Stop is intentional under the owner's instruction. No claim of v3 readiness, verified bundle, successful canary or deployment.

October 15 continuation: superseded for the canary by the owner's clarified
chain-format ruling, authority to make implementation decisions, and fresh
VM100 creation. See EXECUTE-V3.md and CANARY-V3-RESULTS.md. The current .211
consumer contract gap is documented separately in DEPLOY-211-DRAFT.md.
