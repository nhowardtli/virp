# TLI AI infrastructure rollout — phase one, October 16, 2026

## Result

Dedicated qualification environment built, production C baseline reconciled,
full batteries green, and the final cage → C daemon → FRR GREEN/refusal proof
passed. This clears the previous helper/runbook qualification blockers.
Production .211 and SW-3850 were not accessed or changed. iDRAC excluded.
The owner keyboard deployment procedure is ready; production RW on this build
remains the next milestone, not a completed claim.

## Dedicated environment and recovery

Colo pve1 VM103 `virp-qualify`, 10.0.10.231, VLAN10, 4 CPUs/4 GiB. Independent
root copy from VM100's pre-public-demo `before-cage-v3` snapshot; fresh cloud-init,
machine/SSH identity, daemon/test-approver keys, lab credentials/SSH keys and empty
chain. Node ID259. No production keys or inventory were enrolled.
VM100's public lab and SSH restrictions remain unchanged. New VM reservation
is in managed inventory and its PVE description to prevent reuse.

Snapshots `before-identity`, `fresh-identity`, `phase1-qualified`; VM227
`before-tli-qualify`. Owner SSH and QGA control verified. These qualify virtual
recovery access, not the still-unverified 123Net physical-console procedure.
No iDRAC access, physical-host reboot, recurring automation or backup/restore
coverage claim. VM103 is disposable qualification infrastructure, retained for
subsequent work; no automatic deletion of the now-shared VM100.

## Code and tests

Branch `feat/v3-execute-path`:

- `d46802d`: retain production `140f6f9` health dispatch/readiness, watchdog and
  Wazuh TLS-name protections alongside execute-v3 and Cisco auth/denial fixes.
- `7f74291`: imported TLS fixture requires explicit opt-in and loopback target.
- `b7496fb`: Wazuh protected-agent declaration also visible to test loader builds.

The production health test failed before integration. Full-build enforcement
also caught the imported probe's missing live-contact guard and a declaration
hidden by `VIRP_ONODE_PROD_NO_MAIN`; both fixed without disabling checks.
Final all-driver `all-tests` exit0: core61/61, O-Node169/169, 589 Python unittest
cases including13 helper cases, 87 API pytest, remaining C/security suites and
operability test. Separate TLS fixture and 26 renderer checks passed.
No Rust changes.

Installed canary source `b7496fb`, binary SHA256
`e8a1c7d19c5e2b0cdc3c4105a7cbac609e5f122402ec50ea8734c1d7e8a86c3b`.
The shared helper consumer is unchanged; only the canary wrapper's expected
node pin is changed from256 to259 for this fresh node.

## Model-driven proof

Existing configured model `gpt-4.1-mini-2025-04-14`, root-trusted runner onVM227,
fixed two-operation helper onVM103. No network credentials, approval keys or
signing keys supplied to model tools. This is not protection against cage-root
compromise; the trusted runner retains its own API/transport credentials.

Session `tli-rollout-qualify-20261016`:

- Final GREEN request `11fa5ccbb97a9592ae413857fbe7d1f5`, wire session
  `52f99399b3ec1971e77d960913489d7f`, subtype7 and real FRRouting8.4.4 output.
- Final RED request `022816db81f03ae8809331f83d87d70b`, wire session
  `041a147311dbd9f21b41bb4f1d789f4d`, subtype15, RED/maxGREEN refusal and
  proposal `04b4686b2c06329f6c10cd3ff1c40b21`. No approval/apply issued.
- Final head `5c469d393d366c3031761df27a3a605c5dd42a2404dda3da90db7f3bfbf81527`.

All12 entries,4 heads,4 v3 observations independently verified off-node using
only public key pin `e6a06a29c1e3c949a242ac86e946dc54`. Exact observed bytes match
stored artifacts. Native verification covered every session's complete range,
with zero open executions. No witness submission or virp-verify0.1.3 claim.

An earlier GREEN attempt failed authentication and was honestly stored as a
signed ERROR; it remains in the evidence alongside its RED refusal. The lab's
startup script reapplied the old mounted password during container restart.
Updating the protected credential source before restart fixed it. No failed
record was erased or replaced. Initial offline boot also required marking the
disconnected clone NIC optional; QGA/SSH were verified after correcting boot.

## Containment and next milestone

Helper STOP set after export. Temporary Forti62710/CAGE-QUALIFY-V3 and exact
PVE103/PVE227 cage path rules removed; other rules preserved. Owner management
access retained. New runner does not replace the production cage runner.

Next: owner follows [the .211 runbook](DEPLOY-211-RUNBOOK.md), with provisioned
node-local chain-sign key. Then qualify production routine RW and exact-change
approval/apply/replay/restore with nhoward-admin as sole operator approver.
Network-wide autonomous RW, generalized risk policy, physical recovery and
CMMC readiness remain separate tracked work; this milestone proves the
execution/evidence foundation only.

Private audit: `/home/nhoward/audits/tli-ai-rollout-20261016/phase1/`.
Case-study evidence includes test-first failures, corrected lab setup, exact
build identities, both model runs, public export, verification and recovery.
No external case-study publication performed.
