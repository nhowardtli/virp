# Execute v3 canary qualification — 2026-10-15

Tasks 1 and 2 passed on disposable VM100 `virp-canary`, 10.0.10.230,
cloned from VM211 clean-base root snapshot with a fresh cloud-init disk.
4 vCPU / 8 GiB, VLAN10, fresh SSH identity, daemon keys, test approver and chain.
Snapshots: canary-before-bootstrap, canary-sanitized, canary-before-kex-fix.
Keep this VM until branch merge; no production device is in its inventory.

## Code and deployment

- 62ba679: v3 Ed25519 execute responses, typed refusal payload, signed replay rejection.
- ecb2051: Cisco custom KEX preserves strict-KEX signaling.
- Deployed binary: `/opt/virp-canary/bin/virp-onode-prod`.
- SHA256: `5d0c941cbee74240be15bf2e010a3cbdd901dd80c7395a2ae56ac2c41e0e491d`.
- Service `virp-canary`, dedicated uid997, active, not boot-enabled.
- Flags `-3 -S /etc/virp-canary/chain-sign.key`; key stays on canary.
- Public key_id `e75d7ee71aa7a4caa5db94b565d3777e`.
- Two real FRRouting 8.4.4 containers; driver talks SSH/vtysh to frr1.
  No emulated command output or mock driver in the live proof.

## Tests

Final `umask 077; make ASA=1 all-tests` exit 0 at ecb2051: all 71
prerequisite targets passed, dependency check confirms no optional battery
silently skipped. The log includes 576 unittest cases in 16 Python batteries
and 87 API pytest cases. The additional typed-v3 contract file passes 6/6.
C examples: core 61/61, O-Node 169/169; full per-suite results are in the log.
New execute-v3, consumption ordering, historical v3 vectors, Ed25519 negative
and forge batteries passed. Replay regression was first observed failing
before implementation, then passing. No Rust toolchain/version changes.

## Live proof

GREEN show version: signed v3 DEVICE_OUTPUT. RED configure terminal:
signed v3 ERROR with proposal `b1205994ba8886035154f8bf47006a68`.
Test approver key only: approval, successful apply, replay -37. Replay adds
signed gate_rejection with approval id and original outcome id. Original
outcome row bytes are unchanged. Approved end returns to EXEC.

Description set proposal `229e3a89ab71b68e82d0a61e42b133a6`;
restore proposal `98a1ea5002cd0935ffb2eb283fc52f7a`.
FRR eth1 description set to VIRP-V3-CANARY-20261015, captured, then removed
through a separate proposal/approval/apply. Before and restored running-config
capture bodies match byte for byte. show running-config is YELLOW under the
existing classifier, so test-key approvals were used; the GREEN ceiling was
not relaxed. Description is YELLOW, not mislabeled RED.

| Chain session | Entries |
|---|---:|
| canary-v3-20261015-3 | 18 |
| gate-enforce:canary-frr1 | 20 |
| approval:canary-frr1 | 22 |
| node-config:00000100 | 4 |
| canary-v3-20261015 | 1 |
| canary-v3-20261015-2 | 1 |

The last two retain signed failed reads from setup, not successful proof.
All 66 entries checked over explicit complete ranges, zero open executions.
An off-node Python/cryptography check using only the public key verified
66 entry signatures, 6 head signatures, hashes/links/artifact bindings, and
all 20 stored execute observations' v3 signatures. Chain-entry format is
unchanged. Primary observation session head:
`096a820d6068e7205f9aaba5083e9714d795c3af1946740ac1317dcb96284655`.

## Limits and handoff

No .211 install-prod, switch commands, firewall changes or AWS changes.
Bundle exported with all 66 artifact bodies; no witness submission, and no
virp-verify 0.1.3 VERIFIED claim. PATH's verifier is an older dirty 0.1.0
binary, which was not substituted for the requested acceptance version.
No old v1 history was rewritten. Original Kestrel packet must be a new run.

.211's live cage helper accepts only v1 and lacks session binding. Its
signing key is not provisioned. Stop condition and draft deployment/enrollment
steps are in DEPLOY-211-DRAFT.md; those commands were not executed.

Private evidence: `/home/nhoward/audits/virp-canary-20261015/` includes exact
logs, test-first failure, public evidence tar, verification script/result,
per-session checks, original/replayed outcome rows and before/after captures.
