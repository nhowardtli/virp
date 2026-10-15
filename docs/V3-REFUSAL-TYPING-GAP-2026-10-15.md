# Execute-path v3: refusal typing contract gap

## Owner rulings applied
No new chain format: retain VIRP-CHAIN-ENTRY-SIG-v1 and existing chain canonical bytes. Only execute-path observation frames are to become v3, signed under the node's chain-sign key; v1/v2 verification remains compatible. Creation of a disposable canary from VM211 clean-base is now explicitly authorized. These rulings resolve the earlier chain-format ambiguity and absent-canary authorization blocker.

Owner stop rule: “If a frame on that path can't be v3 for a reason the code tells you, stop and say which.” The previous instruction to stop at any contract gap remains in effect.

## Finding: gate_rejection and replay-refused response typing
The current v3 builder can sign arbitrary refusal text. The cryptography is not the blocker. The missing contract is how a consumer identifies that signed payload as a broker ERROR rather than device output.

- `include/virp.h`: v3 reuses the 88-byte v2 header. Fields are version/channel/tier/reserved, node/time/sequence, session, device, command hash and payload length. There is no observation subtype. The reserved byte must be zero.
- `include/virp_crypto.h` and `src/virp_crypto.c`: `virp_build_observation_ed25519` takes payload bytes, not an observation-type parameter. It does not add the v1 typed observation subheader.
- `report/verify.py:parse_observation_v2_payload` (the v3 payload layout) returns `obs_type=None`.
- Existing execute errors use `VIRP_OBS_ERROR` (0x0f) in v1. This is distinct from `VIRP_OBS_DEVICE_OUTPUT` (0x07). The existing `tests/test_obs_type_not_device_output.py` pins that distinction as an enforcement property.

Simply switching the refusal builder to v3 would drop the signed ERROR discriminator. Treating the text prefix `ERROR:` as a substitute is unsafe: a device can print the same bytes. Treating RED tier as ERROR is also wrong: a successfully approved RED operation is not a refusal. Writing a subtype into the reserved byte violates the existing v3 verifier. Introducing JSON or a binary subtype prefix inside the payload would require an explicit producer/consumer payload contract; none was silently introduced under “Everything else untouched.”

Affected frames are the requested **gate_rejection** and **approval_reused (-37) replay-refused** responses, plus other execute error responses that currently use the same typed v1 error builder. Successful output frames can use the existing v3 builder; there is no general cryptographic inability to emit v3.

## Local reproduction
`tests/test_v3_refusal_type_contract.py`: three characterization tests pass. Fixture Ed25519 signatures over existing-format v3 frames verify; both gate-refusal and replay-refusal text expose `obs_type=None`; identical device-produced text cannot be distinguished by that field. Mutating payload invalidates the signature. These are observations of the existing gap, not acceptance tests for the requested execute implementation. No production key used.

Counts: 3 Python characterization tests passed; 0 C tests run; full batteries not run. No execute implementation or Task2 replay-chain mutation written. No canary sessions.

## Canary preflight, read only
On colo pve1, VM211 has snapshot `clean-base` dated 2026-07-29 14:08:28. Snapshot config has 8 cores/32768 MiB, VLAN10 on vmbr0, static IP10.0.10.211, a cloud-init disk and owner SSH key. `pvesh get /cluster/nextid` returned100 at inspection time; this is not a reservation. The clone must receive a fresh instance identity/IP/MAC/host keys and private VIRP keys before network activation; the snapshot's production IP must never be booted unchanged.

The code gap was identified before clone creation. No VM was created or changed; no snapshot beyond existing source inventory was taken. No .211 command/install/restart, no SW3850 commands, no FortiGate/PVE firewall or AWS changes. Read-only commands ran on the hypervisor, not inside VM211. Existing snapshot inventory is not a restore test.

## Required ruling to resume
Define the authenticated v3 payload discriminator for execute responses (DEVICE_OUTPUT versus ERROR), including how existing readers distinguish legacy untyped v3 payloads. A bounded option is a versioned typed payload envelope with explicit subtype and exact body length inside the existing signed v3 payload, without changing the chain format or the outer v3 header. This is a proposal, not an implemented encoding. The chosen format must be understood by the intended consumer and verifier; no claim is made that released virp-verify0.1.3 already interprets it.

After that ruling: implement/refusal tests, full batteries, clone and sanitize the stopped canary, snapshot it before guest changes, deploy only there, run FRR qualification with test approver, and record sessions. Task3 remains conditional on Tasks1/2 completion; no exact .211 deployment commands or AWS enrollment line have been invented.
