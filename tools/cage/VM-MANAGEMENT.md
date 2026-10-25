# Kestrel VM management milestone

Owner-authorized 2026-10-18: “work towards that don't stop until a major milestone”.

This adds an isolated second management domain alongside the existing two switch
ports. It does not grant fleet-wide administration.

## Qualified execution path

Owner CLI `kestrel vm '<request>'` -> root-controlled VM227 Responses runner
(GPT-6 Astra, existing model selection) -> fixed SSH transport to211 -> protected
VM helper -> dedicated requester UID977 -> native VIRP C instance UID978 ->
source211-only, password-authenticated forced-command principal on coloPVE1 ->
fixed Proxmox status/graceful-reboot operation for VM231.

The model receives no infrastructure password, SSH key or signing key. Trusted
runner bootstrap/admin and independent verification use separate owner management
access; those are not represented as Kestrel operations. Existing C binary remains
93d10333199b7e371d610205e0a1fd576a5f05d8ac3ec444327b6d2467c23ed6.

## Enforced scope

- Target `colo-vm231`, commands exactly `qm status 231` / `qm reboot 231`.
- Root hypervisor helper pins name, SMBIOS UUID, no NIC, and complete config hash
  through a root-installed grant; pre-reboot guest boot ID must match.
- Reboot requires unexpired, unrevoked single-use authorization. Durable intent
  is reserved before dispatch. Replayed request IDs and additional reboot
  attempts fail. The cage cannot mint or renew grants.
- Separate native key, chain, daemon, credential and requester identities.
  All other inventoried guests are protected VMIDs in the native Linux gate;
  forced-command validation also refuses targets outside the singleton scope.
- Native v3 frame and chain entry verification occurs before interpreting results.
  Native wrapper execution success is distinct from the JSON operation result.
- `kestrel vm-status` reports control state. `kestrel vm-stop` revokes future
  requests; it is not cancellation of an already dispatched operation.

## Qualified result

Disposable no-NIC Ubuntu VM231, 2vCPU/2GB/8GB, autostart off. One actual reboot,
11 reads by the model; changed boot ID, same machine/config identity, QGA back.
Independent Proxmox task completed OK; all other VM/container running states
unchanged. Recovery took about154seconds after dispatch because the no-NIC image
waited for network-online during boot. No application-health claim.

Live denials: other-VM request, unsupported action, native host reboot, protected
broker-VM reboot, forced-stop arguments, expired grant, stop/revocation, consumed
grant and exact request replay. Direct cage probes to coloPVE22/8006, homePVE22
and switch22 timed out. This tests specific paths, not every possible escape.

15 policy/acceptance tests pass. Offline bundle:91entries/5chains,
CRYPTOGRAPHICALLY-VERIFIED,23native frames; no external witness timestamp.

## Remaining work

Fleet inventory and additional targets/operations; scoped API credentials rather
than Linux forced-command transport where suitable; independent grant issuance
workflow; formal crash/timeout/UNKNOWN reconciliation; adversarial egress/proxy
coverage; service/application checks; automatic backup/recovery orchestration.
No automatic grant renewal or general shell is provided. The qualification grant
is consumed. Current status reads remain available within a64request attempt cap.

## Recovery

Owner can invoke `kestrel vm-stop`. Disable `virp-kestrel-vm` on211 and lock the
new `kestrel-vm` principal oncoloPVE1 to retire this scope. Retain chain and all
consumed grant/attempt records. Restore only the router branch from the before
copy if no subsequent changes exist; do not overwrite newer switch routing.
Snapshots211/227:before-kestrel-vm-20261018; VM231:fixture-ready-20261018.
Never restore over evidence or revive a consumed grant by reverting a snapshot.
Private report: `/home/nhoward/audits/kestrel-vm-milestone-20261018/REPORT.md`.
