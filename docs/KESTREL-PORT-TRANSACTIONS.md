# Bounded port transaction integration

Status: source-only implementation, 2026-10-18. Not deployed or live-qualified.
The existing native classifier and per-command Ed25519 approval gate remain in
force. No policy tier is lowered by these modules. No new chain format is used.

## Authority and custody

The cage may choose a fixed operation and describe its reason. It cannot supply
credentials, signing material, authenticated observations, arbitrary commands,
or a successful verification result. A trusted helper collects v3 frames, checks
external producer pins, session/device/command/sequence/freshness bindings and
native chain membership. `port_evidence` parses those verified outputs.

`port_plan` renders a finite operation and an exact rollback from captured
configuration. `port_transaction` binds the entire bundle to an independent
Ed25519 approval, owner identity, boot identity and both wall/boot-time lease
limits. The envelope domain separates transaction approval from native VAP1
command approval. This is an approval artifact, not a change to chain signing.

The approval signer must remain on the independent owner control plane. Its
production adapter must perform real Duo authentication for nhoward-admin and
validate the complete immutable plan before signing. The `port_owner` library implements a durable coordinator with injected Duo
and signer adapters; no production entrypoint is enabled by this source-only
change. Its signed envelope includes the authorization method, Duo transaction
reference and decision time. Test approvals are explicitly labeled and require
a separately configured test policy. Canary qualification uses a
separate test approver, never the owner's private key.

## Durable sequence

1. Collect and verify every prerequisite. Render the plan, prepare the immutable
   bundle, and append its proposal event to the native chain.
2. Independently authorize and sign the exact transaction envelope. Store it and
   append the approval event. Lease time begins at its signed issuance time.
3. Recheck all prerequisites through the preallocated preflight read authority.
   Only an unchanged, fully verified baseline advances to preflight_verified.
   Reserve one apply request. Flush its event through `EventLedger` before
   reserving a native challenge for its exact command and pinned device.
4. Flush the native approval intent. `native_signable` durably consumes issuance
   before returning exact VAP1 bytes to the trusted signer adapter. The independent
   owner coordinator requires the signed producer-chain intent for that exact
   approved transaction and proposal before signing. Repeated
   issuance is refused. Submit the returned signature to the native gate.
5. Flush issuance evidence, recheck transaction/lease, and consume dispatch
   before device execution. Native approval remains independently mandatory.
6. Validate and chain the result frame. The trusted adapter, not the model,
   records executed or UNKNOWN. Exact expected-result reads and machine-side
   comparison determine verification.
7. Restore the rendered baseline, verify restoration, and close. Never save
   configuration as part of this transaction.

An ambiguous signer response or dispatch is not automatically retried. A crash
with an outstanding intent requires trusted reconciliation; the recovery adapter
must still establish that the worker is no longer active. The trusted
`record_interruption` API closes that request as UNKNOWN without fabricating a
native observation. UNKNOWN permits only the bound reconciliation read set.

After expiry, forward apply is refused. Only the transaction's expected reads
and baseline restoration may continue. Restore uses a fresh, bounded native
challenge under the *existing* transaction approval; it does not reuse a consumed
native approval or extend its TTL. Expiry is recorded with transaction state.
Expiry before dispatch closes as expired-before-apply. Completed transactions do
not acquire new expiry events merely because someone queries their status later.

## Chain and outbox

Events are existing `evidence_item` artifacts signed by the native
VIRP-CHAIN-ENTRY-SIG-v1 mechanism. Execute observations remain v3 frames.
`EventLedger` checks exact artifact bytes, Ed25519 chain signature against the
external pin, unique membership, and full native chain verification. Lost append
replies are reconciled by stable event ID; corrupt, duplicate, or orphaned
artifacts fail closed. Local receipt-shaped dictionaries are not evidence in
production; only the verified adapter may acknowledge delivery.

The SQLite store and paths are trusted root-owned deployment inputs. Approval
signatures bind immutable plans and deadlines; this is not a claim of protection
against root rewriting the entire coordinator and its trust configuration.

## Current limits and remaining integration

- There is no new cage-facing endpoint or production deployment in this change.
- Precondition parsers currently accept only an isolated, shutdown port and a
  zero-channel-group device. Populated production EtherChannel output requires
  captured-format qualification before production activation.
- LLDP disabled is a failed prerequisite, not proof of neighbor absence.
- Complete VLAN tables are required; unsupported wrapped rows fail closed.
- The current transaction verification read set is switchport plus complete
  interface configuration. VLAN membership/log delta checks still need integration
  before claiming the original VLAN work-order acceptance.
- The trusted `finish` API is internal. A real adapter must independently verify
  frame bytes and compare device state; caller-provided success/hash strings are
  not a cage API and must never become one.
- Root-owned service entrypoints and transport integration, signed replay-refusal
  linkage, host/worker recovery checks, endpoint lease exceptions, production TACACS changes and
  off-box live evidence qualification remain outstanding.
- Neither .211 nor SW-3850 has been changed by this implementation.

Run `make test-cage-v3` for the local Python suite. Native C behavior is unchanged.
These unit tests are not live Cisco or Duo acceptance evidence.

## Owner authorization timing and verification

The independent coordinator durably records push intent before contacting Duo,
requires explicit factor authentication (not preauth bypass), and binds the Duo
transaction to the immutable plan hash and both forward/restore commands. An
ambiguous push or signing result cannot be automatically retried.

The authorization deadline begins at Duo's allow decision. A later executor
signature request may only use the remaining duration; it cannot restart the
full window. Both owner and executor enforce wall-clock and boot-clock limits.
Forward native approval can be issued once. Restore can be issued once after
forward issuance, including after expiry. Config verification signatures are
limited to eight per transaction. The owner closes on a verified signed producer
close event. Production transport identity and protected filesystem checks remain
requirements of the service entrypoint, not supplied by a caller or the model.

`port_result.capture_after` rejects a verification frame whose signed timestamp
predates the action or whose chain entry is not later in the same chain session.
The comparator checks exact interface config, port identity, shutdown/down state,
mode and access VLAN. It does not yet implement the full VLAN membership, log
delta or operational port-security acceptance reads.

The synthetic pipeline test joins the coordinator, transaction state and signed
ledger for expiry/restore/closure. It uses generated test keys, mock Duo and
mock device outcomes. It is not live qualification evidence.

## Root owner entrypoint (source-only)

`port_owner_service.py` is a one-request stdin/stdout entrypoint, not a listener.
It requires root, a root-owned profile and all local modules, a pinned machine
ID, a private state directory, and a matching Ed25519 PEM private key/public pin.
Production identity is fixed to nhoward-admin. Duo secrets stay in the existing
root-protected Auth Proxy configuration. They are not command arguments or output.
The source `port_duo` adapter preserves the already-qualified description
coordinator's no-redirect/no-proxy/no-retry behavior. Verified-push requirements
are not downgraded: without an owner number-display interface, that flow refuses.

Allowed JSON actions are prepare, authorize, sign_envelope, sign_native, close
and status, each with exact fields. No arbitrary command, file path, owner or
signing key can be supplied through the JSON request. Device provisioning comes
from the protected profile. The profile has schema `kestrel-port-owner/1` and
fields machine_id, database, private_key, public_key_hex, duo_config, duo_section,
max_lease_seconds and producers. Each producer is keyed by a provisioned device
name and contains public_key_hex, node_id and chain_session. Private files and
the state directory must disallow group/other permissions. Public modules/pins
must disallow group/other writes. Maximum supported lease is ten hours; the
protected profile and per-proposal owner decision may set a shorter duration.

This entrypoint is **not installed**. A separate executor-authenticated transport
and restricted forced-command account must be provisioned before .211 can use
it. The existing ThinkPad-to-PVE-to-CT224 administrative route does not establish
that transport. No SSH key, sudoers entry, account or daemon was created here.

## Target identity and transport findings, 2026-10-18

The approved target carries device, host, physical port, transport_port and explicit device_node_id.
The canary config pins device_node_id to 260 (hex 00000104); it is not derived
from its IP address. The current canary SSH transport port is 22; the current
production C config uses 10.0.10.2:2223 with device node 0A000A02. These are
observed config pins, not instructions to alter either device. Producer node identity and the 64-bit observation device ID
are separate bindings and must also be checked by the helper. The signed native
challenge uses the configured device node ID.

Read-only management checks found CT224's SSH active at 10.0.20.224, reachable
from .211 without firewall changes. Its existing signing key and Duo config are
root-owned 0600, and its approval state directory is root-owned 0700. The new
wrapper and restricted kestrel-approve account are absent. Public SSH/approver
pins were captured through the existing authenticated Proxmox management route;
no private material was exported.

`port_owner_remote` fixes the owner destination and command, disables inherited
SSH config, agent use/forwarding, multiplexing, proxy commands, password auth and
host-key updates, and requires a root-protected explicit known-hosts file. JSON
travels only on stdin. Timeout or malformed response is indeterminate and never
automatically retried. This client is source-only until restricted account,
forced command, client key and pinned host file are provisioned.

## Native approval verification and remaining integration contracts

`port_native_approval` reconstructs the existing 72-byte VAP1 payload from the
native approval artifact and checks the approver's external public pin, operator,
proposal, command, configured device node and TTL. `ApprovalLedger` additionally
checks exact artifact bytes, producer signature, unique membership, the explicitly
pinned epoch session and native chain verification. The real canary approval
session is `approval:kestrel-ios@cml-v3-20261016`. A compatibility check against the
previously captured cc7dc593c61c1d349727746e81dff01a approval passed using public
pins and its historical issuance time; it confers no present execution authority.

Before enabling the runtime, native forward/restore proposals must be filed and
bound into the transaction *before* owner approval. The existing C daemon can
issue a fresh challenge for an unconsumed, already-filed proposal; this permits a
fresh short-lived restore signature without creating a new restore proposal at
expiry. The transaction bundle now pins an inventory of forward, restore, preflight
and two to eight verification proposals, each with its native artifact and chain
entry hashes. Both coordinator and helper refuse an unlisted proposal even if
a valid producer signs a later intent for it. The runtime must verify each native
proposal reference before preparing this bundle; lexical reference validation
alone is not proof that a native proposal was filed.

The runtime must also recheck the complete approved baseline before forward
apply. The state engine now requires preflight success and refuses apply when that
check is more than 30 seconds old by either wall or boot time. Expiry during
preflight closes before apply; a late read result cannot reopen the transaction.
The runtime adapter must collect that second preflight using authenticated
frames and the complete precondition set. A trusted caller supplying a hash or `matches` is not sufficient
for an exposed cage endpoint. Live dispatch remains disabled until these adapters
are wired and qualified.

The checked virp-verify 0.1.3 build is c38c4f8 (clean release). Its standalone
verdict authenticates chain signatures and carried artifact hashes; it does not
by itself implement this transaction state machine or check the native VAP1
approval semantics. Keep the existing verifier and report supplementary public-
pin approval/v3 checks separately. No Rust version or verifier code was changed.

## Native helper adapter

`port_native.NativePort` uses the existing `execute_observed` helper and constrained
requester transport. It exposes only the fixed prerequisite reads and the exact
validated forward/rollback commands. Baseline collection can start with a pinned
target and read-only command set; it does not need fake proposal placeholders.
The caller's target/plan is copied so later dictionary mutation cannot retarget
an initialized adapter.

The actual canary UID policy was inspected: UID 980 has execute, session binding,
observation append and chain verification; approval challenge/submit remain on
the existing root control identity. The adapter therefore separates the execute
transport from the approval control transport. No UID permission was widened.
Approval submit must be fresh, attributed to the pinned approver/operator, and
backed by an independently verified native approval artifact before returning.

The new native ledger readers also passed a read-only check against the canary's
actual SQLite database and `chain_verify` endpoint. That check used the historical
cc7dc593c61c1d349727746e81dff01a record at its historical issuance time. It sent
zero device commands, did not install code, and grants no current authority.

The enclosing endpoint must supply the protected host/config/binary/scope guard,
hold the scope lock, and latch STOP on an unexpected preapproval success. That
runtime composition is still under construction; these modules are not deployed.

## Outer scope and runtime guards

`ScopeGuard` holds the existing scope lock across one helper operation, preserves
STOP/pending markers and the 96-request ceiling, and records each request once.
It requires the existing wall/boot work lease on every check. A policy edit while
an operation is running refuses continuation. It cannot renew leases or resolve
pending outcomes. Transaction-lease recovery does not bypass this outer scope.

`RuntimePins` requires protected file hashes, exact machine/caller/requester
identity, producer public pin, enforced gate and GREEN requester ceiling. It
checks the configured target's hostname, host, device node and transport port.
It also checks the active service's running executable hash and full startup
arguments, not just the binary currently on disk. Pins must come from a reviewed
root-owned deployment profile. Checking these files does not independently prove
which configuration bytes a process loaded at startup; deployment must establish
that binding and retain its evidence.

`NativePort` now requires a STOP-latch callback. Unexpected success while filing
an unapproved proposal invokes it before returning a refusal. The actual endpoint
must wire this to the locked scope's durable STOP marker. The guards and adapter
are tested locally; no new runtime endpoint is installed yet.

## Transaction workflow adapter

`PortFlow` now joins the state engine, independent owner signing, native approval
submission, fixed helper commands and machine comparisons. Every step requires
the outer scope guard. Verification reads are rechecked against public pins,
command/session/device identity, action time and chain ordering. Preflight's
entire read collection must finish within 30 seconds. A signed command response
advances only to applied; fresh read comparisons are still needed for verified.

Each machine comparison is a signed `evidence_item` referencing all observation
hashes/receipts, the native approval artifact, exact transaction and bundle hash.
The transaction outcome links that comparison and its last observation. The
proposal event carries the complete immutable bundle, including its prefiled
native proposal inventory, for portable inspection.

A transport exception leaves the request outstanding and latches STOP. A signed
UNKNOWN is preserved as native evidence and leaves the transaction unknown.
Neither path automatically retries a write or fabricates a device result. The
existing pending marker still requires separately qualified reconciliation.
Owner closure consumes the signed close event. These integration tests use real
Ed25519 signatures with synthetic device/chain transport and mocked Duo; they
are not a live packet or standalone-verifier acceptance.

## Preparation and exclusion

`PortPreparation` collects all seven baseline reads through the public-key helper
before rendering anything. The complete collection must be fresh, and MAC,
neighbor, protected-port and supported-format checks precede native proposal
filing. Forward, restore, preflight and bounded verification proposals are then
filed and their authenticated references included in the immutable bundle.

The initial interface-config read still requires an independently issued native
YELLOW approval. The preparation API takes that already-approved proposal ID;
it does not invent authority, weaken the classifier, or accept model evidence.
Production provisioning of this initial read approval remains outstanding.

Only one transaction may be open on a given target port. A closed transaction's
outbox must reach the signed chain before another starts, and native proposal
IDs cannot be reused in a later transaction. Prepared or ambiguous transactions
remain blocking until explicitly resolved; there is no automatic deletion of
state or consumed approvals.

`PortAuthorization` durably reserves one owner handoff before contacting the
owner service. It cannot automatically repeat a push or signature request after
a lost response. The signed executor envelope uses only the duration remaining
from the owner's original authorization deadline. The owner independently checks
that deadline again. Handoff failure latches STOP and preserves the attempt for
reconciliation; it does not create an approval or silently retry with a new ID.

## Explicit canary authority

`CanaryOwnerRequests` is a separate lab-only adapter with fixed identity
canary-test-approver and only the kestrel-ios target. It signs envelopes labeled
`authorization.method=test` and never contacts Duo. The production owner
entrypoint does not import or expose this adapter. Production transaction state
requires `duo` and rejects a test envelope even if otherwise correctly signed.
The lab entrypoint must additionally pin VM105 and its provisioned test key.
No test signer or key has been installed by this source change.

## Canary custody finding (read-only, 2026-10-18)

The running canary binary still matches 938027b7...e6c182. Its device config,
producer public file and approver registry currently belong to service UID995,
GID987, mode0600. The binary and helper modules are root-owned. The new runtime
guard intentionally requires root-controlled configuration inputs and also pins
the running daemon's effective UID. It accepts a root-owned device config with
read-only daemon-group access (0640), but rejects world-readable credentials.

Deployment therefore needs an explicit metadata-only custody adjustment after a
snapshot: root ownership, daemon group read access for files the daemon must read,
and protected parent directories. Preserve every config byte and hash; retain
original ownership/modes for rollback. No such change was made by the read-only
inspection. Do not weaken the profile guard to make the current layout pass.

`port_replay.verify_pair` supplements full chain verification with semantic
checks for the native -37 gate_rejection and its original successful outcome.
It verifies both producer signatures and artifact bytes, the exact device,
command and approval ID, executed:false, the prior outcome hash, and ordering.
It accepts existing native database and exported signature representations.
A read-only compatibility check passed against the already accepted October16
production description packet using its external producer pin. That is historical
format compatibility, not a new write, witness head or acceptance packet.

## Local native integration and export regression

`make CISCO=1 test-port-native-pipeline` starts a real local C O-Node with an
in-memory test device. The production Cisco classifier, Unix socket protocol,
approval store, v3 signing and native chain implementation are exercised. Its
callbacks perform no network I/O. This is a test binary, excluded from production
installation. The pipeline uses generated test keys and explicit test authority.

The first successful round trip produced 29 v3 frames and 122 native entries in
four chains. Forward and restore each reached the simulated device once; replay
returned -37, the prior outcome row remained byte-for-byte unchanged, and every
native chain verified with zero open executions. These are local integration
results, not VM227, VM105 or physical Cisco acceptance.

The independent offline verifier found an exporter defect: SQLite TEXT records
using the `base64:` transport wrapper were copied as wrapper text instead of
original frame bytes. `virp_export_bundle.py` now strictly decodes that storage
representation. Literal UTF-8 and BLOB bytes remain exact; malformed encoded
storage refuses before bundle output. No chain, frame, signature or verifier
format changed. The failed export is retained in the private session audit.

With the corrected export, the unchanged virp-verify 0.1.3 returned
CRYPTOGRAPHICALLY-VERIFIED for all122 entries/four chains in a network-disabled,
read-only container as UID65534 with only the external test public pin and
bundle mounted. No witness receipt exists for this synthetic run; it does not
establish a physical device or a real Duo approval.

The real-C suite also exercises wall-clock expiry after apply, rejection of an
unrelated read, restore under the original approval, ordered expiry/restore/close
entries, expiry before apply without a write, and rejection of a tampered rollback
bundle. The test deliberately restores its injected store bytes afterward solely
for fixture cleanup, then performs the original authorized rollback. This is not
an exposed repair API.

A one-second real-clock test found that rounding remaining duration to integer
seconds made short approvals unusable. The envelope now preserves the original
owner decision timestamp and a conservative corresponding boot-clock instant.
Both deadlines remain anchored to the original approval; no time is added.
An owner timestamp ahead of the executor refuses explicitly. Production clock
alignment and the remote owner transport still require live qualification.

A separate local C fault test changes the simulated state but drops its response.
The C daemon returns a signed v3 UNKNOWN, commits the native outcome, and consumes
the approval. The helper records unknown and preserves STOP/pending. Both retry
and restore through the ordinary helper are blocked. Root reconciliation of that
pending state remains a separate, not-yet-wired port recovery path.

A follow-up membership check corrected the proposed custody layout before any
deployment: virp-kreq UID980 is a member of the existing virp-canary socket group
987. That shared group must **not** receive credential read access. The guard now
requires a separate pinned credential group with exactly daemon UID995 as its
member, devices.json root-owned0640 under that group, and the running daemon
actually holding that group. The existing995:987 mode0600 config under a0700
service-owned directory is not claimed to leak credentials today. No ownership
or group change was executed. The private audit contains the deployment decision
and original metadata for recovery.

`port_endpoint` accepts only operation/request_id/rationale, maps thirteen fixed
operations, and takes transaction selection and lease duration from trusted
services. It rejects supplied CLI, target, transaction ID, approval status and
lease fields. STOP/pending/expiry and duplicate requests fail before dispatch.
Reconciliation and replay qualification are not exposed as ordinary cage verbs.
Request/response files remain explicitly helper records, not native observations.

## Canary host entrypoint (source only)

`port_canary_service.py` is a separate, canary-only entrypoint. It hard-pins VM105's
machine identity, virp-cage-test caller, virp-kreq UID980 execute path, daemon UID995,
the existing service argv, producer public key, and canary test approver public
key. It accepts no command-line paths. All local modules are root-protected and
hash-pinned before import, then rechecked during each scope check. A test checks
the complete transitive local import manifest, including deferred imports.

Its fixed root profile is `/etc/virp-canary/port-helper.json`; private test-key
loading is restricted to `/root/canary-test-approver.key`, mode0600, raw64 bytes
`seed || public`. Both the stored public half and derived Ed25519 public key must
match the independently pinned canary test public key. No private bytes are in
the repository. Wrong host/caller, changed runtime, expired work scope, STOP or
pending outcome refuse before private-key loading or transaction-store opening.

The lab bootstrap may approve only `show running-config interface Ethernet0/1`
on the fixed canary. Its native proposal/approval are chained and signed by the
test approver, explicitly not Duo. Production has no such automatic bootstrap
authority. Execute remains UID980; root control is restricted by the adapter to
native approval submission and signed evidence appends. The model never receives
either socket or a signing function.

This entrypoint has not been installed or executed on VM105. Its caller/host
refusal, key parsing and profile checks are local tests. The real local C fixture
uses the same CanaryClient owner adapter, but does not qualify host deployment,
SSH forced-command routing, VM227 model behavior, real Cisco timing or recovery.
The existing expired scope and unapproved lab prerequisites remain unchanged.

### Lease enforcement boundary

The transaction lease is enforced by the trusted helper and independent owner
coordinator. Native VAP1 command approvals retain the existing300-second TTL;
the C daemon does not parse the new transaction envelope. Scope and transaction
state are checked before dispatch. An already-dispatched operation can finish
after lease expiry; this is not cancellation or a claim of device-side deadline
enforcement. A command signature can also remain cryptographically valid longer
than a short transaction lease, although the ordinary fixed helper refuses its
use outside the approved transaction state. No arbitrary approval-ID or raw
socket path is exposed to the cage.

If acceptance requires the C gate itself to bind every native approval to the
transaction's shorter deadline, that is an additional contract/implementation
gap. Do not claim the local expiry tests prove that stronger property, change
approval TTL semantics silently, or expose the raw command executor to compensate.

### Forced-command router (source only)

`port_canary_router.py` stages routing for the existing authenticated canary
forced command. It pins two root-owned destination files in a root-only
`/etc/virp-canary/port-router.json` profile. Thirteen port operations go to the
new service; existing diagnostic reads/status/stop go to a preserved legacy
endpoint. The old description apply/restore/replay verbs are deliberately not
exposed during this port qualification: two independent write workflows must
not operate on the same port between transaction steps. The old endpoint remains
recovery material, not a second agent-accessible executor.

Only operation/request_id/rationale are accepted. Duplicate JSON keys, extra
fields and unlisted operations refuse. Handoff uses exec with an anonymous
request file and an allowlisted environment, so the router introduces no child
timeout that could kill a running transaction. A subprocess test checks exact
request bytes, same PID and exclusion of inherited environment secrets. Both
destinations retain their own identity, work-scope, lock and runtime checks.
The VM227 transport timeout and model turn limit still need qualification;
this router alone does not solve those limits or prove end-to-end deployment.
