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
3. Reserve one apply request. Flush its event through `EventLedger` before
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
