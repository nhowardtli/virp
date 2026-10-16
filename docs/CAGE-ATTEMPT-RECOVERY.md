# Caged execute attempt recovery

`execute_observed` now reserves `<frame>.intent.json` durably before session binding or command dispatch. An existing frame or intent refuses the request before any transport operation. Intents survive successful completion and crashes; a caller must never generate a new ID merely to retry an ambiguous write.

Callers can pass a root-owned `recovery_dir`. The helper atomically creates `pending.json` before dispatch and removes it only after frame validation, durable storage, successful chain append and session close. An unresolved attempt blocks every subsequent operation using that scope. Caller lease locks, target and binary pins remain required. The scope must be stable across requests and restarts, not derived from model input.

Invalid received frames are retained as `.unverified.frame`, never accepted as observations. Chain-append failures preserve the original raw frame. Session-close failures preserve prior exceptions and leave the scope pending. There is no automatic retry or automatic reconciliation.

A successful apply observation does not replace a verification read. The coordinator must still compare fresh observed state with the approved postcondition and restore through its separately authorized path.

## Trusted reconciliation

Keep STOP and the scope marker in place. Inspect the durable intent, original raw frame, native intent/outcome/rejection records, consumed approval state and target state using a separate restricted recovery channel. Do not infer a safe retry from a timeout or missing local result. Capture signed recovery observations and operator disposition. Only then archive the marker, preserving its bytes and the reconciliation record, and create a genuinely new authorized operation if needed. A changed boot, expired lease or changed target requires fresh qualification.

The unit suite injects reply loss, storage failure, invalid frames, duplicate attempts and close failure. Live qualification results and deployment status belong in the audit report; this document alone does not assert deployment or recovery testing.

Signed errors are not necessarily safe refusals. Unknown/new error vocabulary retains the recovery marker; only explicitly recognized native pre-dispatch refusal families release it. Live tests proved this using an actual signed UNKNOWN. The exact-port diagnostic avoids the current inline artifact-size cap; see KESTREL-ROLLOUT-POLICY.md for unresolved large-output and FRR health contracts.

## Root-only audited recovery helper

`tools/cage/recovery.py --profile /root/protected-profile.json` implements a
single-attempt reconciliation of a retained **signed v3 UNKNOWN**. It is not a
model tool. Root profile and all ancestors must be root-owned and not writable
by group/other. The profile pins host, binary, public key, node/device, original
request/frame/pending hash, scope, ledger, and expected interface state.

The only implemented state checker is a fixed Cisco `show interfaces <interface>`
read with exact description and administrative-state expectations. Unsupported
operations, absent/unverified observations, missing chain records and partial
recovery failures stay pending; there is no generic retry or arbitrary command.
The helper takes the endpoint's scope lock and verifies the original observation
signature, exact chain artifact, pinned Ed25519 entry signature and native chain.
Historical UNKNOWN verification deliberately permits its original timestamp;
reconciliation is a freshly bound v3 exchange with normal freshness checks.

After a matching observation is stored and verified, root submits an
`evidence_item` body tagged `cage_recovery/1`. Its chain signature commits to the
UNKNOWN and reconciliation hashes/entry references, pending/request hashes,
observed state and explicit `original_outcome: UNKNOWN`. It attests to verified
**current state**, not certainty about the original operation. The daemon does
not reinterpret this helper attestation as a native execution outcome. No new
chain format or observation subtype is introduced. Existing offline0.1.3 verifies
cryptographic integrity; application-level recovery semantics are separately
checked by this helper and qualification tests.

Only the trusted root identity receives `evidence_item` append permission. Cage
requesters remain observation-only and cannot invoke recovery, mint approvals,
or supply expected-state/profile arguments. The CLI itself refuses non-root.

The original `pending.json` is renamed into an exclusive reconciliation journal
only after authenticating the stored recovery record. Its bytes, original
frame/intent, and UNKNOWN chain entries remain intact. STOP and lease are never
changed by this command. Resuming service requires a separately authorized
lease/STOP transition; approvals remain consumed. Crash or lost append reply
leaves pending/journal for inspection, with no automatic second reconciliation
read or duplicate append. Do not delete the journal to retry.

`helper.public_error` exposes the fixed pending/duplicate reasons without
leaking arbitrary exception details. Deployed endpoints must call it explicitly;
upgrading the library alone does not update an old endpoint's error envelope.
