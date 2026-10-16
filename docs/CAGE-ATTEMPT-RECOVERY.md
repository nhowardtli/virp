# Caged execute attempt recovery

`execute_observed` now reserves `<frame>.intent.json` durably before session binding or command dispatch. An existing frame or intent refuses the request before any transport operation. Intents survive successful completion and crashes; a caller must never generate a new ID merely to retry an ambiguous write.

Callers can pass a root-owned `recovery_dir`. The helper atomically creates `pending.json` before dispatch and removes it only after frame validation, durable storage, successful chain append and session close. An unresolved attempt blocks every subsequent operation using that scope. Caller lease locks, target and binary pins remain required. The scope must be stable across requests and restarts, not derived from model input.

Invalid received frames are retained as `.unverified.frame`, never accepted as observations. Chain-append failures preserve the original raw frame. Session-close failures preserve prior exceptions and leave the scope pending. There is no automatic retry or automatic reconciliation.

A successful apply observation does not replace a verification read. The coordinator must still compare fresh observed state with the approved postcondition and restore through its separately authorized path.

## Trusted reconciliation

Keep STOP and the scope marker in place. Inspect the durable intent, original raw frame, native intent/outcome/rejection records, consumed approval state and target state using a separate restricted recovery channel. Do not infer a safe retry from a timeout or missing local result. Capture signed recovery observations and operator disposition. Only then archive the marker, preserving its bytes and the reconciliation record, and create a genuinely new authorized operation if needed. A changed boot, expired lease or changed target requires fresh qualification.

The unit suite injects reply loss, storage failure, invalid frames, duplicate attempts and close failure. Live qualification results and deployment status belong in the audit report; this document alone does not assert deployment or recovery testing.
