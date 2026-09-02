# Proposal — durable late-closer spool for outcome appends that fail after execution

Status: PROPOSED, deliberately NOT built on `fix/evidence-required`. Sep 1
review, Task 5 / 1.3.

## The gap this addresses

Evidence-required execution commits a `gate_intent` entry *before* the
driver runs and a closer (`gate_execution` / `outcome`) *after*. The intent
closes the "did the device act with no record at all" window. It does not
close the window *between* the two chain appends, across the device I/O: the
intent commits, the device acts, and then the closer append fails (chain
went read-only, disk full, a crash before the second append). The execution
happened; its outcome is not on the chain.

Today (this branch) that window is made **honest but lossy**:

- the caller receives a signed ERROR observation citing
  `unchained-execution` and the open intent hash (never silence);
- the daemon latches **evidence-degraded** and refuses every further
  dispatch at the intent step until restart;
- the intent stays OPEN and both verifiers report it as an open execution.

What it is **not**: recovered. The outcome record is gone, the daemon is out
of service until an operator restarts it, and reconciliation is manual
against the target. That is the correct fail-safe, but it is a denial of
service on the first storage hiccup.

## Proposal

A durable **late-closer spool** so a closer that cannot reach the chain in
its normal window is retried, and lands later as a marked late entry rather
than being lost.

### Spool

- A directory (e.g. `/var/lib/virp/late-closers/`), owner-only, on the same
  filesystem as the chain db so an ENOSPC that stops the chain also stops
  the spool (fail-closed, not a false sense of durability elsewhere).
- On a closer-append failure the daemon writes the fully-built closer body
  to the spool with `write-temp / fsync / rename` (the `consumed.list` and
  `seqstore` discipline), keyed by the intent's `chain_entry_hash`.
- Only after the spool write is durable does the daemon return success to
  the caller. If the spool write also fails, fall back to today's
  degraded-refuse behaviour — the spool is an optimisation over the
  fail-safe, never a replacement for it.

### Late-append marker

A closer drained from the spool carries two timestamps in its body so a
reader can never mistake it for an in-window closer:

- `completion_ns` — when the device actually returned (captured at
  execution time, spooled with the body);
- `appended_ns` — when this entry was finally committed;
- `late: true` and `spooled_reason` (the original append error).

The gap `appended_ns - completion_ns` is the exact interval the outcome was
only in the spool, not the chain — auditable, not hidden.

### Verifier treatment

- A late closer closes its intent exactly as an in-window closer does; the
  binding checks (device / command / uid / session / proposal /
  approval_entry_hash) are unchanged.
- `late: true` is surfaced in the report (a "late outcomes" section) and in
  the C/Python summaries as a distinct, non-failing count — the chain is
  intact, the *timeliness* is what was degraded.
- An intent that is open **and** has a matching spool entry the chain never
  received (spool lost) is reported as open, as today: a spool is not a
  chain and its contents are not evidence until committed.

### Drain

- A background drain (or a startup pass) commits spool entries oldest-first,
  under the same per-device serialization, before accepting new work on that
  device. The daemon leaves degraded state only when the spool is empty.

### What happens if the spool is lost

- Lost spool = lost closer = the intent stays OPEN forever. This is the same
  outcome as today, and the same reconciliation: the open intent names the
  device, command, tier, uid and (for an apply) the approval, which is
  enough to check the target out of band. The spool narrows the window in
  which this can happen; it does not eliminate it. No spool design can,
  because the spool is not the chain.

## Why it is deferred

- It changes the closer body schema (the two timestamps, `late`,
  `spooled_reason`) and adds a verifier surface (late-closer accounting) —
  both belong in their own review, not folded into the evidence-required
  landing.
- The degraded-refuse fail-safe on this branch is correct and shippable on
  its own; the spool is a availability improvement layered on top, and
  should be judged as such rather than rushed to avoid a restart.

## Open questions for that branch

- Whether the drain runs in the daemon or in a separate, least-privilege
  helper (the daemon already holds the chain key; a helper would need it).
- Whether a late closer past some bound (hours?) should refuse to commit and
  instead force manual reconciliation, so a very stale outcome cannot
  silently reappear.
- Interaction with `-S` detached chain signing: a late entry is signed at
  `appended_ns`, so its signature time and completion time differ by design;
  the marker makes that explicit.
