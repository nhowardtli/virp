# Evidence-degraded mode and concurrency

**Status: memo. No code change accompanies this document.**
Written for VIRP-OVERNIGHT-WORK-ORDER-2 item 4. It states what the daemon
does today when the evidence-degraded latch is set while other requests are
already in flight, and lays out two ways to change that, with their cost.
There is deliberately no recommendation section: the choice is Nate's.

---

## 1. The mechanism as it stands

Three pieces, all in `src/virp_onode.c`:

- **The latch.** `onode_mark_evidence_degraded()` (`src/virp_onode.c:809`)
  takes `state_mutex`, sets `state->evidence_degraded = true`, releases it,
  and logs once on the first transition. It is a process-lifetime latch:
  `onode_init()` clears it (`src/virp_onode.c:5324`) and nothing else ever
  does. It is a no-op when `evidence_required` is false.

- **Who sets it.** Four call sites, all of them *after* the device has
  acted: the two real closer-append failures (`gate_emit_execution` at
  `src/virp_onode.c:1149`, `approval_emit_outcome` at
  `src/virp_onode.c:905`) and their two `-DVIRP_FAULT_INJECT` twins
  (`:991`, `:883`).

- **Who reads it.** Exactly one place: `gate_emit_intent()`
  (`src/virp_onode.c:1219-1228`) reads it under `state_mutex` and returns
  `VIRP_ERR_EVIDENCE_UNAVAILABLE` when set. The caller turns that into a
  signed ERROR observation citing `evidence-unavailable` and never reaches
  the driver.

The enforcement point is therefore the **pre-execution intent commit**, and
nothing else. That is the whole design: the latch stops the *next* dispatch
from starting, and says nothing about dispatches already past that point.

### Concurrency the daemon actually has

- Each accepted connection runs on its own detached worker thread, capped
  at `ONODE_MAX_WORKERS` = 32 (`include/virp_onode.h:65`).
- `batch_execute` fans out one thread per item, up to `ONODE_MAX_BATCH` = 16
  (`include/virp_onode.h:39`).
- `exec_mutex[dev_idx]` (`include/virp_onode.h:455`, 64 slots) serializes
  execution **per device**. Different devices never contend.
- `state_mutex` protects the latch itself and is held only for the read and
  the write — never across device I/O.

So the achievable concurrency is up to 32 in-flight executions, bounded by
distinct devices; two requests for the same device are already serialized.

## 2. What happens today, precisely

Take request A (device D1) and request B (device D2), both admitted, both
past their intent commit, both inside `drv->execute()`.

1. A's device acts. A's closer append fails. `onode_mark_evidence_degraded()`
   latches. A returns the signed `unchained-execution` ERROR observation and
   A's intent stays OPEN on the chain.
2. B is *not* interrupted, signalled, or cancelled. Nothing polls the latch
   between the intent commit and the closer. B finishes its device I/O,
   attempts its own closer append, and — because the latch is not a
   chain-write veto — that append is attempted normally.
   - If the chain has recovered by then, B's closer lands. B returns an
     ordinary success observation. The daemon is degraded; B's caller has no
     indication of that, and no reason to have one: B is fully recorded.
   - If the chain is still failing, B's closer fails too. B latches (a
     no-op, already set), B returns its own `unchained-execution` error, and
     a second intent is left OPEN.
3. Request C, which has not yet reached `gate_emit_intent`, is refused there
   with `evidence-unavailable`. Nothing reaches its device.

Two consequences worth stating plainly:

- **The count of actions that ran after the latch is not recorded anywhere.**
  Each unchained execution leaves an OPEN intent, so a verifier can count
  open intents from the chain — but only for the executions whose closer
  *failed*. An in-flight execution whose closer *succeeded* after the latch
  (case 2, first bullet) leaves an ordinary closed pair and is
  indistinguishable, in the chain, from one that ran before the latch. The
  operator reconciling against the target has no marker saying "these ran
  while the node was already known-degraded".
- **The latch itself is not on the chain.** It is process state and a stderr
  line. A bundle exported afterwards shows open intents, which is the
  evidence that matters, but never shows the moment the node decided to stop
  dispatching, nor how many actions were still in flight at that moment.

There is no correctness violation here: no action escapes an intent, and no
action is silently unrecorded — that is what item 1 and the Sep 1 1.3 work
established. What is missing is a *bound*: the operator cannot read, from
the evidence alone, how wide the reconciliation window was.

## 3. Option (a) — serialize intent → execute → outcome under one lock

**Shape.** Introduce a node-wide `evidence_lock` (or promote the existing
`virp_approval_consume_lock` to cover the whole span). Acquire it before the
`gate_emit_intent` call and release it after the closer append. Re-check the
degraded latch under that lock at the intent step. The window between the
latch being set and another action being in flight closes: the latch can
only be set while the lock is held, and no other execution can be inside the
intent → closer span at that time.

**Guarantee obtained.** At most one execution is ever in the
intent-to-closer span. Therefore: when the latch is set, the number of
in-flight actions is zero by construction, the open-intent count is the
complete count of unchained executions, and "degraded" means exactly "no
action ran after this point".

**Cost.** The lock is held across `get_connection()` and `drv->execute()` —
i.e. across SSH/REST I/O — so the node's whole execution throughput becomes
serial at fleet scale.

- Today: up to 32 concurrent workers (`ONODE_MAX_WORKERS`), bounded by
  distinct devices, since `exec_mutex` is per-device
  (`include/virp_onode.h:455`) and "different devices are independent" is an
  explicit invariant in that comment. A 43-device fleet poll runs 32-wide.
- Under (a): one execution at a time, fleet-wide. Ceiling is
  `1 / mean_execution_seconds` commands/second.
- Order of magnitude for the mean: a single SSH `show`-class command on this
  fleet is dominated by connect/prompt handling, not by the command. The
  recorded prompt-learn figures alone are ~7 s for the ASA driver and ~13 s
  for pa-850; a warm cached connection running one `show` is far cheaper but
  still hundreds of milliseconds of round-trip. So the serialized ceiling is
  roughly **0.3–3 commands/second for the entire node**, against a current
  ceiling of ~32× that.
- Concretely: a 43-device sweep that today finishes in about the time of its
  slowest device would instead take the **sum** of all 43 device times.
- Secondary cost: the lock is held across device I/O, so one hung device
  (the connect path is bounded, but bounded at seconds) stalls every other
  device's requests behind it, including GREEN reads. That is a new
  cross-device failure coupling that the per-device `exec_mutex` design
  explicitly avoids today. It also inverts the documented lock-ordering
  discipline in `include/virp_onode.h:446` ("conn_mutex and exec_mutex[*]
  must never be held at the same time"), which would need restating.
- The batch fan-out (`ONODE_MAX_BATCH` = 16 threads) becomes pointless: the
  16 threads would queue on the same lock. `ONODE_RECV_TIMEOUT_SEC` = 5
  means queued clients can time out on the socket read while waiting.

**Test shape.** Two devices, two concurrent executes, the first armed with
`evidence_fail_closer_once`; assert the second never reaches its driver
(`virp_driver_mock_exec_attempts`), and that exactly one intent is open.

## 4. Option (b) — let in-flight actions finish, count them, record the count

**Shape.** Keep the current concurrency. Add a counter of executions that
are past their intent commit and have not yet completed their closer:
increment under `state_mutex` immediately after a successful
`gate_emit_intent`, decrement after the closer attempt returns (success or
failure). When `onode_mark_evidence_degraded()` fires the first time, it
reads that counter — the number of actions in flight at the moment of the
latch, excluding the one that just failed — and writes a **new**
daemon-reserved chain entry recording the latch:

```
degraded_latch/1
  { "reason": "outcome record could not be chained",
    "device": "<the device whose closer failed>",
    "intent_entry_hash": "<the OPEN intent>",
    "in_flight_at_latch": <int>,
    "latched_ns": <int> }
```

This is a **new entry type**, so it adds nothing to and changes nothing in
the canonical bytes of `gate_intent`, `gate_execution`, `outcome` or any
other existing type; the D-0 fixtures and the D-1 golden vectors in
`tests/vectors/chain-signing-v1.json` are untouched by it.

Each in-flight action then completes as it does today: its closer either
lands (ordinary closed pair) or fails (its own `unchained-execution` error
and a second OPEN intent).

**Guarantee obtained.** Weaker than (a) and honest about it: actions may run
after the latch, but the chain now states *how many could have*, at the
moment the node knew it was degraded. An operator reconciling against the
target gets a bound — "at most N actions were in flight" — instead of an
unbounded question. Combined with the open intents already on the chain, the
reconciliation set is fully described.

**Cost.**
- Throughput: unchanged. The counter is two `state_mutex` acquisitions per
  execution, both outside device I/O, on a mutex already taken per execution
  for `observations_sent`.
- Correctness of the count: the counter must be decremented on **every**
  exit from the span, including the four early-return closer sites
  (`src/virp_onode.c:2509, 2556, 2686, 2762`) and the success site
  (`:2891`). A missed decrement makes the count monotonically wrong. A
  scope-guard-style helper, or a single accounting point, is what keeps this
  honest in C.
- The latch entry is itself a chain append, made at the exact moment the
  chain has just proven it cannot take a write. It will usually fail. That
  is not fatal — the latch is still set, and the failure is logged — but the
  entry must be best-effort by construction and the design must not claim
  the count is always durable. A late-append (the deferred spool in
  `docs/PROPOSAL-LATE-CLOSER-SPOOL.md`) is the only way to make it reliably
  land.
- `in_flight_at_latch` is a snapshot, not a set. It says how many, not
  which. Naming the intents would mean holding a list of in-flight intent
  hashes under `state_mutex` — a further increment in scope, and bounded at
  `ONODE_MAX_WORKERS`.

**Test shape.** Two devices; hold device 2 inside the mock driver on a
barrier; arm `evidence_fail_closer_once` on device 1; assert the latch entry
records `in_flight_at_latch == 1`, that device 2's execution still completes
and closes, and that the counter returns to zero.

## 5. What both options leave alone

- Neither changes what is hashed or signed for any existing entry type.
- Neither changes the meaning of an OPEN intent, or the C/Python
  open-execution grading.
- Neither provides *recovery*. Recovering a lost closer is the deferred
  late-closer spool (`docs/PROPOSAL-LATE-CLOSER-SPOOL.md`); the latch remains
  the fail-safe, cleared only by restart.
