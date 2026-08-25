# Camera driver — three open items

Opened 2026-08-25. **Not implemented.** Each is scoped to the minimum that
makes a currently-invisible condition visible. Item 3 is the real one.

Branch `feat/camera-driver`, code commit `50444f0`. Filed from the source
answers in `CAMERA-OPEN-ITEMS-2026-08-25.md`; the underlying behaviour is
cited there with file:line.

---

## Item 1 — `submit-spool`: log the chain-keyed backstop as ACTIVE or DEGRADED at startup

**Size:** small. One line of output, one probe.

**Now.** The backstop works and is on by default: `--db` carries
`default=CHAIN_DB` (`virp_camera.py:1550`), the production submitter does
not pass the flag and still gets it, and uid `virp` can read
`/var/lib/virp/chain.db` — verified live against a real artifact hash.

**Problem.** `_on_chain` (`:1326-1343`) returns `False` on *any* failure:
missing file, permission denied, locked database, schema drift. The `--db`
help text acknowledges this — *"unreadable degrades to sidecar-only
dedup"* — and the failure direction is the safe one (a duplicate append,
never a dropped record). But **nothing reports the degradation.** If the
database moved, or its ownership changed, the backstop would stop working
and the only symptom would be duplicate appends nobody is watching for.

**Minimum.** In `submit_spool`, probe the db once at startup and emit one
line either way:

```
backstop: chain-keyed idempotency ACTIVE (/var/lib/virp/chain.db)
backstop: DEGRADED to sidecar-only (/var/lib/virp/chain.db: <reason>)
```

It goes to the submitter's journal, where an operator or a grep can find
it. No behaviour change, no new flag, no schema change.

**Done when:** a submitter start with an unreadable db prints DEGRADED
with the reason, and a normal start prints ACTIVE.

---

## Item 2 — `live`: catch the reconciliation refusal, with a distinct exit code

**Size:** small. Four lines plus an exit code, copied from an existing
handler.

**Now.** Fix C correctly refuses to start a capture over unshippable
residue (`_reconcile_workdir`, `:1142-1144`) — that refusal is right and
should stay. But it raises `SubmitError` from `run_live:1194`, and:

- `run_live`'s own `except SubmitError` (`:1268`) is inside the
  steady-state polling loop, reached only *after* reconciliation;
- `main()`'s `live` branch (`:1622-1657`) wraps `run_live` in **no
  try/except**, unlike the `replay` branch (`:1613-1620`), which prints a
  clean `SUBMIT REFUSED: … fix and re-run.` and returns 1.

So the refusal escapes as an uncaught exception: a raw Python traceback
on stderr and **exit code 1** — demonstrated. The same error class is
handled well on one path and not at all on the other.

**Minimum.**

1. Wrap the `live` branch the way `replay` already is, so the operator
   gets the refusal message rather than a traceback.
2. Return a **distinct exit code (3)** for "refused to start", so a
   wrapper or supervisor can tell *refused on residue* from *crashed*
   from *clean exit*. Exit 1 cannot express that difference.

**Explicitly not in scope:** changing the refusal itself. Refusing to
start a capture that would bury real footage is correct.

**Done when:** a residue refusal prints `SUBMIT REFUSED: …` with no
traceback and exits 3; a genuine crash still exits 1.

---

## Item 3 — 313: alert when a capture host goes quiet *(the real one)*

**Size:** small-to-medium, and the only one that catches the failure
nobody is watching for.

**Now.** Items 1 and 2 both improve what the capture host *says*. Neither
helps when nobody is looking at the capture host — which is the actual
operating condition. Live capture is a **manual command on the laptop**
(runbook step 3); there is no systemd unit for it on the capture host —
verified, neither system nor user scope, no unit files. So there is no
journal, no `Restart=`, no supervisor, and no retry.

The consequence: **a capture that refused to start, a capture that
crashed, a laptop that slept, and a camera that is simply quiet are
indistinguishable from 313.** The submitter keeps running and receives
nothing. An evidence pipeline going silent is exactly the condition the
pipeline exists to make impossible, and right now silence is its
least-visible failure mode.

This is the same fail-closed-and-silent tension as the
`Restart=on-failure` finding from the 313 burn-in: the system does the
safe thing and then tells nobody.

**Minimum.** A staleness check on 313, where the chain already knows the
answer. For each camera id expected to be capturing, look at the newest
`camera:<id>:<date>` entry; if nothing has landed within N minutes during
an expected capture window, alert. Roughly:

- config: `camera_id`, expected segment cadence, tolerance (a few
  multiples of `segment_time`), and the window during which capture is
  expected;
- a periodic read-only query against `chain.db` (the same read-only
  access `audit` and `docket view --db` already use — no daemon change,
  no new privilege);
- one alert on transition to stale, one on recovery. Not a per-tick page.

**Why this one matters most:** it is the only one of the three that does
not depend on the capture host being observed, and it is the check that
would have caught the original 2026-08-24 incident, where footage stopped
landing and the gap was discovered afterwards from the chain rather than
at the time.

**Deliberately not decided here:** where the alert goes, and whether the
expected-capture-window config lives beside the submitter unit or in the
device registry. Both need a decision rather than a default.

**Done when:** stopping a capture host mid-session produces an alert
within the configured tolerance, and restarting it clears the alert.

---

## Not filed, needs a decision first

`kill -9` on the driver **orphans its ffmpeg child**, which keeps writing
segments into the workdir (observed live, 2026-08-25: residue grew from 3
to 14 files while the driver was already dead). Fix C reconciles the
residue correctly and Fix F's lock protects the data dir, so this caused
no loss — but the lock binds the driver, not a stray ffmpeg, and an
immediate restart puts a second ffmpeg on the same filenames as the
orphan. The fix is a choice (kill the process group on startup vs. leave
it to reconciliation), so it wants a decision rather than a small
addition.

---

## Item 4 — `live`: kill the orphaned process group at startup, before reconciliation

**Size:** small. One kill, before an existing call, plus logging.

**Decision (2026-08-25):** process-group kill at startup, placed **before
reconciliation**. Rationale: `_reconcile_workdir` assumes the files it
inspects are **at rest** — it hashes them, tests them for a moov box,
attests them and removes them. An orphaned ffmpeg still writing into that
workdir violates the assumption directly. A file can grow between the
hash and the attestation, or gain its moov after being classified a
partial. Reconciliation cannot be made safe against a live writer, so the
writer must be gone before it runs.

**Now.** Observed live, 2026-08-25 (this is not hypothetical): SIGKILL on
the driver left its ffmpeg child running, and it kept writing segments —
residue grew from 3 files to 14 while the driver was already dead. Fix F's
instance lock binds the *driver*, not a stray encoder, so a prompt restart
puts a second ffmpeg on the same filenames the orphan is still writing.

**Placement.** In `_run_live_locked` (`virp_camera.py:1186`), the current
order is:

```
makedirs → checkpoint_load → _resume_state
  → _reconcile_workdir(...)        # :1192
  → pending_gap                    # :1195-1199
  → _spawn_ffmpeg(cfg)             # :1202
```

The kill goes **between `_resume_state` and `_reconcile_workdir`** — i.e.
after the instance lock is already held (so no other driver races it) and
before anything reads the workdir.

**Minimum.**

1. Identify encoder processes whose open files live in this run's
   `workdir` — the workdir is the ownership test, so a second capture
   against a *different* data dir is never touched.
2. Kill that process group and wait for exit; if anything survives the
   wait, refuse to start rather than reconcile against a live writer
   (consistent with Fix C's existing refusal discipline).
3. **Log every process killed with its pid and the filenames it held**,
   one line each, e.g.

```
live: killed orphaned encoder pid 2947226 (pgid 2947214) holding seg_000014.mp4, seg_000015.mp4, seg_000016.mp4
```

That line is the record of why the residue set is what it is, and it is
what makes the subsequent reconcile log readable after the fact.

**Done when:** starting `live` with an orphaned ffmpeg present kills it,
logs it with pid and held filenames, and only then reconciles; and an
encoder writing into a different data dir is left alone.

---

## Item 5 — fixture test: a pure `capture-discontinuity` on the **live** path, no restart

**Size:** small. One fixture test, no product change.

**Why.** The 2026-08-25 synthetic run produced four discontinuities and
**all four were `driver-restart`**. `continuity_gap` (`:486-498`) gives an
outstanding restart gap unconditional precedence:

```python
if pending_gap:
    return pending_gap
if state is not None and (start_ns - state["last_end_ns"]
                          > CAPTURE_GAP_TOLERANCE_NS):     # 2 s
    return {"reason": "capture-discontinuity", ...}
```

so the second branch is unreachable in any run that gapped because of a
restart. A stall *within a single run* is the only way to reach it, and
that path has never been exercised end to end on the live side.

**Existing coverage — do not redo it.** `tests/test_camera_restart_integrity.py`
already has:

- `test_69s_hole_produces_continuity_gap` (:486) — the seg-77 hole at the
  attestation level, asserting `capture-discontinuity`;
- `test_restart_gap_takes_precedence` (:510) — the precedence rule itself;
- `test_replay_path_flags_capture_hole` (:521) — end to end, but through
  **`run_replay`**.

**The actual hole:** no test drives **`run_live` / `_run_live_locked`**
through a mid-run stall with no restart and asserts the emitted body
carries `{"reason": "capture-discontinuity", "after_seq": N}`. That is
where the precedence rule lives, and it is the branch a real camera stall
(RTSP drop, encoder hiccup, network stall) would take while the driver
keeps running.

**Minimum.** `_run_live_locked` already accepts injectable `_spawn` and
`_clock`, so no hardware and no ffmpeg are needed: a fake spawn drops
prepared segment files whose mtimes leave a hole > `CAPTURE_GAP_TOLERANCE_NS`
between two segments **within one run**, and the test asserts:

- the segment after the stall carries `reason: "capture-discontinuity"`
  with the correct `after_seq`;
- `pending_gap` is `None` at that point — i.e. the gap is genuinely not a
  restart artifact;
- segments either side of the stall carry `gap: null`;
- `segment_seq` stays contiguous across the stall (a stall is not a drop).

**Done when:** the live path produces a `capture-discontinuity` body in a
fixture with no restart anywhere in the run, and the test fails if the
reason comes back `driver-restart` or `null`.
