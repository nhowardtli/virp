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
