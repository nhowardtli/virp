# Camera driver — three open items, answered from source

Answered against the **committed tip**, `feat/camera-driver` on 313.
Branch tip `4ee5950`; the deployed code is `50444f0` (the tip commit adds
only `SESSION-SUMMARY-CAMERA-RESTART.md`). Deployed file
`/var/lib/virp/camera/virp_camera.py` sha256
`6b9998cc3921e76d6a92189831dc9cd12640ce801042d2ab3e2d5888eacbaba0`,
byte-identical to the repo file at both commits — verified before any
other work. All access to 313 for this document was read-only.

---

## 1. Is the spool-side chain-keyed idempotency backstop on by default?

**It is on by default. It is a real backstop, not a flag.** But it
degrades to off *silently*, which is worth its own line below.

Evidence, in source:

- `camera/virp_camera.py:1550` —
  `sp.add_argument("--db", default=CHAIN_DB, …)`, and
  `CHAIN_DB = "/var/lib/virp/chain.db"` (line 79). The flag has a
  default, so omitting it still yields a path.
- `:1669` — `cfg["db"] = args.db` unconditionally.
- `:1395-1400` — `submit_one` calls
  `_on_chain(cfg.get("db"), body_sha)` before appending, and on a hit
  reconstructs the sidecar and skips.

Confirmed in production rather than inferred. The live submitter does
**not** pass `--db`:

```
virp 343826 /usr/bin/python3 /var/lib/virp/camera/virp_camera.py submit-spool \
  --data-dir /var/lib/virp/camera --sock /run/virp/onode.sock \
  --incoming /var/spool/virp-capture/incoming --done /var/spool/virp-capture/done --interval 1
```

…and it still gets the backstop, because the default supplies the path
and uid `virp` (999) can read the database
(`/var/lib/virp/chain.db`, `virp:virp 0644`). Executed as uid `virp`
against the deployed module:

```
sample artifact_hash: c185e5fc3c3a2508389ab4d479bb3ada44140146a06568f4aae0e641461b6941
CHAIN_DB default   : /var/lib/virp/chain.db
_on_chain(real hash): True
_on_chain(bogus)    : False
_on_chain(no db)    : False
```

### The caveat that matters

`_on_chain` (`:1326-1343`) returns `False` on **any** failure — missing
file, permission denied, locked database, schema change — and its own
docstring accepts this: *"ANY failure … returns False — the worst case is
then the pre-existing behavior, a duplicate append, never a dropped
record."* The `--db` help text says the same: *"unreadable degrades to
sidecar-only dedup."*

That direction of failure is the right one (a duplicate is recoverable, a
drop is not). But **nothing reports the degradation.** If the database
were moved, its ownership changed, or SQLite's WAL made it unreadable to
uid 999, the backstop would stop working and the only symptom would be
duplicate appends that no one is watching for. This is the same
fail-quietly shape as item 3 below.

**Minimum to close it (not implemented):** have `submit_spool` probe the
db once at startup and log one line either way —
`backstop: chain-keyed idempotency ACTIVE (<db>)` or
`backstop: DEGRADED to sidecar-only (<db>: <reason>)`. One line, at
start, in the journal. It costs nothing and turns an invisible
degradation into a greppable fact.

---

## 2. Era note — the capture window (Fix E)

### A correction to the premise, first

**`duration_s` did not change meaning in Fix E.** It has been the
moov/mvhd value of the attested bytes since live capture was introduced.
Traced across every camera commit:

| Commit | `duration` in `process_live_segment` | `end_ns` |
|---|---|---|
| `2d2b79a` | (no live path yet) | — |
| `4c7ee90` | `mp4_duration_s(path)` | `time.time_ns()` |
| `eff9bb3` | `mp4_duration_s(path)` | `time.time_ns()` |
| `c3ac51f` | `mp4_duration_s(path)` | `time.time_ns()` |
| `63cbacc` | `mp4_duration_s(path)` | `time.time_ns()` |
| `3cc6faf` | `mp4_duration_s(path)` | `time.time_ns()` |
| **`7e2365c` (Fix E)** | `mp4_duration_s(path)` — unchanged | **`st.st_mtime_ns`** |
| `50444f0` | `mp4_duration_s(path)` | `st.st_mtime_ns` |

What Fix E changed is **`capture_end_utc_ns`**, and therefore
`capture_start_utc_ns` (which is `end − duration` in both eras). The
window's *width* was always honest; its *position on the timeline* was
not. The era note below is written accordingly — it would be wrong to
publish a note saying `duration_s` changed.

### Draft note, in the form of the two ISSUE-A body-semantics notes

> ### Era boundary — camera capture-window semantics (2026-08-25)
>
> **Applies to:** every `camera_segment/1` body produced by the live
> capture path before commit `7e2365c`, i.e. all live segments from
> `4c7ee90` (2026-08-24) onward. Replay-produced bodies are unaffected:
> they read `capture_end` from file mtime in both eras and carry
> `time_source: "file-mtime"`.
>
> **What changed.** `capture_end_utc_ns` was `time.time_ns()` — the host
> clock sampled *when the driver processed the segment*, not when the
> device captured it. `capture_start_utc_ns` is derived as
> `capture_end − duration_s`, so the whole window moved with it.
>
> **What this means for bodies written before the boundary:**
>
> - `capture_end_utc_ns` records **when the driver got to the segment**,
>   which equals the capture moment only when processing was prompt. It
>   MUST NOT be read as the instant the footage was recorded.
> - Any delayed processing — a restart draining a backlog, a slow ship,
>   a re-offer of an already-captured segment — moved the window forward.
>   Where that happened, **old footage is stamped with a recent
>   timestamp**. The 2026-08-24 session contains this: the replayed
>   segments 65–76 carry a burst-shaped re-stamp, and the re-stamped
>   clones occupy the wall-clock window of footage that was separately
>   dropped, so the record is doubly misleading in that span.
> - `duration_s` is **not** affected and never was: it is the moov/mvhd
>   duration of the attested bytes in both eras, and any verifier can
>   recompute it from the artifact. The *length* of every window is
>   trustworthy across the boundary; only its *position* is not.
> - `time_source: "host-clock"` is accurate in both eras but means
>   different things: before the boundary, the host clock at processing;
>   after, the host clock as sampled by the kernel when ffmpeg finalized
>   the segment.
>
> **After the boundary:** the capture window is a pure function of the
> segment. `capture_end` is the file's finalize mtime, `duration_s` is
> the moov of the attested bytes, `start = end − duration`. Both are
> fixed at capture and immutable across re-offers and late submission, so
> a re-offered segment rebuilds byte-identical signed bytes. Submission
> delay is recoverable without any schema addition: it is the chain
> entry's append timestamp minus `capture_end_utc_ns`.
>
> **No existing chain entry was altered, rewritten, or back-signed.** The
> damaged 2026-08-24 session remains exactly as signed. This note changes
> only how it must be read.
>
> **Detectability.** As with the two VIRP body-semantics boundaries, a
> bundle verifier cannot detect this: the bytes are unaltered and the
> signature over them is valid. The defect was in the *truth* of a
> timestamp at composition time. This is the fourth instance of that same
> boundary — after Item 5 (length accounting), the camera re-emit
> (segment windows), and ISSUE-A (prompt and identity) — and it has the
> same shape as all three: **the body was intact; the metadata asserted
> about it was false.**

---

## 3. Fix C refuses startup on unshippable residue — how does an operator learn?

**Current behaviour: they learn only if a human is watching the terminal
at that moment. Nothing else records it, and nothing alerts.**

### Traced path

1. `_reconcile_workdir` (`:1090`) raises `SubmitError` when staged
   residue cannot be re-shipped (`:1142-1144`):
   `"…re-ship of staged pair %s failed (unshipped residue; refusing to
   start capture over it)"`.
2. It is called from `run_live` at `:1194` — **before** the capture loop.
3. `run_live`'s own `except SubmitError` (`:1268`) is inside the
   steady-state polling loop, which is reached only *after* line 1194.
   It does not cover reconciliation.
4. `main()`'s `live` branch (`:1622-1657`) calls
   `run_live(cfg, ship, stop_after_s=stop_after)` with **no try/except**.
   Contrast the `replay` branch (`:1613-1620`), which *does* guard:
   ```python
   except SubmitError as e:
       print("SUBMIT REFUSED: %s" % e, file=sys.stderr)
       print("continuity state NOT advanced; fix and re-run.", file=sys.stderr)
       return 1
   ```
5. So the exception escapes `main()` and `sys.exit(main())` never runs.

### What that produces, demonstrated

Running the committed tip's `live` branch into an uncaught exception
(triggered here by a missing `producer.pub`, which takes the identical
unguarded path):

```
EXIT CODE: 1
...
  File ".../virp_camera_tip.py", line 1625, in main
    with open(pk_path, "rb") as f:
FileNotFoundError: [Errno 2] No such file or directory: '.../producer.pub'
```

- **Exit code:** 1 — Python's default for an uncaught exception. Not a
  distinct code, and indistinguishable from any other failure.
- **Output:** a raw traceback on stderr, with the refusal message as the
  last line. The operator does not get the clean
  `SUBMIT REFUSED: … fix and re-run.` that the replay path gives.
- **Destination:** the stderr of whatever launched it. Per the runbook,
  live capture is a **manual command on the laptop** (step 3). Verified:
  there is no systemd unit for camera capture on the capture host —
  neither system nor user scope, no unit files. So there is no journal,
  no `Restart=`, no supervisor.
- **Alerting:** none. Nothing on 313 notices either. The submitter keeps
  running and simply receives nothing; an absence of new segments is not
  distinguishable from a camera that is quiet.

### Why this is the Restart=on-failure tension again

The refusal itself is correct and I would not change it — refusing to
start a capture that would bury real footage is the right call, and it
matches the fail-closed discipline everywhere else. The problem is the
same one found during the 313 burn-in: **the system fails closed, and
then says so only into a void.** A capture that refuses to start and a
capture that was never started look identical from every vantage point
except a terminal nobody is reading. Worse here than in the burn-in case,
because the failure mode is *silence in an evidence pipeline*, which is
exactly the condition the pipeline exists to make impossible.

### Minimum that makes it noticeable (proposed, not implemented)

In order of cost, smallest first. The first two together are the real
minimum:

1. **Wrap the `live` branch the way `replay` already is.** Four lines,
   copied from `:1613-1620`, giving a clean `SUBMIT REFUSED:` message and
   a deliberate `return 1` instead of a traceback. This is a strict
   improvement with no design question attached, and it removes the
   inconsistency where the same error class is handled well on one path
   and not at all on the other.
2. **Use a distinct exit code for "refused to start", e.g. 3.** A
   supervisor or wrapper can then tell "refused on residue" from "crashed"
   and from "clean exit", which exit 1 cannot express.
3. **Write the refusal where something durable can see it** — the
   simplest being a one-line marker file in the data-dir
   (`refused.json`: timestamp, reason, residue filenames) that the *next*
   successful start clears. It survives the terminal closing and gives
   the operator something to find after the fact.
4. **Make the absence itself detectable on 313**, which is the only
   change that catches the case where nobody looks at the laptop at all:
   a staleness check on the newest `camera:<id>:<date>` entry — if no
   segment has landed in N minutes during an expected capture window,
   that is an alert. This is the one that would have caught the original
   incident, and it is the only one that does not depend on the capture
   host being observed.

I would land 1 and 2 together as the minimum, and file 4 as the real fix.
