# Phase 1 — Source Survey: camera driver restart integrity

Branch `feat/camera-driver`, HEAD `4c7ee90` (2026-08-24 23:14:17 +0000).
All references are to `camera/virp_camera.py` unless stated. No edits were made.
Where the chain record is cited, it was read from `/var/lib/virp/chain.db`
(world-readable, opened `mode=ro`) on 2026-08-25.

A timeline fact that reframes several answers: **commit `4c7ee90` (Phase 2 live
capture) was made at 23:14:17 UTC — after runs B through E/F had already
happened** (run B starts 22:49:33, run E/F ends 23:08:24, all UTC, from body
`capture_end_utc_ns`). Only the final run (segs 65 onward, starting 23:30:49)
can have run the committed code. Runs B–E ran uncommitted work-in-progress from
the capture host (Nate's laptop — not this machine, not recoverable from git).
Everything below describes the committed tree; where the record disagrees with
what the committed code would produce, that is called out.

---

## 1. Spool: location, layout, submitted-marker, fsync, ordering

There are two hosts and two different "submitted" notions.

**O-node spool** (this host, 313). Provisioned by `deploy/camera-spool-access.sh`:
chroot `/var/spool/virp-capture` (root-owned, line 30), `incoming/` and `done/`
owned by `virp-capture` 0700 with ACLs granting uid `virp` rwx (lines 63–77).
Layout per job: `<name>.mp4`, `<name>.body`, `<name>.done`, where
`name = "%06d.%s" % (seq, seg_sha)` (line 816). The capture host uploads
`.part` files, renames, then uploads the `.done` marker last (`sftp_ship`,
lines 744–780), so the submitter only sees complete jobs.

- What marks a job as chain-submitted: **two things, both after the append is
  acknowledged** — the sidecar `<data_dir>/artifacts/<body_sha256>.json`
  written at lines 1016–1027, and the move of all three job files into `done/`
  at lines 1063–1068. Ordering is correct (append ack at line 1010 precedes
  both).
- **Neither is fsynced.** `grep -rn fsync camera/ deploy/` returns nothing.
  The sidecar is a plain `open(...,"w")`/`json.dump` with no flush/fsync and
  no directory fsync; the `done/` move is `os.replace` with no directory
  fsync. A crash between chain-append ack and sidecar write re-offers the job,
  and `submit_one`'s idempotency check (line 997) is **sidecar-file-based, not
  chain-based** — a lost sidecar means a duplicate `chain_append`.

**Capture host.** The per-segment "handled" marker is `state.json`
(`state_save`, lines 298–303: tmp + `os.replace`, **no fsync**, no dir fsync)
plus a `<name>.handoff.json` in the outbox (lines 832–843, no fsync). Both are
written **after the sftp ship is acknowledged (lines 826–828), not after the
chain append** — the capture host considers a segment done the moment it lands
in the spool. It never learns whether the chain accepted it.

Crucially, **no marker of any kind is written against the workdir segment file
itself** — see Q4.

## 2. Where `segment_seq` and the resume point persist

`segment_seq` persists only in `state.json` (`{"segment_seq", "last_segment_sha256",
"last_session_id", "last_end_ns"}`, lines 405–411 / 845–851), loaded at startup
(line 880). The resume point *for numbering and prev-hash* is the same store, so
those two cannot disagree with each other.

But the resume point *for which files still need submitting* **does not exist
on disk at all**. It is the in-memory set `processed` (line 894), which dies
with the process. So yes — the two views disagree across every restart:
`state.json` says "seq 13 done," while every `seg_*.mp4` still sitting in the
workdir looks unsubmitted to the next run. That disagreement is defect 1.

## 3. Graceful shutdown path (hypothesis §1.3 of the session prompt)

Trace of `run_live` (lines 871–946): SIGINT/SIGTERM only set a flag (lines
889–892). The loop then calls `proc.terminate()` (line 920) — ffmpeg finalizes
the in-progress segment with a moov (hence the truncated 1.067 s / 0.6 s final
segments in the record) — and `continue`s (line 925). On the next iteration
`ffmpeg_done` is true, `_closed_segments` returns **all** names (line 867), the
just-finalized final segment is processed and shipped like any other, and the
loop breaks (line 918). Nothing cleans or marks the workdir; the function
returns with every segment file of the run still on disk.

**The prompt's hypothesis is refuted in its mechanism and confirmed in its
effect.** The shutdown handler does not "walk the working set and treat the
finalized segment as handled" — it correctly submits the finalized segment and
treats *nothing* as durably handled. The replay is caused by the **startup**
path (Q4) re-listing the surviving workdir with a fresh, empty `processed`
set. The "minus the last one" signature falls out of line 868: at the next
start the previous run's highest-numbered file is excluded as "the open,
growing segment" while ffmpeg runs, and by the time it would become eligible,
the new ffmpeg (which restarts numbering at `seg_000000.mp4` and overwrites)
has destroyed it.

The graceful/hard-kill asymmetry in the record (B and F replayed; D and E did
not) is **not explained by the committed code**, which would replay after any
restart that finds a populated workdir. Runs B–E predate the commit; the one
restart that demonstrably ran the committed code (segs 65–76, 23:30:49) *did*
replay, in exactly the shape the committed code predicts (see Q5). Whether the
non-replaying restarts ran different WIP code or the operator cleaned the
workdir between runs is not determinable from this host.

**Operator determination (2026-08-25, Phase 2 scoping):** the graceful-versus-
hard-kill asymmetry was an artifact of uncommitted WIP on the capture host,
not a property of the committed shutdown paths. The committed shutdown handler
is correct and was left unchanged; the fix is startup workdir reconciliation
(Fix C), and the tests assert the SAME invariants — zero duplicate
`segment_sha256`, zero dropped segments — for graceful stop and hard kill
alike, rather than asserting the two endings behave differently.

Supporting evidence that the gap-in-coverage is known to the tests: the
existing restart test `tests/test_camera_phase2.py:144–147` **manually deletes
the first run's segments** ("second run: a fresh work dir") before restarting —
the test fixture performs by hand the cleanup the driver never does, which is
why the suite passes.

## 4. Startup path

`run_live` startup (lines 878–886): loads `state.json` (numbering + prev-hash
+ pending restart-gap) and nothing else. The rule for "still needs submitting"
is: **every `seg_*.mp4` in the workdir except the highest-sorted one while
ffmpeg runs (`_closed_segments`, lines 859–868), minus names already in this
process's in-memory `processed` set (line 901)**. No durable doneness check of
any kind — not against `state.json`, not against the outbox handoffs (which
exist and would suffice), not against sidecars.

Contrast: the replay path `run_replay` *does* check durable doneness — sidecar
`artifacts/<seg_sha>.json` existence (lines 445–449). (Note that check is
keyed on content hash alone, so it would also wrongly skip a legitimate
re-capture of identical bytes; the spool-side `submit_one` gets this right by
keying on `body_sha256`, lines 989–1000.)

A second, worse consequence of the name-keyed in-memory set, confirmed in the
record: after the startup drain marks stale names `seg_000000..N` as processed,
the new ffmpeg reuses those same names for **new** footage, which is then
**silently skipped** (line 901–902). The record proves ~72 s of real captured
footage was dropped this way at 23:30:52–23:32:04: 12 stale names drained as
clones 65–76, then 12 new files under those names skipped, with file 000012
surfacing as seg 77 — which is precisely the 69.1 s `gap: null` hole (69.12 s
observed vs ~71.6 s of skipped capture minus drain overlap; seg 77's
`capture_start` 1787614325523357095). The same arithmetic fits run C
(~36 s dropped, papered over by the re-stamped clones 14–19 occupying the same
wall-clock window, which is why segs 19→20 show a clean 0.057 s seam).

## 5. Capture-time assignment sites

Two sites can assign a capture window, and both stamp **at processing time,
unconditionally** — any re-offered file is re-stamped:

1. `process_segment` lines 361–371 (Phase-1/replay path): `mode == "replay"` →
   `end_ns = st_mtime_ns`, `time_source = "file-mtime"`; else → `time.time_ns()`,
   `"host-clock"`. The else branch is unreachable from the CLI today
   (`run_replay`'s cfg hardcodes `mode: "replay"`, line 1180), but the branch
   exists. The mtime hazard is real and already visible in the record: run A's
   seven replay bodies all carry `capture_end` 22:17:04.949–.950 — the rsync/copy
   time of the files onto 313, not capture time.
2. `process_live_segment` lines 794–796: `end_ns = time.time_ns()`,
   `start_ns = end_ns - duration`, hardcoded `"host-clock"`/`"live"` (line 803).
   This is the re-stamp site for replayed clones in the committed code.

On the prompt's "two shapes means two code paths — find both": **the committed
tree contains only one live-path stamp site (line 794)**, and it reproduces
replay shape 2 (run G) exactly — the drain re-stamps each clone as it is
processed, and the observed 65→76 stamps are 0.55 s apart (pure
hash+ship pacing), with `capture_start` back-computed to overlapping 6 s
windows. Shape 1 (run C: constant +202.2 s offset, original ~6 s spacing
preserved — verified: clone intervals 6.230/6.071/6.076/5.581/6.057 s vs
originals 6.239/6.054/6.056/5.541 s) **cannot be produced by the committed
code**, whose drain would burst-stamp. Run C predates the commit by ~21
minutes; its stamping shape came from a WIP variant that no longer exists in
the tree. The fix (never re-stamp) removes the mechanism in either case.

## 6. Gap record construction and trigger

Built in exactly two places, both with `reason: "driver-restart"`, both
triggered **only by the existence of prior `state.json` at startup**:
`run_replay` lines 437–439 and `run_live` lines 881–884. The pending gap is
attached to the first *successful* record of the run and cleared (lines 905,
915). No code anywhere compares `capture_start` against the predecessor's
`capture_end`.

Record confirmation: the session's only gap records sit at segs 7, 14, 28, 52,
65 (all `driver-restart`), and at seg 65 the gap record rides a *duplicate*
(the first clone). The 69.1 s hole at 76→77 carries `gap: null` because no
restart happened there — segs 65–355 are one driver run.

## 7. Existing lock / PID file / single-instance guard

None. `grep -ni 'lock\|pid\|flock\|singleton' camera/virp_camera.py` matches
nothing relevant (only "clock" substrings). Nothing in the deploy script
either. Two live drivers pointed at the same camera/spool, or two
submit-spools at the same incoming/, would interleave freely.

## 8. How `mode` is set

From invocation, never inferred: the `replay` subcommand hardcodes
`"mode": "replay"` (line 1180); the `live` subcommand hardcodes
`"mode": "live"` (line 1213); `process_live_segment` additionally hardcodes
`"live"` into the body (line 803). This is why re-emitted old media in a live
run is labeled `mode: live` — the label describes the invocation, not the
provenance of the bytes.

## Key custody check

Confirmed: the driver holds **no VIRP key material**. The only key it touches
is its own producer Ed25519 keypair (`producer.key`/`producer.pub` under
`--data-dir`, lines 1170–1171, 1194–1195); `producer_load_sk` is the only
private-key read. The `submit-spool` cfg (lines 1231–1237) carries no key at
all — it relays already-signed bytes verbatim; chain entries are D-1-signed by
the daemon with its own key. The deploy script actively verifies `virp-capture`
cannot read any daemon key (lines 53–60).

---

## Record findings that revise the session prompt (§1 "ground truth")

Verified mechanically against `/var/lib/virp/chain.db`:

1. **The session now holds 356 entries (segs 0–355), not 254**, plus a
   7-entry continuation session `camera:tapo-c100:2026-08-25` (segs 356–362,
   capture ran across the UTC midnight rollover, ending 00:00:37; the
   cross-day prev-hash link is intact and gap-less as designed). The reviewer
   saw a snapshot; capture continued afterward.
2. **There were 6 driver runs, not 8.** Gap records exist only at segs 7, 14,
   28, 52, 65. There is **no gap at seg 20 and none at seg 77** — the prompt's
   runs C/D are one driver run (14–27: clone drain then live capture), and G/H
   are one driver run (65–355: clone drain, ~72 s of silently dropped new
   capture, then live from 77).
3. **The run-F→G replay is 12 pairs, not 3**: 52–63 → 65–76, every pair
   byte-identical (`segment_sha256` and `byte_len` equal; spot pairs from the
   prompt all confirmed, e.g. 7/14 `fb76bea0…`, 12/19 `d18a7e61…`, 52/65
   `e1b67dea…`). The full duplicate set of the session is exactly
   {7–12→14–19} ∪ {52–63→65–76}; nothing else repeats.
4. **The ingest inversion is confirmed and sharper**: segs 20–27 appended
   22:53:32–22:54:14 (each within ~1.5 s of its capture end — submit-spool was
   live and healthy), while segs 14–19 appended 23:03:30–33 in a single ~3 s
   drain pass. Since submit-spool processes markers in sorted order and would
   have appended 000014… before 000020…, the six clone jobs (or at least
   their `.done` markers) **did not reach `incoming/` until ~23:03:30** —
   ten minutes after their bodies were stamped and after the driver had
   stopped. What un-stuck them at 23:03:30 (45 s before run D began) is not
   determinable from this host.
5. **seg 20's `prev_segment_sha256` ambiguity confirmed**: `d18a7e61…` is the
   hash of both seg 12 and its clone seg 19. Walked by `segment_seq` the chain
   is linear. Not touched, per scope.
6. A `submit-spool` process is currently running on this host as uid `virp`
   (`/var/lib/virp/camera/virp_camera.py`, started Aug 24) — note it runs a
   **deployed copy** of the driver, not the repo file, and the copy is not
   readable by this uid (0700 `virp` dir). Relevant to Phase 4 planning: any
   fixed submit-spool behavior needs that deployment refreshed, and the
   acceptance run should use a distinct `--camera-id` so its session id is
   fresh rather than appending to `camera:tapo-c100:2026-08-25`, which
   already holds last night's tail.
7. **The capture host was the laptop; only run A ran on 313.**
   `~/camera-segments/seg_000..006.mp4` on 313 match run A's `byte_len`s
   exactly, and run A's bodies all carry the file-copy mtime (22:17:04.949) as
   their capture window — seven segments claiming the same instant. (Replay
   key/mode questions remain out of scope; recorded here only as evidence for
   the mtime re-stamp site.)

## Implications carried into Phase 2 (no redesign, just where each fix bites)

- Fix 1 (durable submit checkpoint) must live on **both** sides: capture-side
  a durable, fsynced per-segment record keyed on `(segment_seq, segment_sha256)`
  — the name-keyed in-memory `processed` set is the root cause of both the
  replay and the silent footage drop; spool-side the sidecar/done-move already
  order correctly but need fsync and a chain-backed idempotency check.
- Fix 2 (clean shutdown) is, per Q3, really "shutdown must leave the workdir
  in a state startup can trust" — converging graceful and hard-kill means the
  startup rule stops depending on how the last run ended.
- Fix 3 (never re-stamp): both sites in Q5; `duration_s` choice to be stated
  in Phase 2.
- Fix 5 (continuity gap): the 69.1 s hole (seg 76 `capture_end`
  1787614256399015562 → seg 77 `capture_start` 1787614325523357095) is the
  acceptance fixture; normal boundaries in this record jitter within ±0.5 s,
  which bounds the tolerance constant from below.
