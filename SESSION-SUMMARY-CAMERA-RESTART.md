# Session Summary — Camera Driver Restart Integrity

Branch `feat/camera-driver`, 2026-08-25. Base `4c7ee90`; this session ends at
`50444f0`. Nothing pushed. Companion document: `PHASE1-SOURCE-SURVEY.md`
(full source survey with file:line citations and the chain-record findings).

## What was found (and what differed from the session prompt)

The Phase 1 survey is the full account; the load-bearing points:

1. **The replay/skip machinery was one defect, not several.** `run_live`
   tracked handled segments in an in-memory set keyed by workdir *filename*.
   Nothing durable marked a segment as submitted, nothing cleaned the workdir,
   and ffmpeg renumbers from `seg_000000.mp4` on every restart. Startup
   re-listed the survivors (replay), and new footage written under
   just-drained names was silently skipped (drop).
2. **The silent drop was worse than the replay.** The 69.1 s `gap: null` hole
   before seg 77 is ~72 s of real captured footage that was dropped by
   name-collision; run C dropped ~36 s more, and its re-stamped clones
   occupied exactly the wall-clock window of the dropped footage.
3. **Prompt corrections, verified against the chain:** 6 driver runs, not 8
   (no gap record at segs 20 or 77 — "C/D" and "G/H" were each one run); the
   second replay was 12 clone pairs (52–63 → 65–76), not 3; the session had
   grown to 356 entries plus a healthy 7-entry `…:2026-08-25` continuation
   across UTC midnight.
4. **The graceful/hard-kill asymmetry was an artifact of uncommitted WIP.**
   Runs B–E predate commit `4c7ee90` (23:14:17Z); only the final run
   demonstrably ran committed code, and it replayed exactly as the committed
   code predicts (0.55 s burst re-stamp). The constant-offset re-stamp shape
   of run C exists in no committed code path. The committed shutdown handler
   is correct and was not changed. Confirmed on-host: the deployed submit
   side at `/var/lib/virp/camera/virp_camera.py` was byte-identical to
   `4c7ee90` (sha256 `b47b0f5f…`, preserved in the session scratchpad), so
   all WIP variance was capture-side, on the laptop.
5. The prompt's §1.3 hypothesis (shutdown handler walks the working set) was
   refuted in mechanism, confirmed in effect: the replay came from the
   *startup* path, not the shutdown path.

## What was changed — one commit per fix

| Commit | Fix |
|---|---|
| `d672f5a` | (prelim) `unittest.main()` sat mid-file in `test_camera_phase2.py`; `NoSilentDropTests` never ran as a script |
| `eff9bb3` | **A** — durable fsynced submit checkpoint (`shipped.jsonl`), keyed on `(segment_sha256, segment_seq)`, written after ship-ack and before the continuity cursor advances; checkpoint authoritative over stale `state.json`; `state_save` fsyncs; spool-side **chain-keyed** idempotency backstop (`--db`, artifact_hash lookup, sidecar reconstruction). Named open item, not designed: no ack path from O-node back to the capture host — the checkpoint marks ship-acked, not chain-acked; the backstop is what makes re-offers harmless. |
| `c3ac51f` | **B** — segment identity is content, not filename: (size, mtime) change signatures, closed = quiescent + parseable (never "highest name"), content dedup against the checkpoint, attested segments removed from the workdir; `mp4_duration_s` raises `ValueError` (not `struct.error`) on torn files |
| `63cbacc` | **C** — startup workdir reconciliation before ffmpeg spawns: attested residue removed; closed-unshipped residue attested *first* (seq order stays capture order; staged outbox pairs re-shipped byte-for-byte); partials removed with the loss logged; unshippable residue refuses startup; restart gap rides the first NEW segment, not residue |
| `3cc6faf` | **D** — `continuity_gap()` on every record: hole > `CAPTURE_GAP_TOLERANCE_NS` (2 s; > 4× the record's healthy jitter, well under one 6 s segment) ⇒ `reason: "capture-discontinuity"`; restart gap kept and takes precedence; reasons distinguishable |
| `7e2365c` | **E** — never re-stamp: capture window is a pure function of the segment (`capture_end` = finalize mtime — the host clock sampled at the honest moment, so `time_source` stays `host-clock`; `duration_s` = moov/mvhd of the attested bytes, chosen because any verifier can recompute it from the artifact; `start = end − duration`). Replay keeps `file-mtime` and loses its unreachable host-clock branch. Late submission keeps the original window exactly; the delay is already recorded as chain-append timestamp − capture_end (no schema addition). Bodies are now deterministic, so a re-offer rebuilds byte-identical signed bytes and the spool dedup is exact. |
| `50444f0` | **F** — flock-based single-instance lock: live+replay share `<data-dir>/instance.lock`, submit-spool locks `<incoming>/.submit-spool.lock`; second instance refused with holder pid; stale lock never blocks (flock dies with its holder) and its recovery is logged. Honest limits: the lock binds the local state it protects (data-dir / incoming); it cannot stop a second instance using a *different* data-dir against the same camera, nor span hosts. |

## Tests

`tests/test_camera_restart_integrity.py`, 23 tests, written red-first per fix
(failure states shown in the session transcript before each implementation).
Amended fixtures: the phase2 restart test no longer deletes the first run's
files by hand (the driver does), and "open segment" is modeled as a growing
moov-less file, not "the highest name". Per the Phase 3 amendment, graceful
stop and hard kill are asserted to the *same* invariants: zero duplicate
`segment_sha256`, zero dropped segments. The filename-reuse test
(`test_reused_name_old_bytes_skipped_new_footage_lands`) models the seg-77
defect directly. Exact record values used where available: the
69,124,341,533 ns hole, seg 12's window `…697990689`, run A's mtime stamp.

Final state: `test_camera_driver.py` 17/17, `test_camera_phase2.py` 10/10,
`test_camera_restart_integrity.py` 23/23 — all green.

## Deployment (Phase 4, executed portion)

- Old deployed copy preserved (scratchpad, sha256 `b47b0f5f…`) — byte-equal
  to `4c7ee90`.
- **Deployed commit: `50444f0`** — `/var/lib/virp/camera/virp_camera.py`
  sha256 `6b9998cc3921e76d6a92189831dc9cd12640ce801042d2ab3e2d5888eacbaba0`,
  identical to the repo file; root:root 0755 as before.
- `virp-camera-submitter.service` restarted 03:19:12Z, active; the old
  instance exited cleanly ("341 job(s) appended this run"). The new instance
  took `.submit-spool.lock` in `incoming/` on startup.
- **Fix F verified in production:** a second `submit-spool` run as `virp` was
  refused: "another instance (pid 343826) holds …/.submit-spool.lock".
- **Driver audit over the real chain still grades correctly:**
  `audit --db /var/lib/virp/chain.db` with both pinned producer keys →
  "audited 363 camera evidence entries … all stored bodies hash to their
  recorded artifact_hash; prev-hash chain intact; producer signatures valid".
- The damaged session was not touched: no rewrites, no deletions, no
  back-signing.

## Acceptance run: blocked at the capture side — not performed

Reported plainly: **the live capture against the Tapo C100 was not run**, and
no acceptance checks against a new session are claimed. From this host (313):
the camera at 10.0.3.100 is unreachable (100% packet loss; 313 has only
10.0.0.13/24), ffmpeg is not installed, and the capture host (the laptop,
FROM_PIN 10.0.3.102 / 10.0.0.222) has no reachable SSH. The capture must be
started from the laptop.

Operator runbook for the capture side (313 is ready and waiting):

1. Copy `camera/virp_camera.py` at `50444f0` to the laptop.
2. Fresh acceptance data-dir; **copy the existing laptop `producer.key` /
   `producer.pub` into it** (fresh `state.json`/`shipped.jsonl`, unchanged
   producer identity — key handling stays untouched). A fresh data-dir is
   required: reusing the old one would make the first `tapo-c100-accept`
   record cite a `tapo-c100` segment as prev, which `audit` rightly flags.
3. `virp_camera.py live --camera-id tapo-c100-accept --data-dir <accept-dir>
   --spool virp-capture@10.0.0.13 --ssh-key <key> --known-hosts <pinned file>
   --rtsp-config <0600 file>` (`--known-hosts` is required as of the Sep 1
   review: the spool host key is pinned, never accepted on first contact)
4. During the run: two graceful stops (SIGTERM/Ctrl-C), one `kill -9`, and
   one stop of > 60 s before restarting.
5. Then, on 313, the seven acceptance checks run read-only against
   `camera:tapo-c100-accept:<date>` (duplicate shas, window ordering, seq
   monotonicity, append-order vs seq, gap reasons per discontinuity, the
   long stop as `capture-discontinuity` not `gap: null`, and virp-verify /
   docket grading). I can run these on request once the session exists.

## Open items (named, not started)

- Upstream ack path (chain-append-ack back to the capture host) — Fix A's
  named open item.
- `shipped.jsonl` grows unbounded (~1.5 MB/day at 6 s segments); harmless
  for now, compaction eventually.
- The instance lock cannot span hosts or distinct data-dirs (above).
- Everything in the prompt's §6 out-of-scope list remains untouched
  (schema fields, stream fingerprint, provenance labels, key identity,
  Docket, VIRP C tree).
