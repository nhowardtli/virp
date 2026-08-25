# Synthetic restart-integrity run — `synthetic-restart-accept`, 2026-08-25

## What this is, and what it is not

**This exercises restart integrity only. It is NOT a Tapo acceptance.**

Every segment in session `camera:synthetic-restart-accept:2026-08-25` was
produced by ffmpeg's `testsrc2` synthetic generator with a wall-clock
overlay (`--test-source`). **No camera participated. No frame in this
session depicts anything.** The camera at 10.0.3.100 was unreachable from
the capture host (no 10.0.3.x lease; 100% packet loss) and no RTSP
credential was present, so a real acceptance was impossible — that
remains open and will be run separately once the IoT lease and RTSP URL
are in place.

The session is named `synthetic-restart-accept` precisely so that it
cannot be mistaken for camera evidence in the chain, in Docket, or in any
later audit. It is deliberately not `tapo-c100-accept`, and it shares no
session id, device name or artifact-id prefix with the Tapo sessions.

What it *does* prove is the restart machinery — Fixes A–F — against a
live driver, a live spool, a live O-node and the real chain, rather than
against fixtures. In particular it takes the **ffmpeg renumber /
name-collision** case out of fixtures, which was the point.

## Provenance

| | |
|---|---|
| Driver | `feat/camera-driver` tip `4ee5950`; code commit `50444f0` (tip adds only the runbook `.md`) |
| Deployed submit side (313) | `/var/lib/virp/camera/virp_camera.py` sha256 `6b9998cc3921e76d6a92189831dc9cd12640ce801042d2ab3e2d5888eacbaba0` |
| Capture side (laptop) | same file, hash-verified byte-identical before the run |
| Producer key | existing laptop identity `008353cf219c224e970f03455aa50e82`, copied into a fresh data dir; key material unchanged |
| Data dir | `~/camera-accept-synthetic` — fresh; no inherited `state.json` / `shipped.jsonl` / `work` / `outbox` |
| Result | 67 segments, `segment_seq` 0–66, no holes |

## Run sequence — every required event

| Run | Segments | Ended by |
|---|---|---|
| A | seq 0–18 | **graceful stop 1** (SIGTERM) — drained, workdir empty |
| B | seq 19–33 | **graceful stop 2** (SIGTERM) — drained, workdir empty |
| C | seq 34–36 | **`kill -9`** — 14 files left as residue |
| D | seq 37–60 | SIGTERM, then a **75 s stop** (> 60 s required) |
| E | seq 61–66 | final graceful stop |

Four restart gaps resulted, at seq 19, 34, 50 and 61.

## The renumber / name-collision case — the reason for tonight

Set up naturally, not staged. `kill -9` on run C left **14 closed-or-torn
segments in the workdir, named `seg_000003` … `seg_000016`, none of them
attested** — i.e. real footage sitting under exactly the names the next
ffmpeg would reuse when it renumbered from `seg_000000`. Hashes were
snapshotted before the restart.

On restart, Fix C reconciled the workdir **before ffmpeg respawned**:

```
live: recovered stale instance lock … (unclean exit of pid 2947214); proceeding
reconcile seg_000003.mp4: re-shipped staged pair 000037.8fc3b803… (seq=37, original body bytes)
live seq=38 … 1840a27d…      ← seg_000004
…
live seq=49 … 80ad9c39…      ← seg_000015
reconcile seg_000016.mp4: unfinalized partial (no moov box); removing — this footage is lost
live seq=50 … 5bef91f5…  GAP(driver-restart)   ← first NEW segment
```

Cross-checking the pre-restart snapshot against the chain:

```
seg_000003.mp4  8fc3b803…  -> chain seq 37     seg_000010.mp4  06cdc16c…  -> chain seq 44
seg_000004.mp4  1840a27d…  -> chain seq 38     seg_000011.mp4  4950c076…  -> chain seq 45
seg_000005.mp4  0edd1923…  -> chain seq 39     seg_000012.mp4  1b64070d…  -> chain seq 46
seg_000006.mp4  f3841f82…  -> chain seq 40     seg_000013.mp4  53f3fd29…  -> chain seq 47
seg_000007.mp4  8dfd68f0…  -> chain seq 41     seg_000014.mp4  0ae040ef…  -> chain seq 48
seg_000008.mp4  0e252a7c…  -> chain seq 42     seg_000015.mp4  80ad9c39…  -> chain seq 49
seg_000009.mp4  6e11cb01…  -> chain seq 43     seg_000016.mp4  f339092d…  -> absent (declared lost)
```

**13 of 13 closed segments preserved. 1 torn partial removed — and
declared, not dropped silently.** `seg_000016` was the file ffmpeg was
mid-write on when SIGKILL landed; it has no moov box, so it is not a
decodable segment and cannot be attested at all. The driver says so in
one plain line naming the file and the reason. That is the honest outcome,
and it is the exact difference the fix exists to make: the pre-fix defect
dropped *finalized* footage under reused names and said nothing.

New footage then landed under those same reused names as seq 50+, with
hashes distinct from every residue hash, and the restart gap rode seq 50 —
the first NEW segment, not the residue. That is Fix C's specified
behaviour, observed live.

Two things also demonstrated incidentally:

- **Fix E, end to end.** `seg_000003` had a staged outbox pair from the
  killed run and was re-shipped **byte-for-byte with its original body
  bytes** — not re-stamped with a new window. That is the whole point of
  Fix E, confirmed across a real kill.
- **Fix F stale-lock recovery.** The restart recovered the lock left by
  the SIGKILLed process and named the dead pid.

## Finding: `kill -9` orphans ffmpeg

Not in the runbook, and worth recording. When the driver was SIGKILLed,
its ffmpeg child **survived and kept writing segments into the workdir**
(observed growing from 3 files to 14 while the driver was already dead).
Residue is therefore larger after a hard kill than the driver's own
bookkeeping would suggest, and an operator restarting immediately would
have had a second ffmpeg writing the same filenames as the orphan.

Fix C handles the residue correctly, so this did not cause loss here, and
Fix F's lock protects the data dir — but the lock binds the *driver*, not
a stray ffmpeg. **Decided 2026-08-25 and filed as item 4:** process-group
kill at startup, before reconciliation, because `_reconcile_workdir`
assumes files at rest and a live writer violates that assumption.

## The seven read-only checks, run from 313

All read-only against `/var/lib/virp/chain.db`. Actual output:

**1 — duplicate `segment_sha256`**
```
distinct 67 of 67 ; duplicates 0  ->  PASS
```

**2 — window ordering (`start < end`)**
```
malformed windows: 0  ->  PASS
```

**3 — `segment_seq` monotonic, no holes**
```
monotonic=True  holes=[]  ->  PASS
```

**4 — append order vs `segment_seq`**
```
inversions: 0  ->  append order == capture order
```

**5 — every discontinuity carries a gap reason**
```
seq 19  hole    52.61s  reason=driver-restart
seq 34  hole    56.65s  reason=driver-restart
seq 50  hole    30.41s  reason=driver-restart
seq 61  hole    95.24s  reason=driver-restart
discontinuities: 4 ; explained: 4 ; gap-null holes: 0  ->  PASS
```

**6 — the long stop is a real reason, not `gap: null`**
```
seq 61  hole 95.24s  gap={"after_seq": 60, "reason": "driver-restart"}
long stops found: 1 ; all carry a reason: True  ->  PASS
```

Stated plainly rather than glossed: the runbook words this check as
"*the long stop as `capture-discontinuity` not `gap: null`*", and the
reason recorded is **`driver-restart`**, not `capture-discontinuity`.
That is correct, not a miss — Fix D specifies that the restart reason
takes precedence, and this hole *was* a restart. The check's substantive
criterion (a reason is present, never `null`) passes. **A pure
`capture-discontinuity` was never exercised by this run**, because every
gap here was a restart; producing one requires the capture to stall
without the driver restarting, which this sequence does not do. That case
remains unproven live.

**7a — driver audit, with the pinned producer key**
```
audited 67 camera evidence entries
all stored bodies hash to their recorded artifact_hash; prev-hash chain intact; producer signatures valid
```
Negative control, same session with the wrong pinned key — the signature
check is real, not a no-op:
```
FAIL: … producer_key_id 008353cf219c224e970f03455aa50e82 is not among the pinned keys
```
(The "producer signatures valid" clause appears only when `--pubkey` is
supplied; without it the audit checks hashes and prev-chain only.)

**7b — Docket grading**
```
67 matching entries across 1 session(s).
session camera:synthetic-restart-accept:2026-08-25 — 67 of 67 entries match
signed under key_id c1104805e1044d63a0c531eb7a025e68
CRYPTOGRAPHICALLY-VERIFIED
artifact_binding ✓ VERIFIED — 67/67 entries have carried bodies (SHA-256 recomputed against artifact_hash)
```

**Seven of seven pass**, with the wording caveat on check 6 above.

## Still open

- **The Tapo acceptance.** Not run, not claimed. Blocked on the laptop's
  IoT lease and RTSP URL, which the operator is fixing.
- A pure `capture-discontinuity` gap (stall without restart) was not
  exercised — filed as item 5. Existing tests cover it at the attestation
  level and end to end through `run_replay`; the untested path is
  `run_live` stalling mid-run with no restart.
- Orphaned ffmpeg after `kill -9` — decided and filed as item 4.
