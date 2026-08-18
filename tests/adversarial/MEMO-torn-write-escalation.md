# Torn-write escalation — envelope memo (design only, HELD for review)

**Base:** follows test #3 runs 1–2 (transcript 06). Daemon under test `a1f4bc99`.
**Status:** DESIGN ONLY. No run. Approved-in-principle; this memo is the
prerequisite the reviewer asked for before any torn-write run.

## Goal — produce a *silent truncation*, the one PASS case runs 1–2 could not

Run 1 (L3 `drop_writes`) lost the tail **atomically**: head and entries
reverted together, verify VALID over an honestly-shorter chain that claims
nothing it cannot show. Run 2 (L2 dm-error) failed **closed**. Neither produced
the failure the completeness check exists to catch: a recovered chain whose
signed head claims sequence N while only M < N entries survive, with
`virp chain verify` still reporting VALID. That is a *silent truncation* — the
chain asserting evidence it cannot produce, undetected.

The escalation deliberately tries to manufacture that state. Its value is
symmetric:
- If we produce it → a real FINDING (the head/entry completeness check misses
  an inconsistent recovery).
- If we cannot, after a bounded search → a positive result: the chain inherits
  SQLite's WAL crash-atomicity, and "atomic loss" (run 1) is the general case.

## Why it is hard (and what that means)

SQLite WAL is engineered against exactly this. One `chain_append` writes its
`chain_entries` row AND its `chain_heads` update in ONE transaction → one set
of WAL frames terminated by a single **commit frame** carrying the running
checksum and the post-commit db size. On recovery SQLite replays frames only up
to the last VALID commit frame; a torn or bad-checksum frame truncates replay
at the previous good commit — **all-or-nothing per transaction**. So a naïve
partial write yields atomic loss, not tearing.

To get head > survived we must defeat that, which means one of:
1. persisting the commit frame of append N while losing a frame it depends on
   (SQLite should reject on checksum → atomic, not torn), or
2. corrupting the **main db** file's `chain_heads` page during a checkpoint so
   it reads a higher last_sequence than the entries present, while the WAL that
   would correct it is also gone.

Both require *surgical*, offset-targeted damage, not a whole-device cut.

## Mechanism options (surgical cut), fidelity + feasibility

| Option | How | Feasibility on virp-lab | Fidelity |
|---|---|---|---|
| **A. Sector-targeted dm-flakey** | `filefrag -e chain.db` / `.db-wal` to map the physical blocks of the `chain_heads` page and the WAL tail, then a dm-flakey table with `error_writes`/`drop_writes` scoped to that sector range | Doable; needs the ext4 block map and stable file layout (WAL grows, so map just-in-time) | Highest — targets the exact page whose survival-vs-loss makes the state torn |
| **B. Checkpoint interruption** | `PRAGMA wal_checkpoint(TRUNCATE)` then cut mid-checkpoint so the main db gets some pages, not all; combine with dropping the WAL so recovery cannot repair | Moderate; timing-sensitive, hard to hit the window | Medium — most interruptions still WAL-recover to consistent |
| **C. LD_PRELOAD pwrite filter** | preload a shim over `pwrite`/`pwritev` that silently drops writes whose offset falls in the `chain_heads` page (or the entry pages), letting the head update "persist" (in cache) while entry frames vanish | No root, no dm, per-process, zero host residue; most *controllable* | High — lets us choose exactly which of head/entry "survives" |

Recommended primary: **C (LD_PRELOAD)** for control and zero blast radius, with
**A** as the block-layer cross-check if C suggests a finding. B is a poor
first choice (too timing-dependent).

## Blast radius

- Same disposable envelope as runs 1–2: 256 MB loop image, uniquely-named dm
  node, everything under the session scratch, **never** `/var/lib`, `/run`, or
  the production socket. The safety fence already refuses those paths + tmpfs.
- **A** additionally reads the ext4 block map (`filefrag`/`debugfs -R`) of files
  *on the disposable image only* — no production filesystem is inspected.
- **C** is a `LD_PRELOAD` on the isolated test daemon only; it is a per-process
  environment variable, leaves no artifact, and cannot affect any other process.
  It touches no block device and needs no privilege beyond starting the daemon.
- No new persistent host state. dm-flakey is already loaded (run 1). The shim
  `.so` is built into the session scratch and removed on teardown.

## Teardown

The existing single `trap` (umount → dmsetup remove → losetup -d → rm) covers
A/B. For C add: unset `LD_PRELOAD`, `rm` the shim `.so` (both inside the scratch
dir the trap already deletes). The shim is inert once the process exits — no
handler, no persistence.

## Pass / finding condition

- **FINDING** — a recovered chain with `chain_heads.last_sequence > surviving
  entries` AND `virp chain verify … → VALID`. The completeness check accepted a
  chain that claims a tail it cannot produce.
- **PASS (detected)** — the same inconsistent recovery, but verify FAILS
  (head/entry mismatch caught). The completeness check did its job.
- **PASS (could not tear)** — after a bounded number of attempts (say 20 per
  mechanism) no torn state is producible: every cut yields atomic loss or a
  detected mismatch. Conclusion: the chain inherits SQLite WAL atomicity; the
  run-1 "atomic loss" is general. Log the attempt count — a silent cap is a lie.

## Recommendation

Build `fi-torn-write.sh` on mechanism **C** first (controllable, zero blast
radius), bounded to 20 attempts, with **A** as the block-layer confirmation only
if C surfaces a candidate finding. First run held for review. Everything else
(image size, teardown, path fence, commit pinning per CONVENTIONS.md) is
inherited unchanged from `fi-powerloss.sh`.
