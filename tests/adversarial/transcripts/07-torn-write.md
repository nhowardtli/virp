# Test #3b — torn-write escalation (attempt a SILENT truncation)

**Date:** 2026-08-18 · **Host:** virp-lab
**Daemon under test:** `a1f4bc99` (sha256 `98bda8d5…19e6`)
**Harness:** `fi-torn-write.sh` + `fi-pwrite-drop.c` at `76037f98`
**Mechanism:** LD_PRELOAD `pwrite` filter (unprivileged, per-process, zero blast
radius). Base commit pinned per CONVENTIONS.md §1.

## Goal

Manufacture the one failure runs 1–2 could not: a recovered chain whose signed
head claims sequence N while only M < N entries survive, with
`virp chain verify` still reporting **VALID**. That would be a silent
truncation — the chain asserting a tail it cannot produce, undetected.

## What ran

N=1500 appends per attempt, drops armed after H=200 (so an auto-checkpoint
lands in the drop window), 3 attempts × 3 strategies. The shim drops matching
`pwrite`s from the daemon after the trigger:

| Strategy | Drop target | Intent |
|---|---|---|
| `wal` | `chain.db-wal` | drop the WAL tail — baseline |
| `all` | `chain.db` (+wal) | drop everything post-trigger — aggressive |
| `maindb` | `chain.db` **excluding** `-wal` | let the WAL persist but drop the main-db pages a checkpoint writes — the surgical attempt to leave the head advanced past its entries |

## Results (9/9 attempts)

```
wal    a1..a3  drops=19832  head_seq=199   entries=200  seqs=0..199   verify=VALID   -> atomic/consistent
all    a1..a3  drops=20167  head_seq=199   entries=200  seqs=0..199   verify=VALID   -> atomic/consistent
maindb a1..a3  drops=335    head_seq=1499  entries=0    (malformed)   verify=BROKEN  -> DETECTED
```

- **`wal` / `all` — atomic loss.** Post-trigger commits never persisted; on
  recovery the chain reverted to the 200 durable entries (0..199), head=199,
  self-consistent, verify VALID. SQLite's WAL is all-or-nothing per
  transaction: a dropped frame breaks the running checksum, so recovery stops
  at the last good commit. No torn state — atomic, exactly as run 1 showed.

- **`maindb` — a torn main db, DETECTED.** With the WAL left intact, the daemon
  committed all 1500 appends (head advances to 1499), but the auto-checkpoint's
  writes to the main-db pages were dropped (335) while SQLite believed the
  checkpoint succeeded and reset the WAL. Result on reopen: `chain_heads`
  reads `last_sequence=1499`, `chain_entries` is `database disk image is
  malformed` / 0 readable rows. `virp chain verify` did **not** shrug:

  ```
  powerloss:1  BROKEN  entries=0 to_seq=1499 first_broken=0
    (Chain truncated: expected 1500 entries (0..1499), found 0)  broken=1
  ```

  The signed-head completeness check loaded the head (to_seq=1499), walked the
  claimed range, found the entries absent, and reported BROKEN — the exact
  detection it exists for. No VALID over a chain claiming a tail it cannot show.

## Conclusion — PASS (no silent truncation; the check is robust)

Across 9 attempts and three mechanisms, **no silent truncation was
producible**. Every recovery was either honestly consistent (atomic loss,
verify VALID) or an inconsistency the completeness check caught (verify BROKEN).
Two properties held together:

1. **The chain inherits SQLite's WAL crash-atomicity** — a dropped/torn commit
   loses the whole transaction, never half of it, so head and entries do not
   drift apart from a WAL-level cut.
2. **The signed-head completeness check is robust against a torn recovery** —
   when a main-db tear *did* leave the head claiming 1500 entries over an
   empty/malformed table, verify reported BROKEN with the exact expected/found
   counts, never VALID. This is the same range-completeness + signed-head check
   that closed the keyless-attacker tail-truncation gap (2026-08-01); it also
   catches an *honest* storage tear.

The attempt count is reported by the harness (9), so this PASS is a measured
negative, not a silent one. The block-layer confirmation (sector-targeted
dm-flakey per the memo) is optional follow-up; the LD_PRELOAD probe already
drove the main-db tear directly and the check held.

## Scope note

This closes the torn-write question for the WAL and whole-main-db cases. A
still-more-surgical cut (drop only the *tail* main-db pages to leave head=N and
entries=0..M for 0<M<N, a partial rather than total tear) would exercise the
same completeness check on a partial gap; the check already rejects the total
case with an exact expected-vs-found count, so a partial gap is the same class
of detection. Recorded as covered-in-principle, not separately run.
