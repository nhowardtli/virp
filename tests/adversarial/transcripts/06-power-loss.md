# Test #3 — power loss (storage cut), run 1 (L3 dm-flakey drop_writes)

**Date:** 2026-08-18 · **Host:** virp-lab
**Daemon under test:** `a1f4bc99` (deployed prod binary, sha256 `98bda8d5…19e6`)
**Harness:** `tests/adversarial/fi-powerloss.sh` at `b55e393e` · **Rung:** L3 (`drop_writes`)

Per CONVENTIONS.md §1 the finding below is a statement about `a1f4bc99`.

## What ran

256 MB disposable loop image → dm-linear → ext4 → an isolated prod daemon
writing its chain there. 200 commitment-only `fed_observation` appends landed
and were `sync`+`blockdev --flushbufs`'d to the image (the durable prefix).
Then dm-flakey `drop_writes` was armed — writes ack at the syscall but never
reach the image — and 200 more appends were issued. The daemon was
hard-killed, the mapping torn down, the page cache dropped
(`echo 3 > drop_caches`), and the underlying image re-exposed straight for a
cold read.

## What survived

```
durable prefix = 200      (synced before the cut)
post-cut appends refused by the writer = 0 / 200
entries surviving on the image after the cut = 200
signed head last_sequence = 199        (seqs 0..199 = 200 entries)
virp chain verify --session powerloss:1 -> VALID  entries=200 to_seq=199  broken=0
```

## Verdict — PASS (atomic loss), with one real exposure named

**Chain integrity held.** The 200 post-cut appends vanished with the cut
(survived stayed at 200). On the cold reopen the chain reverted *atomically*:
the signed head (`last_sequence=199`) matches exactly the 200 surviving
entries, so `virp chain verify` reports VALID over an honestly-shorter chain.
The chain makes **no claim** to the lost tail — no dangling commitment, no
head asserting a length the entries do not reach. SQLite's WAL atomicity held
under a uniform write-drop: head, entry, and body land or vanish together.

This is the **PASS** side of the memo's pass condition: loss is never
*silently accepted as present*. It is not the "verify FAILED / truncation
detected" branch, because there was no torn state to detect — a uniform
`drop_writes` loses whole transactions atomically, so nothing was left
inconsistent.

**The exposure this makes concrete** (the SIGKILL-vs-power-loss caveat, in the
storage direction): the daemon **acked all 200 post-cut appends** —
`post-cut-refused=0` — for writes that never became durable. A federation
caller that received those 200 successes has no durable record of them. The
chain does not lie about them, but the *acknowledgement* preceded durability.
This is exactly the honest limit `SECURITY.md`/`VIRP-CLAIMS.md` now carry:
under power loss a success reply is not proof of persistence.

## Not yet exercised — the torn-write case

`drop_writes` drops writes uniformly, which yields atomic loss. To try to
*produce* a silent truncation (head durable, entries not → verify wrongly
VALID over a chain that DOES claim the lost tail), a follow-up needs a
surgical cut: drop only the WAL body/frame writes while letting the head
update through, or error a specific sector range mid-commit (dm-flakey
`error_writes` on an offset, or dm-error scoped to part of the device). That
is the L3+ escalation this run motivates but did not perform.

## Companion not yet run

L2 (dm-error, whole-device I/O failure → the writer must fail CLOSED, refusing
the append rather than acking an unpersistable write) is the approved
companion and has not been run. Under L3 the writer acked (drop_writes is
silent at the syscall); L2 is the test of whether a HARD error is caught.

## Conclusion — the finding of this run

**Ack-before-durability.** VIRP's success reply to a `chain_append` is an
acknowledgement that the daemon *committed* the transaction, NOT proof that
the commit reached durable storage. Under a power-loss-style silent write-drop
the two come apart: the daemon acked 200 appends that the cut discarded. The
chain does not lie about them (the head reverted atomically, so nothing dangles
and the verifier does not claim the lost tail) — but a caller holding those 200
"successes" has no durable record. This is the honest limit `SECURITY.md`'s
crash-test caveat now states explicitly in the power-loss direction:
persistence must be read from the chain's own head/entry consistency, never
inferred from the ack. It is a limit, not a defect — the chain's integrity
guarantee held; what does not hold is any equation of "acked" with "durable".
