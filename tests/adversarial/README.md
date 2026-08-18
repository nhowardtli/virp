# Adversarial test program — index

Independent, hostile testing of VIRP's core guarantees: authorization
single-use, crash/durability of the evidence chain, parser/identity robustness,
and device-boundary behaviour. Binding conventions in `CONVENTIONS.md` (pin the
commit a transcript tested; rebase onto merged main before a new test;
reconcile-don't-refix a stale finding).

## Tests (complete)

Listed in transcript file order. "Result" links each to what it changed.

| Transcript | Subject | Result |
|---|---|---|
| `transcripts/00-witness.md` | Target-side witness — an independent record of what the *target* did, so no later transcript has to trust VIRP for column 1 | infrastructure |
| `transcripts/01-f1-authorization-reuse.md` | **#1** — spending one approval twice (F1 apply/approve/TTL races) | findings fixed |
| `transcripts/02-crash-around-execution.md` | **#2** — crash around execution; the "recorded-happened-once, not happened-was-recorded" limit | findings → EXECUTION_INTENT |
| `transcripts/03-fixes.md` | fixes from the #1/#2 findings and what they taught (incl. the mid_outcome atomicity fix) | writeup |
| `TRANSCRIPT-04-audit-blockers.md` | **#4** — parser bounds, approval attribution, framing, identity | findings fixed |
| `TRANSCRIPT-05-device-adversarial.md` | **#5** — making a real target misbehave at the execute boundary | findings |
| `transcripts/06-power-loss.md` | **durability, L2/L3** — storage cut: dm-error (hard I/O error) and dm-flakey `drop_writes` (silent write-drop) | PASS + the ack-before-durability finding |
| `transcripts/07-torn-write.md` | **durability, torn-write** — attempt to manufacture a *silent truncation* | PASS — none producible; completeness check robust |

> Naming note: the durability arc (`06`, `07`) was tracked in-session as
> "test #3 / #3b". It sits at transcripts 06–07 in file order, after the earlier
> #4/#5 from a prior session — the transcript files are the authoritative
> sequence; the in-session "#3" was the fault-injection *durability* sub-track,
> not the `03-fixes` writeup.

## The measured durability boundary

The headline result of the durability arc, now the durability statement in
`SECURITY.md` (§"Crash and storage-failure durability"):

| Storage failure | VIRP | Evidence |
|---|---|---|
| Hard I/O error | **fails closed** (refuses; never acks an unpersistable write) | 06, L2 dm-error |
| Silent write-drop (power loss / lying disk) | **atomic loss** — head+entries revert together, verify VALID over an honest shorter chain; caveat: *ack ≠ persistence* | 06, L3 drop_writes |
| Torn recovery (head claims more than survived) | **detected** — completeness check reports BROKEN, never VALID | 07, main-db tear 9/9 |

## Memos / design proposals

- `MEMO-execution-intent.md` — EXECUTION_INTENT, the remedy for the #2
  recorded-happened-once gap (after-consume-before-contact, non-atomic by design).
- `MEMO-disposable-fs-ceiling.md` — durability-arc sizing (mechanism ladder, envelope).
- `MEMO-torn-write-escalation.md` — torn-write design (LD_PRELOAD primary, dm-flakey confirm).

## Proposed / remaining — the program HOLDS here

No further hostile test runs until the program owner brings a target. Carried
forward as open design work, not scheduled tests:

1. **EXECUTION_INTENT reconciliation procedure.** The record (proposal_id,
   approval_entry_hash, device+node_id, command_hash, attempt_at_ns,
   daemon_build_id) is specified in `MEMO-execution-intent.md` /
   `docs/virp-audit-design-proposals.md`; what is NOT yet specified is the
   *operator procedure* for an unresolved intent — how a "attempted,
   disposition unknown" row is reconciled against the target and retired. The
   durability arc confirms this gap is orthogonal to storage (it lives between
   consume and the OUTCOME append), so it survives every result above.
2. **Federation ack-durability design question.** Run 06 showed a `chain_append`
   success reply precedes durability under power loss. For a federated caller
   (netclaw / a peer O-Node) this matters more than for a local one: the peer
   may treat the ack as a durable receipt. Open question — should the federation
   protocol carry a *durability* acknowledgement distinct from the *commit*
   acknowledgement (e.g. an fsync-confirmed or checkpoint-confirmed reply), or
   is out-of-band chain re-verification the intended contract?
3. **(optional) Torn-write block-layer confirmation.** Transcript 07 drove the
   main-db tear directly with LD_PRELOAD and the completeness check held; the
   sector-targeted dm-flakey cross-check in `MEMO-torn-write-escalation.md` is
   available if a block-layer reproduction is ever wanted. Not required by the
   result.
