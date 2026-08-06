# Design memo — durable EXECUTION_INTENT record

**To:** Nate · **From:** adversarial test program, test #2 · **Date:** 2026-08-03
**Status:** recommendation only. Nothing implemented. Decision is yours.

## Recommendation

**Yes, warranted — but not for the reason it looks like, and the cheap version does not work.**

The value is *not* "record that we tried". VIRP already half-records that: `consumed.list` proves an
authorization was spent. The value is that an intent record is the **only** thing that can separate

- `post_consume` — authorization burned, **device never contacted**, and
- `post_exec` — authorization burned, **device executed**

which test #2 showed are indistinguishable today, in the chain *and* in the spool. Any design that
writes the intent at the same moment as the consume reproduces exactly the current ambiguity and buys
nothing. **The record must be committed at the last instant before the device is contacted** — after
`consume_once()`, immediately before `drv->execute()` — because that is the only line in the code
that separates "not attempted" from "attempted, disposition unknown".

## What it would say

```
EXECUTION_INTENT { proposal_id, approval_entry_hash, device, device_node_id,
                   command_hash, attempt_at_ns, daemon_build_id }
```

Chain semantics become:

| chain state | meaning |
|---|---|
| approval, no intent, no outcome | authorization spent or lost; **device was never contacted** |
| approval, **intent**, no outcome | **authorized execution was attempted; disposition unknown** |
| approval, intent, outcome | executed, result recorded |

The middle row is the sentence VIRP currently cannot say and, per test #2, needs to be able to say.

## Cost

**Storage/schema: none.** It is a new `artifact_type` on the existing `virp_chain_append()`. No
migration. Note there is already an unused `intents` table in the chain schema (0 rows in production,
AI-intent shaped: `confidence`, `max_commands`, `proposed_actions`). Do **not** reuse it — different
concept, and its columns would misdescribe this. Mentioning it only so nobody thinks the name is free.

**Latency: one extra `BEGIN IMMEDIATE` → `COMMIT` per privileged apply**, on the critical path before
device I/O. Single-digit milliseconds against SSH connect + command execution. Negligible, and it
applies only to approved RED/YELLOW applies, never to GREEN reads — the autopilot's per-minute load
is untouched.

**Wire impact: none required.** This is a local durable record. Nothing new crosses the socket, and no
client needs to change. It becomes wire-visible only if peers should compare intent counts during
cross-node observation, which is a separate decision.

**Real cost is operational, not technical.** An intent with no outcome is a permanent "unknown" that
someone must reconcile. Today those cases are invisible and therefore free; afterwards they are
visible and demand a procedure. That is the point, but it is not zero — a monitoring surface, a
runbook, and an agreed answer to "what do we do with an unresolved intent" all have to exist or the
records become noise the operator learns to ignore.

## Is it -07 material?

**Probably yes, and it is small.** It adds an artifact type to the PROPOSAL → APPROVAL → OUTCOME
vocabulary that C21 names, so any spec text enumerating chain artifact types has to change. It does
not touch the wire format, the observation header, canonicalization, or any signature construction —
so it should not disturb the PBS canonicalization work or the existing hash lineage. If -07 is
already open, fold it in; it is not worth opening a revision for on its own.

## Two things to decide alongside it

1. **Should the intent commit be atomic with the consume?** Recommend **no** — deliberately. They
   must be separable, because the gap between them is the very distinction being bought. Atomic
   coupling reproduces today's ambiguity.

2. **`chain_append` and `artifact_store` are not in one transaction.** Test #2's `mid_outcome` used
   this to produce a chain entry committing to a body that does not exist, and the same window let a
   plain `cp` of the production database capture a body-less entry that a live read shows as fine.
   An intent record inherits this. Worth fixing on its own merits — it is arguably a better first
   move than EXECUTION_INTENT, because it is smaller, needs no spec change, and today's chain already
   carries 20 body-less entries in production.

## Also worth deciding: ship a verifier

Not strictly part of this recommendation, but it surfaced here. `virp_chain_verify_session()` is
solid and is not reachable from the CLI — `virp chain` offers only `tail`, which verifies nothing. An
auditor currently cannot verify a VIRP chain with shipped tooling; I had to write a verifier to
complete test #2. An EXECUTION_INTENT record makes the chain *more* nuanced to read, which makes the
absence of a verifier command more costly, not less.
