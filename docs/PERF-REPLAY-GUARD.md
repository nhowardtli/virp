# Apply-time replay guard — measured cost, and why an index is not the fix

Status: MEASURED FINDING plus a proposed design. **Nothing is implemented.**
Written 2026-09-02. The branch is named `perf/replay-guard-index` because
an index was the expected fix; the measurement says it is not.

## What the guard does

Before appending a `gate_intent` for an approved apply, the daemon asks
whether this approval has already been spent on a committed intent. The
chain is the authority for that question, which is correct: it closes the
crash window between an intent commit and the `consumed.list` write, where
the cache can be lost while the chain entry survives.

The implementation is `chain_count_intents_for_approval_locked()` in
`src/virp_chain.c`. It runs:

```sql
SELECT a.artifact_content FROM chain_entries c
JOIN artifacts a ON a.artifact_id = c.artifact_id
               AND a.artifact_hash = c.artifact_hash
WHERE c.artifact_type = 'gate_intent'
```

and then, in C, `cJSON_Parse`s **every returned body** and compares its
`approval_entry_hash` field.

So the guard reads and JSON-parses every `gate_intent` ever written, on
every approved apply. The filter it actually wants lives inside a JSON
body, where SQLite cannot reach it.

This runs while holding both the chain lock and `consume_mu`.

## Measured

Synthetic chain shaped like the production reference node: 273239
`chain_entries`, of which ~21000 are `gate_intent`, bodies in the real
shape.

| | per approved apply |
|---|---|
| today | **0.074 s** |
| today, plus `CREATE INDEX ON chain_entries(artifact_type)` | 0.079 s |
| proposed indexed citation | **0.000004 s** |

The index changes the query plan from `SCAN c` to
`SEARCH c USING INDEX idx_chain_type`, which looks like the fix and is
not: measured speedup **1.08x**. Finding the rows was never the expensive
part. Fetching and parsing 21000 JSON bodies is.

**The index alone does not fix this. That is the finding.**

## Why it gets worse

The cost is O(number of `gate_intent` entries ever written). That number
only grows, and nothing prunes it. The guard is on the approval path, so
the most safety-critical operation in the system is also the one whose
cost grows without bound. At ~21000 intents it is 74 ms of lock-held work
per apply; at ten times that history it is roughly ten times the work.

Nothing currently fails. This is a scalability finding, not an outage.

## Proposed fix

Materialise the citation into an indexed column so the guard becomes a
lookup instead of a scan-and-parse:

```sql
CREATE TABLE intent_approval_citation (
  chain_entry_id      INTEGER PRIMARY KEY,
  approval_entry_hash TEXT NOT NULL
);
CREATE INDEX idx_iac_aeh ON intent_approval_citation(approval_entry_hash);
```

The daemon writes the row **inside the same transaction as the intent
append**, so the citation cannot exist without its entry or vice versa.
The guard becomes:

```sql
SELECT COUNT(*) FROM intent_approval_citation WHERE approval_entry_hash = ?
```

which plans as `SEARCH ... USING COVERING INDEX` and is O(log n), flat as
history grows.

### Constraints this has to respect

1. **The chain stays the authority.** The new table is a derived index of
   what the chain already says, never a second source of truth. If it and
   the chain ever disagree, the chain wins and the disagreement is a
   fault to report, not to paper over.
2. **The write must be atomic with the intent append.** A citation row
   that can be lost independently reintroduces exactly the crash window
   the guard exists to close.
3. **Backfill must be verified, not assumed.** Existing intents must be
   backfilled and the result checked against the current scan-and-parse
   implementation, entry for entry, before the fast path is trusted.
4. **Keep the slow path as an oracle.** The existing function should stay
   and be used to cross-check the fast path in tests, so a divergence is
   caught by a test rather than by a double-spend in production.
5. **A missing citation row must not read as "not spent."** An intent
   whose citation is absent has to be treated as unknown and fall back to
   the scan, never as an absence of prior spend. Failing open here would
   turn a performance change into an approval-reuse hole.

## Why this was not implemented tonight

It is a schema change, a migration, a backfill, and a new write inside the
approval path's transaction. That path is the one place where getting it
wrong means an approval can be spent twice.

The v0.2.0 incident this same night is the argument: two individually
correct changes combined into a refusal of the node's own evidence,
deployed unattended, found only in production. A schema change to the
replay guard carries a worse failure mode than that one, and it should
land with someone awake, with the oracle cross-check in place, and with
the backfill verified against real history rather than a synthetic
fixture.

The measurement is the deliverable. The implementation should be a
reviewed change, not a 2am one.

## Reproducing the measurement

The numbers above come from a synthetic SQLite database built to the real
schema at the live node's row counts. It needs no daemon and no chain
key. The shape is: 273239 `chain_entries` with ~21000 `gate_intent` rows,
matching `artifacts` rows carrying real-shaped `gate_intent` bodies, then
timing the current query plus body parse against a single indexed lookup
on the materialised citation table.
