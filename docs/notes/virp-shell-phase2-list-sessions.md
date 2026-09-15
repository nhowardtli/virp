# virp-shell phase 2 note — `show chain` needs a daemon `list_sessions` action

Ruling 2026-09-14 (virp-shell phase 1): `show chain` is NOT built.

Why: `chain_verify` takes a `session_id` and there is no socket action that
enumerates sessions. The only session listing today is `virp-tool chain
tail`, which opens `/var/lib/virp/chain.db` directly — a path the shell is
forbidden to take (everything must go through the gate so it is chained and
judged under uid 988). `chain_verify_session` was considered and rejected:
it is still per-session and would only widen the seat.

What phase 2 needs, as its **own daemon branch** (not a shell change):

- `ONODE_ACTION_LIST_SESSIONS` — read-only, no device reach, returns a
  signed observation whose body lists `session_id`, first/last sequence,
  entry count and open executions for the last N sessions (bounded; the
  body must fit `VIRP_OUTPUT_MAX`, so page or cap).
- A per-uid allowlist verb like any other; uid 988's row gains exactly it.
- Then `show chain` = `list_sessions` + one `chain_verify` per listed
  session, rendered as sessions / entries / broken / seconds.

Until then the operator supplies the id: `verify chain <session-id> [from] [to]`.
