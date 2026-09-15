# virp-shell phase 2 note — `show chain` needs a daemon `list_sessions` action

**Status 2026-09-15: BUILT on branch `feat/onode-list-sessions`** —
`ONODE_ACTION_LIST_SESSIONS` (18, wire name `list_sessions`),
`virp_chain_list_sessions()` in the chain library, template rows for
`${VIRP_UID}`, 1000 and 988 (colo) and `${VIRP_UID}`/1000 (node2), tests
in `tests/test_chain.c`, `tests/test_onode.c` and `tests/test_virp_shell.py`,
and the shell's `show chain [n]`. It is a DAEMON change: the template row
and the binary must land together (`make install-prod` on virp-lab, with
its rollback), which is why it is not on `feat/virp-shell`. The daemon
already running knows no such verb, so the template on this branch must
not be installed ahead of the binary: the old loader treats an unknown
action name as a malformed row and installs **DENY-ALL for that uid**
(fail closed, `virp_onode_prod.c`), which here would strip every verb
from 999 (autopilot), 1000 (operator) and 988 at the next restart.
Order on virp-lab: `make install-prod` (binary) → `install-devices-template`
→ restart, in one window, with the rollback path noted. Below is the
original note, kept for the record.

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
