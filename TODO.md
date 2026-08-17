# TODO — post-consolidation follow-ups

## 1. Re-land chain_append verify-before-append on main — DONE

Landed as fresh, reviewed changes on main (the archive tags
`archive/harden-chain-recut-2026-08-07-2026-08-10` and
`archive/feature/frr-driver-2026-08-10` were reference material only and
were not merged):

- sha256 == artifact_hash verification of submitted bodies — DONE
  (GATE 2 in src/virp_onode.c, constant-time, fail-closed on a body
  that does not decode).
- O-Key HMAC verify of observation bodies — DONE (GATE 3: v1 O-Key
  HMAC, v2 session-HMAC, v3 Ed25519; explicit version dispatch,
  unknown versions refused).
- replay rejection via virp_chain_hash_exists — SUPERSEDED, not
  implemented, by design: re-applying replay rejection on the append
  path would refuse the very message being registered (see the GATE 3
  design note in src/virp_onode.c). The federation duplicate case is
  covered by GATE 5 instead: an id reused with different bytes is
  refused, a byte-identical retry succeeds.

Aug 7 review findings:

- **F2**: fail-open on non-parsing body — CLOSED (GATE 2/GATE 3 refuse
  undecodable and unverifiable bodies; fed_outcome citation scanning is
  fail-closed).
- **F3**: checks keyed on client-supplied artifact_type — CLOSED
  (GATE 1 reserves every daemon semantic type; fed_observation is held
  to the identical signature standard as observation).
- **F4**: TOCTOU — the fix belongs inside the append transaction —
  CLOSED on branch fix/concurrency-evidence-path (2026-08-17): the
  GATE 5 conflict query now runs inside chain_append_locked's own
  BEGIN IMMEDIATE instead of as a pre-append probe, with a
  deterministic concurrency regression test
  (test_chain_fed_id_conflict_check_is_inside_append_txn). Not yet
  running in the installed daemon until the next restart window.
