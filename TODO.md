# TODO — post-consolidation follow-ups

## 1. Re-land chain_append verify-before-append on main (FIRST post-freeze ticket, not backlog)

Re-land as a fresh, reviewed change on main:

- sha256 == artifact_hash verification of submitted bodies,
- O-Key HMAC verify of observation bodies,
- replay rejection via virp_chain_hash_exists.

Reference material: tag `archive/harden-chain-recut-2026-08-07-2026-08-10`
(the chain-recut branch tip, 6fa6e60b) and tag
`archive/feature/frr-driver-2026-08-10` (the original unreviewed cut,
9fad81cb). Do NOT merge either tag — re-implement on current main.

Must also close the Aug 7 review findings:
- **F2**: fail-open on non-parsing body,
- **F3**: checks keyed on client-supplied artifact_type,
- **F4**: TOCTOU — the fix belongs inside the append transaction.
