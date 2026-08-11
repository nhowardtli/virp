# VIRP Deployment Record — netclaw (10.0.30.30)

- **Role**: netclaw-local O-Node — the daemon Nexus writes to. A trust
  domain SEPARATE from virp-lab (.211) and separate from the
  virp-remote-tunnel path that carries bridge traffic to .211.
  (DEPLOYED.md in this repo is virp-lab's record, imported with the
  bundle history; this file is the record for THIS host.)

## Current state (2026-08-11 15:46 UTC)

- **Installed binary**: /usr/local/lib/virp/virp-onode-prod
  sha256 `27c0788354234cce2e19426b18f9eea70da680ab1c709ac7370516dd7b614bb5`
- **Source commit**: `cc841caa38ca539f37fa7b6edf5eefef56878bc3` (local
  main = consolidated main `c224596` + netclaw unit-tracking commit;
  clean tree at install)
- **Rollback**: `sudo make rollback-prod ROLLBACK_FROM=/var/backups/virp/20260811T154642Z`
- **RUNNING daemon**: LIVE on the gated binary as of 2026-08-11
  17:46:32 UTC (MainPID exe = /usr/local/lib/virp/virp-onode-prod,
  sha 27c07883; GATE 2/3 reject strings confirmed in the running
  process image). 3/3 devices connected, chain intact.
  - Restart also required a render fix (commit a904575): the template
    named \${VIRP_BRIDGE_UID} in socket_allowed_uids but
    render-devices.sh had no resolver, latent since the daemon had not
    re-rendered since 2026-08-06. Fixed; live allowlist is now
    [999, 1000, 994] — uid 994 (virp-bridge) is an allowed peer of
    netclaw local O-Node for the first time (declared but never
    rendered before this restart).

## Why this deploy exists (provenance finding, 2026-08-11)

The previously installed binary (sha256 `43c4d7b7c3163d0b889a57ebb0…`,
mtime 2026-08-04 04:05, preserved in the rollback capture) had no
commit or build identifier and no deployment record. Provenance was
established two ways, no live probe needed:

1. **Timeline**: GATE 3 (`e2f69cb`, chain_append signature binding) was
   authored 2026-08-08 — four days AFTER the binary's mtime.
2. **Runtime-string differential** (old binary vs a fresh build of
   current main): the old binary lacks the GATE 3 reject path
   (`chain_append REJECTED: observation body failed signature
   verification`), the `chain_append_verify_observation` symbol, the
   `artifacts_unverifiable` grading counter — and ALSO the GATE 1/2
   reject strings (`artifact_type ... daemon-generated`, `declared
   artifact_hash does not match`). The running Aug-4 daemon therefore
   accepts external chain_appends with NO type/hash/signature gating.

The rebuild closes that: the installed binary is built from a recorded
commit whose ancestry contains `e2f69cb` (verified with
`git merge-base --is-ancestor`), and carries all three gates' runtime
paths.
