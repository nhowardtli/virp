# Deploy runbook: 10.0.10.211 (virp-onode, colo)

Reached across the colo tunnel. No pve1 access, by design. System unit,
WAL-aware backup, `install-prod` blast radius as described in
`docs/RELEASE-PROVENANCE.md`.

This file currently carries the two deploy rules that 2026-09-07 forced.
The full pre-deploy checklist for the HAM remediation set (the
`chain_entry_hash` index migration that runs on first open, and
`emit_schema_version: 2` for uid 995) is written separately and is gated
on 48 hours of clean 313 nightlies.

## Rule 1: deploy via `make install-prod` only, never a manual copy

Identical to 313, and for the same reason. See
`docs/RUNBOOK-DEPLOY-313.md`, "Rule 1", including what a hand-copied
flagless binary cost on 313 on 2026-09-07: 21 minutes with zero drivers
registered, 39 devices unreachable, and one accounting record lost.

`install-prod` depends on `prod`; `prod` recurses with the driver flags;
a flagless build in the same `build/` directory silently replaces the
driver-enabled objects and `make` cannot tell them apart by timestamp.
The only safe path is the make target.

## Rule 2: deploy is binaries plus python, never binaries alone

`install-prod` installs one set: the two binaries, the `virp` hardlink,
the scripts including `render-devices.sh`, and the python modules. Ship
all of it or none of it.

The pieces are one release because they agree on formats the chain
enforces:

* **Artifact type names are length-bounded by the chain.** The autopilot
  writes `chainwalk_summa` and `comparator_verd` because the column will
  not take `chainwalk_summary` or `comparator_verdict`. A new binary with
  an old autopilot means those appends are rejected at the daemon and the
  record never lands.
* **The verifiers must agree.** `report/verify.py` and the C verifier
  grade the same chain. The signature-era axis (`SIGNED`,
  `SIGNED_FROM_N`, `UNSIGNED_ERA`, `NOT_GRADED`) and the exit-3
  "intact but unclean" verdict exist in both. Upgrade one and the two
  disagree about the same database, which is the one thing a verifier
  may never do.
* **`render-devices.sh` renders what the daemon parses.** It FATALs on an
  unknown placeholder, so a template that the installed script cannot
  resolve takes the daemon down at start, not at first use. This is the
  crash loop of 2026-08-11.

Before restarting, render the device file with both the installed script
and the new one, to temp paths, and diff. Stop if they differ.

## Read-only during the current run

.211 is read-only until the 48 hour 313 soak completes. Snapshots for
verification are `sudo cp` of `chain.db`, `chain.db-wal` and
`chain.db-shm` into a temp dir, checkpointed on the copy. Never run
sqlite3 against the live database and never checkpoint the live WAL.
