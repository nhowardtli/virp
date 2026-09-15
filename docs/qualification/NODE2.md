# Node2 epoch qualification — exploratory, not deployment

Owner-designated C base: `8881e8a4b1fc71958682b9f7de3e2817165e1e9a`, nhowardtli/virp.
Execution host: nhoward-ThinkPad-E16-Gen-2. Target: virp-node2 / VM212.
Source acquired from the existing local `virp-remediation-2026-08-31` clone;
no fetch, host contact or modification of existing checkouts.

Nate's 2026-09-15 designation attributes the reference daemon and source equivalence
to virp-lab; this qualification does not independently reobserve that host.
C remains the comparator implementation. Rust and the frozen hardening schedule
are outside this exploratory branch. No remote adapter is installed.

All suite executions must go through `scripts/isolated`. The wrapper is adapted
from the existing Rust isolation wrapper, but mounts only this checkout writable,
not the user's whole home. No host network, production /run or /var, or host
/etc/virp is available. An existing dependency-only Python venv is mounted read-only
if present. Private keys are never supplied. Synthetic keys cannot establish
production HMAC authenticity or historic database integrity.

The pre-change inventory and blocked-target report remain at
`/home/nhoward/audits/virp-node2-update-20260915/` and
`/home/nhoward/audits/virp-node2-epoch-qualification-20260915/`.

Status: isolation preparation; no transition implementation or acceptance yet.
