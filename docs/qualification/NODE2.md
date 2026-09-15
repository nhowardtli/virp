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

## STOP: baseline safety-policy inconsistency

Full driver-enabled battery stopped in `test-autopilot`:
`test_template_carries_no_blocked_address` rejects `10.0.10.1` in the tracked
colo `deploy/devices.template.json`. That is the actual template tested, not
node2's separate template. Do not interpret this as observed unauthorized
network execution; isolation excluded host network access. Do not remove the
assertion, change its target, remove the fleet row or repair policy during this
qualification. Nate/independent reviewer must disposition the inconsistency.

The exact battery command is recorded in evidence/c-battery-3.json. Exit 2,
126.09076070785522 seconds. It did not complete all suites. Core 61/61 passed
before the later failure; passed earlier suites do not override the failed gate.
The initial isolation failure and missing-awk environment failure remain in
preflight.log and c-battery-1.log. The Wazuh NO_MAIN build failure remains in
c-battery-2.log. The declaration-only build fix is committed separately and is
not a repair of this safety-policy finding.

The actual node2 renderer passed with synthetic credentials, exactly three
expected devices, list_sessions for 999/1000, and evidence_required=true.
Production ownership/chown and real credential validity were not tested.

No production database snapshot was available in the before-state captures;
no fresh snapshot was obtained because no host contact was authorized. No
legacy authenticity claim, candidate startup on legacy evidence, transition
implementation or epoch/replay/crash/rollback qualification has been performed.
All seven requested epoch checks remain NOT RUN. Stop is before remediation.

## Review handoff (not a reviewer verification note)

Different reviewer: Claude Code. Inspect base
8881e8a4b1fc71958682b9f7de3e2817165e1e9a and the qualification branch diff,
then independently classify the safety-policy/template inconsistency. Do not
claim the C battery passes, source 8881e8a was tested without modifications,
or node2 is deployable. Current branch contains isolation support, a loader
prototype-scope build fix, a renderer check and retained logs only.

Future authorized deployment recipe, after a qualified epoch implementation:
`make install-prod` from the exact clean reviewed checkout, retain its emitted
record, then `make deploy-record` against installed artifacts. This installs
the daemon, client and helper modules; it does not solve old database adoption,
install every service unit, or authorize a restart. Select
`deploy/devices.node2.template.json` explicitly. Never use the colo fleet on
node2. A rollback runbook must preserve both epochs and consumed approvals;
none is qualified by this blocked run. Do not execute either install command
as part of isolated inventory/qualification on the host.
