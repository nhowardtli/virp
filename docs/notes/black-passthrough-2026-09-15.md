# Passthrough super-admin: the `black` ceiling and the open seat (2026-09-15)

Ruling (Nate): "a CCIE that needs to reload a locked-up Nexus core at 2am … make me
CCIE super admin, can wr erase because sometimes you need to." Engineers accept
accounting (ISE/TACACS already does it); they refuse gates on their own hands.
So VIRP gets a **tracking-only** identity: everything applies, everything is
signed and chained under the person's own uid.

## What changed

- **Ceiling value `black`** in `socket_uid_tier_ceilings` = PASSTHROUGH. The
  loader accepts it (loudly). `gate_tier_blocks()` refuses BLACK for every
  ceiling except an explicit `black`; the gate logs
  `[GATE] BLACK PASSTHROUGH: uid=… device=… command=…` and the decision
  column reads `BLACK-PASSTHROUGH`. Tier is still classified and recorded as
  BLACK; SHADOW mode and approvals play no part — it is a named human's hand.
- **`virp_exec_passthrough`** (thread-local, `include/virp_driver.h`) is set by
  the daemon for exactly one `execute()` and cleared after. The CLI drivers'
  BLACK backstops (cisco, asa, fortigate, linux) yield to it and log their own
  line; REST drivers (wazuh, pbs, zammad, librenms) keep refusing.
- **Cisco confirmation**: under passthrough, a BLACK command that stops at
  `[confirm]` / `(y/n)` / `[yes/no]` gets ONE answer (Enter or `y`), then the
  session is treated as ended: result = sent-and-confirmed, **outcome unknown**
  (never success), connection marked down for a fresh reconnect, transcript
  signed. Nothing else is ever auto-answered.
- **Explicit per-uid ceilings are authoritative in both directions.** Before
  today a looser row never bound ("only tightens"), which meant the RED seat
  (984) on a YELLOW node was silently YELLOW. Rows are policy the operator
  wrote; they decide. `onode_ceiling_source` reports `per-uid` /
  `per-uid passthrough`.
- **Open seat**: `/usr/local/bin/virp-shell` runs the shell as the *invoking*
  uid — no sudo, no `enable` — when that uid has its own row in the rendered
  policy (`--own`). The row's ceiling is the person's trust level:
  `green` read-only, `yellow` guarded, `red` open, `black` passthrough. Shared
  seats (`enable`, `enable red`) remain for people whose own row is lower.
- **1000 (nhoward) = black** on virp-lab: the first passthrough identity.

## What did NOT change

Service identities, agents and the shared seats keep their ceilings; nothing
below `black` can reach BLACK; proposals/approvals are untouched. `black` is
written on rows of named humans only — the template note says so.

## Tests

`test_onode`: black ceiling → `decision=BLACK-PASSTHROUGH`, RED ceiling still
blocks BLACK, RED row binds above a YELLOW node, no-row uid stays node-wide,
thread-local cleared. `test_driver_cisco_description`: backstop refuses without
the flag, yields with it, refuses again after. Existing BLACK suites unchanged.

## Deploy

Binary change: `make install-prod` on virp-lab, then the template (1000 → black,
ASA-5525 restored), restart, `deploy-record`, `install-virp-shell` (wrapper).

## Found by the test, fixed before deploy

`onode_set_uid_ceilings()` still rejected `VIRP_TIER_BLACK` as a config
error (its old comment: "a BLACK ceiling would forbid everything"). With
the prod loader now emitting BLACK for `"black"`, the daemon would have
refused the template at start. `test_per_uid_black_ceiling_is_passthrough_and_red_binds_above_node`
failed with `-4` (INVALID_TYPE) on the setter, the setter now accepts
BLACK with the passthrough meaning, and the suite is 165/167 (the two
PENDING refusal-with-body tests are pre-existing, unrelated).

Suites on this branch (2026-09-15, `unshare -Umr` tmpfs, flags
CISCO/FORTIGATE/ASA/LINUX): test-onode 165/167 (+2 PENDING pre-existing),
test-refusal-contract 5/5, test-cisco-description 15/15, test-cisco-gate
208/208, test-cisco 52/52, test-fortigate 149/149, test-asa 180/180,
test-linux-gate 199/199; python: shell 54, template policy 25, render 22,
autopilot 65. `WAZUH=1` on test-onode fails to build for a pre-existing
reason (`wazuh_gate_set_protected_agents` implicit declaration in
`virp_onode_prod.c`), not touched here.
