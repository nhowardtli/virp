# Cisco: `interface <name> description <text>` is YELLOW (C-04 Option A on the C node)

Ruled 2026-09-15 (Nate), after the first live `enable` session on virp-lab:
the admin seat (uid 985, ceiling YELLOW) typed `interface GigabitEthernet0/0
description hello` on R1 and got a RED proposal, because the C gate's Cisco
table grades every config-mode line RED. The Rust line had already settled
this as **C-04 Option A**: a port description floors at YELLOW; admin-state,
VLAN membership and static MACs are RED; context only escalates. This ports
the description half of that decision to the C driver. Nothing else moves.

## What changed

- `cisco_parse_interface_description()` (`driver_cisco.c`, declared in
  `virp_driver_cisco.h`): strict grammar —
  `interface <[A-Za-z][A-Za-z0-9/.:-]{0,62}> description <1..200 printable
  bytes>` or `… no description`. No abbreviations (the table's rule), no
  `?`, `;`, `|`, `` ` ``, tabs or control bytes, nothing after
  `no description`.
- `cisco_gate_tier()`: a command the parser accepts is **YELLOW**. Every
  other `interface …` line is still RED via the table.
- `cisco_execute()`: such a command is never sent as its literal (IOS would
  answer `% Invalid input` in EXEC). It runs a fixed transaction —
  `configure terminal` → `interface <name>` → `description …` / `no
  description` → `end` — checking the prompt mode after every step
  (`(config)#`, `(config-…)#`, `(config-…)#`, `#`) and refusing before
  any byte if the session is not in privileged EXEC. `end` is always
  attempted; if the session cannot be returned to EXEC the connection is
  marked down so the next request reconnects fresh rather than issuing
  an EXEC-shaped literal into a config prompt. The signed body is the
  whole transcript under the classified command, like every other Cisco
  observation. Mode-moving steps use a 1.5 s settle window instead of the
  10 s read timeout (the old prompt is not coming back), so the whole
  transaction takes a few seconds, not thirty.
- Tests: `tests/test_driver_cisco_gate.c` (`test_description_yellow`),
  `tests/test_driver_cisco_description.c` (parser matrix, classifier
  agreement, pre-transport refusals under the refusal contract).

## What it means at the prompt

| seat | `interface Gi1/0/48 description x` | `interface Gi1/0/48 shutdown` |
|---|---|---|
| virp-shell (988, GREEN) | proposal (YELLOW) | proposal (RED) |
| virp-shell-admin (985, YELLOW) | **applied**, chained under uid 985 | proposal (RED) — a second person |
| uid 1000 / autopilot | applied | proposal |

## Deploy

Binary change: `make install-prod` on virp-lab (rollback captured), no
template change. `make deploy-record` afterwards and paste into
DEPLOYED.md's live block — that is now part of the deploy checklist.
