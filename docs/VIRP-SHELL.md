# virp-shell — operator guide

A Cisco-IOS-style REPL for the VIRP O-Node. Reads execute; config mode
**proposes and never applies**. Every request goes through the gate as
uid 988 (`virp-shell`) and is judged, signed and chained like any other
client's. The shell never opens `chain.db`, never runs as root, and cannot
verify the O-Node's signatures (it holds no key — every reply says so).

Deployed on virp-lab (10.0.10.211) 2026-09-15. Source: `tools/virp-shell.py`
(stdlib only). Install: `make install-virp-shell`. Wrapper:
`/usr/local/bin/virp-shell` → `sudo -u virp-shell`.

## Modes and prompts

| Prompt | Mode | How you get there |
|---|---|---|
| `virp-lab>` | exec | start |
| `virp-lab#` | privileged exec = **the admin seat, uid 985** | `enable` → sudo asks **your** password, the wrapper re-runs the shell as `virp-shell-admin` (ceiling YELLOW); `disable` returns to uid 988 |
| `virp-lab(config)#` | config | `configure terminal` (from `#`) |
| `virp-lab(config-SW-3850)#` | device context | `device <name>` |

`exit` steps out one level (device → config → `#` → leave). `end` returns
to `#` from anywhere in config. `disable` returns to `>`.

## Commands

| Command | Gate action | What you get |
|---|---|---|
| `show devices` | `list_fleet` | name / vendor / status for the fleet |
| `show device <name>` | `health` | a chained `show version` on that device (GREEN) |
| `show node` | `heartbeat` | uptime, onode/rnode ok, active observations, proposal count |
| `verify chain <session-id> [from] [to]` | `chain_verify` | valid / entries_checked / first_broken … |
| `show chain [n]` | `list_sessions` + `chain_verify` | recent sessions, each verified — **needs the daemon on `feat/onode-list-sessions`**; until then `% gate refused` |
| `show proposals` | — | proposals filed by **this session** (no node-wide listing exists) |
| `show services` | — (local) | `systemctl list-units 'virp-*'` |
| `show log [n]` | — (local) | last n journal lines for virp-onode (needs group systemd-journal) |
| `show version` | — (local) | binary sha256s, build string, node_id, DEPLOYED.md live block |
| `show uid [n]` | — (local) | per-uid ceiling / actions from the rendered `/run/virp/devices.json` |
| `(config-X)# <any line>` | `execute` | see below |

IOS conventions: abbreviations (`sh dev`, `sh dev SW-3850`, `conf t`, `en`),
`?` at any point lists what can come next **without submitting** (your
line is re-typed for you), Tab completes words and device names. Errors
begin with `% `.

## `enable` — the tier is chained with your password

`enable` is a real identity change, not a prompt character. The wrapper
(`/usr/local/bin/virp-shell`) re-runs the shell as **`virp-shell-admin`
(uid 985)** through a sudo **PASSWD** rule, so sudo asks for *your* login
password (PAM — TACACS-able later), logs the escalation, and the O-Node
judges the new uid with its own ceiling:

| seat | uid | ceiling | what a config line does |
|---|---|---|---|
| read (`>`) | 988 `virp-shell` | GREEN | reads execute; YELLOW/RED → proposal |
| admin (`#`) | 985 `virp-shell-admin` | YELLOW | reads execute; **YELLOW applies** (on IOS today that is `interface <name> description …` — see docs/notes/cisco-description-yellow-2026-09-15.md); RED → proposal |

| RED (`#`, via `enable red` / `enable 15`) | 984 `virp-shell-red` | RED | reads execute; **YELLOW and RED apply**; BLACK never |
| **own login (open seat)** — the wrapper runs the shell as *you* when your uid has its own policy row; no sudo, no `enable` | your uid | whatever your row says: `green` / `yellow` / `red` / **`black`** | `black` = **passthrough**: everything applies, `reload` and `write erase` included, confirmation prompts answered, every line chained under your name. ISE accounting with a hash chain behind it. |

`enable red` is a third seat, not a wider admin seat: the password is asked
again (even from `#`), the daemon judges uid 984, and every change made
there is chained under that uid — so a RED change is always attributable
to a deliberate escalation, never to routine work. `disable` returns to
the read seat from either.

BLACK never runs from any seat, and no seat can approve anything:
proposer and approver stay two people. Every `[GATE]` line and chain entry
carries the uid, so `show chain` / the daemon log show which seat did what.
`show whoami` prints the live seat, ceiling and verbs. A wrong password
lands you back at `>`. `disable` re-runs the shell as uid 988.

Note: session-local state (`show proposals`) does not cross the seat
boundary — the chain has it.

## Config mode — what actually happens

Each line in `(config-<device>)#` is ONE gated `execute` on that device.
There is no interface sub-mode: write full commands, e.g.
`interface Gi1/0/48 description uplink`.

| Gate classification | Result |
|---|---|
| GREEN (a read) | executes; signed output printed |
| YELLOW / RED (a change) | **not applied** — the gate files a signed proposal; you get `proposal_id` and the operator commands |
| BLACK | refused; no proposal |

uid 988's ceiling is GREEN, so the seat can never change a device by
itself. Applying a proposal is an operator act, as uid 1000:

```
virp-tool approve <proposal_id>
virp-tool apply   <proposal_id>
```

## Every gate reply

```
node_id 0x0a000a02  seq 687  tier GREEN  type device_output  scope local  at 2026-09-15T02:42:13Z
hmac 87053888..9debec96
<body>
HMAC present, not verified by this client (no O-Key at uid 988)
```

The trailer is fixed. The shell never prints VALID; verification is the
verifier's job (`virp-tool inspect`, docket).

## Scripting

`virp-shell -c 'show devices'` runs one line. Piped stdin works too
(`printf 'enable\nshow node\nexit\n' | virp-shell`). `--socket PATH` for
a non-default socket.

## Identity and policy

- uid 988 `virp-shell`, primary group `virp` (socket is group-rw), plus
  `systemd-journal` for `show log` / `show services`.
- Template row (`deploy/devices.template.json`): ceiling `green`, actions
  exactly `list_fleet health heartbeat chain_verify execute`
  (+ `list_sessions` on the daemon branch). `tests/test_virp_shell.py`
  fails the build if the shell's vocabulary and that row ever differ.
- Registry of every service uid: `docs/UID-REGISTRY.md`.

## Not built

- `enable` password (mode only; sudoers gates who may run the wrapper).
- Node-wide proposal listing (no read-only action exists for it).
- Device-side `?` help (the gate executes whole lines only).
