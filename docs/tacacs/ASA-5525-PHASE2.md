# Phase 2 — ASA-Lab as a governed device on node 313

Cisco ASA 5525-X, `ASA-Lab`, 10.0.0.253, governed by `virp-onode-home`
(10.0.0.13, node_id `0000000D`). Completed 2026-09-08 01:10Z.

Phase 0 decisions this is built on are in
[`ASA-5525-PHASE0.md`](ASA-5525-PHASE0.md#decisions-taken-at-this-gate);
accounting came up in [`ASA-5525-PHASE1-RUNBOOK.md`](ASA-5525-PHASE1-RUNBOOK.md).

---

## The row

`deploy/devices.home.template.json`, 40th device:

```json
{
  "hostname": "ASA-Lab",
  "node_id": 167772413,
  "host": "10.0.0.253",
  "vendor": "cisco_asa",
  "username": "aiops-svc",
  "password": "${VIRP_ASALAB_PASSWORD}",
  "port": 22,
  "asa_auto_enable": true
}
```

`ssh_legacy` is absent by decision, not omission. `enable` is absent because
`asa_auto_enable` declares the observed behaviour instead — which is also why
the enable-password rotation on 2026-09-08 needed no VIRP-side change.

`VIRP_ASALAB_PASSWORD` was added to `render-devices.sh`'s required-vars tuple
in the same commit. That tuple is a whitelist: a placeholder not named there is
never substituted and then trips the leftover check as **FATAL**, which stops
the daemon starting across all forty devices rather than degrading to one
unreachable firewall. Secret into `autopilot.env` first, template second.

## Restart — the trap, and what cleared it

Checked `systemctl is-active`, **not** the restart exit code.

```
is-active: active
01:07:59  [O-Node] WARNING: asa_auto_enable=true for ASA-Lab — no "enable"
          credential; the login must already land in enable mode (#14)
01:07:59  [O-Node] Added device: ASA-Lab (10.0.0.253) node_id=0x0a0000fd
01:07:59  [Chain] Detached Ed25519 chain signing ENABLED
          (scheme ed25519-detached-v1, key_id c1104805e1044d63a0c531eb7a025e68)
```

The `#14` line is a **WARNING, not a `Skipping`** — the declared exception was
accepted and the device loaded. A `Skipping ASA-Lab` line would have meant
`asa_auto_enable` failed to parse and the row was dropped. The signing line
carries the expected `key_id` and lands in the same second as the device add,
well inside the 30 s the trap allows.

## Connection

```
01:09:53  [Watchdog] Connecting: ASA-Lab (10.0.0.253)
01:09:54  [SSH] Prompt learned: device=ASA-Lab prompt='ASA-Lab#' ...
01:09:55  [ASA] Connected: aiops-svc@10.0.0.253:22 prompt='ASA-Lab#'
          enable=1 mode=1
01:09:55  [Watchdog] Connected: ASA-Lab
```

`enable=1 mode=1` is the whole Phase 0 pager argument resolving in one line.
The login landed in enable mode, so `asa_connect` took its ENABLE branch and
sent `terminal pager 0` and `terminal width 512`. Host key verification passed
silently against the pin written earlier
(`SHA256:HkGx2HW+0jcp7iSa1EQnMJnBlrW47ivLwmIBHzfYZZM`); with no
`-DVIRP_SSH_TOFU_DEFAULT` in a prod build, an unpinned key would have refused
the connection instead.

## The GREEN read

```
01:10:05  [GATE] mode=ENFORCE device=ASA-Lab driver=cisco_asa tier=GREEN
          threshold=GREEN uid=999 decision=allow command="show version"
01:10:05  [GATE] intent persisted: session=gate-enforce:ASA-Lab seq=0
          hash=9402cc6ee69f7545 tier=GREEN decision=auto-execute
01:10:07  [EXEC] device=ASA-Lab disposition=UNSET success=true exit=0
          exit_trusted=no truncated=no reason="-"
01:10:07  [GATE] execution persisted: session=gate-enforce:ASA-Lab seq=1
          hash=879165cd672426e1 tier=GREEN success=true
          response_sha256=52698b1f21966b4d
```

Client side: `trust_tier=GREEN (0x01)`, `seq=46`, `obs_type=0x07 (signed
observation)`, `signature=VALID`, `gate_decision=allowed`. Chain entries
`gate-enforce:ASA-Lab` sequences 0 and 1 — a new session, this device's first.

The payload came back **unpaged**: the full `show version` with no
`<--- More --->`. That is the `asa_auto_enable` chain of reasoning confirmed
from the output side as well as from `enable=1`.

## The pairing — and why the stated gate criterion cannot be met

The Phase 2 gate was written as *"obs and accounting record same second"*. **It
is unmeetable on this platform, and no configuration change makes it
meetable.** `show version` is a `show` command, so the ASA emits no accounting
record for it at all (`ASA-SHOW-UNACCOUNTED`). There is nothing to put in the
same second.

What the accounting stream does carry is **the session that executed it**:

| time (313 clock) | recorder | what it says |
|---|---|---|
| 01:09:53.584Z | ASA accounting | EXEC **START**, `user=aiops-svc`, `priv_lvl=1`, **`foreign_ip=10.0.0.13`** |
| 01:09:54.624Z | ASA accounting | STOP, `user=aiops-svc`, `priv_lvl=15`, **`cmd=terminal pager 0`** |
| 01:10:05.940Z | gate chain | `gate_intent`, `gate-enforce:ASA-Lab` seq 0, `command="show version"` |
| 01:10:07.410Z | gate chain | `gate_execution` seq 1, `success=true`, `response_sha256=52698b1f21966b4d` |
| — | ASA accounting | **nothing for `show version`** |

Both accounting records are `tacacs_accounting/2`, `client_identity: ASA-Lab`,
`client_identity_source: configured_by_source_address`, `decode:
OBFUSCATED_MD5`, `parse: COMPLETE`, `producer_key_id
0e3f34ab8a40d7d690d3005e79192584`.

**The honest restatement of the criterion: the observation pairs with the
SESSION record that carried it, not with a record of the command.** The gap is
~12 seconds, and it is structural rather than clock error — connect, learn
prompt, set pager, then execute. Any ASA timeline has to show that gap rather
than imply simultaneity.

Two things make the pairing stronger than a bare session record would be:

1. **`foreign_ip=10.0.0.13`.** The firewall independently records that the
   session came from the gate's own address. The gate's claim to have read this
   device is corroborated by the device naming the reader — not by name or
   credential, but by address, which is a statement about the network rather
   than about VIRP's configuration.

2. **`cmd=terminal pager 0` is the DRIVER's command, not a human's.** Nobody
   typed it. `driver_asa.c` emits it on the enable path, and the ASA accounted
   it. So the accounting stream corroborates the driver's internal behaviour
   from outside the gate — an independent check on a code path that is
   otherwise only visible in VIRP's own logs.

`ASA-SHOW-UNACCOUNTED` is now confirmed a third time, in a third setting: on
the console (Phase 1), on an interactive SSH session (Phase 1 gate), and now on
the gate's own automated session.

## Finding: the device runs 9.2(2)4, below the driver's stated range

```
Cisco Adaptive Security Appliance Software Version 9.2(2)4
Device Manager Version 7.2(2)1
System image file is "disk0:/asa922-4-smp-k8.bin"
Hardware: ASA5525, 8192 MB RAM, CPU Lynnfield 2394 MHz, 1 CPU (4 cores)
```

`include/virp_driver_asa.h` declares the driver is for **"ASA-OS 9.8.x through
9.20.x"**. This unit runs **9.2(2)4** — six minor versions below the floor —
and every driver behaviour relied on so far worked: prompt learning, enable
detection, `terminal pager 0`, `terminal width 512`, and the GREEN read.

Stated rather than fixed, because both readings are defensible and this run
does not settle which is right:

- the header range may be conservative, describing what was tested rather than
  what works; or
- this device is outside tested territory and something later — a scrub path,
  a YELLOW config read, a multi-context prompt — may behave differently.

Cisco documentation consulted for Phase 0 was the 9.16/9.19 General Operations
guides. The AAA semantics used here were confirmed empirically on 9.2(2)4
(command accounting excludes `show`; console lands at `ASA-Lab>` while SSH
auto-enables to `ASA-Lab#`), so the version gap has not misled us so far. It is
recorded because the next person to extend this driver should know the fleet
contains a device below its documented floor.

## Gate result

**PASSED**, with the criterion restated as above rather than met as written.

- Device loaded, refusal #14 cleared by declaration, signing ENABLED with
  `key_id c1104805` in the same second.
- Host key pin held; connection refused nothing.
- One GREEN read through the gate, `signature=VALID`, `gate_decision=allowed`,
  chained as `gate-enforce:ASA-Lab` seq 0/1.
- Paired with the accounting record for the session that carried it,
  attributable to 313 by `foreign_ip`.

## Carried into Phase 3

- **`aaa authorization exec LOCAL auto-enable` must become
  `authentication-server`.** With `LOCAL`, the ASA reads authorization
  attributes from the local database; `virp-ro` and `nhoward` will exist only
  on CT 215 with no local entry, so management authorization would deny them
  after a successful TACACS+ authentication. This line was not in the original
  Phase 3 plan and has to be.
- **The pager argument inverts.** `asa_auto_enable` works today because
  `aiops-svc` auto-enables to priv 15. `virp-ro` is intended to be priv 1, and
  a priv-1 session lands at `ASA-Lab>` where the driver does **not** send
  `terminal pager 0`. Either `virp-ro` gets priv 15 from CT 215 with
  `authentication-server auto-enable`, or the global `pager lines 0` from
  Phase 1 Block 1 has to carry it. Which of those holds is a Phase 3
  measurement, not an assumption.
- **`aaa accounting enable console VIRP-ACCT`** is configured on the device and
  was not in the Phase 1 runbook. It is kept: it records enable-mode
  transitions, which is the break-glass visibility `TACACS-ACCOUNTING.md` §9.2
  asks for.
- **Device clock.** Last measured 13m26s behind with NTP configured but not
  converged; one record carried `elapsed_time=-297153320`, a negative elapsed
  time from the clock stepping. It cannot corrupt ASA records (no device
  timestamp is carried) but it should be stable before a Phase 3 timeline is
  drawn.
- **`aiops-svc` is removed at Phase 3**, and the invariant to assert rather
  than assume is that `show running-config username` lists `admin` and nothing
  else.
