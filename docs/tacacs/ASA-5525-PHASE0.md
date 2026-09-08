# Phase 0 — ASA-5525 onto node 313, read-only survey

Cisco ASA 5525-X, `10.0.0.253`, device hostname `ASA-Lab`. Survey run
2026-09-07. **No contact was made with the ASA.** Everything below comes from
the VIRP tree, from `virp-lab` (10.0.10.211) and `virp-onode-home` (10.0.0.13)
as read-only host reads, or from Cisco documentation cited inline.

This is the gate document for the work that follows: accounting (Phase 1),
governed device (Phase 2), authorization (Phase 3). Operator decisions taken at
this gate are recorded in [Decisions](#decisions-taken-at-this-gate) and the
later phases are written to them.

---

## 1. Driver survey

### The driver exists and is mature

`src/drivers/driver_asa.c`, `include/virp_driver_asa.h`, `src/drivers/parser_asa.c`,
plus `tests/test_driver_asa.c`, `test_driver_asa_scrub.c`,
`test_driver_asa_refusal.c`. Vendor string `cisco_asa` maps to
`VIRP_VENDOR_CISCO_ASA` at `src/virp_onode_prod.c:151`.

### GREEN table — 39 rows

Tally of `ASA_ROUTE_TABLE`: **39 GREEN, 17 YELLOW, 2 RED, 5 BLACK.**

GREEN, verbatim and in table order:

```
show version                 show interface               show resource usage
show interface ip brief      show interfaces              show processes
show interface brief         show ip address              show flash
show firewall                show ipv6 interface brief    show disk0
show failover                show arp                     show file system
show conn count              show mac-address-table       show ospf
show route                   show switch vlan             show bgp
show clock                   show xlate                   show eigrp
show cpu usage               show local-host
show memory                  show uptime
show xlate count             show blocks
show conn detail             show traffic
show conn                    show perfmon
show inventory
show module
show environment
show process
show nameif
```

Explicitly RED: `show aaa-server`, `show ssh sessions`. BLACK: `erase`,
`reload`, `delete`, `format`, `write erase`.

`configure terminal` is **RED by absence** — it appears in no row, and the
matcher's default is RED. That is the Phase 3 refusal cell.

### Matcher properties that constrain the CT 215 fence

From `asa_route_command` (`src/drivers/driver_asa.c:161-219`):

- **Case-sensitive** for GREEN/YELLOW/RED rows — the driver executes the
  caller's original bytes, so `SHOW VERSION` falls through to RED. BLACK rows
  alone match case-insensitively, because over-matching a deny list is the
  fail-closed direction.
- **Token boundary required** — a listed prefix can never stand in for a longer
  word. `show process` does not cover `show processes`; both are separate rows
  for that reason.
- **Longest valid match wins.**
- **Separator-carrying strings fail closed to RED** before any row is
  consulted (`virp_command_check_separators`), duplicating the daemon-boundary
  check because `asa_route_command` is directly callable.
- **Default is RED**, not YELLOW (`driver_asa.c:218`).

One stale comment: `include/virp_driver_asa.h` still documents the default as
`VIRP_TIER_YELLOW`. The code returns RED. Cosmetic drift, not a defect; not
touched by this work.

### `ssh_legacy` covers KEX and host key together — one flag

`driver_asa.c:518-528` sets four preferences in a single `if (device->ssh_legacy)`
block: `LIBSSH2_METHOD_KEX` = `diffie-hellman-group14-sha1`,
`LIBSSH2_METHOD_HOSTKEY` = `ssh-rsa`, and both `CRYPT_CS`/`CRYPT_SC` =
`aes256-cbc`. The ASA's `group14-sha1` + `ssh-rsa` are both inside that one
flag. **No second setting is needed.**

**It should nevertheless be left unset on this device, and there is measurement
behind that.** The driver's *non*-legacy path already offers
`diffie-hellman-group14-sha1` in its KEX list and `ssh-rsa` in its host-key
list. The only thing `ssh_legacy=true` changes for this unit is forcing the
cipher to `aes256-cbc`. `virp-lab`'s existing fleet row for this exact box
records a live negotiation from 2026-08-09:

> `ssh_legacy` is deliberately NOT set — verified 2026-08-09 from this node that
> the driver's default algorithm set negotiates with this unit (kex
> diffie-hellman-group14-sha1, hostkey ssh-rsa, cipher **aes256-ctr**; the ASA
> offers nothing newer and all three are in the default preference list).

Setting the flag would swap a measured, working combination for an unmeasured
one. This is the opposite of LAB-SWITCH-1, where legacy mode was required and
was tested before it was written down.

### Host-key pinning

`src/virp_ssh_hostkey.c`, called from `asa_connect` after
`libssh2_session_handshake()` and **before** authentication
(`driver_asa.c:555`). libssh2 known-hosts, file from `VIRP_KNOWN_HOSTS`,
default `~/.virp/known_hosts`; on 313 the `virp` account's home is
`/var/lib/virp`, so the file is `/var/lib/virp/.virp/known_hosts` — 40 entries
today, **none for 10.0.0.253**.

- MATCH → OK. MISMATCH → `VIRP_ERR_HOST_KEY_MISMATCH`, always fatal.
- NOT_FOUND → fatal **unless TOFU is on**, and TOFU is **off in prod builds**:
  `-DVIRP_SSH_TOFU_DEFAULT` is set only by the `dev` target
  (`Makefile:823-828`). `VIRP_SSH_TOFU=1` in the environment would override,
  and is not set on 313.

So the key must be pinned into that file before the fleet row goes live, or the
device simply fails to connect. The type mask is derived from the *key* type
(`LIBSSH2_HOSTKEY_TYPE_RSA` → `LIBSSH2_KNOWNHOST_KEY_SSHRSA`), not from the
signature algorithm, so a single `ssh-rsa` entry satisfies both an `ssh-rsa`
and an `rsa-sha2-*` negotiation. The `ssh_legacy` decision does not change what
has to be pinned.

### Pager handling is in the driver, but not on the path a priv-1 identity takes

`terminal pager 0` and `terminal width 512` are sent in exactly two places:
after a successful `enable` transition (`driver_asa.c:414-418`), and at connect
when the learned prompt is already `ASA#` or `ASA(config)#`
(`driver_asa.c:643-647`). The connect logic is:

```c
if (conn->current_mode == ASA_MODE_USER) {
    if (device->enable_password[0] != '\0') { asa_enter_enable(conn); }
} else if (ENABLE || CONFIG) { /* pager 0; width 512; relearn prompt */ }
```

A priv-1 `virp-ro` with no enable credential lands at `ASA>`, enters the first
branch, and the branch body is skipped because there is no enable password.
**The pager is never disabled on that path**, and `show version` returns paged
behind `<--- More --->`.

This is LAB-SWITCH-1's identity plan — priv 1, no enable — transplanted onto a
driver that assumes enable mode. It is a real difference between the two
devices and it is why Phase 1 carries a `pager` line that the 2960 work did not
need. See [Decision 2](#decisions-taken-at-this-gate).

### Load-time refusal #14 — `cisco_asa` only

`src/virp_onode_prod.c:984-1000`: a `cisco_asa` device with no `enable`
credential is **skipped at load** unless its row declares
`"asa_auto_enable": true`. The JSON key for the enable secret is `enable`,
mapped to `device.enable_password` at `virp_onode_prod.c:735`.

This refusal has no `cisco_ios` equivalent, which is why LAB-SWITCH-1's row
needed nothing like it. The Phase 2 row must carry either an enable secret or
that flag.

---

## 2. Cisco documented semantics

Sources:

- [ASA 9.16 General Operations CLI Configuration Guide — Management Access](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config/admin-management.html)
- [ASA 9.16 General Operations CLI Configuration Guide — AAA and the Local Database](https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config/aaa-local.html)
- [ASA Series Command Reference, A–H Commands — `aa`–`ac`](https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/aa-ac-commands.html)
- [ASA Series Command Reference, I–R Commands — `q`–`res`](https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/q-res-commands.html)
- [Cisco TAC doc 215792 — Analyze AAA Device Administration Behavior for ASA](https://www.cisco.com/c/en/us/support/docs/security/adaptive-security-appliance-asa-software/215792-analyze-aaa-device-administration-behavi.html)

### `aaa authentication ssh console <group> LOCAL`

Syntax: `aaa authentication {serial | enable | telnet | ssh | http} console {LOCAL | server_group [LOCAL]}`.

Authenticates SSH admin sessions against the named group. The trailing `LOCAL`
(case-sensitive) is a **fallback**, and it engages only when *no server in the
group responds*. A server that **rejects** does not trigger it: "If server 1
responds with an authentication failure (such as user not found), the ASA does
not attempt to authenticate to server 2."

### Serial console is a separate method list and can stay LOCAL

`aaa authentication serial console LOCAL` is independent of the `ssh` list. Yes
— console authentication can remain local while SSH goes to TACACS+. This is
the property the identity plan rests on.

### `aaa authorization exec {authentication-server | LOCAL} [auto-enable]`

Management authorization. Checks the authenticated user's service-type or
TACACS+ attributes to decide Full / Partial / No Access. `auto-enable` "lets
administrators who have sufficient authorization privileges enter privileged
EXEC mode automatically when they log in."

**Serial console is excluded from management authorization** — "Serial console
access is not included in management authorization" (Management Access chapter,
Additional Guidelines). Consequence: `auto-enable` has no effect on a console
login.

### `aaa authorization command <group> [LOCAL]`

Syntax: `aaa authorization command {LOCAL | tacacs+ server-tag [LOCAL]}`.
Authorizes **every command entered at the CLI**, including `show` commands.

With `LOCAL` appended: "if the TACACS+ servers in the group are all
unavailable, the local database is used to authorize commands based on
privilege levels." Without it: "command authorization requests will fail" when
the server is unreachable.

Local command authorization is by privilege level, and by default all commands
are level 0 or level 15.

### `aaa accounting command [privilege <level>] <server-tag>`

"Send[s] accounting messages to the TACACS+ accounting server when you enter
**any command other than show commands** at the CLI." The command reference and
the configuration guide agree on this wording.

**This is the central divergence from IOS** and it is recorded as a named
finding — see [§4](#4-named-finding-asa-show-unaccounted).

### `aaa accounting {serial | telnet | ssh | enable} console <server-tag>`

Generates records marking "establishment and termination of admin sessions" for
that access method. Session START/STOP only; no per-command content.

### In-progress SSH session when the TACACS+ server becomes unreachable

Cisco does not document this explicitly in the Management Access chapter, and
it is not asserted here. What the documentation *does* establish is that
authorization is evaluated **per command**, not once per session, so an
established session is not torn down when the server goes away — each
subsequent command is re-evaluated. Without `LOCAL`, those evaluations fail and
the session becomes a live prompt that refuses everything. With `LOCAL`, they
fall back to local privilege levels.

**Unverified. Must be measured on this box before Phase 3 is signed off**, with
the `reload in` net armed.

### `reload in` exists on ASA

Syntax: `reload [at hh:mm [month day | day month]] [cancel] [in [hh:]mm] [max-hold-time [hh:]mm] [noconfirm] [quick] [reason text] [save-config]`.
`reload cancel` cancels a pending reload; a reload already in progress cannot
be cancelled.

**The net works only because the ASA reloads to the *saved* configuration.** So
the rule for every block in every runbook here is: arm `reload in`, make the
change, verify it, `reload cancel`, and only then `write memory`. Never pass
`save-config`. This matches Cisco's own recovery advice: "Do not save your
configuration until you are sure that it works the way you want. If you get
locked out because of a mistake, you can usually recover access by restarting
the ASA."

The safety-net form used throughout:

```
reload in 10 noconfirm reason virp-tacacs-change
!   ... type the block, verify it ...
reload cancel
!   ... only once verified:
write memory
```

Note `reload` is BLACK in the driver's route table, so the gate can never issue
this. It is a console-only instrument by construction.

---

## 3. Lockout analysis

### The ASA is not the 2960, and the difference is where the console sits

On IOS, `aaa authorization commands` binds to a **line**, and the console line
can be left out of the list. That is what let `docs/TACACS-ACCOUNTING.md` §9.1
keep humans exempt while fencing the gate.

On ASA, `aaa authorization command` is a **global** switch. It has no line
scoping and no console keyword. The exemption ASA documents is for
*management* authorization (`aaa authorization exec`), not for *command*
authorization; Cisco TAC doc 215792 states command authorization "applies to
all the ASA sessions (serial console, ssh, telnet)."

**Therefore: with `aaa authorization command GRP` and no `LOCAL`, if CT 215
goes down the serial console is locked out too.** The operator would be holding
a console cable at a prompt that refuses every command, and the only documented
recovery is a reload to an unsaved configuration. This is why `reload in`
matters on this device and did not on LAB-SWITCH-1.

### The gate fails closed at authentication, not at authorization

The stated concern at the top of this work was: with LOCAL fallback on command
authorization, `virp-ro` could run anything if 215 is down, unless no LOCAL
`virp-ro` exists on the ASA. That is correct, and there is a second effect that
makes the guarantee stronger than asked for.

If there is no LOCAL `virp-ro`, then with 215 down `virp-ro` **cannot
authenticate at all**. Authentication fallback to LOCAL finds no such user and
the SSH login fails. The gate never reaches a prompt, so command authorization
is never consulted. The gate fails closed one layer earlier and for a simpler
reason.

### The hole that `LOCAL` on the SSH authentication line would open

With `LOCAL` on the SSH list and 215 down: local `admin` (priv 15)
authenticates over SSH, and command-authorization `LOCAL` fallback then
authorizes it by privilege level — everything. That is the IOS §9.3
self-escalation route reappearing on the ASA in a different shape.

`admin` is console-only only if SSH has **no local path** to it.

### Configuration that resolves it

| | setting | CT 215 up | CT 215 down |
|---|---|---|---|
| SSH authentication | `aaa authentication ssh console GRP-VIRPAZ` — **no `LOCAL`** | `virp-ro`, `nhoward` via 215 | **nobody can SSH in.** Gate fails closed; `admin` has no SSH path |
| serial authentication | `aaa authentication serial console LOCAL` | `admin`, local | `admin`, local — unaffected |
| command authorization | `aaa authorization command GRP-VIRPAZ LOCAL` | every command decisioned on 215 | console `admin` works via priv-15 local fallback |

Dropping `LOCAL` from the SSH authentication line is what makes "admin stays
console-only" true by construction rather than by convention. Keeping `LOCAL`
on the command-authorization line is what preserves the console break-glass
when 215 is down. The two lines pull in opposite directions on purpose.

### Identity plan

- **`admin`** — LOCAL on the ASA, priv 15, reachable **only** via the serial
  console. Not present on CT 215. Break-glass. Graded RED if it ever appears in
  accounting, under `BREAKGLASS_USED` per `docs/TACACS-ACCOUNTING.md` §9.2.
- **`nhoward`** — exists **only** on CT 215. Permit-all. Reaches the ASA over
  SSH.
- **`virp-ro`** — exists **only** on CT 215. Fenced to the 39-row ASA GREEN
  table with `\A…\z` anchors and the same deny on `;` and pipe modifiers as
  LAB-SWITCH-1. **No LOCAL `virp-ro` on the ASA, ever.**
- Nothing else in the ASA's local database.

**The invariant to assert, not assume.** The safety of the priv-15 path chosen
in [Decision 2](#decisions-taken-at-this-gate) rests entirely on "no LOCAL
`virp-ro` on the ASA." Phase 3 must check it rather than trust it:
`show running-config username` on the console must list `admin` and nothing
else. That read is not in the GREEN table, so it is an operator console read,
not a gate read.

---

## 4. Named finding: `ASA-SHOW-UNACCOUNTED`

**The ASA does not emit TACACS+ command accounting for `show` commands, at any
privilege level.** `aaa accounting command [privilege N]` accounts "any command
other than show commands." IOS 12.2(55)SE6 on LAB-SWITCH-1 accounts every
command including `show clock`, and the 2026-09-07 milestone's method depends
on that.

**Confirmed on hardware, 2026-09-07 23:57Z.** In one SSH session on ASA-Lab an
operator ran `show aaa-server VIRP-ACCT` and `terminal pager 24`. The ASA
emitted an accounting record for `terminal pager 24` (`user=admin`,
`priv_lvl=15`, `service=shell`) and **no record at all** for the `show`. The
finding is measured, not merely cited.

**A second gap found in the same decode: ASA accounting carries no device
clock.** The record bodies carry `task_id`, `elapsed_time`, `service`, `port`,
`foreign_ip`, `local_ip` — and no absolute device timestamp. There is no
`start_time` arg of the kind IOS 12.2(55)SE6 sends, which the 2026-09-07
milestone used (`start_time=1788815267` → 21:07:47Z) to place the switch's own
clock in the timeline. So on ASA the device column of a timeline is timed by
the receiver's chain timestamp — 313's clock — and must say so. The upside is
that device clock skew cannot corrupt an ASA record: this unit was found ~13
minutes slow, which on IOS would have poisoned every `start_time`.

Two consequences, both structural:

1. **A permitted GREEN read on the ASA has no device-side accounting record.**
   The three-column timeline that
   `docs/tacacs/MILESTONE-2026-09-07-model-in-loop.md` establishes becomes
   two-and-a-half columns for a `show` cell: gate observation on 313,
   authorization decision on 215, and nothing from the device's own accounting
   stream. What the accounting stream still carries is session
   establishment/termination via `aaa accounting ssh console`, and any non-show
   command.

2. **The cadence witness moves hosts.** The milestone's proof that nothing
   leaked past a refusal is an unbroken 60-second `show clock` cadence in the
   accounting log, continuing across the moment of the refusal. On the ASA that
   cadence will not exist in accounting. It *will* exist in CT 215's
   `authz.log`, because `aaa authorization command` **does** authorize `show`
   commands. So the witness survives — and it moves from a recorder on 313 to a
   recorder on a genuinely different host, which is a stronger exhibit than the
   2960's, not a weaker one.

The refusal cell is unaffected in either case: `configure terminal` is refused
at 313's ingress separator/tier check, so 215 has zero lines and accounting has
zero records, exactly as before.

This finding is recorded in the milestone doc as well, since it qualifies the
method that document establishes.

---

## 5. Which node should govern it

**313 (`virp-onode-home`, 10.0.0.13, node_id `0000000D`) should govern it, and
`virp-lab` should stop.** This is forced by the accounting design, not
preferred:

- The receiver keys sources by address (`recv.json` `relationships[].source_addr`).
- The ASA will send accounting to `10.0.0.13:4949`.
- The reconciler matches accounting records against gate observations **on the
  same node**.

If `virp-lab` keeps a session open, its reads produce ASA accounting records
that 313 receives and cannot match against any gate observation of its own.
They land in `UNGOVERNED` permanently. Split governance breaks the
corroboration argument that is the entire point of the exercise.

The device is also physically on the home LAN, which is where 313 is.

### `virp-lab`'s fleet row

From `/run/virp/devices.json` on 10.0.10.211 (44 devices), with credentials
redacted:

```json
{
  "_comment": "IronClaw colo fleet stage 1. The only stage-1 row with enable:
   the ASA driver enters (and re-enters) enable mode. ssh_legacy is
   deliberately NOT set — verified 2026-08-09 from this node that the driver's
   default algorithm set negotiates with this unit (kex
   diffie-hellman-group14-sha1, hostkey ssh-rsa, cipher aes256-ctr; the ASA
   offers nothing newer and all three are in the default preference list).",
  "hostname": "ASA-5525",
  "node_id": "0A0000FD",
  "host": "10.0.0.253",
  "vendor": "cisco_asa",
  "username": "aiops-svc",
  "password": "<redacted>",
  "enable":   "<redacted>",
  "port": 22
}
```

Same row in `/etc/virp/devices.template.json`, in
`/etc/virp/devices.template.stage2.json`, and in the repo at
`deploy/devices.template.json`.

**It is not a stale inventory entry — it is live.** From `virp-lab`'s journal:

```
Sep 07 16:17:36  [O-Node] Added device: ASA-5525 (10.0.0.253) node_id=0x0a0000fd
Sep 07 16:18:00  [Watchdog] Connected: ASA-5525
Sep 07 22:32:57  [SSH] Prompt learned: device=ASA-5525 prompt='ASA-Lab#' ...
```

The watchdog reconnects on a **~4m49s cadence** and has done so continuously.
It authenticates as `aiops-svc` and lands directly in enable mode. No autopilot
battery runs against it — `journalctl -u virp-autopilot` has no ASA-5525 lines
over the last day — so `virp-lab` holds a connection and reads nothing from it.

Two things follow. First, the device's real hostname is **`ASA-Lab`**, not
`ASA-5525`; the fleet row name and the device disagree, and 313's row is
written to the device's own name. Second, once Phase 1 lands, every one of
those reconnects emits an EXEC START/STOP for `aiops-svc` from 10.0.10.211 —
roughly twelve records an hour with no gate observation anywhere. That is why
the row is removed **before** Phase 1 rather than after.

The correction to an earlier assumption is worth stating: this row did not come
from the Aug 10 import. Its comment dates it to the IronClaw colo stage-1 set,
and the algorithm probe behind it is 2026-08-09.

---

## Decisions taken at this gate

Operator decisions, 2026-09-07. Later phases are written to these.

1. **`ssh_legacy` left unset** on the 313 row. The default algorithm set is
   measured working against this unit; forcing `aes256-cbc` would replace a
   measured combination with an unmeasured one.
2. **The pager is fixed in ASA configuration, not in the driver.** Global
   `pager lines 0`, typed on the console in Phase 1. If that does not take
   effect on an SSH session, the fallback is priv 15 for `virp-ro` via 215 exec
   authorization plus `"asa_auto_enable": true` on the fleet row. **No driver
   patch this run.**
3. **`aaa authentication ssh console GRP-VIRPAZ` with no `LOCAL`.** This is
   what makes `admin` console-only by construction. Command authorization keeps
   its `LOCAL` fallback so the console break-glass survives a 215 outage.
4. **Phase 1 gate restated** to option (i): one SSH session record pair plus
   **one non-show command** typed on that session, so `cmd` and `priv_lvl` are
   actually exercised. Two `show` commands would have produced zero command
   records — see `ASA-SHOW-UNACCOUNTED`.
5. **`virp-lab`'s row removed before Phase 1**, from both live templates and
   the repo template, with a restart. **Fleet hostname corrected to `ASA-Lab`**
   for the 313 row.
6. **`ASA-SHOW-UNACCOUNTED` accepted** as a structural property of the
   platform, recorded here and in the milestone doc, with CT 215's `authz.log`
   as the substitute cadence witness.

## Open items carried into later phases

- **Unverified:** what an established SSH session does when CT 215 becomes
  unreachable mid-session. To be measured in Phase 3 with `reload in` armed.
- **Unverified:** whether global `pager lines 0` suppresses paging on SSH
  sessions. Cisco documents the global `pager` command in terms of Telnet
  sessions; the Phase 1 runbook verifies it on an SSH session rather than
  assuming it. Decision 2's fallback exists for this.
- **To remove at Phase 3:** the ASA holds a local `aiops-svc` account — that is
  the identity `virp-lab` authenticated as, and it landed in enable mode. With
  the fleet row gone it is unused, and its enable secret is burned (below). It
  is a second local account with an SSH path and a known-bad credential, which
  is exactly what the identity plan says must not exist. Phase 3's invariant is
  that `show running-config username` lists `admin` and nothing else, so
  `aiops-svc` is removed there. Phase 1 leaves it alone because Phase 1 changes
  no authentication path.
- **To rotate:** the `aiops-svc` enable secret for this device was disclosed
  into a session transcript during this survey and should be treated as burned.
  It is `${LAB_ENABLE}` in `virp-lab`'s template and is changed on the ASA and
  in that node's `autopilot.env`. Not blocking Phase 1, because Phase 1 does
  not authenticate as `aiops-svc`; blocking nothing later either, because the
  account leaves the picture entirely at Phase 3.
