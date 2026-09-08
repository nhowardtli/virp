# Phase 3 runbook — authorization for ASA-Lab

Moves ASA-Lab from "governed, but authenticating as a local priv-15 service
account" to "every command decisioned on CT 215, and no local gate identity
exists at all".

Built on [`ASA-5525-PHASE0.md`](ASA-5525-PHASE0.md#decisions-taken-at-this-gate),
[`ASA-5525-PHASE2.md`](ASA-5525-PHASE2.md). Every ASA line is typed by the
operator on the **serial console**. The gate sends nothing to this device
except governed reads.

---

## READ THIS BEFORE TYPING ANYTHING — the lockout analysis

**The ASA is not the 2960, and the difference is where the console sits.**

On IOS, `aaa authorization commands` binds to a **line**, and the console line
can be left out of the list. That is what let `TACACS-ACCOUNTING.md` §9.1 keep
humans exempt while fencing the gate.

On ASA, `aaa authorization command` is a **global** switch with no line scoping
and no console keyword. The exemption ASA documents is for *management*
authorization (`aaa authorization exec`), not for *command* authorization;
Cisco TAC doc 215792 states command authorization "applies to all the ASA
sessions (serial console, ssh, telnet)".

**So with `aaa authorization command VIRP-AUTHZ` and no `LOCAL`, if CT 215 goes
down your serial console is locked out too.** You would be holding a console
cable at a prompt that refuses every command, and the only documented recovery
is a reload to an unsaved configuration. This is why `reload in` is armed
throughout this runbook and was not needed on the 2960.

The resolution is **asymmetric on purpose**, and the two lines pull opposite
ways:

| | setting | CT 215 up | CT 215 down |
|---|---|---|---|
| SSH authentication | `aaa authentication ssh console VIRP-AUTHZ` — **no `LOCAL`** | `virp-ro`, `nhoward` via 215 | **nobody can SSH in.** Gate fails closed; `admin` has no SSH path |
| serial authentication | `aaa authentication serial console LOCAL` | `admin`, local | `admin`, local — unaffected |
| command authorization | `aaa authorization command VIRP-AUTHZ LOCAL` | every command decisioned on 215 — **including the console's, as `enable_15`** | console works via priv-15 local fallback |

**Dropping `LOCAL` from the SSH authentication line is what makes "admin stays
console-only" true by construction rather than by convention.** With `LOCAL`
there, a 215 outage would let local `admin` in over SSH, and command
authorization's own `LOCAL` fallback would then authorize it by privilege
level — everything. That is the IOS §9.3 self-escalation route reappearing in
a different shape.

### CORRECTION, 2026-09-08 — `LOCAL` on command authorization is NOT the whole console story, and this caused a real lockout

The original analysis said: *"keeping `LOCAL` on the command-authorization line
is what preserves the console break-glass."* **That is true only for the case
where CT 215 is UNREACHABLE, and it is the less likely failure.** Two facts
were missed, and together they locked the console during the live switchover:

1. **The serial console does not present `admin`. It presents `enable_15`.**
   An unauthenticated console session on this ASA authorizes its commands as
   user `enable_15`, with no usable `rem-addr`. Cisco TAC doc 215792 says this
   about *accounting* — "command accounting will still show username
   `enable_15` instead of the real username" — and that sentence was quoted in
   the Phase 0 survey without following it through to **authorization**, which
   uses the same identity.

2. **`LOCAL` fallback engages on UNREACHABLE, never on DENY.** Cisco is
   explicit: fallback happens only when "no server in the group responds". A
   server that responds with a denial is a completed transaction, not a
   failure, so no fallback occurs.

Put together: with 215 **up** and no `enable_15` account on it, every console
command was sent to 215, denied for an unknown user, and **not** covered by
`LOCAL`. The console refused everything while the server was perfectly healthy.
The `LOCAL` keyword protects against the outage case and does nothing at all
about this one.

**The fix, applied on CT 215:** a `user enable_15` with a
`console_breakglass_profile` — **no source acl** (the console has no usable
`rem-addr` to test), `nas`-scoped to `asa_devices` so the identity is
meaningless on any other device, priv-lvl 15, permit-all. It is reachable only
from the console in practice: SSH must authenticate through 215 first, and no
password is defined for `enable_15`.

**This does not weaken the identity plan; it relocates the break-glass.** Every
command `enable_15` types is accounted by the ASA to 313 and grades
`BREAKGLASS_USED` / RED there, exactly as `admin` would have. What changed is
that the console's break-glass now depends on 215 holding an account — so the
honest statement of the failure modes is:

| CT 215 state | console |
|---|---|
| up, `enable_15` present | works, every command decisioned and graded RED |
| up, `enable_15` ABSENT | **locked out** — denied, and `LOCAL` does not cover it |
| unreachable | works, via `LOCAL` priv-15 fallback |

The middle row is the one that bit. `reload in` is the recovery for it, which
is why the net is armed from Step 2.

**The gate fails closed at AUTHENTICATION, not at authorization.** With no
LOCAL `virp-ro` on the ASA, a 215 outage means `virp-ro` cannot authenticate at
all — the login fails and command authorization is never consulted. That is a
stronger and simpler guarantee than relying on the authorization layer, and it
is why Step 6 removing `aiops-svc` is not optional tidying: it is the step that
makes the guarantee true.

---

## Already done on CT 215 — 2026-09-08

Recorded so the runbook is auditable. `tac_plus-ng -P` returned **rc=0** before
each reload, both reloads went through the guarded `tacacs-reload` script, the
daemon's **MainPID stayed 174** across both, and LAB-SWITCH-1's 60-second
`show clock` cadence continued unbroken through each (01:28:52 → 01:29:56 →
01:30:57, and 01:32:01 → 01:33:02). Backups
`tac_plus-ng.cfg.bak-20260908T012912Z-pre-asa` and `*-pre-privlvl`.

1. **`/etc/tacacs/green-asa.conf` installed** — 39 GREEN rows generated from
   `src/drivers/driver_asa.c` by `deploy/tacacs/gen-green-conf.py`, same
   `\A…\z`-anchored PCRE2 form as the 2960's `green.conf`, sharing the same
   `guard.conf` floor.

2. **`net asa_devices { address = 10.0.0.253/32 }`** declared before
   `virp_ro_profile`. A `net` object rather than the host name is **forced, not
   stylistic**: `host` blocks live in `secrets.conf`, which is included LAST so
   user blocks can reference profiles, so a host name is unresolvable at that
   point. Measured — `if (nas == ASA-Lab)` fails the parse with *"Expected a
   net or host name or an IP address/network in CIDR notation"*.

3. **`virp_ro_profile` is now device-scoped.** The `guard.conf` floor applies
   to every device; *which* commands are GREEN does not. The ASA branch sits
   **after** the guard, so an ASA permit cannot opt out of the metacharacter
   floor, and ends in `deny` so an ASA command can never fall through to the
   IOS table and be judged by the wrong driver's rules.

4. **`virp-ro` gets priv-lvl 15 on ASA-Lab, priv 1 everywhere else.** A
   deliberate divergence from the 2960 — see the argument in the config
   comment. In short: it costs nothing when 215 is down (no LOCAL virp-ro, so
   authentication fails first), the privilege level is a weak fence on ASA
   anyway because `aaa authorization command` asks 215 about every command
   including `show`, it is what makes the read work at all (a priv-1 session
   lands at `ASA-Lab>` where `driver_asa.c` never sends `terminal pager 0`),
   and it keeps the fleet row's `asa_auto_enable` declaration honest.

5. **`10.0.0.36` added to `net operator_sources`** — the operator ThinkPad.
   Without it `nhoward` fails at **authentication** with `AUTHC-FAIL-ACL`, not
   at authorization, because that acl is evaluated for authc as well. **It is
   DHCP-assigned, like 10.0.0.45, and both want FortiGate reservations**: the
   day either lease moves, that operator is refused on every enrolled device at
   once.

6. **`user enable_15` + `console_breakglass_profile`** — added during the live
   switchover, for the reason argued in the CORRECTION above. `nas`-scoped to
   `asa_devices`, no source acl, priv 15, permit-all.

**Naming note.** The `host` block on 215 is called **`ASA-5525`**, while the
fleet row, the accounting `client_identity` on 313 and this document all use
**`ASA-Lab`**. That is cosmetic and not a broken join: the `authorization log`
format writes `${nas}`, which renders the **address** (`10.0.0.253`), not the
block name, and the device-scoping match is `net asa_devices` on the address
too. Recorded so nobody later assumes the two names must agree, or "fixes" one
of them expecting a correlation to change.

### Still to do on 215 — the key, which is yours

`secrets.conf` holds shared secrets, so this is an operator step.

```sh
ssh root@10.0.0.35
pct exec 215 -- bash
umask 077
KEY=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-32)
cp -a /etc/tacacs/secrets.conf /etc/tacacs/secrets.conf.bak-$(date -u +%Y%m%dT%H%M%SZ)-pre-asa
cat >> /etc/tacacs/secrets.conf <<EOF

host ASA-Lab {
	address = 10.0.0.253/32
	key = $KEY
}
EOF
chmod 0600 /etc/tacacs/secrets.conf
/usr/local/sbin/tac_plus-ng -P /etc/tacacs/tac_plus-ng.cfg && echo "PARSE OK"
/usr/local/sbin/tacacs-reload $(systemctl show virp-tacacs-authz -p MainPID --value)
systemctl is-active virp-tacacs-authz
echo "$KEY"      # read it here, type it at the ASA console. Do not paste it anywhere else.
```

**A `host` block must exist before the ASA is pointed at 215**, or every
authorization request is refused for an unknown client and the gate stops
reading this device.

You also need `virp-ro`'s **login password** for Step 4 — it already exists in
`secrets.conf` as `user virp-ro`. It is the same identity LAB-SWITCH-1 uses, so
do **not** rotate it here; that would break the 2960.

---

## The safety net

Arm before Step 2 and leave armed until Step 7.

```
reload in 15 noconfirm reason virp-phase3
```

Re-arm as needed; each new `reload in` replaces the pending one. **Never pass
`save-config`.** The net only works because the ASA reloads to the *saved*
configuration — which is why `write memory` is the last line of this runbook
and not any earlier one.

Cancel only after the gate passes:

```
reload cancel
```

---

## Step 1 — baseline

```
show clock
show running-config aaa
show running-config aaa-server
show running-config username
show running-config pager
show nameif
```

Two things to read out:

- **`show running-config username`** — expect `admin` and `aiops-svc`. Record
  it; Step 6 has to reduce this to `admin` alone.
- **`show clock`** against 313. At the Phase 2 handover the ASA was **13m26s
  behind** with NTP configured but not converged. It cannot corrupt ASA
  accounting records — no device timestamp is carried, per Phase 1's second
  finding — but the three-column timeline at the end of this runbook is
  unreadable with that skew.

  **FINDING 2026-09-08 — NTP needed a default route on `management`.** The
  server was configured and reachable-looking, and still never synced, because
  the ASA had no route to it out the management interface. This is the *same*
  failure shape as the `aaa-server` `(INSIDE)`/`(management)` defect in Phase 1
  and it presents the same way: configured, plausible, silently doing nothing.
  Two pre-existing outside default routes were removed as part of the fix.
  **On this device, assume nothing management-plane works until its path out
  of `management` is proven.**

---

## Step 2 — the authorization server group, and PROVE it before relying on it

```
configure terminal
 aaa-server VIRP-AUTHZ protocol tacacs+
 aaa-server VIRP-AUTHZ (management) host 10.0.0.215
  key <the 32 characters from CT 215>
  server-port 49
 exit
end
```

**`(management)`, not `(INSIDE)`.** This is the defect that cost Phase 1 an
hour: the route to the 10.0.0.0/24 network is via `management`, the ASA accepts
a real-but-wrong nameif without complaint, and the only symptom is a rising
timeout counter. Confirm with `show route 10.0.0.215` before typing it.

**Port 49, not 4949.** 4949 is the accounting receiver on 313. CT 215 listens
on the standard port.

**Now prove the key and the path before anything depends on them** — this is
the step Phase 1 did not have and should have:

```
test aaa-server authentication VIRP-AUTHZ host 10.0.0.215 username virp-ro password <virp-ro password>
```

`INFO: Authentication Successful` means key, interface, route and account are
all correct. Anything else — stop, fix, and do not proceed to Step 3. A failure
here is harmless; the same failure discovered in Step 3 is a lockout.

**Test `virp-ro`, not `nhoward`, and know why.** `test aaa-server` sends
`0.0.0.0` as the remote address, so `nhoward` fails it with `AUTHC-FAIL-ACL` —
`operator_profile`'s acl compares the source against `operator_sources` and
`0.0.0.0` is not in it. **That failure is expected and is not a fault**;
measured 2026-09-08. `virp-ro`'s profile has no source acl, so it is the
identity that gives a meaningful answer here. The operator path is proven for
real in Step 5a, from an actual SSH session with a real source address.

**Rollback (do Step 3's rollback first if both are in):**

```
configure terminal
 no aaa-server VIRP-AUTHZ (management) host 10.0.0.215
 no aaa-server VIRP-AUTHZ protocol tacacs+
end
```

---

## Step 3 — the switchover

**This breaks gate reads of ASA-Lab until Step 4 completes**, and that gap is
unavoidable rather than sloppy: `aiops-svc` is local, the new authentication
list has no `LOCAL`, and creating a temporary local `virp-ro` is precisely what
the identity plan forbids. It is one device, failing closed, for a few minutes.

Keep the console session open the entire time.

```
configure terminal
 aaa authentication serial console LOCAL
 aaa authorization exec authentication-server auto-enable
 aaa authorization command VIRP-AUTHZ LOCAL
 no aaa authentication ssh console LOCAL
 aaa authentication ssh console VIRP-AUTHZ
end
```

Order within the block matters. Serial-console LOCAL is asserted **first**, so
the recovery path is explicit before anything else moves. SSH authentication
changes **last**, because it is the line that can lock you out.

**FINDING 2026-09-08 — the old SSH authentication line must be REMOVED first,
not overwritten.** `aaa authentication ssh console LOCAL` already existed on
this device (it is how `aiops-svc` and `admin` logged in through Phase 2).
Typing the new line on top of it does **not** replace it: the ASA refuses with

```
ERROR: Range already exists
```

and the old `LOCAL` line stays in force, which means the switchover silently
does not happen — you would be left believing SSH authenticates against 215
while it still authenticates locally. Hence the explicit `no` line above.

This is not the general ASA idiom: `aaa authorization exec` and
`aaa authentication serial console` **do** overwrite in place, which is why the
other lines in this block need no `no`. Only the `ssh console` list behaved
this way here.

**`aaa authorization exec authentication-server auto-enable` replaces
`aaa authorization exec LOCAL auto-enable`** and is not optional. With `LOCAL`,
the ASA reads authorization attributes from the local database; `virp-ro` and
`nhoward` exist only on CT 215 with no local entry, so they would authenticate
successfully and then be denied by management authorization. This line was not
in the original Phase 3 plan — it was found by reading `show running-config
aaa` during Phase 2.

**Rollback — type this from the console the moment anything looks wrong:**

```
configure terminal
 aaa authentication ssh console LOCAL
 no aaa authorization command VIRP-AUTHZ LOCAL
 aaa authorization exec LOCAL auto-enable
end
```

If the console itself is refusing commands, `reload` is the recovery — nothing
has been saved.

---

## Step 4 — move the fleet row to virp-ro

On 313. The placeholder **name** does not change; only its value and the
row's username.

```sh
cd ~/virp-wt/asa-5525
# edit deploy/devices.home.template.json: "username": "aiops-svc" -> "virp-ro"

sudo sed -i 's/^VIRP_ASALAB_PASSWORD=.*/VIRP_ASALAB_PASSWORD=<virp-ro password>/' \
     /etc/virp/autopilot.env
sudo grep -c VIRP_ASALAB_PASSWORD /etc/virp/autopilot.env    # must print 1

make install-devices-template VIRP_DEVICES_TEMPLATE_SRC=deploy/devices.home.template.json

sudo VIRP_RENDER_OUT=/tmp/probe.json /usr/local/lib/virp/render-devices.sh && \
  sudo python3 -c "import json;d=json.load(open('/tmp/probe.json'));print([(x['hostname'],x['username']) for x in d['devices'] if x['host']=='10.0.0.253'])"
sudo rm -f /tmp/probe.json
```

Expect `[('ASA-Lab', 'virp-ro')]`. **If the probe fails, stop** — nothing is
restarted and the running daemon is untouched.

**Restart trap applies.** Check `is-active`, never the start exit code, and
confirm the signing line within 30 s:

```sh
sudo systemctl restart virp-onode
systemctl is-active virp-onode
journalctl -u virp-onode --since "1 min ago" --no-pager \
  | grep -E "ENABLED|ASA-Lab|tier gate|Skipping"
```

Wanted: `active`, `Added device: ASA-Lab`, the `asa_auto_enable` **WARNING**
(not a `Skipping` line), and `Detached Ed25519 chain signing ENABLED … key_id
c1104805e1044d63a0c531eb7a025e68`.

---

## Step 5 — the tests, in order

**5a. `nhoward` login, decisioned on 215.** From the ThinkPad (10.0.0.36 —
added to `operator_sources` for exactly this):

```
ssh nhoward@10.0.0.253
show version
exit
```

On 215: `tail /var/log/tacacs/authz.log` must show `nhoward` … `operator_profile`
… `permit` … `show version`. And `access.log` must show `AUTHC-PASS`, not
`AUTHC-FAIL-ACL` — the latter means the source address is wrong.

**5b. `virp-ro` through the gate, permitted.**

```sh
sudo -u virp /usr/local/lib/virp/virp-tool exec ASA-Lab "show version"
```

Expect `trust_tier=GREEN`, `signature=VALID`, `gate_decision=allowed`, and
output that is **not paged** — no `<--- More --->`. Paged output means the priv
15 / auto-enable path did not take, and Step 6 must not proceed until it does.

On 215, one `AUTHZ-PASS` for `virp-ro` … `virp_ro_profile` … `show version`.
**Note the exact `cmd` string**: whether the ASA appends ` <cr>` like IOS is
unmeasured, and this is the log that settles it. `green-asa.conf` accepts both
forms, so either way it permits — but the answer belongs in the record.

**5c. `configure terminal` through the gate, refused RED, switch never asked.**

```sh
sudo -u virp /usr/local/lib/virp/virp-tool exec ASA-Lab "configure terminal"
```

`configure terminal` is **RED by absence** — it appears in no row of
`ASA_ROUTE_TABLE` and the matcher's default is RED. The gate must refuse it
**before anything leaves 313**, and the proof is two absences:

- **zero** new lines in 215's `authz.log` for that command, and
- **zero** new ASA accounting records on 313.

Capture the `authz.log` lines either side of the refusal. On the 2960 the
witness was the unbroken 60-second `show clock` cadence in the *accounting*
log; on the ASA that cadence lives in **215's authorization log** instead,
because ASA accounts no `show` commands but 215 authorizes them
(`ASA-SHOW-UNACCOUNTED`). Same argument, different recorder — and on a
genuinely different host, which is the stronger position.

**5d. The Spark console cells.** Cell 1 identical to the 2960's cell 1; then
the RED cell.

---

## Step 6 — remove `aiops-svc`, and assert the invariant

Only after 5b passes. This is the step that makes the fail-closed guarantee
true rather than conventional.

```
configure terminal
 no username aiops-svc
end
show running-config username
```

**`show running-config username` must list `admin` and nothing else.** No
LOCAL `aiops-svc`, no LOCAL `virp-ro`. Assert it, do not assume it — this read
is not in the GREEN table, so it is a console read, not a gate read.

Re-run 5b afterwards to confirm the gate still reads the device.

**Rollback:** re-create `aiops-svc` with a fresh password and point the fleet
row back at it. Note its old password is now only in 313's `autopilot.env`, and
its enable secret was rotated 2026-09-08.

---

## Step 7 — close out

```
reload cancel
write memory
```

Only once Step 5 has passed and Step 6's invariant reads clean.

---

## Test results — 2026-09-08 02:52Z–02:56Z

### 5b — GREEN read, permitted

```
device=ASA-Lab command="show version"
trust_tier=GREEN (0x01)  seq=105  obs_type=0x07 (signed observation)
signature=VALID
gate_decision=allowed
```

Output **unpaged** — `grep -c "More"` over a full `show version` returns 0.
CT 215: `02:55:53 … virp-ro … virp_ro_profile permit shell show version
AUTHZ-PASS`.

### 5c — RED refusal, both other recorders silent

```
device=ASA-Lab command="configure terminal"
trust_tier=RED (0x03)  seq=110  obs_type=0x0f (ERROR — signed rejection, nothing executed)
gate_decision=blocked
ERROR: tier gate blocked 'configure terminal' on 'ASA-Lab' (tier=RED max=GREEN)
       proposal_id=2ebb7593abec1abdede11f5a913578d8
```

Refused at 02:56:01. **CT 215 has no line for `configure terminal` at all** —
its decisions either side are `02:55:54 show version` and `02:56:09 show
clock`. **313 has no accounting record** — the last one is the EXEC START at
02:52:04. Two empty cells, same finding as the 2960.

The cadence witness works as designed and on the recorder the Phase 1 finding
predicted: 215's authorization log carries an unbroken `show clock` rhythm
across the refusal — 02:55:50, 02:56:09, 02:56:27, 02:56:46 — on a different
host from the gate. The accounting log could not have provided it, because the
ASA accounts no `show` commands.

### Settled: the ASA does NOT send `<cr>`

215 logs the command as `show version`, not `show version <cr>`. IOS on
LAB-SWITCH-1 logs `show clock <cr>`. This was flagged as an open measurement
in `green-asa.conf`'s header and in Step 5b; it is now answered. The generated
rules make the terminator optional, so they were correct for both platforms —
but the reason they are correct is now measured rather than hoped.

### Confirmed: `enable_15` console commands are accounted and attributable

313's chain carries the console work under `user=enable_15`, e.g.
`cmd=route management 0.0.0.0 0.0.0.0 10.0.0.1 1`, `cmd=ping management
8.8.8.8`, `cmd=write`. The break-glass identity is fully visible in the
accounting stream and grades `BREAKGLASS_USED` / RED, which is what makes
relocating the break-glass to `enable_15` acceptable rather than a hole.

The console lockout is also visible in 215's denial log as its own artefact —
`show running-config`, `show running-config aaa`, `end` and `exit` denied for
the console before `user enable_15` existed.

---

## Finding `ASA-DRIVER-SETUP-UNAUTHORIZED`

**CT 215 denies `terminal pager 0`, which the driver issues itself on every
connect.** Observed three times, once per gate connection:

```
02:52:05 10.0.0.253  virp-ro  22  10.0.0.13  virp_ro_profile  deny  shell  terminal pager 0  AUTHZ-FAIL
03:00:17 10.0.0.253  virp-ro  22  10.0.0.13  virp_ro_profile  deny  shell  terminal pager 0  AUTHZ-FAIL
```

**Why it happens.** `gen-green-conf.py` derives the permitted set from the
driver's **gate table** — the commands a *caller* may ask the gate to run.
`driver_asa.c` also issues commands of its own as transport conditioning
(`terminal pager 0`, `terminal width 512` on the enable path; `exit` on
teardown). Those never traverse the gate and are in no tier table, so the
generated policy has no rule for them and the trailing `deny` catches them.
The gate and the policy server do not disagree about what GREEN means — they
disagree about whether the driver's own housekeeping is a command at all. The
ASA has no such category: it authorizes every line.

**Why it is harmless here.** Global `pager lines 0` is configured on this
device, so paging is already off and the denied command was redundant. Measured
above: a full `show version` through the gate returns unpaged. Note the
denial also means the command is never executed, so — unlike Phase 2, where it
was permitted and produced `cmd=terminal pager 0` in accounting — there is now
no accounting record for it either.

**Why it is not nothing.** It writes an `AUTHZ-FAIL` into the decision log on
every single gate connection, shaped exactly like a real policy violation. That
is the log a reader consults to establish that nothing leaked past a refusal,
and a permanent benign denial in it trains readers to skim denials. It also
means the "215 is silent" argument for a refused cell needs a caveat, which is
precisely the kind of caveat that erodes an evidence claim.

**Scope: it is a class, not one command.** `exit` is denied on the same
grounds (observed for `aiops-svc` at 02:50:09). `terminal width 512` does not
appear in the log at all, permitted or denied, and no claim is made here about
why — it was not investigated.

### Decision: the driver stops sending it. The generator does NOT widen.

**Rejected — adding driver setup commands to the generated permit set.** It
would make the authorization server **looser than the gate**: `terminal pager
0` is RED-by-absence in `ASA_ROUTE_TABLE`, so the gate refuses it from any
caller, and 215 would then permit a command the gate itself would not. The
whole point of generating the policy from the driver table is that the two
cannot silently disagree, and `check_no_green_shadows_worse` exists to stop the
policy admitting more than the gate does. Buying log tidiness by inverting that
relationship is the wrong trade, especially when the functional need is already
met by `pager lines 0`.

**Chosen — the driver should not send a pager command to a device whose pager
is already disabled**, declared per device in the same idiom as
`asa_auto_enable`: a row-level flag (working name `asa_pager_preset`) meaning
*this device has `pager lines 0` globally; do not issue the session command*.
That keeps the fence exactly equal to the gate table, removes the recurring
denial, and — like `asa_auto_enable` — makes the driver's behaviour follow an
operator's declaration about the device rather than a guess.

It is deliberately **not** "skip the pager when the pager is already 0" as a
runtime check: reading the current setting means `show running-config pager`,
which matches the YELLOW `show running-config` prefix and would itself be
refused. The declaration avoids needing to ask.

**Not implemented this run.** Phase 0 Decision 2 said no driver patch, and that
still holds; this is the change that decision deferred, now with a measured
reason to make it. **Interim state: the denial stands and is documented**, and
any reader of 215's log for this device should expect exactly one benign
`terminal pager 0` `AUTHZ-FAIL` per gate connection. Anything else denied is
real.

---

## Bundle

`spark-asa-tacacs-<date>`, same exhibit shape as `spark-2960-tacacs-20260907`,
verified with the 0.1.3 release asset
(`virp-verify-x86_64`, SHA-256
`8970b4c96a629b84dad841d89ed988fe39b7ec87e83e23c08df46d20aeda8736`), pinned to
chain key `c1104805e1044d63a0c531eb7a025e68`, then loaded into the face.

**The exhibit set differs from the 2960's in one documented way**, and the
bundle README must say so rather than let a reader assume parity: the permitted
cell's third column carries no device-side record of the command, because the
ASA accounts no `show` commands. What it carries instead is the **session**
record — attributable to 313 by `foreign_ip=10.0.0.13` — and the cadence
witness for the refused cell moves from the accounting log to CT 215's
`authz.log`.

## Three-column timeline shape for the permitted cell

| gate observation (313) | 215 authz decision | 313 accounting |
|---|---|---|
| `[GATE] … device=ASA-Lab driver=cisco_asa tier=GREEN decision=allow command="show version"` | `… virp-ro … virp_ro_profile permit shell show version … AUTHZ-PASS` | EXEC START, `user=virp-ro`, `foreign_ip=10.0.0.13` — **the session, not the command** |

And for the refused cell, the two empty cells are the finding:

| gate observation (313) | 215 authz decision | 313 accounting |
|---|---|---|
| separator/tier rejection persisted, `executed=no` | **nothing** — with the `show version` cadence unbroken either side | **nothing** |
