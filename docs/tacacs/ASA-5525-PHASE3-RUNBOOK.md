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

**So with `aaa authorization command GRP-VIRPAZ` and no `LOCAL`, if CT 215 goes
down your serial console is locked out too.** You would be holding a console
cable at a prompt that refuses every command, and the only documented recovery
is a reload to an unsaved configuration. This is why `reload in` is armed
throughout this runbook and was not needed on the 2960.

The resolution is **asymmetric on purpose**, and the two lines pull opposite
ways:

| | setting | CT 215 up | CT 215 down |
|---|---|---|---|
| SSH authentication | `aaa authentication ssh console GRP-VIRPAZ` — **no `LOCAL`** | `virp-ro`, `nhoward` via 215 | **nobody can SSH in.** Gate fails closed; `admin` has no SSH path |
| serial authentication | `aaa authentication serial console LOCAL` | `admin`, local | `admin`, local — unaffected |
| command authorization | `aaa authorization command GRP-VIRPAZ LOCAL` | every command decisioned on 215 | console `admin` works via priv-15 local fallback |

**Dropping `LOCAL` from the SSH authentication line is what makes "admin stays
console-only" true by construction rather than by convention.** With `LOCAL`
there, a 215 outage would let local `admin` in over SSH, and command
authorization's own `LOCAL` fallback would then authorize it by privilege
level — everything. That is the IOS §9.3 self-escalation route reappearing in
a different shape.

**Keeping `LOCAL` on the command-authorization line is what preserves the
console break-glass.** Without it, a 215 outage locks out the console as well.

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
- **`show clock`** against 313. As of the Phase 2 handover the ASA was
  **13m26s behind** with NTP configured but not converged. It cannot corrupt
  ASA accounting records (no device timestamp is carried) but the three-column
  timeline at the end of this runbook is unreadable with that skew. Fix it
  before Step 7.

---

## Step 2 — the authorization server group, and PROVE it before relying on it

```
configure terminal
 aaa-server GRP-VIRPAZ protocol tacacs+
 aaa-server GRP-VIRPAZ (management) host 10.0.0.215
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
test aaa-server authentication GRP-VIRPAZ host 10.0.0.215 username virp-ro password <virp-ro password>
```

`INFO: Authentication Successful` means key, interface, route and account are
all correct. Anything else — stop, fix, and do not proceed to Step 3. A failure
here is harmless; the same failure discovered in Step 3 is a lockout.

**Rollback (do Step 3's rollback first if both are in):**

```
configure terminal
 no aaa-server GRP-VIRPAZ (management) host 10.0.0.215
 no aaa-server GRP-VIRPAZ protocol tacacs+
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
 aaa authorization command GRP-VIRPAZ LOCAL
 aaa authentication ssh console GRP-VIRPAZ
end
```

Order within the block matters. Serial-console LOCAL is asserted **first**, so
the recovery path is explicit before anything else moves. SSH authentication
changes **last**, because it is the line that can lock you out.

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
 no aaa authorization command GRP-VIRPAZ LOCAL
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
