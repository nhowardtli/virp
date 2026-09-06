# Runbook — pointing the GNS3 fabric at the VIRP authorization server

**Status: DERIVED, NOT APPLIED.** No Cisco device was touched producing
this. Every line below is typed by an operator from this runbook. The
fabric (R1–R35) was powered off throughout and remains so.

| | |
|---|---|
| Authorization + authentication server | **10.0.0.215 port 49** (CT 215 `virp-tacacs`, pve-lab) |
| Accounting receivers — **do not change** | 313 at **10.0.0.13:4949**, .211 at **10.0.10.211:4949** |
| Identities | `virp-ro` (priv 1), `virp-rw` (priv 15). No human accounts. |
| Shared key | `/etc/tacacs/secrets.conf` on CT 215, `host gns3_home_fabric`. 0600 root. Read it there. |
| Fabric addressing | R*n* = `10.0.0.(49+n)`; R1 = `.50` … R35 = `.84` |

This server does **authentication and authorization only**. It has no
`accounting log` directive and must never get one — §9.4 of
`TACACS-ACCOUNTING.md` depends on accounting surviving an authorization
outage, and that only holds while they are separate processes on
separate addresses.

---

## 0. Before you type anything

**Arm the reload first.** Every step below can lock you out of the vty.

```
reload in 10
```

Confirm when prompted. If you lose the session, the device reverts to its
last saved config in ten minutes. **Do not `write memory` until §5 says
so.** When the change is verified:

```
reload cancel
```

Re-arm (`reload in 10`) before each device. Ten minutes is per-device, not
per-session.

**One device first.** Do R1 end to end, verify §4, then the rest.

---

## 1. The shared key

Read it off the server; it is not printed in this file.

```
ssh root@10.0.0.35
pct exec 215 -- grep -A40 'host gns3_home_fabric' /etc/tacacs/secrets.conf | grep 'key ='
```

The `host gns3_home_fabric` block lists `10.0.0.50`–`10.0.0.84`
individually. A router outside that range is refused at the server
regardless of key, so if you add R36 you must add its address there and
`tacacs-reload`.

---

## 2. IOS 15.x (the GNS3 fabric — 7206VXR / c7200, IOS 15.2(4)M7)

This is the platform §7.3 of `TACACS-ACCOUNTING.md` was measured on.

```
! --- ARM FIRST (§0) ---
! reload in 10
!
configure terminal
!
! aaa new-model must come first: none of the "tacacs server" block
! parses without it, and it is also the line that puts login under AAA.
! The CONSOLE list below is created in the SAME change for that reason.
aaa new-model
!
! --- the authorization server (this is the new one) ---
tacacs server VIRP-AUTHZ
 address ipv4 10.0.0.215
 port 49
 key <key from §1>
!
! --- accounting receivers: UNCHANGED, listed so you do not remove them ---
tacacs server VIRP-ACCT-313
 address ipv4 10.0.0.13
 port 4949
 key <existing accounting key — do not rotate>
!
tacacs server VIRP-ACCT-211
 address ipv4 10.0.10.211
 port 4949
 key <existing accounting key — do not rotate>
!
aaa group server tacacs+ GRP-VIRPAZ
 server name VIRP-AUTHZ
!
aaa group server tacacs+ GRP-VIRPACCT
 server name VIRP-ACCT-313
 server name VIRP-ACCT-211
!
! --- AUTHENTICATION ---
! The gate authenticates against the authorization server.
! Humans authenticate LOCALLY on the console and are never sent here.
aaa authentication login VIRPNET group GRP-VIRPAZ
aaa authentication login CONSOLE local
!
! --- AUTHORIZATION ---
! NOTE: no "local" and no "none" as a fallback method on the vty list.
! §9.3 measured that IOS cannot scope a local fallback to a user: the
! method binds to the LINE and authorizes whoever reaches it, including
! the gate. A fallback here is a gate self-escalation route, not a
! safety net. If this server is down the gate stops, which is intended.
aaa authorization exec VIRPNET group GRP-VIRPAZ
aaa authorization commands 1  VIRPNET group GRP-VIRPAZ
aaa authorization commands 15 VIRPNET group GRP-VIRPAZ
!
! Humans on the console are EXEMPT from authorization entirely (§9.1).
! Authentication is "local", NOT "none": §7.3 measured that a console
! authenticating with "none" produces NO command accounting at all,
! because there is no AAA user to attribute a command to.
aaa authorization exec CONSOLE none
aaa authorization commands 1  CONSOLE none
aaa authorization commands 15 CONSOLE none
!
! --- ACCOUNTING: unchanged, still pointed at 313 and .211 ---
aaa accounting commands 1  default start-stop broadcast group GRP-VIRPACCT
aaa accounting commands 15 default start-stop broadcast group GRP-VIRPACCT
!
! --- lines ---
line con 0
 login authentication CONSOLE
 authorization exec CONSOLE
 authorization commands 1  CONSOLE
 authorization commands 15 CONSOLE
!
line vty 0 4
 login authentication VIRPNET
 authorization exec VIRPNET
 authorization commands 1  VIRPNET
 authorization commands 15 VIRPNET
 transport input ssh
!
end
```

### The address-collision trap

**IOS keys TACACS+ servers by address alone** (§7.3, measured). A second
server block at an address the device already has is refused even on a
different port, the address is silently dropped, and
`show running-config` still looks correct while the server can never send
a packet.

The three addresses above — `10.0.0.215`, `10.0.0.13`, `10.0.10.211` —
are distinct, so they coexist. **Verify with `show tacacs`, never with
`show running-config`:**

```
show tacacs | include Server|address
```

Any `Server address: UNKNOWN` means that block is dead.

---

## 3. Cisco 2960, IOS 12.2 — what differs

**You decide separately whether the 2960 gets authorization.** This
section is what to type *if* you decide it does. Authentication and
accounting alone are the smaller change and are listed first.

Four differences, and the first is the one that breaks a copy-paste:

1. **No named `tacacs server` block.** That syntax is 15.x/IOS-XE only.
   12.2 uses the legacy global form, and the key is on the same line:

   ```
   tacacs-server host 10.0.0.215 port 49 key <key from §1>
   ```

   `aaa group server tacacs+` then references it **by address, not by
   name**:

   ```
   aaa group server tacacs+ GRP-VIRPAZ
    server 10.0.0.215
   ```

2. **`aaa authorization commands 1` may not exist** on older 12.2 images
   — some support only `commands 15`. Check `aaa authorization commands ?`
   before relying on level 1. If only 15 is available, per-command
   authorization on that box covers config-level commands and **not**
   `show` commands, which is a materially weaker control than the 15.x
   fabric gets. That is a reason to decide the 2960 does *not* get
   authorization, rather than to pretend it has the same coverage.

3. **`ip tacacs source-interface` matters more here**, because a 2960's
   management address is often an SVI. If it is set, the server sees the
   *sourcing* address — which must be inside `host gns3_home_fabric` on
   the server or the request is refused. Read it off `show tacacs`.

4. **`transport input ssh` may be unavailable** without a crypto image.
   If the box is telnet-only, its vty credentials cross the wire in
   clear, and pointing it at this server publishes `virp-ro`'s password
   to anyone on the segment. **Do not enrol a telnet-only device.**

The 12.2 `show` verb is also older: use `show tacacs` (same) but expect a
different field layout; the check is still "is there a real address".

---

## 4. Verify, before `write memory`

On the device:

```
show tacacs | include Server|address
show aaa servers | include TACACS|10.0.0.215
```

Then, from the authorization server, watch the decision land:

```
ssh root@10.0.0.35
pct exec 215 -- tail -f /var/log/tacacs/authz.log
```

Log in as `virp-ro` from the gate and run one permitted and one denied
command. You must see both, one line each:

```
... virp-ro ... virp_ro_profile  permit  shell  show version <cr>
... virp-ro ... virp_ro_profile  deny    shell  configure terminal <cr>
```

**A denial appears only here.** The router does not account a command it
refused to run, so accounting on 313 and .211 will show the permitted
command and nothing at all for the denied one. That is expected and is
the reason this log exists.

Confirm accounting is still flowing to both receivers — the permitted
command should appear on 313 and .211 as before. If it does not, stop:
you have changed accounting, which this runbook must not do.

---

## 5. Commit or back out

Verified:

```
reload cancel
write memory
```

Not verified, or you lost the session: **do nothing.** The armed reload
returns the device to its last saved config. Then re-read §2.

---

## 6. Backing a device out afterwards

Once written, the reload no longer saves you. On the console:

```
configure terminal
line vty 0 4
 no authorization commands 15 VIRPNET
 no authorization commands 1  VIRPNET
 no authorization exec VIRPNET
 login authentication CONSOLE
end
write memory
```

Removing authorization from the vty is enough to restore access; leave
`aaa new-model` and the accounting lines alone, since removing
`aaa new-model` also removes accounting and that is the thing this whole
programme is protecting.

---

## 7. What this runbook deliberately does not do

- **No `local` or `none` fallback on any vty authorization list.** §9.3,
  measured: IOS binds the method to the line, not the user, so any
  fallback the operator can reach the gate can reach too. A network
  break-glass path is a gate self-escalation route and is not shipped.
  Break-glass is the console, and only the console.
- **No change to accounting.** Both receivers stay exactly as they are.
- **No `aaa authorization config-commands`.** Adding it sends every line
  typed inside `configure terminal` for authorization, which with an
  empty `approved.conf` stops the gate mid-config with a half-applied
  change. Revisit once the approved.conf writer exists and can grant a
  whole config block.
