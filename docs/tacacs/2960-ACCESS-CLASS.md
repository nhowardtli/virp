# LAB-SWITCH-1 (2960, IOS 12.2) — vty access-class

Restrict which addresses may open a VTY session on the 2960 to 313
(`10.0.0.13`) and the operator Mac (`10.0.0.45`). The console stays
exempt and is the recovery path.

Device: `WS-C2960-24TC-L`, `IOS 12.2(55)SE6`, `10.0.0.10`.

---

## 0. DO THIS FIRST — the DHCP reservation

**`10.0.0.45` is DHCP-assigned. Reserve it on the FortiGate before you
apply anything below.**

An `access-class` permitting `10.0.0.45` is only as stable as that
lease. The day it moves, you are locked out of the VTY of every device
carrying this ACL, simultaneously, with no warning and no obvious cause —
the switch will simply refuse the connection, and `show running-config`
will look perfectly correct.

This is the same failure the `tac_plus-ng` `net operator_sources` rule
has, and it bites the same day. Reserve the address once and both
controls become stable.

The console remains exempt, so this is recoverable — but only if you can
physically reach the console.

---

## 1. Before you touch anything — record the current state

```
show running-config | include ^line vty|access-class
show line | include VTY
show users
```

`show users` matters: it tells you which line **you** are on. If it says
`vty`, you are about to modify the path you are sitting on. Prefer the
console for this change.

**The 12.2 `| section` filter does not exist on this train.** Use
`| include` or `| begin`.

---

## 2. Count your VTYs — the mistake that leaves a door open

```
show running-config | include ^line vty
```

Older configs commonly have **two** blocks:

```
line vty 0 4
line vty 5 15
```

If both exist you must apply `access-class` to **both**. Applying it to
`line vty 0 4` alone leaves lines 5–15 unrestricted, and an attacker
simply lands on one of those — the config *looks* protected and is not.

If `show running-config` shows only `line vty 0 4`, lines 5–15 may still
exist but be unconfigured; `show line | include VTY` lists what the box
actually has.

---

## 3. Build the ACL — numbered, not named

```
configure terminal
access-list 10 remark VIRP vty ingress -- 313 + operator Mac
access-list 10 permit 10.0.0.13
access-list 10 permit 10.0.0.45
access-list 10 deny   any log
end
```

**Numbered, deliberately.** `access-class` on 12.2 reliably accepts a
numbered standard ACL (1–99). Named-ACL support in `access-class` varies
by train, and this is not the moment to discover yours is one that does
not. If you prefer a name, confirm first with:

```
line vty 0 4
 access-class ?
```

`deny any log` is explicit although the implicit deny would refuse
anyway — the point is the log line. Without it a refused login is
invisible and indistinguishable from a network problem. If the switch
logs too noisily, drop `log`, not the `deny`.

### Check before applying

```
show access-lists 10
```

You should see exactly two permits and one deny. **Read the addresses
back.** An ACL with a typo in it applies just as cleanly as a correct
one, and the failure arrives only when you disconnect.

---

## 4. Apply — one block at a time, checking between

```
configure terminal
line vty 0 4
 access-class 10 in
end
```

Check immediately, **before touching the second block**:

```
show running-config | include ^line vty|access-class
```

Then, from the Mac, in a **separate window, leaving your console session
open**:

```
ssh admin@10.0.0.10
```

If that succeeds, the ACL permits you. Only now do the second block:

```
configure terminal
line vty 5 15
 access-class 10 in
end
show running-config | include ^line vty|access-class
```

Verify from 313 as well, since it is the address that matters for the
gate:

```
ssh nhoward@10.0.0.13 'timeout 5 bash -c "exec 3<>/dev/tcp/10.0.0.10/22" && echo reachable'
```

---

## 5. Confirm the console is still exempt

`access-class` applies to VTY lines only — it does not touch `line con 0`.
Confirm nothing has attached itself to the console:

```
show running-config | begin line con 0
```

You want no `access-class` under `line con 0`. Combined with the AAA
posture (`authorization commands N CONSOLE none`, see
`docs/TACACS-ACCOUNTING.md` §9.1), the console remains reachable and
unauthorized-by-design. **That is the recovery path for everything on
this page.**

---

## 6. Rollback

From the console, per block:

```
configure terminal
line vty 0 4
 no access-class 10 in
line vty 5 15
 no access-class 10 in
end
```

And to remove the ACL entirely:

```
configure terminal
no access-list 10
end
```

**Do not `write memory` until a VTY session has actually succeeded from
both permitted addresses.** An unsaved bad ACL is cleared by a power
cycle — and this lab has lost power twice in one day, which is a
recovery path, not a joke. A saved bad ACL survives the reboot and needs
the console.

---

## 7. What this does and does not protect

**Does**: refuses TCP from any source other than the two named, before
authentication. An attacker on the segment cannot reach the login prompt.

**Does not**:

- **Protect the console.** Physical access still wins, by design.
- **Authenticate anything.** `access-class` is an address filter. The
  TACACS+ identity controls are separate and independent.
- **Survive address reuse.** If `10.0.0.45` is ever handed to another
  host by DHCP, that host inherits VTY reach. §0 exists for this reason.
- **Stop a spoofed source address.** It is a filter on a claimed source.
  A determined on-segment attacker can forge one; they will not complete
  a TCP handshake easily, but do not read this as cryptographic.

## Relationship to the tac_plus-ng rule

Two controls, deliberately separate, and they fail differently:

| | `access-class` (here) | `net operator_sources` (tac_plus-ng) |
|---|---|---|
| enforced by | the switch | the TACACS+ server |
| refuses at | TCP, before login | authentication |
| failure leaves | dropped connection, log line on the switch | `AUTHC-FAIL-ACL` decision record on 215 |
| if bypassed | login prompt reachable | identity still refused |

The switch-side rule stops the connection; the server-side rule makes
the refusal a **decision record**. Neither replaces the other, which is
why both exist.
