# Phase 1 runbook — ASA-Lab accounting to node 313

Cisco ASA 5525-X, `ASA-Lab`, 10.0.0.253. Accounting only. **Nothing in this
runbook touches authentication or authorization** — those are Phase 3, and the
one line that would change SSH authentication is deliberately absent.

Gate decisions this is written to are in
[`ASA-5525-PHASE0.md`](ASA-5525-PHASE0.md#decisions-taken-at-this-gate).

Every ASA line below is typed by the operator on the **serial console**. The
gate sends nothing to this device in Phase 1; it does not yet know it exists.

---

## Already done — 313 and virp-lab

Do not repeat these. They are recorded so the runbook is auditable.

**`virp-lab` (10.0.10.211) — the old fleet row is gone.** Removed from
`/etc/virp/devices.template.json` and `/etc/virp/devices.template.stage2.json`,
both backed up as `*.bak-20260907T225420Z-pre-asa-removal`. Test-render clean
(43 devices, no `10.0.0.253`, 0 unresolved placeholders). `virp-onode`
restarted; `systemctl is-active` = **active**, 43 devices added, no ASA lines,
gate line unchanged at `default=ENFORCE max_tier=YELLOW`. The repo copy
`deploy/devices.template.json` is updated on branch `feat/asa-5525-governed`
with a dated `_removed_asa5525_note` recording why.

**313 (10.0.0.13) — the receiver knows the device.**

- Secret generated **as `virp-tacacs`**, `openssl rand -base64 24 | tr -d "/+=" | cut -c1-32`,
  the same generator `deploy/tacacs/install-authz-server.sh` uses. Written to
  `/etc/virp/tacacs/secret-asalab`, 0600 `virp-tacacs:virp-tacacs`, 30 bytes.
  **SUPERSEDED — that first value was disclosed in a transcript and is burned.
  See [Block 2R](#block-2r--re-key-2026-09-07).** The replacement is generated
  the same way and must not travel the same route.
- `/etc/virp/tacacs/recv.json` gained a third relationship —
  `source_addr 10.0.0.253` → `client_identity "ASA-Lab"` — with the same secret
  inline, which is the convention the `LAB-SWITCH-1` entry already follows
  (verified by hash: `secret-2960` and the inline value are the same bytes).
  Backed up as `recv.json.bak-20260907T225728Z-pre-asalab`.

**A restart WAS required, and this is the answer to "say which".**
`tacacs/virp_tacacs_recv.py` calls `load_config()` exactly once, in server
setup at line 647. There is no mtime re-read, no `SIGHUP` config handler — the
only signal handler installed is `SIGTERM`. So a new relationship is inert until
the process restarts.

Contrast with CT 215: `tac_plus-ng` **does** have a reload path, and
`deploy/tacacs/tacacs-reload` is the guarded way to use it (`tac_plus-ng -P`
syntax check first, signal only on success, because spawnd's `SIGHUP` handler
`execve()`s directly and a broken config on disk at that moment kills the
master). **That script is for 215's authorization daemon and does not apply to
313's accounting receiver.** Two different daemons, two different reload
stories; only 215's can be reloaded in place.

`virp-tacacs.service` restarted, `systemctl is-active` = **active**, listening
on `10.0.0.13:4949` (TCP), pre-restart counters flushed clean
(`accepted 190, recorded 190, append_failed 0, unconfigured_source 0`).

**Order matters and is already correct.** 313 was configured *before* the ASA
is told to send anything. A packet from an unconfigured source is not dropped —
`build_receipt` still chains it, with `client_identity_source:
"unconfigured_source"` and no secret, which means it can never be decoded. Those
records would be permanent undecodable junk in the chain. Configuring the
receiver first is what avoids them.

---

## The safety net

**Arm this before Block 1 and leave it armed until the gate passes.** The ASA
reloads to the *saved* configuration, so an unsaved mistake is undone by the
reload. This only works if you have not written memory.

```
reload in 15 noconfirm reason virp-phase1
```

Cancel it only once the gate has passed:

```
reload cancel
```

And only after that:

```
write memory
```

**Never pass `save-config` to `reload`.** It defeats the entire net. Re-arm it
(`reload in 15 …`) if you need more than fifteen minutes; each new `reload in`
replaces the pending one.

Phase 1 changes no authentication or authorization path, so the realistic
failure here is a typo in the `aaa-server` block, not a lockout. The net is
armed anyway because the next two phases will need the habit.

---

## Block 0 — baseline, changes nothing

Type these first and keep the output. Rollback for this block: none needed.

```
show clock
show version | include Version
show nameif
show ip address
show running-config pager
show running-config aaa
show running-config aaa-server
show running-config ssh
show running-config username
```

Three things to read out of it before continuing:

1. **The interface name facing 10.0.0.13.** From `show nameif` + `show ip
   address`, the interface holding a `10.0.0.x` address. It goes in the
   `aaa-server` host line below as `<IFNAME>`. Almost certainly `inside`.

2. **`aaa authentication ssh console` must already be present.** `virp-lab` has
   been logging in as `aiops-svc` over SSH, so some form of it is configured.
   **If `show running-config aaa` shows no `aaa authentication ssh console`
   line, stop and report** — without it the ASA has no authenticated username
   to put in an accounting record, and the Phase 1 gate cannot pass. Do not add
   one; that is a Phase 3 change.

3. **The local user list.** Expect at least `admin` and `aiops-svc`.
   `aiops-svc` is now unused — `virp-lab` no longer holds a session — and its
   enable secret was disclosed into a session transcript during the Phase 0
   survey, so it is burned. **It is a second local account with an SSH path and
   a known-bad credential.** Removing it is a Phase 3 step, recorded here so it
   is not forgotten: the Phase 3 invariant is that
   `show running-config username` lists `admin` and nothing else.

---

## Block 1 — disable paging globally

This is [Decision 2](ASA-5525-PHASE0.md#decisions-taken-at-this-gate): the
pager is fixed in ASA configuration rather than by patching the driver, because
the driver only sends `terminal pager 0` on paths that pass through enable mode
and a priv-1 gate identity does not take one.

```
configure terminal
 pager lines 0
end
```

**Rollback:**

```
configure terminal
 pager lines 24
end
```

`24` is the documented default. Note the global `pager` command is documented
by Cisco in terms of Telnet sessions; whether it suppresses paging on an SSH
session is exactly what Block 4 measures. If it does not, the fallback is priv
15 for `virp-ro` via 215 exec authorization in Phase 3 — not a driver patch this
run.

---

## Block 2 — the accounting server group

**This block was typed on 2026-09-07 and its key is burned — go to
[Block 2R](#block-2r--re-key-2026-09-07) after reading it.** The block is kept
as written because the group, host, port and bindings it creates are all still
correct; only the key value changed.

You need the shared secret. **Read it on 313, on your own terminal, and type it
straight into the ASA. Do not paste it anywhere.**

```sh
ssh nhoward@10.0.0.13 'sudo -n cat /etc/virp/tacacs/secret-asalab'
```

It is 29 characters, alphanumeric, no trailing newline once you strip it. It is
not in this document and not in any transcript.

```
configure terminal
 aaa-server VIRP-ACCT protocol tacacs+
 aaa-server VIRP-ACCT (<IFNAME>) host 10.0.0.13
  key <the 29 characters from 313>
  server-port 4949
 exit
end
```

**Rollback** — the group cannot be removed while Block 3's bindings reference
it, so if you are rolling back both, do Block 3's rollback first:

```
configure terminal
 no aaa-server VIRP-ACCT (<IFNAME>) host 10.0.0.13
 no aaa-server VIRP-ACCT protocol tacacs+
end
```

Verify before continuing:

```
show running-config aaa-server VIRP-ACCT
```

The `key` renders as `*****` — that is correct, and `src/virp_scrub.c` also
redacts first-token `key <string>` lines if this config is ever captured
elsewhere in VIRP.

---

## Block 2R — re-key, 2026-09-07

**Why this block exists.** The Block 2 `key` line was pasted into a session
transcript in cleartext during the first run, which discloses the shared secret
to every reader of that transcript. The value is burned. Both sides move
together: a new secret is generated on 313, and the ASA is re-keyed to match.

Nothing was lost by it. No accounting had reached 313 yet — Block 3 was not
typed, and `show version` is not accounted anyway — so the rotation costs one
config line and no evidence.

**The rule this violates, restated.** The secret is read on 313 and typed
straight into the ASA. It is never pasted into a chat, a ticket, a commit, or a
terminal that is being recorded. `deploy/tacacs/install-authz-server.sh` never
prints a secret for exactly this reason, and `src/virp_scrub.c` redacts
first-token `key <string>` lines so a captured config does not leak one either.
Those defences only hold if the value does not travel through a transcript by
hand.

### On 313 — operator runs this

This writes credential material, so it is not an agent action. Run it in a
terminal that is not being recorded.

```sh
sudo cp -a /etc/virp/tacacs/recv.json \
     /etc/virp/tacacs/recv.json.bak-$(date -u +%Y%m%dT%H%M%SZ)-pre-rekey

sudo -u virp-tacacs bash -c 'umask 077; openssl rand -base64 24 \
     | tr -d "/+=" | cut -c1-32 > /etc/virp/tacacs/secret-asalab'

sudo python3 -c '
import json
p = "/etc/virp/tacacs/recv.json"
new = open("/etc/virp/tacacs/secret-asalab").read().strip()
d = json.load(open(p))
hits = [r for r in d["relationships"] if r["source_addr"] == "10.0.0.253"]
assert len(hits) == 1, hits
hits[0]["secret"] = new
open(p, "w").write(json.dumps(d, indent=1) + "\n")
print("rewritten:", [(r["source_addr"], r["client_identity"])
                     for r in json.load(open(p))["relationships"]])
'

sudo chmod 0600 /etc/virp/tacacs/recv.json /etc/virp/tacacs/secret-asalab
sudo chown virp-tacacs:virp-tacacs /etc/virp/tacacs/recv.json \
     /etc/virp/tacacs/secret-asalab
sudo systemctl restart virp-tacacs
systemctl is-active virp-tacacs
```

`is-active` must print `active`. The restart is mandatory for the same reason
it was the first time: the receiver reads its config once at startup and has no
reload path.

### On the ASA console

Replace the key in place. The group and its bindings stay; only the key
changes.

```
configure terminal
 aaa-server VIRP-ACCT (<IFNAME>) host 10.0.0.13
  key <the new 29 characters — read from 313, typed not pasted>
 exit
end
```

Read it with `sudo cat /etc/virp/tacacs/secret-asalab` on 313 and type it at
the console.

**Rollback: none, deliberately.** A re-key has no rollback, because the old
value must not come back. If the new key is mistyped, `show aaa-server
VIRP-ACCT` shows a rising error count and you re-type it.

---

## Block 3 — bind accounting, and nothing else

```
configure terminal
 aaa accounting ssh console VIRP-ACCT
 aaa accounting command VIRP-ACCT
end
```

**Rollback:**

```
configure terminal
 no aaa accounting command VIRP-ACCT
 no aaa accounting ssh console VIRP-ACCT
end
```

**Why one `aaa accounting command` line and not two.** The original plan called
for `privilege 15` and `privilege 1` lines, mirroring LAB-SWITCH-1. That form
does not map. On ASA the syntax is
`aaa accounting command [privilege level] server-tag`, where `privilege level`
**limits** accounting to commands *at or above* that level, and the default is
0. So the broadest possible setting is the one with no `privilege` keyword at
all, and it is a single global setting rather than a per-level list. Adding
`privilege 1` would narrow it; adding `privilege 15` would narrow it further.
One line at the default covers everything the platform will account.

**What it will not account, and this is expected:** `show` commands. Cisco:
`aaa accounting command` sends records "when you enter any command other than
show commands at the CLI." This is finding `ASA-SHOW-UNACCOUNTED`
([Phase 0 §4](ASA-5525-PHASE0.md#4-named-finding-asa-show-unaccounted)), it is
a platform property, and no setting turns it back on. It is why Block 4 types a
non-`show` command.

**Confirm nothing else moved.** Diff against Block 0:

```
show running-config aaa
```

There must be **no** change to any `aaa authentication` or `aaa authorization`
line. The only additions are the two `aaa accounting` lines. If anything else
differs, roll back Block 3 and report.

---

## Block 4 — the gate test

Leave the console session open. From a host on the LAN, SSH in **as `admin`**
and type exactly this, in this order:

```
show version
show clock
terminal pager 24
exit
```

`terminal pager 24` is the non-`show` command the gate needs. It is chosen
because it is session-scoped and reverts the moment you log out — it changes
nothing persistent, and it does not disturb Block 1's global setting for any
other session.

**Watch for two things while you are in there:**

1. Did `show version` come back **unpaged**? No `<--- More --->`. That is
   Block 1's global `pager lines 0` reaching an SSH session. Say either way.
2. What is the prompt — `ASA-Lab>` or `ASA-Lab#`? It tells us what privilege
   level `admin` lands at over SSH, which Phase 3 needs.

Then, on the console:

```
show aaa-server VIRP-ACCT
```

Non-zero request counters and zero errors mean the ASA reached 313 and the
secret matched. A rising error count means the key is wrong — roll back Block 3
then Block 2 and re-type the key.

---

## Gate — what I check on 313, and what passes

Report back that you have typed Block 4 and I will decode. The gate is
[Decision 4](ASA-5525-PHASE0.md#decisions-taken-at-this-gate), option (i):

**Passes if all of:**

- One `tacacs_accounting/2` record pair for the SSH session — an EXEC **START**
  and an EXEC **STOP** — with `user: "admin"`, `client_identity: "ASA-Lab"`,
  `client_identity_source: "configured_by_source_address"`, and a
  `producer_key_id` of `0e3f34ab8a40d7d690d3005e79192584` (`virp-tacacs`'s own
  key, not the chain key and not the gate's).
- **One** command record, `cmd` = `terminal pager 24` (whatever exact spelling
  the ASA reports), `user` = `admin`, with a `priv_lvl` present and correct for
  wherever `admin` landed.
- Both chained under session `tacacs:virp-onode-home`, decoding cleanly —
  `decode` and `parse` in their closed vocabularies with no error state.
- Receiver counters: `unconfigured_source` **0**, `append_failed` **0**,
  `malformed` **0**, `refused_authen` **0**, `refused_author` **0**.

**Expected and NOT a failure:** zero command records for `show version` and
`show clock`. That is `ASA-SHOW-UNACCOUNTED`. If command records *do* appear
for them, that is a genuine surprise and I want to know — it would mean this
platform or train behaves differently from the documentation and the finding
needs rewriting before Phase 3 is designed around it.

Once the gate passes: `reload cancel`, then `write memory`.

---

## Full rollback

If Phase 1 is abandoned, in this order, from the console:

```
configure terminal
 no aaa accounting command VIRP-ACCT
 no aaa accounting ssh console VIRP-ACCT
 no aaa-server VIRP-ACCT (<IFNAME>) host 10.0.0.13
 no aaa-server VIRP-ACCT protocol tacacs+
 pager lines 24
end
```

Do not `write memory`. If you have already written memory, the above is the
undo; if you have not, `reload` is faster and provably complete.

On 313, the receiver side can be left as it is — a configured source that never
sends is inert and costs nothing. To remove it anyway: restore
`/etc/virp/tacacs/recv.json.bak-20260907T225728Z-pre-asalab`, delete
`/etc/virp/tacacs/secret-asalab`, and **restart** `virp-tacacs` (it will not
re-read the file on its own).
