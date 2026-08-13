# Proxmox VE gate classifier (linux driver)

Added 2026-08-12. Lives in `src/drivers/driver_linux.c` alongside the
FRR/vtysh table; tests in `tests/test_driver_linux_gate.c`
(`make LINUX=1 test-linux-gate`).

A Proxmox host is registered as a `linux` device — Proxmox VE is Debian,
the transport is the same SSH exec channel — so both tables live behind
one classifier. The Proxmox rows are entirely additive: the branch is
entered only when the first whole word of the command is one of `qm`,
`pct`, `pvesh`, `pveversion`, `pvecm`, `pvesm`, `vzdump`, and no FRR,
peer-health or bare-shell row changed.

## Order of evaluation

Load-bearing, top to bottom. Each step's refusal is final.

1. **Raw metacharacter scan** — `;` `|` `&` `` ` `` `$(` `${` `>` `<` and
   every control byte (newline included), on the ORIGINAL request bytes,
   before tokenizing or matching anything. `qm list; rm -rf /` opens with
   a GREEN row's exact spelling, so a prefix match running first would
   classify the whole compound string on the strength of its first two
   words.

   Note `>` and `<` are in NEITHER `virp_command_check_separators()` nor
   the daemon's ingress filter — this scan is the only thing refusing
   redirection, and it is repeated here in full rather than delegated so
   the table is correct for a caller that reaches the classifier directly.

2. **Argument charset** — `[A-Za-z0-9 ._/:=,-]`. Everything an API path,
   node name or option value needs, and no quote, backslash, paren,
   brace, glob byte or `~`.

3. **Self-protection** (below) — before any tier is assigned.

4. **Verb tiers** — BLACK/RED rows, then GREEN, then YELLOW, then RED by
   absence. Case-sensitive, as in the FRR table: `QM LIST` is not a
   spelling of `qm list`.

Step 0, ahead of all of the above, is the **never-tier scan** (see
"BLACK" below). It runs before the separator guard because it issues no
permits — only BLACK or fall-through — so running it first can only
tighten. It has to run first: `qm list; shutdown -h now` trips the
separator guard and would otherwise classify as approvable RED, and an
approved apply re-submits the raw bytes, separator included.

## Tier table

Updated 2026-08-13 — added `pvesm list <storage>` to GREEN and excluded the
guest-agent API subtree from every `pvesh` method (see "Reads the API
answers" below). Previously updated 2026-08-12 — host-health GREEN reads,
`snapshot`, and the BLACK never-class.

| Tier | Commands |
|---|---|
| GREEN | `qm list`, `pct list`, `pveversion`, `pvecm status`, `pvecm nodes`, `pvesm status`, `pvesm list <storage>`, `qm status <vmid>`, `qm config <vmid>`, `pct status <vmid>`, `pct config <vmid>`, `pvesh get <path>` where `<path>` is not under `/access` and carries no `agent` segment; host reads `df -h`, `uptime`, `uname -a` (exact match only) |
| YELLOW | `qm`/`pct` `start`, `stop`, `shutdown`, `reboot`, `suspend`, `resume`, `create`, `set`, `clone`, `migrate`, `snapshot`; `pvesh create`, `pvesh set`; `vzdump …` without a deletion flag; `pvesh get /access…` |
| RED | `qm guest …`, `qm agent …`, `pct exec`, `pct enter`, `pvesh <any method>` on a path with an `agent` segment, `qm delsnapshot`, a malformed or unconfigured VMID, and everything else by absence. Blocked, but approvable. |
| BLACK | `qm destroy`, `pct destroy`, `pvesh delete`, `pvesm remove\|free\|wipedisk`, `vzdump --delete\|--remove\|--prune-backups`, any command naming a **protected VMID**, host halt (`shutdown`, `reboot`, `poweroff`, `halt`, `init`, `telinit`, `systemctl poweroff\|reboot\|halt`), and gate takedown (`systemctl stop\|disable\|mask\|kill\|restart virp-*`, `pkill\|killall virp-*`). |

## BLACK — the never-class

This reverses the table's original rule that every refusal stays
approvable. That rule was sound while no approval key was enrolled: RED
cost nothing because nobody could unlock it. Once an operator key exists,
RED is exactly as strong as the key holder's judgement, and a key that
can approve `systemctl stop virp-onode` can approve away the gate.

BLACK is refused twice in `virp_onode.c`: no proposal is filed
(`gate_tier != VIRP_TIER_BLACK` guards the propose branch) and the apply
path returns `VIRP_ERR_TIER_VIOLATION` before any signature is checked.
There is no flag that re-enables it.

What earns BLACK is one property: executing it would remove the gate's
own ability to refuse anything afterwards. The cost is deliberate —
nobody can halt this host or stop this daemon *through VIRP*. Both remain
available on the host console and over ordinary SSH.

Position matters for the host-halt words: `reboot` at a command position
halts the host and is BLACK, while `qm reboot 100` reboots a guest and is
an ordinary YELLOW action. Path spellings fold to their basename, so
`/sbin/shutdown` is `shutdown`.

`PROX_VMID_BAD` (a VMID that was expected and did not parse) and
`PROX_VMID_UNCONFIGURED` (a VMID present with no `protected_vmids`
declared) stay **RED**, not BLACK — those are malformed input and a
missing config, both of which a human should be able to look at and
escalate rather than hit a permanent wall.

The GREEN rows are exact shapes, not prefixes — `qm list --full` and
`pvesh get /cluster/resources --output-format json` drop to RED by
absence rather than riding a permitted verb.

`pvesh get /access…` is deliberately not GREEN. It is a read, but the
access tree returns credential material (user records, token ids, ACLs,
realm configuration), and an observation body is HMAC-signed and appended
to a chain that cannot be trimmed. YELLOW keeps it reachable through
propose/approve/apply, where a human sees what is about to be signed.

`qm guest exec` is arbitrary command execution inside a guest: the gate
would sign "ran a classified command" over a payload it never classified.
The whole `guest` subtree is refused, not just `exec` — the bypass is the
subtree's purpose. `pct exec` / `pct enter` are the container equivalents
and were already RED by absence; naming them changes only which reason
the signed refusal carries.

## Reads the API answers (2026-08-13)

`pvesh get` is GREEN as a **whole verb**, not as a list of allowed paths.
`get` is read-only by construction in the Proxmox REST API, so the method
is already the boundary a path allowlist would be approximating — and
approximating badly: the API has 341 GET endpoints, an operator question
arrives as whichever one answers it, and every path nobody enumerated
would be a false RED on a pure read.

Checked against the published schema (`pve-docs` api-viewer `apidoc.js`,
678 endpoints, read 2026-08-13) rather than assumed:

- **No GET endpoint returns a UPID.** A Proxmox endpoint that starts a
  background worker returns one, so zero UPID-returning GETs means no GET
  spawns a task. Every mutation is POST/PUT/DELETE — including paths
  where GET is the read half of the same URL (`GET …/apt/update` lists
  pending updates; `POST` on that path runs the `apt-get update`).
- **One subtree is excluded:** `/nodes/<node>/qemu/<vmid>/agent/…`. Those
  GETs are described as "Execute get-osinfo", "Execute get-users" …, and
  that is literal — they dispatch a command to the QEMU guest agent
  *inside the guest*. Same boundary `qm guest` is RED for. The exclusion
  covers **every** `pvesh` method, because the same subtree holds `exec`,
  `file-write` and `set-user-password`, which would otherwise be
  approvable YELLOW through the `pvesh create` row. `qm agent <vmid>
  <cmd>` is the short spelling and is RED with the same reason.

Three further GET classes do act on the world and are already unreachable
because GREEN rows are exact shapes — each needs at least one `--flag`,
and a fourth token is RED by absence. Recorded so a future widening of
the shape does not reopen them silently:

- `…/scan/{nfs,cifs,iscsi,pbs}` — connects **out** to an operator-named
  server; the `pbs` variant takes `--password`, which would put a
  credential in the signed command bytes.
- `…/{qemu,lxc}/<vmid>/vncwebsocket`, `mtunnelwebsocket` — websocket
  upgrade; needs a ticket only a POST can mint, so it is inert alone.
- `…/storage/<s>/file-restore/download` — materializes a zip extracted
  from a PBS backup.

35 of the 341 GETs need a flag like that; the other 306 are reachable as
a clean three-token `pvesh get <path>`, which is the surface this row
deliberately opens.

### Raw host shell stays RED — a deliberate hold

`cat`, `ip`, `ss`, `pvs`, `vgs`, `lvdisplay` and `lsblk` remain RED. Not
because they are dangerous — `ip addr` is as harmless as `uptime` — but
because of what the gate would then have to know. Every read the probing
session needed had an API answer: `pvesh get /nodes/<node>/network` for
`ip`, `pvesm status` + `pvesm list <storage>` for `pvs`/`vgs`/`lvdisplay`,
`pvesh get /nodes/<node>/disks/list` for `lsblk`, config and status
endpoints for anything `cat` was aimed at. Those arrive as a bounded verb
over a structured path.

Generic host shell changes the job description. `cat <path>` makes the
gate decide which of a filesystem's paths are reads worth signing
(`cat /etc/shadow`?), and `ip`/`ss` bring subcommand trees where
`ip addr` and `ip route add` differ by one word. That is no longer "know
the Proxmox API"; it is "police arbitrary Linux" — open-ended, with no
schema behind it and no natural place to stop. The three host-health rows
are exact spellings precisely because they are the exception; a fourth is
earned only by a read the API genuinely cannot answer.

## Self-protection: `protected_vmids`

`qm stop 313` is an ordinary bounded YELLOW action on any other guest and
is the gate powering itself off on 313. Nothing downstream can tell the
two apart, so the target VMID is judged before a tier exists and its RED
cannot be outranked by a permitted verb.

VMID positions recognised:

- `qm|pct <verb> <vmid>` — argv position 2 (all verbs except `list`)
- `qm guest <sub> <vmid>` — argv position 3
- `pvesh <method> …/qemu/<vmid>…` and `…/lxc/<vmid>…` — the segment
  following a `qemu` or `lxc` path segment

Two deliberate over-reaches, both in the refusing direction:

- **Every** purely-numeric token after a `qm`/`pct` verb is checked, not
  just argv[2] — `qm clone 100 313` names the protected id in argv[3].
  The cost is that `qm set 100 --memory 313` also refuses. A wrong
  refusal is a config edit; a wrong permit is the gate.
- `vzdump`'s numeric arguments are checked the same way, so
  `vzdump 313` refuses.

A VMID position that is **expected but unparseable** is RED and never
falls through to the verb tier: `qm stop notanumber` must not become
"well, the verb is YELLOW".

### Configuration

The set is per-device config, not a constant in the driver — a hardcoded
VMID would be silently wrong on the next node. In `devices.json`:

```json
{
  "hostname": "pve-lab",
  "host": "10.0.0.35",
  "vendor": "linux",
  "username": "root",
  "port": 22,
  "_protected_vmids_note": "VMIDs this gate refuses to touch at any tier. 313 is virp-onode-home, the O-Node's own VM: without this, `qm stop 313` is a YELLOW action that switches off the gate evaluating it.",
  "protected_vmids": [313]
}
```

A JSON array of integers is the natural spelling; an equivalent
comma-separated string (`"313,400"`) is also accepted. The loader
normalizes to CSV and registers it with the classifier at startup.

Two operational consequences worth knowing before applying the config:

- **Unconfigured fails closed.** With no device declaring the field, every
  VMID-bearing Proxmox command classifies RED, with the reason naming
  `protected_vmids`. Commands carrying no VMID (`qm list`, `pveversion`,
  `pvecm status`, `pvesm status`, `pvesh get /cluster/…`) are unaffected.
  "Nobody said 313 was special" must not read as "313 is not special".
- **An unparseable list is a fatal config error.** The daemon refuses the
  whole config rather than loading the host without the protection it
  declares.

The registry is the **union** across all linux/proxmox devices, because
the `route_command()` hook is handed a command and no device (the same
constraint that put `write_ops_allow` in the device struct instead — see
`include/virp_driver.h`). With two Proxmox hosts, a VMID protected on
either is refused on both. Over-refusal is an operator inconvenience;
under-refusal is the loop switching off its own gate. The set is written
once at startup, before the daemon serves, and read-only afterwards.
