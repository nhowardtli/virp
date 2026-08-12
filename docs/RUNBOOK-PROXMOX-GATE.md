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

4. **Verb tiers** — RED rows, then GREEN, then YELLOW, then RED by
   absence. Case-sensitive, as in the FRR table: `QM LIST` is not a
   spelling of `qm list`. The table never returns BLACK, so every RED
   stays approvable through propose/approve/apply.

## Tier table

| Tier | Commands |
|---|---|
| GREEN | `qm list`, `pct list`, `pveversion`, `pvecm status`, `pvecm nodes`, `pvesm status`, `qm status <vmid>`, `qm config <vmid>`, `pct status <vmid>`, `pct config <vmid>`, `pvesh get <path>` where `<path>` is not under `/access` |
| YELLOW | `qm`/`pct` `start`, `stop`, `shutdown`, `reboot`, `suspend`, `resume`, `create`, `set`, `clone`, `migrate`; `pvesh create`, `pvesh set`; `vzdump …`; `pvesh get /access…` |
| RED | `qm destroy`, `pct destroy`, `pvesh delete`, `qm guest …`, `pct exec`, `pct enter`, and everything else by absence |

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
