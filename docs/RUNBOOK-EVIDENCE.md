# Compliance-evidence collector

A scheduled, **no-AI, read-only** automation on virp-lab. For each target
device it collects a defined **set of evidence items** — each item is one
named read-only command whose signed output is the evidence for a
control. Every result goes through the VIRP gate as a GREEN read, is
O-Key signed by the daemon, and is chain-registered. **Nothing is ever
written to a device.**

Companion to the config-backup runbook
(`docs/RUNBOOK-CONFIG-BACKUP.md`), whose security pattern it reuses: a
dedicated least-privilege identity, a runtime refusal to start if it can
reach key material, and evidence stored rather than self-verified.

## What it does (daily, `virp-evidence.timer`)

For each FRR node (frr1–4) and each item in `evidence-items.json`:

1. **Submit** the item's command through the gate. It classifies GREEN,
   executes, and returns an O-Key-signed observation.
2. **Chain-register the signed observation** (`obs:<device>:<nanos>`),
   storing the raw signed bytes.
3. **Chain-register an evidence record** (`evidence:<device>:<item>:<nanos>`,
   schema `evidence_item/1`) carrying the metadata that makes those bytes
   mean something: item name, device, timestamp, **the exact command
   run**, the control reference from the mapping file, the honest
   caveats, the collection status, and the SHA-256 + path of both data
   files it was produced from. The chain entry's `artifact_hash` commits
   to that body, so the caveats and the mapping cannot drift from the
   evidence after the fact.
4. **Store locally** under
   `/var/lib/virp/evidence/<run>/<device>/<item>.json` (umask 0077),
   including the raw signed observation for any key holder to verify.

Exit codes: `0` clean, `1` any alert (the unit shows failed — same
convention as the autopilot and the backup runbook), `3` identity check
refused.

## Identity model

Runs as **`virp-evidence`**: a dedicated system account, member of **no**
group but its own, and deliberately **separate from `virp-backup`** —
each automation owns its own identity and its own evidence tree, so a
compromise of one runbook does not reach the other's evidence. Socket
reach is granted by ACL (`deploy/evidence-access.sh`), *not* by joining
group `virp`, because group `virp` can read the rendered `devices.json`
credentials.

At startup the collector **refuses to run** (exit 3) if it is root, the
daemon user, `virp-backup`, a member of group `virp` or `virp-backup`, or
if it can read ANY of: `onode.key`, `chain.key`, `approval.key`,
`/etc/virp/autopilot.env`, `/run/virp/devices.json`. The systemd unit
additionally masks all of those (`InaccessiblePaths=`), sandboxes the
filesystem (`ProtectSystem=strict`), and grants write access only to the
evidence tree.

Consequences, and one honest caveat:

- The collector **cannot verify** observation HMACs; it stores the raw
  signed bytes (`signed_observation_b64` in each stored record).
  `virp-evidence-report` re-verifies them at render time as a key holder.
  Under symmetric HMAC a verifier needs the signing key, so the
  least-privilege client is the one that stores evidence rather than
  pretending to check it.
- The collector **cannot approve anything**: it holds no approval secret,
  is not in `/etc/virp/approvers.json`, cannot read the approvals store
  (0700 `virp`), and its source contains no approval code path — pinned
  by test, its action vocabulary is exactly `execute` and `chain_append`.
- **Known, accepted:** `/var/lib/virp/chain.db` is mode 0644 on this
  deployment, so at the filesystem level `virp-evidence` could read the
  chain if run outside its unit. The unit masks it (`InaccessiblePaths`),
  the chain holds no key material, and this is identical to the
  `virp-backup` runbook's position. It is recorded here rather than
  quietly ignored.

## Read-only, structurally

The item list is **data**, so adding an item is a config edit. That makes
the file an attack surface, so the collector re-derives the linux
driver's GREEN row locally (`assert_green_form`) and **refuses to submit
anything that is not exactly `vtysh -c "show <rest>"` with rest limited
to `[a-z0-9 ./-]`**. Validation happens at *load* time, so a bad edit
fails the whole run loudly rather than being discovered mid-collection.

A hostile or careless edit therefore cannot turn the collector into a
mutation tool — it will not even ask. The gate remains the authority on
tier; this guard only bounds what is ever submitted. Every returned
observation is additionally checked to be GREEN `DEVICE_OUTPUT`; a
YELLOW/RED tier is a loud alert, never stored as evidence.

## The two data files

Both live in `/etc/virp/`, with the tracked copies under `deploy/` as a
fallback so a fresh checkout runs. Whichever was used is recorded — path
**and SHA-256** — in every result, so a report always names the mapping
it came from.

| File | What |
|---|---|
| `evidence-items.json` | the item set: name, title, command, `proves`, `does_not_prove`, optional `evidence_gap` |
| `controls.json` | item name → `{control_id, control_description, framework}` |

**`controls.json` ships with PLACEHOLDER ids and framework.** They are
not compliance assertions. The client's compliance owner must replace
them with real framework references before the output means anything; the
report prints the framework on every page, so a report built against the
shipped file is visibly stamped PLACEHOLDER throughout.

Changing either file **never requires a code change**. An item with no
mapping is still collected, still signed, still chain-registered, and
appears in the report under an explicit UNMAPPED heading — evidence is
never dropped for want of a mapping. It also alerts, so the operator
to-do surfaces rather than sitting unnoticed.

## The v1 item set, and what it honestly covers

| Item | Command | Control | Note |
|---|---|---|---|
| `access_accounts` | `show running-config` | AC-1 | FRR has no `show users`/`show line`/`show vty`; accounts live in the running-config. Says nothing about host OS accounts, SSH keys or PAM. |
| `logging_config` | `show logging` | AU-1 | Per-daemon destinations and levels. Does not prove delivery, retention or review. |
| `time_sync` | `show zebra` | AU-8 | **Declared evidence gap.** FRR has no NTP subsystem at all — `show ntp status`, `show ntp associations` and `show clock` are all unknown commands (verified live on frr1, 2026-07-30). This control is UNEVIDENCED. |
| `running_config_baseline` | `show running-config` | CM-2 | Snapshot only; comparison is the config-backup runbook's job. Running, not startup, config. |
| `management_services` | `show daemons` | CM-7 | FRR daemons only. Does not enumerate host listening ports, so it does not prove insecure protocols are disabled. |

Two items deliberately share a collection method: `access_accounts` and
`running_config_baseline` both read the running-config. They are
collected and signed independently, and the report says so.

`time_sync` is the honest case worth understanding. Rather than
substitute a weak read and let it render as a satisfied control, the item
carries an `evidence_gap` string; the report boxes it in amber, lists it
in a **Declared evidence gaps** section, and the limitations section says
the control should be treated as UNEVIDENCED. Closing it needs a
host-level collector that does not exist yet.

## Results that observe nothing

FRR answers an unrecognised command on stdout with a `%` diagnostic and
still exits 0, so the gate sees an ordinary GREEN read **and signs it**.
The signature is perfectly valid; the content evidences nothing. The
collector detects this (`collection_status = device_rejected_command`),
alerts, and the report flags it in place — otherwise
`% Unknown command` would render as a satisfied control. Empty output is
flagged the same way.

## The report

```
report/virp-evidence-report --db /var/lib/virp/chain.db \
    --out evidence.pdf [--session evidence:YYYY-MM-DD]
```

Runs as a **key holder** (needs the O-Key and chain key) — the deliberate
division of labour with the least-privilege collector. It reuses
`report/verify.py` and `report/chain_read.py`, so every hash, link and
signature is recomputed from the chain at render time exactly as
`virp report` does; nothing is copied from a stored value and shown as if
it had been checked.

It selects the **whole** evidence session, not just the evidence rows:
filtering to evidence entries alone would manufacture sequence gaps and
report a healthy chain as broken.

Sections: header + mapping provenance, integrity summary, **evidence by
control**, unmapped items, declared evidence gaps, limitations. The
limitations section states, always: read-only point-in-time snapshot;
control mapping is operator-supplied not tool-asserted; HMAC is not a
digital signature (no non-repudiation); the collector cannot verify its
own evidence; unmapped items listed by name; declared gaps; results that
observed nothing; and the coverage bound of the report.

Exit `1` on any verification failure — the PDF is still written, because
a report of a broken chain is exactly when you most need the report.

## Cadence

Daily by default. Override without editing the tracked unit:

```
systemctl edit virp-evidence.timer
[Timer]
OnCalendar=
OnCalendar=weekly
```

The empty assignment matters: `OnCalendar=` is a list, so a drop-in
without it *adds* a schedule instead of replacing one.

## Files

| Path | What |
|---|---|
| `autopilot/virp_evidence.py` | the collector (`run`, `check`, `plan`) |
| `deploy/evidence-items.json` | item set (installed to `/etc/virp/`) |
| `deploy/controls.json` | control mapping, PLACEHOLDER ids (installed to `/etc/virp/`) |
| `report/virp_evidence_report.py` / `virp-evidence-report` | control-mapped PDF |
| `deploy/virp-evidence.service` / `.timer` | daily unit (User=virp-evidence) |
| `deploy/evidence-access.sh` | ACLs + evidence dir; fails loud on a mis-provisioned identity |
| `deploy/virp-onode-evidence.dropin.conf` | virp-onode ExecStartPost drop-in re-granting the ACL each daemon start |
| `tests/test_evidence.py` | behaviour + policy tests (`make test-evidence`) |
| `/var/lib/virp/evidence/<run>/<device>/<item>.json` | stored results + raw signed bytes |
| `/var/lib/virp/evidence/<run>/manifest.json` | per-run manifest |
| `/var/lib/virp/evidence/alerts.jsonl` | alert sink (journal is the other) |

## Deploy (virp-lab)

```
useradd --system --shell /usr/sbin/nologin --home-dir /nonexistent \
        --no-create-home virp-evidence
install -m 0644 deploy/evidence-items.json /etc/virp/evidence-items.json
install -m 0644 deploy/controls.json       /etc/virp/controls.json
install -m 0644 deploy/devices.template.json /etc/virp/devices.template.json
install -m 0644 deploy/virp-evidence.{service,timer} /etc/systemd/system/
install -d /etc/systemd/system/virp-onode.service.d
install -m 0644 deploy/virp-onode-evidence.dropin.conf \
        /etc/systemd/system/virp-onode.service.d/51-evidence.conf
systemctl daemon-reload
systemctl restart virp-onode    # new allowlist uid + ACL grant (drop-in)
systemctl enable --now virp-evidence.timer
```

Check the identity and the plan before the first run:

```
sudo -u virp-evidence python3 /opt/virp/autopilot/virp_evidence.py check
sudo -u virp-evidence python3 /opt/virp/autopilot/virp_evidence.py plan
```

Retention: results are kept indefinitely (~20 small files/day on this
lab). Prune by hand or add a tmpfiles.d age rule if it ever matters.
