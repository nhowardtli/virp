# VIRP TACACS+ authorization server

**This is not the accounting receiver.** `install-receiver.sh` and
`virp-tacacs.service` in this directory belong to the accounting
receiver and are untouched by anything here. Accounting stays on 313
(`10.0.0.13:4949`) and .211 (`10.0.10.211:4949`).

This server does **authentication and authorization only**, for the two
gate identities. It has no `accounting log` directive and must never get
one: `docs/TACACS-ACCOUNTING.md` §9.4 depends on accounting surviving an
authorization outage, which only holds while they are separate processes
on separate addresses.

Deployed: CT 215 `virp-tacacs`, `10.0.0.215:49`, on pve-lab.

- Build report: `docs/tacacs/TACACS-SERVER-REPORT.md`
- IOS runbook: `docs/tacacs/TACACS-SERVER-RUNBOOK.md`

## Files

| File | What |
|---|---|
| `tac_plus-ng.cfg` | main config: profiles, logging, include order |
| `gen-green-conf.py` | **generates** `green.conf` + `guard.conf` from `src/drivers/driver_cisco.c` |
| `green.conf` | generated — the 38 GREEN commands for `virp-ro` |
| `guard.conf` | generated — hard denials, both profiles, evaluated first |
| `secrets.conf.example` | structure only; real file is generated on the box |
| `install-authz-server.sh` | installer; generates secrets, never prints them |
| `tacacs-reload` | check-then-signal reload wrapper |
| `virp-tacacs-authz.service` | systemd unit |
| `tacacs_probe.py` | stdlib-only TACACS+ client, for proving policy |

## Install

```
# on the server, from a checkout
sudo deploy/tacacs/install-authz-server.sh
sudo systemctl start virp-tacacs-authz
```

Secrets land in `/etc/tacacs/secrets.conf` (0600 root:root) and are not
printed. Re-running the installer never regenerates them — that would
break every device already pointed here, and the gate with it.

## Changing policy

```
# edit /etc/tacacs/approved.conf, then:
sudo tacacs-reload
```

`tacacs-reload` runs `tac_plus-ng -P` first and **refuses to signal** if
the config does not parse, leaving the running policy untouched. Never
send `SIGHUP` directly: spawnd `execve`s on SIGHUP and dies on a bad
config, taking authorization with it.

Regenerating the GREEN policy after a driver-table change:

```
python3 deploy/tacacs/gen-green-conf.py \
  --driver src/drivers/driver_cisco.c \
  --out /etc/tacacs/green.conf \
  --guard-out /etc/tacacs/guard.conf \
  --repo-root . --prefix
sudo tacacs-reload
```

## Three things that will bite

1. **Reload latency is 0–8 s, in both directions.** spawnd processes
   signals only when `tv_sec % 8 == 0` (`mavis/spawnd_main.c:76`). A
   revoked grant stays in force for up to 8 s after `tacacs-reload`
   returns.
2. **Use `\A` and `\z` in rules, never `^` and `$`.** PCRE2 is compiled
   with `MULTILINE`, under which `^`/`$` match at embedded newlines and a
   rule becomes a bypass. See the report §2.2.
3. **Truncate `approved.conf`, never delete it.** A missing include is a
   parse error, not an empty policy.
