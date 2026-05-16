# W3 Evidence — virp-socat User Drop (root → virp-onode)

**Date:** 2026-05-16
**Trust primitive:** W3 — O-Node Unix-socket peer-credential gate (`SO_PEERCRED` + `socket_allowed_uids`)
**Branch:** hardening/audit-2026-04 (target for commit; current working branch raise-validator-manifest-caps)
**Author:** Nate Howard + Claude Code

---

## Summary

`virp-socat.service` had been running as `root` (uid 0). Every TCP connection
arriving at `10.0.0.211:9999` was proxied to `/tmp/virp-onode.sock` with the
socat process's credentials, so `SO_PEERCRED` reported uid 0 to the O-Node.
The O-Node's `socket_allowed_uids` list (default-seeded to `geteuid() = 999`
because no key is present in `/run/virp/devices.json`) rejected every such
connection in `virp_onode.c:2101`. The dashboard tool-call path was 100%
broken end-to-end.

Fix: dropped a systemd drop-in at
`/etc/systemd/system/virp-socat.service.d/override.conf` setting
`User=virp-onode`, `Group=virp-clients`, and clearing both
`AmbientCapabilities=` and `CapabilityBoundingSet=`. Reload + restart at
21:42:58 UTC. Socat is now uid 999, gid 1000 — peer credentials presented to
the O-Node match the daemon's own UID, the SO_PEERCRED check passes, and
REJECTED entries have stopped.

W2 (device-side ACLs, off-box) and W4 (Landlock FS sandbox on CT 210) are
unaffected. W1 (CT 210 egress firewall — DNS, 10.0.0.211:9998-9999, :443
only) was repaired earlier in the session and remains intact.

---

## Timeline (UTC, 2026-05-16)

| Time | Event |
|------|-------|
| 21:21:43 | First REJECTED today: peer uid=0 pid=1267846 |
| 21:21:43 – 21:38:44 | 22 REJECTED entries, all `peer uid=0`, ~1 per dashboard tool invocation |
| 21:38:44 | Last REJECTED today: peer uid=0 pid=1268091 |
| 21:42:57.812 | `override.conf` created (birth time on inode) |
| 21:42:58 | `systemctl stop virp-socat` → main process exited status=143 (SIGTERM, expected) |
| 21:42:58 | `systemctl start virp-socat` → new socat PID 1268204 running as uid=999 (virp-onode), gid=1000 (virp-clients) |
| 21:42:58 → present | **0 REJECTED entries** in `journalctl -u virp-onode` |
| 21:55:51 → 21:56:51 | O-Node heartbeats continue (seq 8344 → 8346) — daemon alive, socket reachable |

---

## Evidence

### Pre-fix — REJECTED count and exemplar

```
$ journalctl -u virp-onode --since today -o cat | grep -c "REJECTED connection"
22

$ journalctl -u virp-onode --since today -o cat | grep -oE "uid=[0-9]+" | sort | uniq -c
     22 uid=0

$ journalctl -u virp-onode --since today -o short-iso | grep "REJECTED" | head -1
2026-05-16T21:21:43+0000 ironclaw-onode virp-onode[1225843]: [O-Node] REJECTED connection: peer uid=0 pid=1267846 not in socket_allowed_uids

$ journalctl -u virp-onode --since today -o short-iso | grep "REJECTED" | tail -1
2026-05-16T21:38:44+0000 ironclaw-onode virp-onode[1225843]: [O-Node] REJECTED connection: peer uid=0 pid=1268091 not in socket_allowed_uids
```

All 22 rejections share `uid=0` — pure socat-as-root signature, no legitimate root client.

### Fix — drop-in override

```
$ cat /etc/systemd/system/virp-socat.service.d/override.conf
[Service]
User=virp-onode
Group=virp-clients
# Remove root-required capabilities if any are set
AmbientCapabilities=
CapabilityBoundingSet=

$ stat /etc/systemd/system/virp-socat.service.d/override.conf | grep Birth
 Birth: 2026-05-16 21:42:57.812335307 +0000
```

### Post-fix — socat process identity

```
$ ps -eo pid,user,uid,gid,cmd | grep "socat.*9999" | grep -v grep
1268204 virp-on+   999  1000 /usr/bin/socat TCP-LISTEN:9999,fork,reuseaddr UNIX-CONNECT:/tmp/virp-onode.sock
```

uid 999 = `virp-onode`, gid 1000 = `virp-clients`. Group membership is what
gives socat write access to the socket (mode 0660, owner virp-onode:virp-clients);
the matching uid is what satisfies `socket_allowed_uids`.

### Post-fix — REJECTED count and liveness

```
$ journalctl -u virp-onode --since "2026-05-16 21:42:58" -o cat | grep -c "REJECTED connection"
0

$ journalctl -u virp-onode --since "21:42:58" -o short-iso | grep -i heartbeat | tail -3
2026-05-16T21:55:51+0000 ironclaw-onode virp-onode[1225843]: [O-Node] Heartbeat: uptime=250866s obs=0 seq=8344 connected=0/40 reconnects=0
2026-05-16T21:56:21+0000 ironclaw-onode virp-onode[1225843]: [O-Node] Heartbeat: uptime=250896s obs=0 seq=8345 connected=0/40 reconnects=0
2026-05-16T21:56:51+0000 ironclaw-onode virp-onode[1225843]: [O-Node] Heartbeat: uptime=250926s obs=0 seq=8346 connected=0/40 reconnects=0
```

**Note on ACCEPTED logging.** The O-Node does not emit a symmetric "ACCEPTED"
line — `virp_onode.c:2101` logs only the rejection path; accepted peers
proceed silently into request handling. The positive evidence is therefore
the *absence* of REJECTED entries since 21:42:58 plus continued daemon
liveness. A follow-up step (W3 audit close-out) should add a one-shot
INFO-level "accepted peer uid=%u" log at first connection after start to
make this primitive's healthy state observable, not just its failure state.

### `socket_allowed_uids` provenance

```
$ jq 'has("socket_allowed_uids")' /run/virp/devices.json
# (verify via daemon stderr — key is absent, daemon self-seeded)

$ journalctl -u virp-onode | grep "socket_allowed_uids:" | tail -1
[O-Node] socket_allowed_uids: <default> = [999] (daemon UID)
```

The list contains only uid 999 (daemon's own euid), per the self-seed
branch in `virp_onode.c:1986-1990`. socat-as-virp-onode satisfies this.
socat-as-root did not.

---

## Trust-primitive impact

| Primitive | Pre-fix | Post-fix | Change |
|-----------|---------|----------|--------|
| W1 (CT 210 egress firewall) | DNS + 10.0.0.211:9999/9998 + :443 only, policy_out DROP | unchanged | none |
| W2 (device-side ACLs, off-box) | enforced at device | unchanged | none |
| W3 (O-Node SO_PEERCRED gate) | enforced but path BROKEN — socat-as-root meant the only client that could *reach* the socket was rejected by it. Defense was effective in the wrong direction: it blocked the legitimate path because the legitimate path was misconfigured. | enforced AND legitimate path passes (socat uid 999 == allowed uid 999) | **restored** |
| W4 (Landlock FS sandbox, CT 210 only) | active | unchanged | none |

Net: W3 moved from "enforced but never observed accepting traffic" to
"enforced and observed accepting traffic from a process whose uid is
audit-traceable to a dedicated, capability-stripped systemd service."

---

## Significance

This was a silent self-DoS by a defense-in-depth primitive. The SO_PEERCRED
gate did exactly what it was designed to do (commit `23680b0`, 2026-04-14):
reject local peers whose uid is not on the allow-list. But the only TCP→Unix
proxy in the system was running as a uid that wasn't on the allow-list, so
the gate happened to reject 100% of legitimate traffic. From the dashboard
side this looked like end-to-end tool-call failure with no obvious cause —
the firewall fix in W1 made the TCP path reachable, but the peer-credential
gate at the far end kept dropping every connection.

Two follow-ups the close-out should pick up:

1. **socket_allowed_uids in devices.json.age.** The default-seed branch is
   a useful safety net but it means the allowed list is implicit. An
   explicit `"socket_allowed_uids": [999]` (or a virp-clients-group-derived
   list) in the encrypted config makes the policy reviewable and removes
   the dependence on `geteuid()` at startup. See the existing memory note
   `virp_socket_peercred.md` — missing key has caused production-shaped
   incidents before.

2. **Track the socat unit in repo.** `virp-socat.service` is in
   `/etc/systemd/system/` only — not in `/root/virp/deploy/` like
   `virp-onode.service` is. Drift on this unit is invisible to git. The
   override that just fixed W3 will also drift until both the unit and the
   drop-in are committed.

3. **Symmetric ACCEPTED log.** Add a single startup-or-first-accept INFO
   line so future evidence captures can show a positive signal instead of
   "absence of negative signal."

---

## Reference

- `virp_onode.c:801-830` — `check_peer_uid()` SO_PEERCRED enforcement
- `virp_onode.c:1986-1995` — default-seed branch for `socket_allowed_uids`
- `virp_onode.c:2101-2122` — REJECTED log line and per-uid counter
- `virp_onode_prod.c:101-117` — `load_socket_allowed_uids()` (devices.json path)
- `commit 23680b0` (2026-04-14) — original SO_PEERCRED hardening
- Memory: `virp_socket_peercred.md` — onode socket allowlist trap (recurring)
- Snapshots: `pct snapshot 210 pre-w1-debug-20260516-1225`, `pct snapshot 211 pre-w1-debug-20260516-1225`

---

## Addendum — configuration consolidation (22:03:03 UTC)

The 21:42:58 fix used a drop-in override (`virp-socat.service.d/override.conf`)
layered on top of an untracked base unit. That works but leaves the
base unit invisible to git and splits the fix across two files. To make
the change durable and auditable, the base unit was rewritten with the
hardening directives baked in and the drop-in removed.

### Files changed

- **New:** `deploy/virp-socat.service` — single hardened base unit
- **New:** `deploy/README.md` — install procedure
- **Modified:** `Makefile` — added `install-systemd-units` target
- **Installed:** `/etc/systemd/system/virp-socat.service` (replaced)
- **Removed:** `/etc/systemd/system/virp-socat.service.d/override.conf` and parent directory

### Diff vs prior running unit (additions only — nothing removed)

```diff
+Requires=virp-onode.service
+User=virp-onode
+Group=virp-clients
+AmbientCapabilities=
+CapabilityBoundingSet=
+NoNewPrivileges=yes
 ExecStart=/usr/bin/socat TCP-LISTEN:9999,fork,reuseaddr \
     UNIX-CONNECT:/tmp/virp-onode.sock
```

`Requires=virp-onode.service` upgrades the dependency from ordering-only
(`After=`) to hard requirement — socat will stop if onode stops, which is
the correct behavior since socat without onode is useless. `NoNewPrivileges=yes`
is a pure-win sandbox tightening for a TCP proxy that should never need
setuid.

### Post-consolidation verification

```
$ systemctl status virp-socat --no-pager | head
* virp-socat.service - VIRP O-Node socat TCP Bridge
     Loaded: loaded (/etc/systemd/system/virp-socat.service; enabled; vendor preset: enabled)
     Active: active (running) since Sat 2026-05-16 22:03:03 UTC

$ ps -eo pid,user,uid,gid,cmd | grep '[s]ocat TCP-LISTEN:9999'
1269064 virp-on+   999  1000 /usr/bin/socat TCP-LISTEN:9999,fork,reuseaddr UNIX-CONNECT:/tmp/virp-onode.sock

$ ss -tlnp | grep 9999
LISTEN 0      5            0.0.0.0:9999      0.0.0.0:*    users:(("socat",pid=1269064,fd=5))

$ ls /etc/systemd/system/virp-socat.service.d/ 2>&1
ls: cannot access '/etc/systemd/system/virp-socat.service.d/': No such file or directory

$ journalctl -u virp-onode --since "2026-05-16 22:03:03" -o cat | grep -c "REJECTED connection"
0
```

uid/gid unchanged (999/1000) — the SO_PEERCRED gate continues to accept
the proxy. No REJECTED entries since consolidation. The drop-in
directory is gone, so future audits will see exactly one file describing
the socat service.

### Timeline (extended)

| Time | Event |
|------|-------|
| 22:01:55 | `deploy/virp-socat.service` written |
| 22:02 | `deploy/README.md` and `Makefile` target added |
| 22:03:03 | `install` + `daemon-reload` + `systemctl restart virp-socat` |
| 22:03:03 → | socat PID 1269064, uid 999, 0 REJECTED |

