# deploy/

Systemd units for the VIRP O-Node and its TCP bridge. The files in this
directory are the source of truth — `/etc/systemd/system/` copies should
match these byte-for-byte.

## Files

| File | Purpose |
|------|---------|
| `virp-onode.service` | O-Node daemon — verifies observations, talks to devices |
| `virp-socat.service` | TCP→Unix proxy on `:9999` → `/tmp/virp-onode.sock`. Runs as `virp-onode` so SO_PEERCRED on the Unix socket passes. |
| `virp-bridge.service` | Python JSON bridge on `:9998` → `/tmp/virp-onode.sock`. Runs as `virp-onode` for the same SO_PEERCRED reason. Stages source from `/root/virp/` to `/opt/virp/` via `ExecStartPre=+` because `/root/` is 0700 and unreadable post-drop-privs. |

## Install

```sh
# From the repo root, as root:
make install-systemd-units

# Or by hand:
install -m 0644 deploy/virp-onode.service  /etc/systemd/system/virp-onode.service
install -m 0644 deploy/virp-socat.service  /etc/systemd/system/virp-socat.service
install -m 0644 deploy/virp-bridge.service /etc/systemd/system/virp-bridge.service
systemctl daemon-reload
systemctl enable --now virp-onode.service virp-socat.service virp-bridge.service
```

If a previous install left a drop-in at
`/etc/systemd/system/virp-socat.service.d/override.conf`, remove it after
the new base unit lands — `User=`/`Group=` are now baked into the base
unit and the drop-in is redundant:

```sh
rm -f /etc/systemd/system/virp-socat.service.d/override.conf
rmdir /etc/systemd/system/virp-socat.service.d 2>/dev/null || true
systemctl daemon-reload
systemctl restart virp-socat
```

The same applies to `virp-bridge.service`: an earlier mid-incident
`virp-bridge.service.d/peercred.conf` drop-in is redundant once this
base unit lands and should be removed:

```sh
rm -f /etc/systemd/system/virp-bridge.service.d/peercred.conf
rmdir /etc/systemd/system/virp-bridge.service.d 2>/dev/null || true
systemctl daemon-reload
systemctl restart virp-bridge
```

## Verification

```sh
# socat must be running as virp-onode (uid 999), gid virp-clients (1000)
ps -eo pid,user,uid,gid,cmd | grep '[s]ocat TCP-LISTEN:9999'

# bridge must be running as virp-onode as well
ps -eo pid,user,uid,gid,cmd | grep '[p]ython3 /opt/virp/virp-bridge.py'

# bridge must have completed the SESSION_BIND handshake — look for an
# "ACTIVE" line on the most recent start
journalctl -u virp-bridge --since "5 min ago" | grep -E 'session ACTIVE|Handshake complete'

# No REJECTED entries should appear in the onode journal during normal use
journalctl -u virp-onode --since "5 min ago" | grep REJECTED || echo "clean"
```

## Why socat and the bridge run as `virp-onode`

The O-Node Unix socket enforces a peer-credential gate via `SO_PEERCRED`
(see `src/virp_onode.c:check_peer_uid`). Only peers whose uid is in
`socket_allowed_uids` may connect. By default the list contains only the
daemon's own euid (999). Both socat and the Python bridge connect to that
socket, so both must run as uid 999 — otherwise every connection is
rejected at the socket boundary regardless of network ACLs.

Group membership (`virp-clients`, gid 1000) gives those processes write
access to the socket file itself (mode 0660, owner `virp-onode:virp-clients`).

### Why the bridge stages source under `/opt/virp/`

`/root/` is mode 0700, owned by root. After `User=virp-onode` drop-privs,
the bridge process cannot traverse that directory to load
`/root/virp/virp-bridge.py` and its sibling `/root/virp/device_registry.py`.
The unit therefore copies both files to `/opt/virp/` during `ExecStartPre`
(escalated via `+`, which runs as root before drop-privs). The bridge then
runs against the `/opt/virp/` copies, which are owned `virp-onode:virp-clients`
mode 0640 — readable post-drop-privs without exposing them widely.

A consequence: edits to `/root/virp/virp-bridge.py` only take effect after
a `systemctl restart virp-bridge` (which re-runs `ExecStartPre`). The
running process holds the staged copy, not the source.
