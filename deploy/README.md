# deploy/

Systemd units for the VIRP O-Node and its TCP bridge. The files in this
directory are the source of truth — `/etc/systemd/system/` copies should
match these byte-for-byte.

## Files

| File | Purpose |
|------|---------|
| `virp-onode.service` | O-Node daemon — verifies observations, talks to devices |
| `virp-socat.service` | TCP→Unix proxy on `:9999` → `/tmp/virp-onode.sock`. Runs as `virp-onode` so SO_PEERCRED on the Unix socket passes. |

## Install

```sh
# From the repo root, as root:
make install-systemd-units

# Or by hand:
install -m 0644 deploy/virp-onode.service  /etc/systemd/system/virp-onode.service
install -m 0644 deploy/virp-socat.service  /etc/systemd/system/virp-socat.service
systemctl daemon-reload
systemctl enable --now virp-onode.service virp-socat.service
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

## Verification

```sh
# socat must be running as virp-onode (uid 999), gid virp-clients (1000)
ps -eo pid,user,uid,gid,cmd | grep '[s]ocat TCP-LISTEN:9999'

# No REJECTED entries should appear in the onode journal during normal use
journalctl -u virp-onode --since "5 min ago" | grep REJECTED || echo "clean"
```

## Why socat runs as `virp-onode`

The O-Node Unix socket enforces a peer-credential gate via `SO_PEERCRED`
(see `src/virp_onode.c:check_peer_uid`). Only peers whose uid is in
`socket_allowed_uids` may connect. By default the list contains only the
daemon's own euid (999). socat, as the only TCP→Unix proxy, must therefore
also be uid 999 — otherwise every TCP-side connection is rejected at the
socket boundary regardless of network ACLs.

Group membership (`virp-clients`, gid 1000) gives socat write access to
the socket file itself (mode 0660, owner `virp-onode:virp-clients`).
