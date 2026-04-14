# VIRP Socket Path Cutover — April 2026

Coordinated change: CT 211 branch `hardening/audit-2026-04` moves the O-Node
Unix socket from `/tmp/virp-onode.sock` to `/run/virp/onode.sock` and adds
`SO_PEERCRED` checks on accept.

## Cutover sequence (performed by Nate on CT 210)

Prerequisites: CT 211 branch has merged and the new socket path is live on 211.

```bash
# 1. Stop the old socat bridge
systemctl stop virp-socket-client.service

# 2. Back up old unit, move new unit into place
cp /etc/systemd/system/virp-socket-client.service \
   /etc/systemd/system/virp-socket-client.service.old
cp /etc/systemd/system/virp-socket-client.service.new \
   /etc/systemd/system/virp-socket-client.service

# 3. Reload and start
systemctl daemon-reload
systemctl start virp-socket-client.service

# 4. Verify the new socket exists and the dashboard can still reach O-Node
ls -la /run/virp/onode.sock
curl -s http://localhost:8080/api/health | python3 -m json.tool
```

## Rollback

If step 4 fails:
```bash
systemctl stop virp-socket-client.service
cp /etc/systemd/system/virp-socket-client.service.old \
   /etc/systemd/system/virp-socket-client.service
systemctl daemon-reload
systemctl start virp-socket-client.service
```

## Post-cutover environment variable

After cutover, set in the dashboard's environment (systemd unit or shell):
```
VIRP_ONODE_SOCKET=/run/virp/onode.sock
```
This updates the documented default in deploy.sh and README.md references.
The dashboard itself (server.py) talks to 211 over TCP, not the local socket,
so this env var only affects the socat bridge unit and documentation.

## UID coordination (pending)

If the socat bridge on 211 runs as a different UID than the O-Node daemon on
211, the `socket_allowed_uids` config on 211 will need an allowlist entry for
the bridge UID. Nate will provide 211 UIDs and this section will be updated.

## IMPORTANT: TCP trust boundary — follow-up required

The SO_PEERCRED change on 211 only protects **local Unix socket consumers on
211**. It does NOT protect the TCP path (CT 210 → 211:9999) that the dashboard
uses. That TCP path is a separate trust boundary that needs its own control:

- **mTLS** between 210 and 211
- **Shared secret / token** in the VIRP protocol handshake
- **Interface binding** (O-Node listens only on the 210↔211 veth/bridge interface)

This is out of scope for the current branch. Flag for follow-up.
