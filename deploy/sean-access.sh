#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# sean-access.sh — root post-step for virp-onode.service.
#
# Grants the `virp-sean` identity (uid 987) exactly the reach it needs
# and nothing else:
#   - traversal (x only, no read) of /run/virp
#   - rw on the onode socket (unix connect() needs write permission)
#
# virp-sean is the REMOTE requester identity for Sean's isolated agent
# VM (sean-agent, 10.0.70.10 on VLAN 70), added 2026-09-06. The sshd
# child that serves that VM's streamlocal forward runs as this uid, so
# SO_PEERCRED presents an authenticated remote identity to the daemon
# instead of a relay's uid. The account is restrict-ed at the sshd layer
# (no shell, no PTY, key in root-owned /etc/ssh/authorized_keys.d/
# virp-sean, TCP forwards denied by virp-sean-egress.service) and
# CLIENT-only at this layer: same shape as virp-netclaw, and
# deliberately a SEPARATE account — one automation's reach is never
# another's.
#
# WHY THIS FILE EXISTS AT ALL: socket_allowed_uids in the device
# template is NOT sufficient on its own. /run/virp/onode.sock is
# srw-rw---- virp:virp and virp-sean is in no group but its own, so
# without this ACL the client cannot even connect() — it fails at the
# filesystem before the daemon's uid gate is ever consulted. The two
# gates are independent and BOTH are required.
#
# ACLs are used instead of group membership because group `virp` is a
# credential group: /run/virp/devices.json (0640 root:virp) carries
# rendered device credentials and chain.key/onode.key are virp-owned.
# The ACL grant is re-applied every daemon start because the daemon
# recreates /run/virp and the socket on restart.
#
# Fails loud if the user is missing or looks over-privileged.
#
# Copyright (c) 2026 Third Level IT LLC. All rights reserved.

set -eu

USER_NAME="virp-sean"
SOCK="/run/virp/onode.sock"

if ! id -u "$USER_NAME" >/dev/null 2>&1; then
    echo "[sean-access] FATAL: user $USER_NAME does not exist" >&2
    echo "  create with: useradd --system --uid 987 \\" >&2
    echo "    --shell /usr/sbin/nologin --home-dir /nonexistent \\" >&2
    echo "    --no-create-home $USER_NAME" >&2
    exit 1
fi

# The uid is policy, not an accident of creation order: the device
# template names the literal 987 in socket_allowed_uids and in all three
# per-uid maps. If the account were created with a different uid the
# daemon would silently gate a stranger and refuse the real client.
actual_uid=$(id -u "$USER_NAME")
if [ "$actual_uid" != "987" ]; then
    echo "[sean-access] FATAL: $USER_NAME is uid $actual_uid, expected 987" \
         "— the device template's socket policy names 987 literally, so a" \
         "mismatched uid means the gate is allowlisting the wrong identity" >&2
    exit 1
fi

# The identity must not be a member of any key/credential group, nor of
# another automation's group.
extra_groups=$(id -Gn "$USER_NAME" | tr " " "\n" | grep -vx "$USER_NAME" || true)
if [ -n "$extra_groups" ]; then
    echo "[sean-access] FATAL: $USER_NAME has supplementary" \
         "groups: $extra_groups — it must be a member of no group but" \
         "its own" >&2
    exit 1
fi

# The identity must not be able to read any key, credential store, or
# the rendered device list. A remote requester that can read secrets is
# a deploy error, not something to limp past. This matters more here
# than for netclaw: the VM at the far end of this tunnel is operated by
# someone outside the estate and has a human with root on it.
for secret in /etc/virp/keys/onode.key /etc/virp/keys/chain.key \
              /etc/virp/keys/approval.key /etc/virp/autopilot.env \
              /run/virp/devices.json; do
    if runuser -u "$USER_NAME" -- test -r "$secret" 2>/dev/null; then
        echo "[sean-access] FATAL: $USER_NAME can read $secret —" \
             "refusing to grant gate access to a privileged identity" >&2
        exit 1
    fi
done

# Traversal only (no read: the identity must not enumerate /run/virp).
setfacl -m "u:${USER_NAME}:--x" /run/virp

# Runs from virp-onode's ExecStartPost: the daemon (Type=simple) is
# already exec'd but may not have bound the socket yet — wait briefly.
for _ in $(seq 1 50); do
    [ -S "$SOCK" ] && break
    sleep 0.2
done
if [ ! -S "$SOCK" ]; then
    echo "[sean-access] FATAL: $SOCK missing — is virp-onode up?" >&2
    exit 1
fi
setfacl -m "u:${USER_NAME}:rw-" "$SOCK"

echo "[sean-access] $USER_NAME: socket ACL ready, secrets unreadable (good)"
