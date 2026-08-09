#!/bin/bash
#
# netclaw-access.sh — root post-step for virp-onode.service.
#
# Grants the `virp-netclaw` identity exactly the reach it needs and
# nothing else:
#   - traversal (x only, no read) of /run/virp
#   - rw on the onode socket (unix connect() needs write permission)
#
# virp-netclaw is the REMOTE requester identity: the sshd child that
# serves netclaw's (10.0.30.30) streamlocal forward runs as this uid,
# so SO_PEERCRED presents an authenticated remote identity to the
# daemon instead of a relay's uid. The account is restrict-ed at the
# sshd layer (no shell, no PTY, no TCP forwards; key in root-owned
# /etc/ssh/authorized_keys.d/virp-netclaw) and CLIENT-only at this
# layer: same shape as virp-backup / virp-evidence, and deliberately a
# SEPARATE account from both — one automation's reach is never
# another's.
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

USER_NAME="virp-netclaw"
SOCK="/run/virp/onode.sock"

if ! id -u "$USER_NAME" >/dev/null 2>&1; then
    echo "[netclaw-access] FATAL: user $USER_NAME does not exist" >&2
    echo "  create with: useradd --system --shell /usr/sbin/nologin \\" >&2
    echo "    --home-dir /nonexistent --no-create-home $USER_NAME" >&2
    exit 1
fi

# The identity must not be a member of any key/credential group, nor of
# another automation's group.
extra_groups=$(id -Gn "$USER_NAME" | tr " " "\n" | grep -vx "$USER_NAME" || true)
if [ -n "$extra_groups" ]; then
    echo "[netclaw-access] FATAL: $USER_NAME has supplementary" \
         "groups: $extra_groups — it must be a member of no group but" \
         "its own" >&2
    exit 1
fi

# The identity must not be able to read any key, credential store, or
# the rendered device list. A remote requester that can read secrets is
# a deploy error, not something to limp past.
for secret in /etc/virp/keys/onode.key /etc/virp/keys/chain.key \
              /etc/virp/keys/approval.key /etc/virp/autopilot.env \
              /run/virp/devices.json; do
    if runuser -u "$USER_NAME" -- test -r "$secret" 2>/dev/null; then
        echo "[netclaw-access] FATAL: $USER_NAME can read $secret —" \
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
    echo "[netclaw-access] FATAL: $SOCK missing — is virp-onode up?" >&2
    exit 1
fi
setfacl -m "u:${USER_NAME}:rw-" "$SOCK"

echo "[netclaw-access] $USER_NAME: socket ACL ready, secrets unreadable (good)"
