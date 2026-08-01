#!/bin/bash
#
# config-backup-access.sh — root pre-step for virp-config-backup.service.
#
# Grants the `virp-backup` identity exactly the reach it needs and
# nothing else:
#   - traversal (x only, no read) of /run/virp and /var/lib/virp
#   - rw on the onode socket (unix connect() needs write permission)
#   - ownership of /var/lib/virp/config-backups (0700)
#
# ACLs are used instead of group membership because group `virp` is a
# credential group: /run/virp/devices.json (0640 root:virp) carries
# rendered device credentials and chain.key/onode.key are virp-owned.
# The ACL grant is re-applied every run because the daemon recreates
# /run/virp and the socket on restart.
#
# Fails loud if the user is missing or looks over-privileged.
#
# Copyright (c) 2026 Third Level IT LLC. All rights reserved.

set -eu

USER_NAME="virp-backup"
BACKUP_DIR="/var/lib/virp/config-backups"
SOCK="/run/virp/onode.sock"

if ! id -u "$USER_NAME" >/dev/null 2>&1; then
    echo "[config-backup-access] FATAL: user $USER_NAME does not exist" >&2
    echo "  create with: useradd --system --shell /usr/sbin/nologin \\" >&2
    echo "    --home-dir /nonexistent --no-create-home $USER_NAME" >&2
    exit 1
fi

# The identity must not be a member of any key/credential group.
extra_groups=$(id -Gn "$USER_NAME" | tr " " "\n" | grep -vx "$USER_NAME" || true)
if [ -n "$extra_groups" ]; then
    echo "[config-backup-access] FATAL: $USER_NAME has supplementary" \
         "groups: $extra_groups — it must be a member of no group but" \
         "its own" >&2
    exit 1
fi

install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$BACKUP_DIR"

# Traversal only (no read: the identity must not enumerate either dir).
setfacl -m "u:${USER_NAME}:--x" /var/lib/virp
setfacl -m "u:${USER_NAME}:--x" /run/virp

# Runs from virp-onode's ExecStartPost: the daemon (Type=simple) is
# already exec'd but may not have bound the socket yet — wait briefly.
for _ in $(seq 1 50); do
    [ -S "$SOCK" ] && break
    sleep 0.2
done
if [ ! -S "$SOCK" ]; then
    echo "[config-backup-access] FATAL: $SOCK missing — is virp-onode up?" >&2
    exit 1
fi
setfacl -m "u:${USER_NAME}:rw-" "$SOCK"

echo "[config-backup-access] $USER_NAME: socket ACL + $BACKUP_DIR ready"
