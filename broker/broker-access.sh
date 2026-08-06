#!/bin/bash
#
# broker-access.sh — root pre-step for virp-broker.service.
# Modeled on deploy/config-backup-access.sh.
#
# Grants the `virp-broker` identity exactly the reach it needs and
# nothing else:
#   - traversal (x only, no read) of /run/virp
#   - rw on the onode socket (unix connect() needs write permission)
#
# ACLs are used instead of group membership because group `virp` is a
# credential group: /run/virp/devices.json (0640 root:virp) carries
# rendered device credentials. The broker is credential-less by
# definition — it must NEVER be able to read devices.json, and this
# script fails loud if it can. The ACL grant must be re-applied after
# a daemon restart because the daemon recreates /run/virp and the
# socket (this unit's ExecStartPre runs it; restart virp-broker after
# restarting virp-onode).
#
# Fails loud if the user is missing or looks over-privileged.
#
# Copyright (c) 2026 Third Level IT LLC. All rights reserved.

set -eu

USER_NAME="virp-broker"
SOCK="/run/virp/onode.sock"
DEVICES="/run/virp/devices.json"

if ! id -u "$USER_NAME" >/dev/null 2>&1; then
    echo "[broker-access] FATAL: user $USER_NAME does not exist" >&2
    echo "  create with: useradd --system --shell /usr/sbin/nologin \\" >&2
    echo "    --home-dir /nonexistent --no-create-home $USER_NAME" >&2
    exit 1
fi

# The identity must not be a member of any key/credential group.
extra_groups=$(id -Gn "$USER_NAME" | tr " " "\n" | grep -vx "$USER_NAME" || true)
if [ -n "$extra_groups" ]; then
    echo "[broker-access] FATAL: $USER_NAME has supplementary" \
         "groups: $extra_groups — it must be a member of no group but" \
         "its own" >&2
    exit 1
fi

# Traversal only (no read: the identity must not enumerate /run/virp).
setfacl -m "u:${USER_NAME}:--x" /run/virp

# Wait briefly for the socket in case the daemon is still starting.
for _ in $(seq 1 50); do
    [ -S "$SOCK" ] && break
    sleep 0.2
done
if [ ! -S "$SOCK" ]; then
    echo "[broker-access] FATAL: $SOCK missing — is virp-onode up?" >&2
    exit 1
fi
setfacl -m "u:${USER_NAME}:rw-" "$SOCK"

# CRITICAL INVARIANT: the broker must not be able to read the rendered
# credential store. Verify, don't assume.
if runuser -u "$USER_NAME" -- cat "$DEVICES" >/dev/null 2>&1; then
    echo "[broker-access] FATAL: $USER_NAME can READ $DEVICES —" \
         "credential-less invariant broken, refusing to proceed" >&2
    exit 1
fi

echo "[broker-access] $USER_NAME: socket ACL ready, $DEVICES unreadable (good)"
