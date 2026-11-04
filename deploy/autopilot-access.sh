#!/bin/bash
#
# autopilot-access.sh — root pre-step for the virp-autopilot units
# (cycle, corpus, chainwalk, comparator), run from virp-onode's
# ExecStartPost (deploy/virp-onode-autopilot.dropin.conf).
#
# Grants the `virp-autopilot` identity (uid 971) exactly the reach it
# needs and nothing else:
#   - traversal (x only, no read) of /run/virp and /var/lib/virp
#   - rw on the onode socket (unix connect() needs write permission)
#   - ownership of /var/lib/virp/autopilot (0755: published.json is read
#     by the peer node's probe account and carries no secrets)
#
# What it deliberately does NOT grant: group `virp` (the credential
# group: /run/virp/devices.json carries rendered device credentials and
# chain.key / onode.key / chain-sign.key are virp-owned), any read on
# /var/lib/virp/evidence or /var/lib/virp/config-backups, and any write
# on chain.db, chain.db-wal or chain.db-shm. The client opens chain.db
# read-only with immutable=1 precisely because it cannot touch -shm.
# chain-sign.pub is root 0644 in a 0755 directory and needs no grant.
#
# ACLs are re-applied every daemon start because the daemon recreates
# /run/virp and the socket on restart. Fails loud if the user is missing
# or looks over-privileged.
#
# Copyright (c) 2026 Third Level IT LLC. All rights reserved.

set -eu

USER_NAME="virp-autopilot"
USER_UID=971
STATE_DIR="/var/lib/virp/autopilot"
SOCK="/run/virp/onode.sock"

if ! id -u "$USER_NAME" >/dev/null 2>&1; then
    echo "[autopilot-access] FATAL: user $USER_NAME does not exist" >&2
    echo "  create with: useradd --system --uid $USER_UID --shell /usr/sbin/nologin \\" >&2
    echo "    --home-dir /nonexistent --no-create-home $USER_NAME" >&2
    exit 1
fi
if [ "$(id -u "$USER_NAME")" != "$USER_UID" ]; then
    echo "[autopilot-access] FATAL: $USER_NAME is uid $(id -u "$USER_NAME"), not $USER_UID" \
         "(docs/UID-REGISTRY.md pins the number; the template row is a literal)" >&2
    exit 1
fi

# The identity must not be a member of any key/credential group.
extra_groups=$(id -Gn "$USER_NAME" | tr " " "\n" | grep -vx "$USER_NAME" || true)
if [ -n "$extra_groups" ]; then
    echo "[autopilot-access] FATAL: $USER_NAME has supplementary" \
         "groups: $extra_groups — it must be a member of no group but" \
         "its own" >&2
    exit 1
fi

install -d -o "$USER_NAME" -g "$USER_NAME" -m 0755 "$STATE_DIR"
# Files the previous (uid 999) autopilot left behind must become this
# identity's, or the first cycle fails writing alerts.jsonl.
chown -R "$USER_NAME:$USER_NAME" "$STATE_DIR"

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
    echo "[autopilot-access] FATAL: $SOCK missing — is virp-onode up?" >&2
    exit 1
fi
setfacl -m "u:${USER_NAME}:rw-" "$SOCK"

echo "[autopilot-access] $USER_NAME: socket ACL + $STATE_DIR ready"
