#!/bin/bash
#
# install-receiver.sh — install the TACACS+ accounting receiver on an O-node.
#
# Run as an operator with sudo ON THE TARGET NODE. Idempotent: existing
# keys and secrets are never regenerated, because regenerating either
# silently breaks a switch that is already pointed here.
#
# What this does NOT do, on purpose:
#   - it does not edit devices.template.json. The uid allowlist change is
#     three keys that must move together and it is reviewed by a human;
#     see UID-ALLOWLIST below and docs/TACACS-ACCOUNTING.md §4.
#   - it does not restart virp-onode. That is an outage on every device
#     the node governs and is a deliberate, announced act.
#   - it never prints a secret or a private key.
#
# UID-ALLOWLIST (do this first, in ONE edit of devices.template.json):
#   socket_allowed_uids            += 992
#   socket_uid_action_allow          "992": ["chain_append"]
#   socket_uid_chain_append_types    "992": ["evidence_item"]
# A uid carrying chain_append with no append-type entry does NOT degrade
# to a refused append -- the daemon refuses to BOOT. Dry-run the render
# before restarting:
#   sudo env VIRP_RENDER_OUT=/root/render-test.json \
#       /usr/local/lib/virp/render-devices.sh
#
# Copyright (c) 2026 Third Level IT LLC. All rights reserved.

set -euo pipefail

UID_NUM="${VIRP_TACACS_UID:-992}"
USER_NAME="virp-tacacs"
LIB=/usr/local/lib/virp
ETC=/etc/virp/tacacs
STATE=/var/lib/virp-tacacs
SRC="$(cd "$(dirname "$0")/../.." && pwd)"

[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }

# 1. Service account. Group `virp` is what reaches /run/virp/onode.sock
#    (srw-rw---- virp:virp) -- the same route virp-spark and virp-laptop
#    take on the home node. It also grants read on /var/lib/virp; that is
#    this node's existing posture for socket clients, not something this
#    script introduces, and it is recorded rather than silently accepted.
if ! getent passwd "$USER_NAME" >/dev/null; then
    useradd --system --uid "$UID_NUM" --no-create-home \
            --home-dir "$STATE" --shell /usr/sbin/nologin "$USER_NAME"
fi
usermod -aG virp "$USER_NAME"
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0750 "$STATE"
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$ETC"

# 2. Code, as an INSTALLED ARTIFACT and never a path inside a worktree --
#    the rule virp-onode.service states at length and for good reason.
install -o root -g root -m 0755 "$SRC/tacacs/virp_tacacs_recv.py"  "$LIB/virp-tacacs-recv.py"
install -o root -g root -m 0644 "$SRC/tacacs/virp_tacacs_codec.py" "$LIB/virp_tacacs_codec.py"
python3 "$LIB/virp-tacacs-recv.py" selftest >/dev/null

# 3. Producer keypair, generated HERE. The private half never leaves this
#    box and is not in any repo. Regeneration is refused: a new key makes
#    every record it already signed unverifiable under the pinned one.
if [ ! -f "$ETC/producer.key" ]; then
    python3 "$LIB/virp-tacacs-recv.py" keygen \
        --sk "$ETC/producer.key" --pk "$ETC/producer.pub" >/dev/null
    chown "$USER_NAME:$USER_NAME" "$ETC/producer.key" "$ETC/producer.pub"
    chmod 0600 "$ETC/producer.key"; chmod 0644 "$ETC/producer.pub"
fi

# 4. Unit.
install -o root -g root -m 0644 "$SRC/deploy/tacacs/virp-tacacs.service" \
        /etc/systemd/system/virp-tacacs.service
systemctl daemon-reload

echo "installed. producer key_id (sha256-raw-16 over the raw public key):"
python3 - "$ETC/producer.pub" <<'PY'
import hashlib, sys
print("  " + hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest()[:32])
PY
echo "next: write $ETC/recv.json (0600 $USER_NAME) with the per-switch"
echo "      shared secrets, then: systemctl enable --now virp-tacacs"
