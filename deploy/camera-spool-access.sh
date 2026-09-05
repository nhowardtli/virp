#!/bin/bash
#
# camera-spool-access.sh — provision the Option B capture spool on the
# O-node host, in the same shape and spirit as netclaw-access.sh.
#
# Creates `virp-capture`: the REMOTE capture-host identity. The sshd
# child that serves the capture host's sftp upload runs as this uid, so
# SO_PEERCRED / the chroot present an authenticated, boxed remote
# identity — never a shell, never a forward, never reach beyond the
# spool. It is:
#   - key-only, from=-pinned to the capture host, restrict-ed at sshd
#   - chrooted (ForceCommand internal-sftp) to /var/spool/virp-capture,
#     a root-owned tree (sshd's chroot ownership requirement)
#   - a member of NO group but its own, and able to read NO key,
#     credential store, socket or rendered device list
#
# The SUBMITTER (virp — the Phase 1 identity, the only camera producer
# already trusted for chain_append) reads the spool. It is granted reach
# into incoming/ and done/ by ACL, not group membership — group `virp`
# is a credential group, exactly as netclaw-access.sh notes.
#
# Fails loud if virp-capture looks over-privileged.
#
# Copyright (c) 2026 Third Level IT LLC. All rights reserved.

set -eu

CAP_USER="virp-capture"
SUBMITTER="virp"
CHROOT="/var/spool/virp-capture"
INCOMING="$CHROOT/incoming"
DONE="$CHROOT/done"
AK_DIR="/etc/ssh/authorized_keys.d"
AK_FILE="$AK_DIR/$CAP_USER"
SSHD_DROPIN="/etc/ssh/sshd_config.d/60-virp-capture.conf"
FROM_PIN="${FROM_PIN:-10.0.3.102,10.0.0.222,10.0.0.36,10.0.0.15}"
PUBKEY="${CAP_PUBKEY:?set CAP_PUBKEY to the capture host public key line}"

# ── capture identity ───────────────────────────────────────────────────
if ! id -u "$CAP_USER" >/dev/null 2>&1; then
    useradd --system --shell /usr/sbin/nologin \
        --home-dir /nonexistent --no-create-home "$CAP_USER"
    echo "[spool] created $CAP_USER"
fi

# Least privilege, checked (mirrors netclaw-access.sh):
extra_groups=$(id -Gn "$CAP_USER" | tr " " "\n" | grep -vx "$CAP_USER" || true)
if [ -n "$extra_groups" ]; then
    echo "[spool] FATAL: $CAP_USER has supplementary groups:" \
         "$extra_groups — must belong to no group but its own" >&2
    exit 1
fi
for secret in /etc/virp/keys/onode.key /etc/virp/keys/chain.key \
              /etc/virp/keys/approval.key /etc/virp/autopilot.env \
              /run/virp/devices.json /run/virp/onode.sock; do
    if runuser -u "$CAP_USER" -- test -r "$secret" 2>/dev/null; then
        echo "[spool] FATAL: $CAP_USER can read $secret — refusing" >&2
        exit 1
    fi
done

# ── chroot tree (root-owned, per sshd) + writable spool dirs ───────────
mkdir -p "$CHROOT"
chown root:root "$CHROOT"
chmod 0755 "$CHROOT"
mkdir -p "$INCOMING" "$DONE"
chown "$CAP_USER:$CAP_USER" "$INCOMING" "$DONE"
chmod 0700 "$INCOMING" "$DONE"

# Submitter reaches the spool by ACL, never by joining a credential
# group. Default ACLs so files the capture host drops are submitter-
# readable/removable without any world bit.
for d in "$INCOMING" "$DONE"; do
    setfacl -m    "u:${SUBMITTER}:rwx" "$d"
    setfacl -d -m "u:${SUBMITTER}:rwx" "$d"
    setfacl -d -m "u:${CAP_USER}:rwx"  "$d"
done

# ── key custody: root-owned authorized_keys, pinned + restricted ───────
mkdir -p "$AK_DIR"
chmod 0755 "$AK_DIR"
printf 'from="%s",restrict %s\n' "$FROM_PIN" "$PUBKEY" > "$AK_FILE"
chown root:root "$AK_FILE"
chmod 0644 "$AK_FILE"

# ── sshd: chroot + sftp-only for this user, nothing else ───────────────
cat > "$SSHD_DROPIN" <<EOF
Match User $CAP_USER
    ChrootDirectory $CHROOT
    ForceCommand internal-sftp -d /incoming
    AuthorizedKeysFile $AK_FILE
    AllowTcpForwarding no
    AllowAgentForwarding no
    AllowStreamLocalForwarding no
    PermitTunnel no
    X11Forwarding no
    PermitTTY no
EOF
chmod 0644 "$SSHD_DROPIN"

if sshd -t; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null
    echo "[spool] sshd config valid, reloaded"
else
    echo "[spool] FATAL: sshd -t rejected the config; drop-in left at" \
         "$SSHD_DROPIN for inspection, NOT reloaded" >&2
    exit 1
fi

echo "[spool] ready:"
echo "  chroot   $CHROOT (root:root 0755)"
echo "  incoming $INCOMING ($CAP_USER, +ACL u:$SUBMITTER:rwx)"
echo "  pin      from=\"$FROM_PIN\" restrict, key-only, internal-sftp"
getfacl -p "$INCOMING" 2>/dev/null | grep -E "^(owner|user)" || true
