#!/bin/bash
#
# install-authz-server.sh -- install the VIRP TACACS+ AUTHORIZATION server.
#
#   THIS IS NOT THE ACCOUNTING RECEIVER. See install-receiver.sh for
#   that. Accounting stays on 313 (10.0.0.13:4949) and .211
#   (10.0.10.211:4949) and this script touches neither.
#
# Run as root ON THE AUTHORIZATION SERVER. Idempotent: existing secrets
# are NEVER regenerated, because regenerating a shared key silently
# breaks every switch already pointed here, and regenerating an account
# password silently breaks the gate.
#
# It never prints a secret. Secrets are written to /etc/tacacs/secrets.conf
# (0600 root:root) and the script tells you the path, not the contents.

set -euo pipefail

ETC=/etc/tacacs
LOGDIR=/var/log/tacacs
SBIN=/usr/local/sbin
SRC=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SRC/../.." && pwd)

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
[ -x "$SBIN/tac_plus-ng" ] || {
    echo "tac_plus-ng is not installed at $SBIN/tac_plus-ng" >&2
    echo "build it first: see README.md" >&2
    exit 1
}

umask 077
mkdir -p "$ETC" "$LOGDIR"
chmod 0700 "$ETC"
chmod 0750 "$LOGDIR"

# ----------------------------------------------------------------------
# 1. Secrets -- generated here, on the box, once.
# ----------------------------------------------------------------------
if [ -f "$ETC/secrets.conf" ]; then
    echo "secrets.conf exists -- NOT regenerating (that would break every"
    echo "device already pointed at this server, and the gate with it)"
else
    echo "generating secrets"
    KEY_GNS3=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-32)
    KEY_TEST=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-32)
    PW_RO=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-32)
    PW_RW=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-32)

    # The GNS3 home fabric is R1-R35 at 10.0.0.50-.84. Emitted as an
    # explicit address list rather than a /24: a prefix here would let
    # ANY host on the home segment authenticate as a device, including
    # one that is not a governed router.
    {
        echo "# GENERATED $(date -u +%Y-%m-%dT%H:%M:%SZ) by install-authz-server.sh"
        echo "# 0600 root:root. NEVER commit, never print, never echo."
        echo ""
        echo "host gns3_home_fabric {"
        for i in $(seq 50 84); do
            echo "	address = 10.0.0.$i/32"
        done
        echo "	key = $KEY_GNS3"
        echo "}"
        echo ""
        echo "host virp_test_clients {"
        echo "	address = 127.0.0.1/32"
        echo "	address = 10.0.0.215/32"
        echo "	address = 10.0.0.13/32"
        echo "	address = 10.0.0.35/32"
        echo "	key = $KEY_TEST"
        echo "}"
        echo ""
        echo "user virp-ro {"
        echo "	password login = clear $PW_RO"
        # PAP is a SEPARATE credential slot in tac_plus-ng; without this
        # line PAP authentication returns FAIL even with a correct login
        # password. `= login` defers PAP to the login password rather
        # than storing the secret twice.
        echo "	password pap = login"
        echo "	profile = virp_ro_profile"
        echo "}"
        echo ""
        echo "user virp-rw {"
        echo "	password login = clear $PW_RW"
        echo "	password pap = login"
        echo "	profile = virp_rw_profile"
        echo "}"
    } > "$ETC/secrets.conf"
    unset KEY_GNS3 KEY_TEST PW_RO PW_RW
fi
chmod 0600 "$ETC/secrets.conf"
chown root:root "$ETC/secrets.conf"

# ----------------------------------------------------------------------
# 2. GREEN policy -- GENERATED from the driver table, never hand-copied.
# ----------------------------------------------------------------------
if [ -f "$REPO_ROOT/src/drivers/driver_cisco.c" ]; then
    echo "generating green.conf from driver_cisco.c"
    python3 "$SRC/gen-green-conf.py" \
        --driver "$REPO_ROOT/src/drivers/driver_cisco.c" \
        --out "$ETC/green.conf" \
        --guard-out "$ETC/guard.conf" \
        --repo-root "$REPO_ROOT" --prefix
elif [ -f "$SRC/green.conf" ] && [ -f "$SRC/guard.conf" ]; then
    echo "no driver source here; installing pre-generated green.conf + guard.conf"
    cp "$SRC/green.conf" "$ETC/green.conf"
    cp "$SRC/guard.conf" "$ETC/guard.conf"
else
    echo "FATAL: no driver_cisco.c and no pre-generated green.conf." >&2
    echo "Refusing to install a server with an empty read policy." >&2
    exit 1
fi
chmod 0644 "$ETC/green.conf" "$ETC/guard.conf"

# ----------------------------------------------------------------------
# 3. approved.conf -- the seam. Starts EMPTY and stays empty here.
#
# Created only if absent. If VIRP has already written grants into it,
# a reinstall must not silently revoke them.
# ----------------------------------------------------------------------
if [ ! -f "$ETC/approved.conf" ]; then
    cat > "$ETC/approved.conf" <<'APPROVED'
# /etc/tacacs/approved.conf -- the virp-rw grant seam. STARTS EMPTY.
#
# VIRP writes one rule per approved command here, for a bounded TTL, and
# truncates the file when the TTL expires. Everything not listed is
# denied by the unconditional `deny` that follows this include in
# tac_plus-ng.cfg -- so an EMPTY file means DENY ALL, which is the
# correct resting state.
#
# TRUNCATE THIS FILE, NEVER DELETE IT. tac_plus-ng treats a
# non-matching include as a parse error (GLOB_NOMATCH,
# mavis/mavis_parse.c:764). Deleting it takes the whole server down on
# the next reload. Emptying it revokes every grant. Those are very
# different outcomes and only one of them is intended.
#
# Rule shape -- one line per approved command, in IOS CANONICAL form:
#
#     if (cmd =~ /\Aconfigure terminal(?: <cr>)?\z/) { permit }
#
# The `(?: <cr>)?` is not decoration. IOS terminates a per-command
# authorization request with cmd-arg=<cr>, which tac_plus-ng reassembles
# into the command string (author.c:eval_args). Without it, nothing
# matches.
#
# USE \A AND \z, NEVER ^ AND $. tac_plus-ng compiles PCRE2 with
# PCRE2_MULTILINE, under which ^ and $ match at embedded newlines -- so
# /^configure terminal$/ also permits
# "configure terminal\n<anything you like>". Measured. \A and \z anchor
# to the absolute start and end of the command line and close that hole.
# A grant written with ^ and $ is a bypass, not a grant.
#
# Write the CANONICAL form, not the operator's typed form. IOS
# re-spells before it authorizes ("interface Loopback91" ->
# "interface Loopback 91") and truncates at ";". Use
# tacacs/virp_tacacs_authz.py:ios_canonical() to produce the string.
#
# After writing: run `tacacs-reload`. It re-checks the config and
# REFUSES to signal if this file is malformed, leaving the running
# policy untouched.
APPROVED
    echo "created empty approved.conf (deny-all resting state)"
else
    echo "approved.conf exists -- left alone (it may hold live grants)"
fi
chmod 0644 "$ETC/approved.conf"

# ----------------------------------------------------------------------
# 4. Main config, reload wrapper, unit
# ----------------------------------------------------------------------
install -m 0600 -o root -g root "$SRC/tac_plus-ng.cfg" "$ETC/tac_plus-ng.cfg"
install -m 0755 "$SRC/tacacs-reload" "$SBIN/tacacs-reload"
install -m 0644 "$SRC/virp-tacacs-authz.service" \
    /etc/systemd/system/virp-tacacs-authz.service

# ----------------------------------------------------------------------
# 5. Check BEFORE enabling. Never enable a config that does not parse.
# ----------------------------------------------------------------------
echo "checking config"
if ! "$SBIN/tac_plus-ng" -P "$ETC/tac_plus-ng.cfg"; then
    echo "FATAL: config does not parse. Not enabling, not starting." >&2
    exit 1
fi
echo "config OK"

systemctl daemon-reload
systemctl enable virp-tacacs-authz.service

echo ""
echo "installed. secrets are in $ETC/secrets.conf (0600 root:root)."
echo "they were NOT printed. read them there when you configure a switch."
echo ""
echo "start with:  systemctl start virp-tacacs-authz"
echo "reload with: tacacs-reload      (checks first, refuses on bad config)"
