#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# sean-denial-proof.sh — the eight denial checks for the virp-sean seat
# on virp-lab (10.0.10.211). Same eight as the virp-netclaw proof of
# 2026-08-09. Run as root ON .211 after the seat is provisioned and the
# daemon has been restarted.
#
# This proves what the seat CANNOT do. The things it can do (health,
# chain_verify, chain_append of evidence_item) are proven separately by
# the Phase 4 end-to-end capture, from the VM side.
#
# Output is meant to be pasted verbatim into the gated-edits document.
# Every check prints the command it ran, so the record is re-runnable by
# someone who does not trust this script.
#
# Copyright (c) 2026 Third Level IT LLC. All rights reserved.

set -uo pipefail

U=virp-sean
EXPECT_UID=987
RC=0
N=0

hdr(){ N=$((N+1)); printf "\n[%d/8] %s\n" "$N" "$1"; }
run(){ printf "      \$ %s\n" "$*"; }
pass(){ printf "      DENIED  (correct) — %s\n" "$1"; }
fail(){ printf "      ALLOWED (FAIL)   — %s\n" "$1"; RC=1; }

echo "=============================================================="
echo " virp-sean denial proof — $(hostname) — $(date -u +%FT%TZ)"
echo " account: $U (uid $(id -u $U 2>/dev/null || echo MISSING))"
echo "=============================================================="

if ! id -u "$U" >/dev/null 2>&1; then echo "FATAL: $U does not exist"; exit 1; fi
if [ "$(id -u "$U")" != "$EXPECT_UID" ]; then
    echo "FATAL: $U is uid $(id -u "$U"), expected $EXPECT_UID"; exit 1
fi

# --- 1. shell ---------------------------------------------------------
hdr "Interactive shell is impossible"
run "getent passwd $U | cut -d: -f7"
SH=$(getent passwd "$U" | cut -d: -f7)
echo "      -> $SH"
[ "$SH" = "/usr/sbin/nologin" ] || [ "$SH" = "/sbin/nologin" ] \
    && pass "login shell is nologin" \
    || fail "login shell is $SH"

# --- 2. PTY -----------------------------------------------------------
hdr "sshd will not allocate a PTY for this account"
run "sshd -T -C user=$U,addr=10.0.70.10 | grep -i permittty"
PTY=$(sshd -T -C "user=$U,addr=10.0.70.10" 2>/dev/null | grep -i '^permittty' || echo "permittty MISSING")
echo "      -> $PTY"
echo "$PTY" | grep -qi "permittty no" && pass "PermitTTY no" || fail "$PTY"

# --- 3. TCP forwarding ------------------------------------------------
hdr "TCP forwarding is denied (nft, not sshd — see the 9.6 quirk)"
run "nft list table inet virp_sean_egress"
if nft list table inet virp_sean_egress >/dev/null 2>&1; then
    nft list table inet virp_sean_egress | sed 's/^/      /'
    if nft list table inet virp_sean_egress | grep -q "skuid $EXPECT_UID .*reject"; then
        pass "uid $EXPECT_UID may not originate new IP connections"
    else
        fail "table exists but has no reject rule for uid $EXPECT_UID"
    fi
else
    fail "table inet virp_sean_egress is NOT loaded — TCP forwards are OPEN"
fi
echo "      (live behavioural proof, from the VM, belongs in the Phase 4 capture:"
echo "       ssh -L 9999:10.0.10.2:22 virp-sean@10.0.10.211 then connect -> must fail)"

# --- 4..7. the four credential reads ----------------------------------
for pair in \
  "O-Node signing key:/etc/virp/keys/onode.key" \
  "chain signing key:/etc/virp/keys/chain.key" \
  "approver secret:/etc/virp/keys/approval.key" \
  "autopilot env (device credentials):/etc/virp/autopilot.env"
do
    LABEL="${pair%%:*}"; PATHV="${pair##*:}"
    hdr "Cannot read the $LABEL"
    run "runuser -u $U -- cat $PATHV"
    if runuser -u "$U" -- test -r "$PATHV" 2>/dev/null; then
        fail "$U can read $PATHV"
    else
        printf "      -> %s\n" "$(runuser -u "$U" -- cat "$PATHV" 2>&1 | head -1)"
        pass "$PATHV unreadable"
    fi
done

# --- 8. authorized_keys self-write ------------------------------------
hdr "Cannot enroll its own ssh key"
KEYF=/etc/ssh/authorized_keys.d/$U
run "ls -l $KEYF ; runuser -u $U -- touch $KEYF"
ls -l "$KEYF" 2>&1 | sed 's/^/      /'
OWNER=$(stat -c '%U:%G %a' "$KEYF" 2>/dev/null || echo "MISSING")
echo "      -> owner/mode: $OWNER"
if runuser -u "$U" -- test -w "$KEYF" 2>/dev/null; then
    fail "$U can write its own authorized_keys"
else
    pass "key file is root-owned and not writable by $U"
fi
# and it must not be able to create a fallback ~/.ssh either
HOME_DIR=$(getent passwd "$U" | cut -d: -f6)
echo "      home is $HOME_DIR (must not exist)"
[ -d "$HOME_DIR" ] && fail "home directory $HOME_DIR EXISTS — a ~/.ssh fallback is possible" \
                   || pass "no home directory, so no ~/.ssh fallback"

# --- supplementary: group membership ----------------------------------
printf "\n[extra] group membership\n"
run "id -nG $U"
echo "      -> $(id -nG "$U")"
[ "$(id -nG "$U")" = "$U" ] && printf "      OK — own group only\n" \
                            || { printf "      FAIL — extra groups\n"; RC=1; }

echo
echo "=============================================================="
[ $RC -eq 0 ] && echo " RESULT: all eight denials hold" \
              || echo " RESULT: AT LEAST ONE DENIAL FAILED — do not hand over the seat"
echo "=============================================================="
exit $RC
