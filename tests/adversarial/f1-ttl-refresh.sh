#!/bin/bash
# f1-ttl-refresh.sh — decide F1's "each re-approval mints a fresh 300s TTL" limb
# EMPIRICALLY, not from source reading.
#
# Method: approve at T0. Re-approve at T0+120 and T0+240 — the client reports
# "APPROVED — single use, TTL 300s from approval time" every time. Then apply at
# T0+310, which is PAST 300s from the first approval but only ~70s past the last.
#
#   apply succeeds  -> the TTL really was refreshed; the authorization window is
#                      extensible without limit and without a chain record. Serious.
#   apply -> expired -> the TTL is anchored to the FIRST approval; the refresh the
#                      client reported was fiction. Fail-closed, but the operator
#                      was told something untrue.
#
# The whole point is that the client's own output cannot answer this. Only the
# apply decision can.

set -uo pipefail
SOCK=/run/virp/onode.sock
KEY=/etc/virp/keys/approval.key
CMD='echo exec >> /tmp/virp-f1-exec.log'
C=clab-frr-ospf-frr1

docker exec "$C" sh -c ': > /tmp/virp-f1-exec.log'
sudo /opt/virp/tests/adversarial/witness/install-witness.sh reset "$C" >/dev/null

sub=$(sudo -u virp /opt/virp/build/virp exec "$C" "$CMD" --socket "$SOCK" \
        --okey /etc/virp/keys/onode.key 2>&1)
P=$(printf '%s' "$sub" | sed -n 's/^proposal_id=\([0-9a-f]*\)$/\1/p' | head -1)
echo "proposal: $P"

rec_at() { sudo sed -n 1p /var/lib/virp/approvals/approvals/$P.rec 2>/dev/null | grep -o '"approved_at_ns":"[0-9]*"'; }
chal_at() { sudo sed -n 1p /var/lib/virp/approvals/challenges/$P.rec 2>/dev/null | grep -o '"approved_at_ns":"[0-9]*"'; }

T0=$(date -u +%s)
echo "=== T+0   approval #1 ==="
/opt/virp/build/virp approve "$P" --socket "$SOCK" --key "$KEY" 2>&1 | grep -E "APPROVED|chain_entry_hash" | sed 's/^/    /'
echo "    approval record : $(rec_at)"
echo "    challenge record: $(chal_at)"

for t in 120 240; do
    while [ $(( $(date -u +%s) - T0 )) -lt $t ]; do sleep 5; done
    echo "=== T+$(( $(date -u +%s) - T0 ))  re-approval ==="
    /opt/virp/build/virp approve "$P" --socket "$SOCK" --key "$KEY" 2>&1 | grep -E "APPROVED|chain_entry_hash" | sed 's/^/    /'
    echo "    approval record : $(rec_at)   <- governs apply"
    echo "    challenge record: $(chal_at)   <- refreshed"
done

while [ $(( $(date -u +%s) - T0 )) -lt 310 ]; do sleep 5; done
echo "=== T+$(( $(date -u +%s) - T0 ))  APPLY (past 300s from first approval, ~70s from last) ==="
sudo -u virp /opt/virp/build/virp apply "$P" --socket "$SOCK" --okey /etc/virp/keys/onode.key 2>&1 | sed 's/^/    /'
echo "    client exit=$?"
echo
echo "--- target-side truth ---"
echo "exec.log lines: $(docker exec "$C" sh -c 'wc -l < /tmp/virp-f1-exec.log')"
sudo /opt/virp/tests/adversarial/witness/witness-count.sh "$C" "$CMD" | sed 's/^/    /'
echo "--- chain ---"
sudo -u virp /opt/virp/build/virp chain tail -n 200 --db /var/lib/virp/chain.db | grep -F "$P" | sed 's/^/    /'
echo "--- journal ---"
sudo journalctl -u virp-onode --since "-7min" --no-pager | grep -F "$P" | sed 's/^.*virp-onode-prod\[[0-9]*\]: /    /'
echo "PROPOSAL_ID=$P"
