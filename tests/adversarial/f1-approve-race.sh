#!/bin/bash
# f1-approve-race.sh — fire N *simultaneous* approvals at ONE proposal.
#
# Usage: f1-approve-race.sh <N> [label]
#
# Simultaneity: children busy-wait on a barrier file rather than relying on
# `&` launch order, so all N enter virp_approval_submit inside the same few
# milliseconds. Launch jitter would otherwise serialise the race and it would
# silently degrade into the sequential case that is already on record.
#
# Must run as nhoward: the approver secret is nhoward-owned by design.
# Every count is scoped to the proposal id, never to spool totals — the spool
# already holds 200+ unrelated proposals.

set -uo pipefail
N="${1:?usage: f1-approve-race.sh <N> [label]}"
LABEL="${2:-race}"
SOCK=/run/virp/onode.sock
KEY=/etc/virp/keys/approval.key
CMD='echo exec >> /tmp/virp-f1-exec.log'
OUT=$(mktemp -d /tmp/claude-1000/-home-nhoward/016c20e7-3fc9-4816-a68f-90722dd7fb00/scratchpad/f1-XXXX)
BARRIER="$OUT/go"

# --- fresh proposal, so counts cannot be contaminated by earlier tests ------
sub=$(sudo -u virp /opt/virp/build/virp exec clab-frr-ospf-frr1 "$CMD" \
        --socket "$SOCK" --okey /etc/virp/keys/onode.key 2>&1)
P=$(printf '%s' "$sub" | sed -n 's/^proposal_id=\([0-9a-f]*\)$/\1/p' | head -1)
[ -n "$P" ] || { echo "FATAL: no proposal id from submit:"; printf '%s\n' "$sub"; exit 1; }

echo "### $LABEL: N=$N concurrent approvals against proposal $P"
echo "workdir: $OUT"

for i in $(seq 1 "$N"); do
(
    while [ ! -f "$BARRIER" ]; do :; done
    s=$(cut -d' ' -f1 /proc/uptime)
    o=$(/opt/virp/build/virp approve "$P" --socket "$SOCK" --key "$KEY" 2>&1)
    rc=$?
    e=$(cut -d' ' -f1 /proc/uptime)
    printf '%s\trc=%s\tstart=%s\tend=%s\t%s\n' "$i" "$rc" "$s" "$e" \
        "$(printf '%s' "$o" | tr '\n' '|')" > "$OUT/child.$i"
) &
done

sleep 0.4          # let every child reach the barrier
touch "$BARRIER"
wait

echo "--- client-reported outcomes ---"
ok=$(grep -l 'rc=0' "$OUT"/child.* 2>/dev/null | wc -l)
echo "clients reporting SUCCESS (rc=0)   : $ok / $N"
echo "clients reporting failure          : $(( N - ok ))"
echo "distinct approved_at_ns printed by clients:"
cat "$OUT"/child.* 2>/dev/null | grep -o 'approved_at_ns":[0-9.e+]*' | sort -u | sed 's/^/    /'
echo "non-zero rc detail (if any):"
cat "$OUT"/child.* 2>/dev/null | awk -F'\t' '$2!="rc=0"' | sed 's/^/    /' | head

echo "--- durable state for proposal $P ---"
echo "approval records on disk : $(sudo ls -1 /var/lib/virp/approvals/approvals/ | grep -cF "$P")"
echo "approval record approved_at_ns : $(sudo sed -n 1p /var/lib/virp/approvals/approvals/$P.rec 2>/dev/null | grep -o '"approved_at_ns":"[0-9]*"')"
echo "challenge  record approved_at_ns : $(sudo sed -n 1p /var/lib/virp/approvals/challenges/$P.rec 2>/dev/null | grep -o '"approved_at_ns":"[0-9]*"')"
echo "APPROVAL chain entries   : $(sudo -u virp /opt/virp/build/virp chain tail -n 400 --db /var/lib/virp/chain.db | grep -cF "approval:$P")"
echo "PROPOSAL chain entries   : $(sudo -u virp /opt/virp/build/virp chain tail -n 400 --db /var/lib/virp/chain.db | grep -cF "proposal:$P")"
echo "journal: chain= values on submit:"
sudo journalctl -u virp-onode --since "-3min" --no-pager | grep -F "[APPROVAL] submitted: proposal=$P" \
    | sed 's/.*chain=/    chain=/' | sort | uniq -c
echo "PROPOSAL_ID=$P"
