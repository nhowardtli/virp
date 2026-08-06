#!/bin/bash
# f1-apply-race.sh — fire N *simultaneous* applies at ONE approved proposal.
#
# Usage: f1-apply-race.sh <N>
#
# This is the limb that matters. Concurrent approvals can only inflate the
# authorization history; concurrent applies are what could actually execute a
# privileged operation on the device more than once.
#
# THREE INDEPENDENT EXECUTION COUNTS are taken, deliberately:
#   1. exec.log line count on the target   — a side effect that ACCUMULATES,
#                                            independent of the witness itself
#   2. witness RECV count (cmdsha-scoped)  — independent of VIRP
#   3. VIRP outcomes / chain entries       — VIRP's own account
# If 1 and 2 ever disagree, the witness is wrong and nothing else in this
# transcript can be trusted. If 1/2 disagree with 3, that is the finding.
#
# The chosen RED operation is `echo exec >> /tmp/virp-f1-exec.log`: reversible,
# harmless, and it appends exactly one line per execution.

set -uo pipefail
N="${1:?usage: f1-apply-race.sh <N>}"
SOCK=/run/virp/onode.sock
KEY=/etc/virp/keys/approval.key
CMD='echo exec >> /tmp/virp-f1-exec.log'
C=clab-frr-ospf-frr1
OUT=$(mktemp -d /tmp/claude-1000/-home-nhoward/016c20e7-3fc9-4816-a68f-90722dd7fb00/scratchpad/f1a-XXXX)
BARRIER="$OUT/go"

# --- clean target-side counters -------------------------------------------
docker exec "$C" sh -c ': > /tmp/virp-f1-exec.log'
sudo /opt/virp/tests/adversarial/witness/install-witness.sh reset "$C" >/dev/null

# --- fresh proposal + exactly ONE approval --------------------------------
sub=$(sudo -u virp /opt/virp/build/virp exec "$C" "$CMD" \
        --socket "$SOCK" --okey /etc/virp/keys/onode.key 2>&1)
P=$(printf '%s' "$sub" | sed -n 's/^proposal_id=\([0-9a-f]*\)$/\1/p' | head -1)
[ -n "$P" ] || { echo "FATAL: no proposal id"; printf '%s\n' "$sub"; exit 1; }

/opt/virp/build/virp approve "$P" --socket "$SOCK" --key "$KEY" >"$OUT/approve.txt" 2>&1
arc=$?
echo "### apply race: N=$N simultaneous applies against proposal $P"
echo "single approval exit=$arc  chain_entry=$(grep -o '"chain_entry_hash":"[0-9a-f]*"' "$OUT/approve.txt" | head -1)"
echo "target exec.log before : $(docker exec "$C" sh -c 'wc -l < /tmp/virp-f1-exec.log')"

for i in $(seq 1 "$N"); do
(
    while [ ! -f "$BARRIER" ]; do :; done
    s=$(cut -d' ' -f1 /proc/uptime)
    o=$(sudo -u virp /opt/virp/build/virp apply "$P" --socket "$SOCK" \
            --okey /etc/virp/keys/onode.key 2>&1)
    rc=$?
    e=$(cut -d' ' -f1 /proc/uptime)
    printf '%s\trc=%s\tstart=%s\tend=%s\t%s\n' "$i" "$rc" "$s" "$e" \
        "$(printf '%s' "$o" | tr '\n' '|')" > "$OUT/child.$i"
) &
done
sleep 0.6
touch "$BARRIER"
wait
sleep 1

echo
echo "--- [2] CLIENT-VISIBLE ---"
ok=$(cat "$OUT"/child.* | awk -F'\t' '$2=="rc=0"' | wc -l)
echo "clients reporting SUCCESS (rc=0): $ok / $N"
echo "failure modes seen:"
cat "$OUT"/child.* | awk -F'\t' '$2!="rc=0"' | sed 's/.*\(O-Node error -[0-9]*[^|]*\).*/    \1/;t;s/^[0-9]*\trc=[0-9]*\t[^\t]*\t[^\t]*\t/    /' | sort | uniq -c | sort -rn

echo
echo "--- [1] TARGET-SIDE INDEPENDENT ---"
echo "exec.log lines (accumulating side effect): $(docker exec "$C" sh -c 'wc -l < /tmp/virp-f1-exec.log')"
sudo /opt/virp/tests/adversarial/witness/witness-count.sh "$C" "$CMD"

echo
echo "--- [3] VIRP DURABLE ---"
echo "approval records : $(sudo ls -1 /var/lib/virp/approvals/approvals/ | grep -cF "$P")"
tail=$(sudo -u virp /opt/virp/build/virp chain tail -n 400 --db /var/lib/virp/chain.db)
for t in proposal approval outcome; do
    echo "chain $t entries : $(printf '%s' "$tail" | grep -cF "$t:$P")"
done
echo "chain rows for this proposal:"
printf '%s\n' "$tail" | grep -F "$P" | sed 's/^/    /'
echo "journal for this proposal:"
sudo journalctl -u virp-onode --since "-4min" --no-pager | grep -F "$P" | sed 's/^.*virp-onode-prod\[[0-9]*\]: /    /' | sort | uniq -c | sort -rn | head -20
echo "PROPOSAL_ID=$P"
