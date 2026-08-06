#!/bin/bash
# fi-run.sh — drive one propose -> approve -> apply cycle against the ISOLATED
# fault-injection daemon, with the daemon armed to SIGKILL itself at a chosen
# boundary. Then report, from three independent sources, what survived.
#
# Usage: fi-run.sh <point|none>
#   points: pre_consume post_consume pre_exec post_exec pre_outcome mid_outcome
#
# ISOLATION (rule 3). Everything lives under /run/virp-fi:
#   socket /run/virp-fi/onode.sock     chain /run/virp-fi/chain.db
#   spool  /run/virp-fi/approvals      keys  freshly generated, NOT production
# The production daemon on /run/virp/onode.sock is never contacted and its
# chain at /var/lib/virp/chain.db is never opened by this script.
#
# The daemon runs in the FOREGROUND under this script and is killed by its own
# instrumentation, never installed and never run as a systemd unit.
#
# THE QUESTION: after the crash, does the target's record of what happened
# agree with VIRP's? The disagreement being hunted is
#     TARGET: operation happened   /   VIRP: no durable outcome

set -uo pipefail
POINT="${1:?usage: fi-run.sh <point|none>}"
FI=/run/virp-fi
D=/opt/virp/build-fi/virp-onode-prod
CLI=/opt/virp/build/virp
C=clab-frr-ospf-frr1
CMD='echo fi >> /tmp/virp-fi-exec.log'
LOG=$FI/daemon.$POINT.log

start_daemon() {
    # $1 = VIRP_FI_POINT value ("" = unarmed)
    # VIRP_KNOWN_HOSTS: the lab daemon refused to connect until given one --
    # it fail-closed on host key verification with no TOFU, which is correct.
    # Seeded by ssh-keyscan and verified byte-identical to the three keys the
    # production daemon already trusts for 172.20.20.5, so the lab is not
    # trusting anything production does not.
    VIRP_FI_POINT="$1" VIRP_KNOWN_HOSTS=$FI/known_hosts \
    "$D" -k $FI/onode.key -s $FI/onode.sock -d $FI/devices.json \
        -c $FI/chain.db -C $FI/chain.key -a $FI/approvals -A $FI/approvers.json \
        >>"$LOG" 2>&1 &
    DPID=$!
    for _ in $(seq 1 40); do [ -S $FI/onode.sock ] && break; sleep 0.25; done
    sleep 0.5
}
stop_daemon() { kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; }

echo "################ FAULT-INJECTION RUN: point=$POINT ################"
: > "$LOG"
rm -f $FI/onode.sock
docker exec $C sh -c ': > /tmp/virp-fi-exec.log'
sudo /opt/virp/tests/adversarial/witness/install-witness.sh reset $C >/dev/null

# ---- phase 1: unarmed daemon, propose + approve -------------------------
start_daemon ""
echo "daemon pid=$DPID (unarmed for propose/approve)"

sub=$("$CLI" exec $C "$CMD" --socket $FI/onode.sock --okey $FI/onode.key 2>&1)
P=$(printf '%s' "$sub" | sed -n 's/^proposal_id=\([0-9a-f]*\)$/\1/p' | head -1)
if [ -z "$P" ]; then echo "FATAL: no proposal id"; printf '%s\n' "$sub"; stop_daemon; exit 1; fi
echo "proposal: $P"

"$CLI" approve "$P" --socket $FI/onode.sock --key $FI/approval.key >/dev/null 2>&1
echo "approve exit=$?"
stop_daemon

# ---- phase 2: armed daemon, apply ---------------------------------------
echo "--- restarting daemon ARMED at '$POINT', then applying ---"
start_daemon "$POINT"
echo "daemon pid=$DPID armed=$POINT"

t0=$(cut -d' ' -f1 /proc/uptime)
out=$("$CLI" apply "$P" --dir $FI/approvals --socket $FI/onode.sock --okey $FI/onode.key 2>&1)
arc=$?
t1=$(cut -d' ' -f1 /proc/uptime)
echo "--- client apply (exit=$arc, ${t0}->${t1}) ---"
printf '%s\n' "$out" | sed 's/^/    /'

sleep 0.5
if kill -0 "$DPID" 2>/dev/null; then
    echo "daemon: STILL ALIVE (crash point not reached)"
    stop_daemon
else
    wait "$DPID" 2>/dev/null; drc=$?
    echo "daemon: DEAD, wait status=$drc  (137 = SIGKILL)"
fi
echo "--- daemon stderr tail ---"
tail -6 "$LOG" | sed 's/^/    /'

# ---- phase 3: what actually happened, from three sources ----------------
echo
echo "=== [1] TARGET — independent of VIRP ==="
echo "exec.log lines : $(docker exec $C sh -c 'wc -l < /tmp/virp-fi-exec.log')"
sudo /opt/virp/tests/adversarial/witness/witness-count.sh $C "$CMD" | sed 's/^/    /'

echo
echo "=== [2] VIRP SPOOL (isolated) ==="
for d in proposals approvals challenges; do
    printf '    %-11s : %s\n' "$d" "$(ls -1 $FI/approvals/$d 2>/dev/null | grep -cF "$P")"
done
echo "    consumed.list  : $(grep -cF "$P" $FI/approvals/consumed.list 2>/dev/null; true) entry for this proposal"

echo
echo "=== [3] VIRP CHAIN (isolated) — restart daemon and re-read ==="
start_daemon ""
"$CLI" chain tail -n 40 --db $FI/chain.db 2>&1 | grep -F "$P" | sed 's/^/    /' || echo "    (no entries)"
for t in proposal approval outcome; do
    n=$("$CLI" chain tail -n 40 --db $FI/chain.db 2>/dev/null | grep -cF "$t:$P")
    printf '    chain %-9s entries: %s\n' "$t" "$n"
done

echo
echo "=== [4] RETRY the apply after restart ==="
retry=$("$CLI" apply "$P" --dir $FI/approvals --socket $FI/onode.sock --okey $FI/onode.key 2>&1)
echo "    retry exit=$?"
printf '%s\n' "$retry" | grep -E "ERROR|payload|trust_tier" | sed 's/^/    /'
echo "    target exec.log after retry: $(docker exec $C sh -c 'wc -l < /tmp/virp-fi-exec.log')"
sudo /opt/virp/tests/adversarial/witness/witness-count.sh $C "$CMD" | grep -E "delivered|completed" | sed 's/^/    /'
stop_daemon
echo "PROPOSAL=$P"
echo
