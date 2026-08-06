#!/bin/bash
# fi-inflight.sh — the "during send" boundary of test #2.
#
# The other crash points are reached by the daemon's own instrumentation, which
# means the kill lands at a code boundary. This one is different on purpose: the
# daemon is SIGKILLed FROM OUTSIDE while an approved operation is genuinely
# in flight at the target. Nothing about where the kill lands is chosen by the
# daemon, which is what makes it the realistic case.
#
# The target operation is /usr/local/bin/virp-fi-slow, which writes
#   "started"   to /tmp/virp-fi-slow.log  immediately, and
#   "COMPLETED" to /tmp/virp-fi-exec.log  six seconds later.
# So the target's own files distinguish began-but-did-not-finish from finished,
# independently of the witness RECV/DONE pair, which measures the same thing a
# second way.
#
# Usage: fi-inflight.sh <seconds-to-wait-before-kill>

set -uo pipefail
WAIT="${1:-2}"
FI=/run/virp-fi
D=/opt/virp/build-fi/virp-onode-prod
CLI=/opt/virp/build/virp
C=clab-frr-ospf-frr1
CMD='virp-fi-slow'
LOG=$FI/daemon.inflight.log

start_daemon() {
    VIRP_FI_POINT="" VIRP_KNOWN_HOSTS=$FI/known_hosts \
    "$D" -k $FI/onode.key -s $FI/onode.sock -d $FI/devices.json \
        -c $FI/chain.db -C $FI/chain.key -a $FI/approvals -A $FI/approvers.json \
        >>"$LOG" 2>&1 &
    DPID=$!
    for _ in $(seq 1 40); do [ -S $FI/onode.sock ] && break; sleep 0.25; done
    sleep 0.5
}

echo "############ IN-FLIGHT KILL: SIGKILL ${WAIT}s into a 6s operation ############"
: > "$LOG"; rm -f $FI/onode.sock
docker exec $C sh -c ': > /tmp/virp-fi-exec.log; : > /tmp/virp-fi-slow.log'
sudo /opt/virp/tests/adversarial/witness/install-witness.sh reset $C >/dev/null

start_daemon
sub=$("$CLI" exec $C "$CMD" --socket $FI/onode.sock --okey $FI/onode.key 2>&1)
P=$(printf '%s' "$sub" | sed -n 's/^proposal_id=\([0-9a-f]*\)$/\1/p' | head -1)
[ -n "$P" ] || { echo "FATAL: no proposal"; printf '%s\n' "$sub"; kill $DPID; exit 1; }
"$CLI" approve "$P" --socket $FI/onode.sock --key $FI/approval.key >/dev/null 2>&1
echo "proposal $P approved (exit=$?)"

echo "--- launching apply, then SIGKILL daemon pid=$DPID after ${WAIT}s ---"
( "$CLI" apply "$P" --dir $FI/approvals --socket $FI/onode.sock --okey $FI/onode.key \
    > $FI/inflight.client.out 2>&1; echo $? > $FI/inflight.client.rc ) &
CPID=$!
sleep "$WAIT"
echo "target state at kill time:"
echo "    slow.log : $(docker exec $C cat /tmp/virp-fi-slow.log 2>/dev/null | tr '\n' ' ')"
echo "    exec.log : $(docker exec $C cat /tmp/virp-fi-exec.log 2>/dev/null | tr '\n' ' ')"
kill -9 "$DPID" 2>/dev/null
echo "    >>> SIGKILL sent to daemon at $(cut -d' ' -f1 /proc/uptime)"
wait "$CPID" 2>/dev/null
echo "--- client ---"
echo "    exit=$(cat $FI/inflight.client.rc 2>/dev/null)"
sed 's/^/    /' $FI/inflight.client.out

echo "--- waiting out the remainder of the 6s operation ---"
sleep 8
echo
echo "=== [1] TARGET — did the operation finish after the daemon died? ==="
echo "    slow.log (began)     : $(docker exec $C cat /tmp/virp-fi-slow.log | tr '\n' ' ')"
echo "    exec.log (completed) : $(docker exec $C cat /tmp/virp-fi-exec.log | tr '\n' ' ')"
sudo /opt/virp/tests/adversarial/witness/witness-count.sh $C "$CMD" | sed 's/^/    /'

echo
echo "=== [2] VIRP DURABLE ==="
echo "    consumed.list : $(grep -cF "$P" $FI/approvals/consumed.list 2>/dev/null; true)"
start_daemon
"$CLI" chain tail -n 40 --db $FI/chain.db 2>/dev/null | grep -F "$P" | sed 's/^/    /'
for t in proposal approval outcome; do
    printf '    chain %-9s: %s\n' "$t" "$("$CLI" chain tail -n 40 --db $FI/chain.db 2>/dev/null | grep -cF "$t:$P")"
done
kill $DPID 2>/dev/null; wait $DPID 2>/dev/null
echo "PROPOSAL=$P"
