#!/bin/bash
# t05-device-abuse.sh — drive one propose -> approve -> apply cycle against a
# GENUINELY ISOLATED sacrificial target, then report what the TARGET did
# (witness + device-side artifact) versus what VIRP claims (client, chain).
#
# WHY A NEW TARGET (read before changing TARGET_HOST)
#   The four clab-frr-ospf-frr1..4 containers that earlier transcripts used are
#   LIVE PRODUCTION MONITORING TARGETS: they are listed in the production
#   daemon's /run/virp/devices.json, the prod daemon holds persistent SSH
#   sessions to all four, and virp-autopilot.timer executes GREEN reads against
#   them every 5 minutes, writing verified observations into the PRODUCTION
#   chain at /var/lib/virp/chain.db. Making one of them misbehave — which is
#   the entire point of this transcript — would fail the autopilot's next run
#   and append error observations to the production chain.
#
#   So this session created clab-frr-sacrifice (172.20.20.90): same image, same
#   clab bridge, witness installed, and ABSENT from the production device list.
#   The fi daemon's devices.json names it and nothing else, so fi-side abuse
#   cannot reach a prod-monitored device even by accident.
#
# THE SPOOL TRAP
#   `virp apply` reads the PRODUCTION approval spool by default even when
#   --socket points at the fi stack. Every apply below passes --dir "$SPOOL"
#   and assert_spool_flag() refuses to run if it is ever missing.

set -uo pipefail

T=/run/virp-fi/t05
SPOOL=$T/approvals
SOCK=$T/onode.sock
CLI=/home/nhoward/virp-work/build/virp
C=clab-frr-sacrifice
CTR=/tmp/virp-t05-ctr

CMD="${1:?usage: t05-device-abuse.sh <command-to-run-on-target> [label]}"
LABEL="${2:-$(echo "$CMD" | tr -c 'a-zA-Z0-9' '_' | cut -c1-40)}"

# --- hard guards ---------------------------------------------------------
assert_isolated_target() {
    python3 - "$T/devices.json" <<'PY' || exit 1
import json, sys
d = json.load(open(sys.argv[1]))
hosts = [(x['hostname'], x['host']) for x in d['devices']]
if len(hosts) != 1:
    sys.exit("FATAL: fi devices.json must name exactly ONE target, found %r" % hosts)
if hosts[0] != ('clab-frr-sacrifice', '172.20.20.90'):
    sys.exit("FATAL: fi target is not the isolated sacrifice container: %r" % hosts)
PY
}
assert_spool_flag() {
    case " $* " in
        *" --dir $SPOOL "*) : ;;
        *) echo "FATAL: apply without --dir $SPOOL — refusing (spool trap)"; exit 1 ;;
    esac
}
assert_isolated_target

echo "################ t05: $LABEL ################"
echo "command: $CMD"

# --- reset target-side evidence (this container only) --------------------
docker exec $C sh -c ": > $CTR; : > /var/log/virp-witness/witness.log; echo 0 > /var/log/virp-witness/counter"

# --- propose -------------------------------------------------------------
sub=$("$CLI" exec $C "$CMD" --socket $SOCK --okey $T/onode.key 2>&1)
P=$(printf '%s' "$sub" | sed -n 's/^proposal_id=\([0-9a-f]*\)$/\1/p' | head -1)
if [ -z "$P" ]; then
    echo "--- no proposal (command may have run directly) ---"
    printf '%s\n' "$sub" | sed 's/^/    /'
else
    echo "proposal: $P"
    "$CLI" approve "$P" --socket $SOCK --key $T/approval.key >/dev/null 2>&1
    echo "approve exit=$?"

    APPLY_ARGS=(apply "$P" --dir "$SPOOL" --socket "$SOCK" --okey "$T/onode.key")
    assert_spool_flag "${APPLY_ARGS[@]}"
    t0=$(cut -d' ' -f1 /proc/uptime)
    out=$("$CLI" "${APPLY_ARGS[@]}" 2>&1); arc=$?
    t1=$(cut -d' ' -f1 /proc/uptime)
    echo "--- apply (exit=$arc, ${t0}->${t1}s) ---"
    printf '%s\n' "$out" | sed 's/^/    /'
fi

sleep 1

# --- [1] TARGET: independent of VIRP -------------------------------------
echo
echo "=== [1] TARGET (independent of VIRP) ==="
echo "    side-effect lines in $CTR : $(docker exec $C sh -c "wc -l < $CTR" 2>/dev/null | tr -d ' ')"
echo "    witness RECV by cmdsha:"
docker exec $C sh -c 'grep RECV /var/log/virp-witness/witness.log 2>/dev/null' \
    | sed -E 's/.*cmdsha=([0-9a-f]+)\tcmd=(.*)$/\1  \2/' | sort | uniq -c | sed 's/^/      /'
echo "    witness DONE count: $(docker exec $C sh -c 'grep -c DONE /var/log/virp-witness/witness.log 2>/dev/null' | tr -d ' ')"

# --- [2] VIRP CHAIN (isolated) -------------------------------------------
echo
echo "=== [2] VIRP CHAIN (isolated fi chain) ==="
"$CLI" chain tail -n 12 --db $T/chain.db 2>/dev/null | sed 's/^/    /'

echo
echo "=== [3] fi daemon stderr tail ==="
tail -8 $T/daemon.log | sed 's/^/    /'
echo "################ end: $LABEL ################"
