#!/bin/bash
# t06-disposition-matrix.sh — regression matrix for the termination-mode
# classifier that replaced `success = (get_exit_status() == 0)`.
#
# WHAT IS BEING PROVEN
#   libssh2_channel_get_exit_status() returns 0 both for a genuine exit-0 and
#   when the peer never sent an exit-status message at all, so an aborted
#   command used to be signed into the chain as success=true (TRANSCRIPT-05).
#   The classifier trusts exit_code ONLY after a clean, complete close.
#
#   Cases 4 and 5 are the point of this matrix. A classifier that answers
#   EXECUTED_UNKNOWN to everything "passes" the abort cases while destroying
#   the product — every GREEN read would go UNKNOWN. 4 and 5 prove the fix
#   did not over-correct.
#
# ISOLATION
#   Target is clab-frr-sacrifice (172.20.20.90), a throwaway container that is
#   ABSENT from the production device list. The four clab-frr-ospf-frr1..4
#   nodes are live production monitoring targets (autopilot writes their
#   observations into /var/lib/virp/chain.db every 5 minutes) and are never
#   touched. assert_isolated_target() enforces this before anything runs.
#
# THE SPOOL TRAP
#   `virp apply` reads the PRODUCTION approval spool by default even when
#   --socket points at the fi stack. Every apply passes --dir "$SPOOL" and
#   assert_spool_flag() refuses to run without it.

set -uo pipefail

T=/run/virp-fi/t06
SPOOL=$T/approvals
SOCK=$T/onode.sock
CLI=/home/nhoward/virp-work/build/virp
C=clab-frr-sacrifice
CTR=/tmp/virp-t06-ctr

assert_isolated_target() {
    python3 - "$T/devices.json" <<'PY' || exit 1
import json, sys
d = json.load(open(sys.argv[1]))
hosts = [(x['hostname'], x['host']) for x in d['devices']]
if hosts != [('clab-frr-sacrifice', '172.20.20.90')]:
    sys.exit("FATAL: fi target is not the isolated sacrifice container: %r" % hosts)
PY
}
assert_spool_flag() {
    case " $* " in
        *" --dir $SPOOL "*) : ;;
        *) echo "FATAL: apply without --dir $SPOOL — refusing (spool trap)"; exit 1 ;;
    esac
}

# run_case <label> <command> <expected-disposition-alternation> <expected-success>
#
# want_disp is an alternation because two of these outcomes are legitimately
# resolvable in more than one way, and the pass criterion is the SECURITY
# INVARIANT, not a guessed label: an aborted command must never come back
# EXECUTED_CONFIRMED and must never carry success=true. Where the peer
# explicitly reports an exit-signal, EXECUTED_FAILED is the correct and
# strictly more informative answer than EXECUTED_UNKNOWN (see the classifier's
# exit-signal branch); where no verdict arrives at all, UNKNOWN is correct.
run_case() {
    local label="$1" cmd="$2" want_disp="$3" want_succ="$4"
    assert_isolated_target

    docker exec $C sh -c ": > $CTR; : > /var/log/virp-witness/witness.log; echo 0 > /var/log/virp-witness/counter" 2>/dev/null
    : > $T/case.log
    local mark_before
    mark_before=$(wc -l < $T/daemon.log)

    local t0 t1 out P sub
    t0=$(date +%s)
    sub=$("$CLI" exec $C "$cmd" --socket $SOCK --okey $T/onode.key 2>&1)
    P=$(printf '%s' "$sub" | sed -n 's/^proposal_id=\([0-9a-f]*\)$/\1/p' | head -1)
    if [ -n "$P" ]; then
        "$CLI" approve "$P" --socket $SOCK --key $T/approval.key >/dev/null 2>&1
        local APPLY_ARGS=(apply "$P" --dir "$SPOOL" --socket "$SOCK" --okey "$T/onode.key")
        assert_spool_flag "${APPLY_ARGS[@]}"
        out=$("$CLI" "${APPLY_ARGS[@]}" 2>&1)
    else
        out="$sub"
    fi
    t1=$(date +%s)

    # Observed disposition, from the daemon's own log for THIS case only.
    local disp succ
    disp=$(tail -n +$((mark_before+1)) $T/daemon.log | grep -oE 'disposition=[A-Z_]+' | tail -1 | cut -d= -f2)
    succ=$(tail -n +$((mark_before+1)) $T/daemon.log | grep -oE '\[EXEC\].*success=(true|false)' | tail -1 | grep -oE 'success=(true|false)' | cut -d= -f2)
    # The UNKNOWN branch returns before the [EXEC] line is reached — it builds
    # a typed ERROR observation instead, which by construction cannot carry
    # success=true. Read that as success=false rather than "unknown".
    if [ -z "$succ" ] && tail -n +$((mark_before+1)) $T/daemon.log | grep -q 'executed=unknown'; then
        succ="false"
    fi
    [ -z "$succ" ] && succ="(none)"
    [ -z "$disp" ] && disp="(none)"

    # Target-side truth, independent of VIRP.
    local recv side outcome
    recv=$(docker exec $C sh -c "grep -c RECV /var/log/virp-witness/witness.log" 2>/dev/null | tr -d ' ')
    side=$(docker exec $C sh -c "wc -l < $CTR" 2>/dev/null | tr -d ' ')
    outcome=$(tail -n +$((mark_before+1)) $T/daemon.log | grep -oE 'outcome persisted.*success=[a-z]+' | tail -1 | grep -oE 'success=[a-z]+' | cut -d= -f2)
    [ -z "$outcome" ] && outcome="n/a"

    local verdict="FAIL"
    if [[ "$disp" =~ ^($want_disp)$ ]] && [ "$succ" = "$want_succ" ]; then verdict="PASS"; fi
    # Hard invariant, independent of which label was expected: nothing that
    # failed to complete may be attested as a confirmed success.
    if [ "$want_succ" = "false" ] && \
       { [ "$disp" = "EXECUTED_CONFIRMED" ] || [ "$succ" = "true" ]; }; then
        verdict="FALSE-ATTEST"
    fi
    printf '%-34s %-20s %-6s %-20s %-6s %-5s %4ss recv=%s side=%s chain_outcome=%s\n' \
        "$label" "$disp" "$succ" "$want_disp" "$want_succ" "$verdict" "$((t1-t0))" "$recv" "$side" "$outcome"
}

echo "=============================================================================================================="
printf '%-34s %-20s %-6s %-20s %-6s %-5s\n' "CASE" "OBSERVED_DISP" "SUCC" "EXPECTED_DISP" "WANT" "R"
echo "=============================================================================================================="
run_case "1 channel death mid-command"  "/usr/local/bin/t06-chankill" "EXECUTED_UNKNOWN|EXECUTED_FAILED" false
run_case "2 TCP session death"          "/usr/local/bin/t06-sshkill"  "EXECUTED_UNKNOWN"                 false
run_case "3 die-only (no side effect)"  "/usr/local/bin/t06-dieonly"  "EXECUTED_UNKNOWN|EXECUTED_FAILED" false
run_case "4 NORMAL exit 0, clean close" "/usr/local/bin/t06-tick"     "EXECUTED_CONFIRMED"               true
run_case "5 clean non-zero exit"        "/usr/local/bin/t06-exit1"    "EXECUTED_FAILED"                  false
run_case "6 hang (never responds)"      "/usr/local/bin/t06-hang"     "EXECUTED_UNKNOWN"                 false
run_case "7a partial/truncated"         "/usr/local/bin/t06-partial"  "EXECUTED_UNKNOWN|EXECUTED_FAILED" false
run_case "7b oversized (buffer full)"   "/usr/local/bin/t06-huge"     "EXECUTED_UNKNOWN"                 false
echo "=============================================================================================================="
echo "GREEN read (unapproved path, exit 0) — proves the gate's normal read path still confirms:"
run_case "4b GREEN read exit 0"         'vtysh -c "show version"'     "EXECUTED_CONFIRMED"               true
echo "=============================================================================================================="
