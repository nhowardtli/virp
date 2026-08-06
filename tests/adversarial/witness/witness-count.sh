#!/bin/bash
# witness-count.sh — count what the TARGET actually did, from the witness log.
# This produces column 1 of the results table. It must never consult VIRP.
#
# Usage: witness-count.sh <container> <command-string>
#
# WHY THIS EXISTS RATHER THAN A GREP
#   1. DONE lines carry only seq= and nonce=, NOT cmdsha=. Grepping the command
#      digest therefore matches RECV lines only; a naive `grep -c` for the digest
#      silently reports the RECV count twice and looks like agreement. Getting
#      this wrong once already produced a bogus line in the build #0 transcript.
#      DONE is resolved here by joining on the nonce from each RECV.
#   2. The containers carry constant background traffic that is NOT the test:
#        - a daemon watchdog probe `uptime` every ~5s (unchained), and
#        - autopilot reads every minute (`show ip ospf neighbor`,
#          `show ip route ospf`).
#      Counting raw lines conflates these with the operation under test. All
#      counting is scoped to the exact command digest.
#
# COUNTING RULE
#   delivered  = RECV lines            -> the target was handed this operation
#   completed  = RECV nonces with DONE -> it ran to completion, rc recorded
#   delivered > completed is the ambiguity window: the operation reached the
#   device and its disposition is unknown. That gap is the point of test #2.

set -uo pipefail
C="${1:?usage: witness-count.sh <container> <command>}"
CMD="${2:?usage: witness-count.sh <container> <command>}"
LOG=/var/log/virp-witness/witness.log

SHA=$(printf '%s' "$CMD" | sha256sum | cut -c1-16)
raw=$(docker exec "$C" cat "$LOG" 2>/dev/null)

recv=$(printf '%s\n' "$raw" | grep -F "	RECV	" | grep -F "cmdsha=$SHA" || true)
n_recv=$(printf '%s' "$recv" | grep -c . || true)

# Join RECV -> DONE on nonce.
n_done=0
rcs=""
if [ "$n_recv" -gt 0 ]; then
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        nonce=$(printf '%s' "$line" | tr '\t' '\n' | sed -n 's/^nonce=//p' | head -1)
        d=$(printf '%s\n' "$raw" | grep -F "	DONE	" | grep -F "nonce=$nonce" | head -1)
        if [ -n "$d" ]; then
            n_done=$((n_done + 1))
            rcs="$rcs$(printf '%s' "$d" | tr '\t' '\n' | sed -n 's/^rc=//p' | head -1)"$'\n'
        fi
    done <<< "$recv"
fi

echo "container      : $C"
echo "command        : $CMD"
echo "cmdsha         : $SHA"
echo "delivered(RECV): $n_recv"
echo "completed(DONE): $n_done"
echo "exit codes     : $(printf '%s' "$rcs" | grep -c . >/dev/null; printf '%s' "$rcs" | sort | uniq -c | awk '{printf "rc=%s x%s  ", $2, $1}')"
echo "witness seqs   : $(printf '%s\n' "$recv" | tr '\t' '\n' | sed -n 's/^seq=//p' | tr '\n' ' ')"
if [ "$n_recv" -ne "$n_done" ]; then
    echo "*** AMBIGUITY WINDOW: $((n_recv - n_done)) operation(s) delivered with no completion record ***"
fi
