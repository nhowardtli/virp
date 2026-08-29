#!/bin/bash
#
# check-obs-build-ordering.sh — assert that nothing carrying captured
# result bytes is committed or signed above the scrub barrier in
# onode_execute_obs_ex().
#
# The invariant: feat/camera-driver inserts virp_scrub_exec_result(&result)
# at a single point and its comment says "do not reorder". A comment is not
# enforcement. A false comment a few lines away ("no_dispatch is proven
# here") is exactly how Defect B survived a fix, a test and a survey, so
# this invariant gets a guard instead.
#
# Why it matters: a refusal body embeds the ATTEMPTED command, and an
# attempted command can carry a credential the caller typed (the
# devices.template note records "username x secret y" as the live case).
# Anything above the barrier commits to, and signs, unredacted bytes.
#
# What counts as a violation is a call CARRYING RESULT PAYLOAD, not a call
# by name. gate_emit_execution() is legitimately called twice above the
# barrier with result=NULL on the driver-errored paths: those commit the
# empty digest and a message built from an error code, never device bytes.
# The observation constructors above the barrier likewise carry only
# err_msg. A guard that flagged those would be noise, and noise gets
# silenced.
#
# The barrier marker stands in the source now, before feat/camera-driver
# merges. That is deliberate: the constraint is enforced BEFORE the code it
# protects arrives, so the rebase cannot quietly land the scrub in the
# wrong place.
#
# Usage:
#   check-obs-build-ordering.sh            exit 1 on a violation
#   check-obs-build-ordering.sh --selftest prove all four directions
#
set -u

SRC="${SRC_OVERRIDE:-src/virp_onode.c}"
MARKER='SCRUB-BARRIER'
FUNC='onode_execute_obs_ex'
CALLS='gate_emit_execution|virp_build_observation_tiered|virp_build_observation_v2'
PAYLOAD='&result|result[.]output|obs_data'
WINDOW=8

check_file() {
    local src="$1"

    local fn_start
    fn_start=$(grep -n "virp_error_t $FUNC" "$src" | tail -1 | cut -d: -f1)
    if [ -z "$fn_start" ]; then
        echo "FAIL: $FUNC not found in $src — the guard cannot verify anything."
        echo "      A guard that finds nothing must fail, not pass."
        return 1
    fi

    local marker_line
    marker_line=$(awk -v s="$fn_start" -v m="$MARKER" \
        'NR>s && index($0,m){print NR; exit}' "$src")
    if [ -z "$marker_line" ]; then
        echo "FAIL: $MARKER marker missing from $FUNC in $src."
        echo "      The barrier is the ordering anchor; without it nothing"
        echo "      constrains where result bytes get committed or signed."
        return 1
    fi

    local bad
    bad=$(awk -v s="$fn_start" -v e="$marker_line" -v c="$CALLS" \
             -v pl="$PAYLOAD" -v w="$WINDOW" '
        NR>s && NR<e && $0 ~ c { cl=NR; ct=$0; pend=w; next }
        NR<e && pend>0 {
            if ($0 ~ pl) { printf "  %s:%d:%s\n", FILENAME, cl, ct; pend=0 }
            else pend--
        }' "$src")

    if [ -n "$bad" ]; then
        echo "FAIL: result-carrying construction ABOVE the $MARKER in $FUNC:"
        echo "$bad"
        echo "      These run before the captured result is redacted, so they"
        echo "      commit to and sign unscrubbed bytes. Move them below the"
        echo "      barrier, or move the barrier — but not silently."
        return 1
    fi
    return 0
}

selftest() {
    local rc=0 tmp
    echo "=== self-testing check-obs-build-ordering.sh ==="
    tmp=$(mktemp -d)

    cat > "$tmp/ok.c" <<'EOF'
virp_error_t onode_execute_obs_ex(int a)
{
    do_work();
    /* SCRUB-BARRIER */
    gate_emit_execution(s, d, dr, c, t, e, m, u,
                        &result, NULL);
    return virp_build_observation_tiered(out, obs_data);
}
EOF
    if SRC_OVERRIDE="$tmp/ok.c" check_file "$tmp/ok.c" >/dev/null 2>&1; then
        echo "  ok: result-carrying calls BELOW the barrier -> pass"
    else
        echo "  FAIL: compliant file was rejected"; rc=1
    fi

    # The direction that matters most: a guard that cannot fail is the bug
    # it exists to catch.
    cat > "$tmp/bad.c" <<'EOF'
virp_error_t onode_execute_obs_ex(int a)
{
    gate_emit_execution(s, d, dr, c, t, e, m, u,
                        &result, NULL);
    /* SCRUB-BARRIER */
    return virp_build_observation_tiered(out, obs_data);
}
EOF
    if SRC_OVERRIDE="$tmp/bad.c" check_file "$tmp/bad.c" >/dev/null 2>&1; then
        echo "  FAIL: result-carrying call above the barrier NOT caught"; rc=1
    else
        echo "  ok: result-carrying call ABOVE the barrier -> caught"
    fi

    # A NULL-result commit above the barrier is legitimate and must not fire.
    cat > "$tmp/nullok.c" <<'EOF'
virp_error_t onode_execute_obs_ex(int a)
{
    gate_emit_execution(s, d, dr, c, t, e, m, u,
                        NULL, err_msg);
    /* SCRUB-BARRIER */
    return virp_build_observation_tiered(out, obs_data);
}
EOF
    if SRC_OVERRIDE="$tmp/nullok.c" check_file "$tmp/nullok.c" >/dev/null 2>&1; then
        echo "  ok: NULL-result commit above the barrier -> allowed"
    else
        echo "  FAIL: NULL-result commit wrongly flagged (guard is noise)"; rc=1
    fi

    # A deleted barrier must fail loudly, not pass silently.
    cat > "$tmp/nomarker.c" <<'EOF'
virp_error_t onode_execute_obs_ex(int a)
{
    return virp_build_observation_tiered(out, obs_data);
}
EOF
    if SRC_OVERRIDE="$tmp/nomarker.c" check_file "$tmp/nomarker.c" >/dev/null 2>&1; then
        echo "  FAIL: deleted barrier NOT caught"; rc=1
    else
        echo "  ok: deleted barrier -> caught"
    fi

    rm -rf "$tmp"
    if [ $rc -eq 0 ]; then echo "  selftest PASSED"; else echo "  selftest FAILED"; fi
    return $rc
}

if [ "${1:-}" = "--selftest" ]; then
    selftest
    exit $?
fi

check_file "$SRC"
exit $?
