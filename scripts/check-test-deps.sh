#!/bin/bash
#
# check-test-deps.sh — assert the optional Python modules that whole test
# suites depend on are importable, so a SKIPPED suite can never let
# `make all-tests` report clean success.
#
# The hole this closes: test-api skips (and exits 0) when fastapi/httpx
# are absent, and test-virp-report skips when reportlab is absent. Run as
# a prerequisite each still returns 0, so `make all-tests` printed a green
# pass line while the API auth + bind-safety guards and the report
# generator were never exercised. A skip is honest; a skip that rolls up
# as success is not.
#
# Usage:
#   check-test-deps.sh MODULE [MODULE ...]   exit 1 if any is not importable
#   check-test-deps.sh --selftest            prove both directions
#
set -u

check_modules() {
    local missing=""
    local m
    for m in "$@"; do
        if ! python3 -c "import $m" >/dev/null 2>&1; then
            missing="$missing $m"
        fi
    done
    if [ -n "$missing" ]; then
        echo "FAIL: required test dependencies not importable:$missing"
        echo "      Whole suites SKIP without these and a skip must not"
        echo "      report clean success. Install them, e.g.:"
        echo "        pip install fastapi httpx pytest reportlab"
        echo "      (or the distro packages, e.g. apt install python3-reportlab)."
        return 1
    fi
    echo "  PASS: all required test dependencies importable:$([ $# -eq 0 ] && echo ' (none)') $*"
    return 0
}

selftest() {
    local rc=0
    echo "=== self-testing check-test-deps.sh ==="

    # Direction 1: a module that is ALWAYS present must pass.
    if check_modules sys os >/dev/null 2>&1; then
        echo "  ok: present modules (sys, os) -> exit 0"
    else
        echo "  FAIL: present modules were reported missing"; rc=1
    fi

    # Direction 2: a module that cannot exist must fail non-zero. This is
    # the case the guard is FOR — the exact shape of a silently-absent
    # test dependency.
    if check_modules virp_no_such_module_xyzzy >/dev/null 2>&1; then
        echo "  FAIL: an absent module was reported present (guard is inert)"; rc=1
    else
        echo "  ok: absent module -> exit 1"
    fi

    if [ $rc -eq 0 ]; then
        echo "  PASS: guard fails closed on a missing dependency"
    fi
    return $rc
}

if [ "${1:-}" = "--selftest" ]; then
    selftest
    exit $?
fi

if [ $# -eq 0 ]; then
    echo "usage: $0 MODULE [MODULE ...] | --selftest" >&2
    exit 2
fi

check_modules "$@"
exit $?
