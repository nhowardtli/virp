#!/bin/bash
#
# check-wazuh-dropins.sh — scan a systemd drop-in directory for units that
# disable Wazuh TLS verification (VIRP_WAZUH_INSECURE), allowing ONLY the
# one documented lab drop-in.
#
# Why this exists: `make check-deploy-unit-source` asserted "no
# VIRP_WAZUH_INSECURE" by grepping ONLY the canonical unit
# deploy/virp-onode.service. But the flag never lives there — it lives in
# a drop-in (deploy/virp-onode-wazuh-lab.dropin.conf on disk;
# /etc/systemd/system/virp-onode.service.d/60-wazuh-lab.conf installed).
# A guard that inspects only the canonical unit can be defeated by any
# other drop-in that sets the flag, and the running daemon carries exactly
# such a drop-in. The guard must inspect drop-ins too.
#
# The lab drop-in is a deliberate, documented opt-in and stays exempt; any
# OTHER drop-in setting the flag is a finding.
#
# Usage:
#   check-wazuh-dropins.sh DIR [EXEMPT_BASENAME]   default exempt:
#                                                  virp-onode-wazuh-lab.dropin.conf
#   check-wazuh-dropins.sh --selftest
#
set -u

FLAG_RE='^[[:space:]]*Environment=.*VIRP_WAZUH_INSECURE'

scan_dir() {
    local dir="$1"
    local exempt="${2:-virp-onode-wazuh-lab.dropin.conf}"
    local bad=0 f base
    [ -d "$dir" ] || { echo "  PASS: no drop-in dir $dir"; return 0; }
    # Match both source (*.dropin.conf) and installed (*.conf) shapes.
    for f in "$dir"/*.conf "$dir"/*.dropin.conf; do
        [ -f "$f" ] || continue
        grep -Eq "$FLAG_RE" "$f" || continue
        base="$(basename "$f")"
        if [ "$base" = "$exempt" ]; then
            continue
        fi
        echo "FAIL: $f sets VIRP_WAZUH_INSECURE — this disables Wazuh"
        echo "      certificate validation. Only the documented lab drop-in"
        echo "      '$exempt' may do so (a manual, lab-only opt-in)."
        bad=1
    done
    if [ $bad -eq 0 ]; then
        echo "  PASS: no drop-in in $dir disables Wazuh TLS outside '$exempt'"
    fi
    return $bad
}

selftest() {
    local rc=0 tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN
    echo "=== self-testing check-wazuh-dropins.sh ==="

    # A clean drop-in dir passes.
    printf '[Service]\nEnvironment=VIRP_SOMETHING=1\n' > "$tmp/10-clean.conf"
    if scan_dir "$tmp" >/dev/null 2>&1; then
        echo "  ok: clean drop-in dir -> exit 0"
    else
        echo "  FAIL: clean dir was flagged"; rc=1
    fi

    # The exempt lab drop-in may carry the flag.
    printf '[Service]\nEnvironment=VIRP_WAZUH_INSECURE=1\n' \
        > "$tmp/virp-onode-wazuh-lab.dropin.conf"
    if scan_dir "$tmp" >/dev/null 2>&1; then
        echo "  ok: exempt lab drop-in with the flag -> allowed"
    else
        echo "  FAIL: exempt lab drop-in was flagged"; rc=1
    fi

    # THE CASE THE GUARD IS FOR: any OTHER drop-in setting the flag must
    # fail. This is exactly what the canonical-unit-only check missed.
    printf '[Service]\nEnvironment=VIRP_WAZUH_INSECURE=1\n' \
        > "$tmp/60-sneaky.conf"
    if scan_dir "$tmp" >/dev/null 2>&1; then
        echo "  FAIL: a non-exempt drop-in set the flag and was NOT caught"
        rc=1
    else
        echo "  ok: non-exempt drop-in with the flag -> exit 1"
    fi

    if [ $rc -eq 0 ]; then
        echo "  PASS: drop-ins are inspected; only the lab drop-in is exempt"
    fi
    return $rc
}

if [ "${1:-}" = "--selftest" ]; then
    selftest
    exit $?
fi

if [ $# -lt 1 ]; then
    echo "usage: $0 DIR [EXEMPT_BASENAME] | --selftest" >&2
    exit 2
fi

scan_dir "$@"
exit $?
