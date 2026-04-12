#!/usr/bin/env bash
# Smoke test: start the exporter, hit /metrics and /health, verify output.
set -euo pipefail

PORT=9199  # use a non-default port for testing
EXPORTER="$(dirname "$0")/virp_prometheus_exporter.py"
PID=""

cleanup() {
    [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Starting exporter on :${PORT} ==="
VIRP_EXPORTER_PORT=$PORT python3 "$EXPORTER" &
PID=$!
sleep 2

# Check process is alive
if ! kill -0 "$PID" 2>/dev/null; then
    echo "FAIL: exporter exited early"
    exit 1
fi

echo "=== Testing /health ==="
HEALTH=$(curl -sf "http://127.0.0.1:${PORT}/health")
echo "$HEALTH"
if ! echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['status']=='ok'"; then
    echo "FAIL: /health did not return ok"
    exit 1
fi
echo "PASS: /health"

echo ""
echo "=== Testing /metrics ==="
METRICS=$(curl -sf "http://127.0.0.1:${PORT}/metrics")

check_metric() {
    if echo "$METRICS" | grep -q "^$1"; then
        echo "PASS: $1 present"
    else
        echo "FAIL: $1 missing"
        exit 1
    fi
}

check_metric "virp_chain_entries_total"
check_metric "virp_chain_entries_by_type"
check_metric "virp_intents_total"
check_metric "virp_intents_by_confidence"
check_metric "virp_intents_by_tier"
check_metric "virp_observation_age_seconds"
check_metric "virp_observation_count_by_device"
check_metric "virp_devices_observed"
check_metric "virp_last_observation_timestamp"
check_metric "virp_observation_rate_per_minute"
check_metric "virp_milestones_total"
check_metric "virp_onode_up"

echo ""
echo "=== All smoke tests passed ==="
echo ""
echo "Sample metrics:"
echo "$METRICS" | grep -E "^virp_" | head -30
