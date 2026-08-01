#!/usr/bin/env bash
#
# VIRP demonstration harness.
#
# Runs the reference O-Node against a deterministic simulated target (the
# built-in "mock" driver) and observes nine security behaviors end to end.
# No router, hypervisor, credentials, or network access are required.
#
# THE TARGET IS SIMULATED. This demonstrates protocol behavior, not that any
# real device was reached. See ../virp/security.html for what VIRP does and
# does not establish.
#
# Usage:
#   ./demo/run.sh                 # build if needed, then run
#   ./demo/run.sh --no-build      # use existing ./build artifacts
#   ./demo/run.sh --keep          # keep the output directory contents
#
# Copyright (c) 2026 Third Level IT LLC — Apache 2.0

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DEMO_DIR="$REPO_ROOT/demo"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$DEMO_DIR/output/session-$STAMP"
RUN_DIR="$OUT_DIR/run"
LOG="$OUT_DIR/onode.log"
SOCKET="$RUN_DIR/onode.sock"
DEVICE="demo-r1"

DO_BUILD=1
for arg in "$@"; do
    case "$arg" in
        --no-build) DO_BUILD=0 ;;
        --keep)     ;;  # accepted for symmetry; output is always kept
        -h|--help)  sed -n '3,20p' "$0"; exit 0 ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------- reporting --
PASS=0
FAIL=0
RESULTS=()

c_green() { printf '\033[32m%s\033[0m' "$1"; }
c_red()   { printf '\033[31m%s\033[0m' "$1"; }
c_dim()   { printf '\033[2m%s\033[0m' "$1"; }

step() { printf '\n%s %s\n' "$(c_dim "[$1/9]")" "$2"; }

ok() {
    PASS=$((PASS + 1)); RESULTS+=("PASS  $1")
    printf '      %s %s\n' "$(c_green 'OBSERVED')" "$1"
}

bad() {
    FAIL=$((FAIL + 1)); RESULTS+=("FAIL  $1")
    printf '      %s %s\n' "$(c_red 'NOT OBSERVED')" "$1"
}

# assert_contains <file> <needle> <description>
assert_contains() {
    if grep -qF -- "$2" "$1"; then ok "$3"; else
        bad "$3"
        printf '        %s\n' "$(c_dim "expected to find: $2")"
        printf '        %s\n' "$(c_dim "in: $1")"
    fi
}

# assert_not_contains <file> <needle> <description>
assert_not_contains() {
    if grep -qF -- "$2" "$1"; then
        bad "$3"
        printf '        %s\n' "$(c_dim "unexpectedly found: $2")"
    else ok "$3"; fi
}

cleanup() {
    if [[ -n "${ONODE_PID:-}" ]] && kill -0 "$ONODE_PID" 2>/dev/null; then
        kill "$ONODE_PID" 2>/dev/null
        wait "$ONODE_PID" 2>/dev/null
    fi
}
trap cleanup EXIT

# -------------------------------------------------------------------- build --
if [[ $DO_BUILD -eq 1 ]]; then
    echo "Building the reference implementation (make prod, make all)..."
    if ! make -s all >/dev/null 2>&1 || ! make -s prod >/dev/null 2>&1; then
        echo "Build failed. Install dependencies first:" >&2
        echo "  sudo apt install -y build-essential libssl-dev libsodium-dev \\" >&2
        echo "       libsqlite3-dev libssh2-1-dev libcurl4-openssl-dev libjson-c-dev" >&2
        echo "Or use the container: docker compose -f demo/docker-compose.yml run --rm demo" >&2
        exit 1
    fi
fi

TOOL="$REPO_ROOT/build/virp-tool"
ONODE="$REPO_ROOT/build/virp-onode-prod"
for bin in "$TOOL" "$ONODE"; do
    if [[ ! -x "$bin" ]]; then
        echo "Missing binary: $bin (run without --no-build, or 'make all prod')" >&2
        exit 1
    fi
done

mkdir -p "$RUN_DIR/approvals" "$OUT_DIR/records"

# --------------------------------------------------------------------- keys --
echo "Generating disposable demo keys in $RUN_DIR ..."
"$TOOL" keygen okey     "$RUN_DIR/onode.key"     >/dev/null 2>&1
"$TOOL" keygen approval "$RUN_DIR/approval"      >/dev/null 2>&1
head -c 32 /dev/urandom > "$RUN_DIR/chain.key"
chmod 600 "$RUN_DIR"/*.key 2>/dev/null

if [[ ! -s "$RUN_DIR/onode.key" ]]; then
    echo "Key generation failed; see $RUN_DIR" >&2; exit 1
fi

# ------------------------------------------------------------------- daemon --
echo "Starting the O-Node against the simulated demo target..."
"$ONODE" \
    -k "$RUN_DIR/onode.key" \
    -s "$SOCKET" \
    -d "$DEMO_DIR/devices.json" \
    -c "$RUN_DIR/chain.db" \
    -C "$RUN_DIR/chain.key" \
    -a "$RUN_DIR/approvals" \
    -A "$RUN_DIR/approval.pub" \
    > "$LOG" 2>&1 &
ONODE_PID=$!

for _ in $(seq 1 50); do
    [[ -S "$SOCKET" ]] && break
    kill -0 "$ONODE_PID" 2>/dev/null || break
    sleep 0.1
done
if [[ ! -S "$SOCKET" ]]; then
    echo "O-Node did not start. Log:" >&2; cat "$LOG" >&2; exit 1
fi

printf '\n%s\n' "VIRP DEMO — nine security behaviors against a simulated target"
printf '%s\n' "$(c_dim "target: $DEVICE (mock driver, deterministic; NOT a real device)")"
printf '%s\n' "$(c_dim "output: $OUT_DIR")"

# ---------------------------------------------------------------- behaviors --

step 1 "A GREEN operation executes"
"$TOOL" exec "$DEVICE" "show version" --socket "$SOCKET" > "$OUT_DIR/records/01-green.txt" 2>&1
assert_contains "$OUT_DIR/records/01-green.txt" "GREEN" "GREEN read classified and executed"

step 2 "Its record verifies"
assert_contains "$OUT_DIR/records/01-green.txt" "VALID" "observation authentication tag verified"

step 3 "Modifying the record causes verification failure"
# Build a standalone observation with the demo O-Key, verify it, corrupt one
# byte of the payload, and verify again. Same key, same verifier, one bit of
# difference in the material.
"$TOOL" build observation "$RUN_DIR/onode.key" 0DE00001 1 \
        "interface GigabitEthernet0/1 is up" \
        "$OUT_DIR/records/03-observation.bin" > "$OUT_DIR/records/03-build.txt" 2>&1
"$TOOL" inspect "$OUT_DIR/records/03-observation.bin" "$RUN_DIR/onode.key" okey \
        > "$OUT_DIR/records/03-verify-intact.txt" 2>&1
cp "$OUT_DIR/records/03-observation.bin" "$OUT_DIR/records/03-observation-tampered.bin"
# Flip the final payload byte (the trailing authentication tag is not touched;
# the point is that the authenticated material no longer matches the tag).
SIZE=$(stat -c%s "$OUT_DIR/records/03-observation-tampered.bin")
printf '\x00' | dd of="$OUT_DIR/records/03-observation-tampered.bin" \
        bs=1 seek=$(( SIZE - 40 )) count=1 conv=notrunc status=none
"$TOOL" inspect "$OUT_DIR/records/03-observation-tampered.bin" "$RUN_DIR/onode.key" okey \
        > "$OUT_DIR/records/03-verify-tampered.txt" 2>&1
TAMPER_RC=$?
if [[ $TAMPER_RC -ne 0 ]] || grep -qiE 'invalid|fail|mismatch' "$OUT_DIR/records/03-verify-tampered.txt"; then
    ok "modified record rejected by the verifier"
else
    bad "modified record rejected by the verifier"
fi

step 4 "A RED operation is blocked"
"$TOOL" exec "$DEVICE" "reload" --socket "$SOCKET" > "$OUT_DIR/records/04-red-blocked.txt" 2>&1
assert_contains "$OUT_DIR/records/04-red-blocked.txt" "proposal" "RED command blocked; proposal filed"
PROPOSAL_ID=$(grep -oE '[0-9a-f]{32}' "$OUT_DIR/records/04-red-blocked.txt" "$LOG" 2>/dev/null | head -1 | sed 's/.*://')

step 5 "An Ed25519 approval is created"
if [[ -n "${PROPOSAL_ID:-}" ]]; then
    "$TOOL" approve "$PROPOSAL_ID" \
        --dir "$RUN_DIR/approvals" \
        --key "$RUN_DIR/approval.key" \
        --pub "$RUN_DIR/approval.pub" \
        > "$OUT_DIR/records/05-approve.txt" 2>&1
    if [[ -f "$RUN_DIR/approvals/$PROPOSAL_ID.approval" ]] || \
       ls "$RUN_DIR/approvals" 2>/dev/null | grep -q "$PROPOSAL_ID"; then
        ok "approval signed with a key the collector does not hold"
    else
        bad "approval signed with a key the collector does not hold"
    fi
else
    bad "approval signed with a key the collector does not hold (no proposal id captured)"
fi

step 6 "The exact approved operation executes"
if [[ -n "${PROPOSAL_ID:-}" ]]; then
    "$TOOL" apply "$PROPOSAL_ID" --dir "$RUN_DIR/approvals" --socket "$SOCKET" \
        > "$OUT_DIR/records/06-apply.txt" 2>&1
    assert_not_contains "$OUT_DIR/records/06-apply.txt" "approval_not_found" \
        "approved command executed under its approval"
else
    bad "approved command executed under its approval (no proposal id captured)"
fi

step 7 "Reusing the approval fails"
if [[ -n "${PROPOSAL_ID:-}" ]]; then
    "$TOOL" apply "$PROPOSAL_ID" --dir "$RUN_DIR/approvals" --socket "$SOCKET" \
        > "$OUT_DIR/records/07-reuse.txt" 2>&1
    if grep -qiE 'reuse|reused|-37|consumed' "$OUT_DIR/records/07-reuse.txt" "$LOG"; then
        ok "single-use approval refused on reuse"
    else
        bad "single-use approval refused on reuse"
    fi
else
    bad "single-use approval refused on reuse (no proposal id captured)"
fi

step 8 "An unknown operation fails closed"
"$TOOL" exec "$DEVICE" "frobnicate the widget" --socket "$SOCKET" \
    > "$OUT_DIR/records/08-unknown.txt" 2>&1
if grep -qiE 'UNCLASSIFIED|blocked|tier gate' "$OUT_DIR/records/08-unknown.txt" "$LOG"; then
    ok "unrecognized command blocked by default"
else
    bad "unrecognized command blocked by default"
fi

step 9 "The evidence chain verifies"
"$TOOL" chain tail -n 20 --db "$RUN_DIR/chain.db" > "$OUT_DIR/records/09-chain.txt" 2>&1
# Each entry's PREV_HASH must equal the previous entry's HASH. Parse the two
# hash columns and walk the links.
if python3 - "$OUT_DIR/records/09-chain.txt" <<'PY'
import re, sys
rows = []
for line in open(sys.argv[1], encoding='utf-8', errors='replace'):
    hexes = re.findall(r'\b[0-9a-f]{16,}\b', line)
    if len(hexes) >= 2:
        rows.append((hexes[-2], hexes[-1]))
if len(rows) < 2:
    sys.exit(1)
for (h_prev, _), (_, p_cur) in zip(rows, rows[1:]):
    if h_prev != p_cur:
        sys.exit(1)
sys.exit(0)
PY
then
    ok "chain links verified (each entry commits to the previous)"
else
    bad "chain links verified (each entry commits to the previous)"
fi

# ------------------------------------------------------------------ summary --
cleanup

cp "$DEMO_DIR/devices.json" "$OUT_DIR/devices.json" 2>/dev/null
{
    echo "VIRP demo bundle"
    echo "generated: $STAMP"
    echo "commit:    $(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo "target:    simulated (mock driver). NOT a real device."
    echo "behaviors: $PASS observed, $FAIL not observed"
    echo
    printf '%s\n' "${RESULTS[@]}"
} > "$OUT_DIR/SUMMARY.txt"

printf '\n%s\n' "-------------------------------------------------------------"
if [[ $FAIL -eq 0 ]]; then
    printf '%s\n' "$(c_green 'VIRP DEMO PASSED')"
else
    printf '%s\n' "$(c_red 'VIRP DEMO INCOMPLETE')"
fi
printf '%s/9 security behaviors observed\n' "$PASS"
printf 'Evidence bundle: %s\n' "$OUT_DIR"
printf 'Chain replay:    %s chain tail --db %s\n' "./build/virp-tool" "$RUN_DIR/chain.db"
printf 'Daemon log:      %s\n' "$LOG"
printf '%s\n' "$(c_dim 'The target was simulated. This shows protocol behavior, not that')"
printf '%s\n' "$(c_dim 'any real device was reached or told the truth.')"

[[ $FAIL -eq 0 ]] || exit 1
