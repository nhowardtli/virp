#!/usr/bin/env bash
#
# VIRP demonstration harness.
#
# Runs the reference O-Node against a deterministic simulated target (the
# built-in "mock" driver) and observes nine security behaviors end to end.
# No router, hypervisor, credentials, or network access are required.
#
# THE TARGET IS SIMULATED. This demonstrates protocol behavior, not that any
# real device was reached. See https://thirdlevel.ai/virp/security.html for
# what VIRP does and does not establish.
#
# Usage:
#   ./demo/run.sh                 # build if needed, then run
#   ./demo/run.sh --no-build      # use existing ./build artifacts
#
# Copyright (c) 2026 Third Level IT LLC — Apache 2.0

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DEMO_DIR="$REPO_ROOT/demo"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$DEMO_DIR/output/session-$STAMP"
RUN_DIR="$OUT_DIR/run"
REC="$OUT_DIR/records"
LOG="$OUT_DIR/onode.log"
SOCKET="$RUN_DIR/onode.sock"
DEVICE="demo-r1"

DO_BUILD=1
for arg in "$@"; do
    case "$arg" in
        --no-build) DO_BUILD=0 ;;
        -h|--help)  sed -n '3,17p' "$0"; exit 0 ;;
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
    [[ -n "${2:-}" ]] && printf '        %s\n' "$(c_dim "$2")"
    return 0
}

# Every positive claim runs through here. It must be evidenced by a string
# only success produces, AND the record must carry no error marker. An
# assertion a failure message can satisfy is a broken assertion: a demo that
# greens a failed step is worse than a demo that fails.
#
#   claim <description> <record-file> <required-regex> [additional-file ...]
claim() {
    local desc="$1" file="$2" needle="$3"; shift 3
    local files=("$file" "$@") f
    for f in "${files[@]}"; do
        [[ -f "$f" ]] || continue
        if grep -qiE '^Error:|Unknown option:|cannot load|No such file|not found' "$f"; then
            bad "$desc" "error text in $(basename "$f"): $(grep -ioE '^Error:.*|Unknown option:.*|.*cannot load.*' "$f" | head -1 | cut -c1-90)"
            return 0
        fi
    done
    for f in "${files[@]}"; do
        [[ -f "$f" ]] || continue
        if grep -qiE -- "$needle" "$f"; then ok "$desc"; return 0; fi
    done
    bad "$desc" "expected /$needle/ in $(basename "$file")"
}

# A step whose success IS a refusal (blocks, reuse rejection). The regex must
# match that specific refusal, never a generic failure.
claim_refusal() {
    local desc="$1" file="$2" needle="$3"; shift 3
    local files=("$file" "$@") f
    for f in "${files[@]}"; do
        [[ -f "$f" ]] || continue
        if grep -qiE -- "$needle" "$f"; then ok "$desc"; return 0; fi
    done
    bad "$desc" "expected /$needle/ in $(basename "$file")"
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
    echo "Building the reference implementation (make all, make prod)..."
    if ! make -s all >/dev/null 2>&1 || ! make -s prod >/dev/null 2>&1; then
        echo "Build failed. Install dependencies first:" >&2
        echo "  sudo apt install -y build-essential libssl-dev libsodium-dev \\" >&2
        echo "       libsqlite3-dev libssh2-1-dev libcurl4-openssl-dev libjson-c-dev" >&2
        echo "Alternative, if your Docker ships the compose plugin: docker compose -f demo/docker-compose.yml run --rm demo" >&2
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

mkdir -p "$RUN_DIR/approvals" "$REC"

# --------------------------------------------------------------------- keys --
# Every key here is disposable and lives only under this session directory.
# Nothing reads or writes /etc/virp or /var/lib/virp.
echo "Generating disposable demo keys..."
OKEY="$RUN_DIR/onode.key"
"$TOOL" keygen okey     "$OKEY"             >"$REC/00-keygen-okey.txt"     2>&1
"$TOOL" keygen approval "$RUN_DIR/approval" >"$REC/00-keygen-approval.txt" 2>&1
head -c 32 /dev/urandom > "$RUN_DIR/chain.key"
chmod 600 "$RUN_DIR"/*.key 2>/dev/null

if [[ ! -s "$OKEY" || ! -s "$RUN_DIR/approval.pub" ]]; then
    echo "Key generation failed. See $REC/00-keygen-*.txt" >&2
    cat "$REC"/00-keygen-*.txt >&2
    exit 1
fi

# The daemon verifies approvals against an ENROLLED approver registry
# (approvers.json), not a bare public key file. `virp enroll` prints one
# registry entry; the registry is a JSON array of such entries.
echo "Enrolling the demo approver..."
REGISTRY="$RUN_DIR/approvers.json"
ENTRY="$("$TOOL" enroll --key "$RUN_DIR/approval.pub" --operator "demo-approver" 2>"$REC/00-enroll.err")"
if [[ -z "$ENTRY" ]]; then
    echo "Approver enrollment failed:" >&2; cat "$REC/00-enroll.err" >&2; exit 1
fi
printf '[\n  %s\n]\n' "$ENTRY" > "$REGISTRY"
cp "$REGISTRY" "$REC/00-approvers.json"
python3 -c "import json; json.load(open('$REGISTRY'))" 2>/dev/null \
    || { echo "Generated registry is not valid JSON: $REGISTRY" >&2; exit 1; }

# ------------------------------------------------------------------- daemon --
echo "Starting the O-Node against the simulated demo target..."
"$ONODE" \
    -k "$OKEY" \
    -s "$SOCKET" \
    -d "$DEMO_DIR/devices.json" \
    -c "$RUN_DIR/chain.db" \
    -C "$RUN_DIR/chain.key" \
    -a "$RUN_DIR/approvals" \
    -A "$REGISTRY" \
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

# If the approval flow did not come up, steps 4-7 cannot be demonstrated.
# Abort rather than report a partial pass against a flow that never started.
if grep -q 'Approval flow disabled' "$LOG"; then
    echo >&2
    echo "FATAL: the O-Node started with the approval flow DISABLED:" >&2
    grep 'Approval flow disabled' "$LOG" >&2
    echo "Registry used: $REGISTRY" >&2
    exit 1
fi

printf '\n%s\n' "VIRP DEMO — nine security behaviors against a simulated target"
printf '%s\n' "$(c_dim "target: $DEVICE (mock driver, deterministic; NOT a real device)")"
printf '%s\n' "$(c_dim "output: $OUT_DIR")"

# ---------------------------------------------------------------- behaviors --

step 1 "A GREEN operation executes"
"$TOOL" exec "$DEVICE" "show version" --socket "$SOCKET" --okey "$OKEY" \
    > "$REC/01-green.txt" 2>&1
claim "GREEN read classified and executed" "$REC/01-green.txt" 'GREEN'

step 2 "Its record verifies"
# The exec client verifies the returned observation against the O-Key it is
# given (--okey). Without that flag it prints signature=SKIPPED, which is not
# a verification result and must never be accepted as one.
if grep -qiE 'SKIPPED' "$REC/01-green.txt"; then
    bad "observation authentication tag verified" \
        "client reported SKIPPED: it was not given the O-Key"
else
    claim "observation authentication tag verified" "$REC/01-green.txt" \
        'signature=VALID|authentication=VALID|VALID'
fi

step 3 "Modifying the record causes verification failure"
"$TOOL" build observation "$OKEY" 0DE00001 1 \
        "interface GigabitEthernet0/1 is up" \
        "$REC/03-observation.bin" > "$REC/03-build.txt" 2>&1
"$TOOL" inspect "$REC/03-observation.bin" "$OKEY" okey \
        > "$REC/03-verify-intact.txt" 2>&1
INTACT_RC=$?
cp "$REC/03-observation.bin" "$REC/03-observation-tampered.bin"
SIZE=$(stat -c%s "$REC/03-observation-tampered.bin")
printf '\x00' | dd of="$REC/03-observation-tampered.bin" \
        bs=1 seek=$(( SIZE - 40 )) count=1 conv=notrunc status=none
"$TOOL" inspect "$REC/03-observation-tampered.bin" "$OKEY" okey \
        > "$REC/03-verify-tampered.txt" 2>&1
TAMPER_RC=$?
# Both halves must hold: intact verifies AND tampered is rejected. A verifier
# that rejected everything would otherwise "pass" this step.
if [[ $INTACT_RC -eq 0 ]] && { [[ $TAMPER_RC -ne 0 ]] || \
        grep -qiE 'invalid|fail|mismatch' "$REC/03-verify-tampered.txt"; }; then
    ok "intact record verifies; modified record is rejected"
else
    bad "intact record verifies; modified record is rejected" \
        "intact_rc=$INTACT_RC tampered_rc=$TAMPER_RC"
fi

step 4 "A RED operation is blocked"
"$TOOL" exec "$DEVICE" "reload" --socket "$SOCKET" --okey "$OKEY" \
    > "$REC/04-red-blocked.txt" 2>&1
claim_refusal "RED command blocked by the tier gate" "$REC/04-red-blocked.txt" \
    'tier gate blocked|tier=RED|blocked'

# Capture the proposal id ONLY from a line that names a proposal. A bare
# 32-hex scrape also matches session ids, command hashes, and key ids: the
# previous harness captured one of those and then reported success against
# the resulting load error.
PROPOSAL_ID=""
for src in "$REC/04-red-blocked.txt" "$LOG"; do
    [[ -f "$src" ]] || continue
    PROPOSAL_ID=$(grep -oiE 'proposal(_id)?[=: ]+[0-9a-f]{32}' "$src" \
                  | grep -oE '[0-9a-f]{32}' | head -1)
    [[ -n "$PROPOSAL_ID" ]] && break
done
if [[ -n "$PROPOSAL_ID" ]]; then
    printf '      %s\n' "$(c_dim "proposal_id=$PROPOSAL_ID")"
    echo "$PROPOSAL_ID" > "$REC/04-proposal-id.txt"
else
    printf '      %s\n' "$(c_dim 'no proposal id found; steps 5-7 will report NOT OBSERVED')"
fi

step 5 "An Ed25519 approval is created"
if [[ -n "$PROPOSAL_ID" ]]; then
    # approve talks to the daemon (challenge -> sign -> submit) and signs with
    # the approver secret key. This subcommand has no --dir option.
    "$TOOL" approve "$PROPOSAL_ID" \
        --socket "$SOCKET" \
        --key "$RUN_DIR/approval.key" \
        > "$REC/05-approve.txt" 2>&1
    if grep -qE "\[APPROVAL\] submitted: proposal=$PROPOSAL_ID" "$LOG"; then
        ok "approval signed with a key the collector does not hold"
    else
        claim "approval signed with a key the collector does not hold" \
            "$REC/05-approve.txt" 'approved|submitted|key_id'
    fi
else
    bad "approval signed with a key the collector does not hold" "no proposal id"
fi

step 6 "The exact approved operation executes"
if [[ -n "$PROPOSAL_ID" ]]; then
    "$TOOL" apply "$PROPOSAL_ID" --dir "$RUN_DIR/approvals" \
        --socket "$SOCKET" --okey "$OKEY" \
        > "$REC/06-apply.txt" 2>&1
    # Positive evidence only: the daemon must log that it VERIFIED the approval
    # for THIS proposal. Absence of an error is not evidence anything ran.
    if grep -qE "approval verified: proposal=$PROPOSAL_ID" "$LOG"; then
        ok "approved command executed under its verified approval"
    else
        bad "approved command executed under its verified approval" \
            "daemon never logged 'approval verified: proposal=$PROPOSAL_ID'"
    fi
else
    bad "approved command executed under its verified approval" "no proposal id"
fi

step 7 "Reusing the approval fails"
if [[ -n "$PROPOSAL_ID" ]]; then
    "$TOOL" apply "$PROPOSAL_ID" --dir "$RUN_DIR/approvals" \
        --socket "$SOCKET" --okey "$OKEY" \
        > "$REC/07-reuse.txt" 2>&1
    # Must be the specific single-use refusal, not any failure: a proposal that
    # was never approved also fails, for a different and uninteresting reason.
    claim_refusal "single-use approval refused on reuse" \
        "$REC/07-reuse.txt" 'reused|approval_reused|-37|already consumed|consumed' "$LOG"
else
    bad "single-use approval refused on reuse" "no proposal id"
fi

step 8 "An unknown operation fails closed"
"$TOOL" exec "$DEVICE" "frobnicate the widget" --socket "$SOCKET" --okey "$OKEY" \
    > "$REC/08-unknown.txt" 2>&1
claim_refusal "unrecognized command blocked by default" "$REC/08-unknown.txt" \
    'UNCLASSIFIED|tier gate blocked|blocked' "$LOG"

step 9 "The evidence chain verifies"
"$TOOL" chain tail -n 25 --db "$RUN_DIR/chain.db" > "$REC/09-chain.txt" 2>&1
if python3 - "$RUN_DIR/chain.db" > "$REC/09-verify.txt" 2>&1 <<'PY'
"""Verify chain linkage PER SESSION, then witness this run's own evidence.

The chain is not one global list. Each session_id is its own hash-linked
sequence: the entry at sequence 0 carries previous_entry_hash =
sha256("VIRP_CHAIN_GENESIS:" + session_id), and each later entry commits to
the previous entry OF THE SAME SESSION.

Walking every row in rowid order instead, as an earlier version of this
harness did, breaks the moment a second session appears: the first entry of
session B looks like a broken link because its previous hash is B's genesis,
not A's last hash. That global-walk mistake is a real defect that has shipped
in a consumer-side bridge verifier, so this walker is written the correct way
deliberately, and this comment exists so the next person copying it does the
same. Per-session linkage is the property; row order is an artifact.
"""
import hashlib, sqlite3, sys
from collections import defaultdict

GENESIS_PREFIX = "VIRP_CHAIN_GENESIS:"

db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
rows = db.execute(
    "SELECT session_id, sequence, chain_entry_hash, previous_entry_hash,"
    "       artifact_type"
    "  FROM chain_entries ORDER BY session_id, sequence"
).fetchall()
if not rows:
    sys.exit("no chain entries")

sessions = defaultdict(list)
for sid, seq, entry, prev, atype in rows:
    sessions[sid].append((seq, entry, prev, atype))

failures = []
for sid, entries in sorted(sessions.items()):
    entries.sort(key=lambda e: e[0])
    expected = hashlib.sha256((GENESIS_PREFIX + sid).encode()).hexdigest()
    for seq, entry, prev, _ in entries:
        if prev != expected:
            failures.append(
                f"{sid} seq={seq}: previous_entry_hash {prev[:16]} "
                f"!= expected {expected[:16]}")
            break
        expected = entry
    else:
        types = ",".join(t for _, _, _, t in entries)
        print(f"OK  {sid}: {len(entries)} entries linked from genesis [{types}]")

for f in failures:
    print(f"BAD {f}")

# The demo just generated a propose -> approve -> apply cycle. Step 9 should
# witness that evidence, not merely count links.
triple = {}
for sid, entries in sessions.items():
    if sid.startswith("approval:"):
        for _, _, _, atype in entries:
            triple[atype.lower()] = True
missing = [t for t in ("proposal", "approval", "outcome") if t not in triple]
if missing:
    failures.append("approval session missing artifact types: "
                    + ", ".join(missing)
                    + f" (saw: {', '.join(sorted(triple)) or 'nothing'})")
    print("BAD " + failures[-1])
else:
    print("OK  approval session carries the proposal -> approval -> outcome triple")

sys.exit(1 if failures else 0)
PY
then
    cat "$REC/09-verify.txt" | sed 's/^/      /'
    ok "every session links from its own genesis; approval triple present"
else
    cat "$REC/09-verify.txt" | sed 's/^/      /'
    bad "every session links from its own genesis; approval triple present" \
        "see $REC/09-verify.txt"
fi

# ------------------------------------------------------------------ summary --
cleanup

cp "$DEMO_DIR/devices.json" "$OUT_DIR/devices.json" 2>/dev/null
{
    echo "VIRP demo bundle"
    echo "generated: $STAMP"
    echo "commit:    $(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo "tool:      $("$TOOL" version 2>/dev/null | head -1)"
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
printf 'Chain replay:    ./build/virp-tool chain tail --db %s\n' "$RUN_DIR/chain.db"
printf 'Daemon log:      %s\n' "$LOG"
printf '%s\n' "$(c_dim 'The target was simulated. This shows protocol behavior, not that')"
printf '%s\n' "$(c_dim 'any real device was reached or told the truth.')"

[[ $FAIL -eq 0 ]] || exit 1
