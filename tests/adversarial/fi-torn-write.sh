#!/bin/bash
# fi-torn-write.sh — adversarial test #3b. Try to manufacture a SILENT
# TRUNCATION: a recovered chain whose signed head claims sequence N while only
# M<N entries survive, with `virp chain verify` still VALID. See
# tests/adversarial/MEMO-torn-write-escalation.md.
#
# Mechanism: the LD_PRELOAD pwrite-filter shim (fi-pwrite-drop.c) silently
# drops matching writes from the isolated test daemon — deterministic choice of
# WHAT survives, zero blast radius, no privilege, no block device. (The
# sector-targeted dm-flakey confirmation in the memo is a separate, privileged
# follow-up; this harness is the primary, unprivileged probe.)
#
# SYMMETRIC RESULT (as memoed):
#   FINDING  — head_seq > surviving entries AND verify VALID (completeness
#              check accepted a chain that claims a tail it cannot produce).
#   PASS(detected) — same inconsistency, but verify FAILED (caught it).
#   PASS(atomic)   — every cut yields a consistent chain (head == entries);
#              after the bounded search, the chain inherits SQLite WAL
#              atomicity. The attempt count is logged — a silent cap is a lie.
#
# HELD FOR REVIEW: build + pre-flight only until the reviewer launches the run.
# Operates ONLY on a disposable chain under the session scratch; never the
# production chain.

set -uo pipefail

SCRATCH="${SCRATCH:-/tmp/claude-tornwrite}"
SHIM="${SHIM:-/tmp/fi-pwrite-drop.so}"
D="${D:-/opt/virp/build/virp-onode-prod}"
CLI="${CLI:-/opt/virp/build/virp}"
ATTEMPTS="${ATTEMPTS:-3}"
N="${N:-1500}"           # total appends; must exceed the ~1000-page WAL
H="${H:-200}"            # autocheckpoint threshold so a checkpoint lands in
                         # the drop window (H = appends before the drop arms)

case "$(readlink -m "$SCRATCH")" in
  /var/*|/run/*|/etc/*|/opt/virp/*|/home/*)
    echo "REFUSING: SCRATCH=$SCRATCH under a protected path"; exit 2;; esac
if findmnt -no FSTYPE --target "$(dirname "$SCRATCH")" 2>/dev/null | grep -q tmpfs; then
  echo "REFUSING: $(dirname "$SCRATCH") is tmpfs — no real fsync"; exit 2; fi

# Build the LD_PRELOAD shim if not already provided.
SHIM_SRC="$(cd "$(dirname "$0")" && pwd)/fi-pwrite-drop.c"
if [ ! -f "$SHIM" ]; then
  gcc -Wall -O2 -fPIC -shared "$SHIM_SRC" -ldl -o "$SHIM" \
    || { echo "shim build failed ($SHIM_SRC)"; exit 1; }
  echo "built shim: $SHIM"
fi

DPID=""
cleanup(){ [ -n "$DPID" ] && { kill -9 "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; }; }
trap cleanup EXIT INT TERM

# One python process appends [start .. start+count-1], each its own connection.
appends(){ # $1 sock  $2 start  $3 count
  python3 - "$1" "$2" "$3" <<'PY'
import socket,struct,sys
sock,start,count=sys.argv[1],int(sys.argv[2]),int(sys.argv[3])
ok=0
for i in range(start,start+count):
    h=("%064x"%i).encode()
    j=b'{"action":"chain_append","session_id":"powerloss:1","artifact_type":"fed_observation","artifact_id":"pl-obs-%d","artifact_hash":"%s"}'%(i,h)
    try:
        s=socket.socket(socket.AF_UNIX); s.settimeout(15); s.connect(sock)
        s.sendall(struct.pack(">I",1+len(j))+b"\x02"+j)
        hdr=s.recv(4)
        if len(hdr)==4:
            n=struct.unpack(">I",hdr)[0]; b=b""
            while len(b)<n:
                c=s.recv(n-len(b))
                if not c: break
                b+=c
            if n>4 and b"chain_entry_hash" in b: ok+=1
        s.close()
    except Exception: pass
print(ok)
PY
}

run_one(){ # $1 strategy label  $2 FI_DROP_MATCH  $3 FI_DROP_EXCLUDE  $4 attempt#
  local label="$1" match="$2" exclude="$3" a="$4"
  rm -rf "$SCRATCH"; mkdir -p "$SCRATCH"
  local M="$SCRATCH/mnt"; mkdir -p "$M"
  local CHAIN="$M/chain.db" KEY="$M/chain.key" TRIG="$SCRATCH/arm" DLOG="$SCRATCH/drops.log"
  head -c 32 /dev/urandom > "$KEY"; chmod 600 "$KEY"
  "$CLI" keygen okey "$M/onode.key" >/dev/null 2>&1; chmod 600 "$M/onode.key"
  cat > "$M/devices.json" <<'JSON'
{ "gate_max_tier":"yellow","gate_default_mode":"enforce","devices":[{"hostname":"pl-dummy","host":"127.0.0.1","port":22,"vendor":"mock","node_id":"0DE0F001"}] }
JSON
  printf '[]' > "$M/approvers.json"

  FI_DROP_MATCH="$match" FI_DROP_EXCLUDE="$exclude" FI_DROP_TRIGGER="$TRIG" FI_DROP_LOG="$DLOG" \
  LD_PRELOAD="$SHIM" \
    "$D" -k "$M/onode.key" -s "$M/onode.sock" -d "$M/devices.json" \
         -c "$CHAIN" -C "$KEY" -a "$M/approvals" -A "$M/approvers.json" \
         >>"$SCRATCH/daemon.log" 2>&1 &
  DPID=$!
  for _ in $(seq 1 40); do [ -S "$M/onode.sock" ] && break; sleep 0.25; done
  [ -S "$M/onode.sock" ] || { echo "  [$label a$a] SETUP FAIL: no socket"; tail -5 "$SCRATCH/daemon.log"|sed 's/^/    /'; return; }

  # phase A: land H appends with drops INACTIVE (trigger absent)
  appends "$M/onode.sock" 1 "$H" >/dev/null
  sync
  # arm drops, then phase B: the remaining appends write into the filter
  : > "$TRIG"
  appends "$M/onode.sock" "$((H+1))" "$((N-H))" >/dev/null
  # hard crash
  kill -9 "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; DPID=""
  sync

  # reopen fresh (no shim, no daemon) and measure
  local head_seq ecount minseq maxseq drops verify
  head_seq=$(sqlite3 "file:$CHAIN?mode=ro" "SELECT COALESCE(last_sequence,-1) FROM chain_heads WHERE session_id='powerloss:1';" 2>/dev/null); head_seq=${head_seq:--1}
  ecount=$(sqlite3 "file:$CHAIN?mode=ro" "SELECT COUNT(*) FROM chain_entries WHERE session_id='powerloss:1';" 2>/dev/null); ecount=${ecount:-0}
  minseq=$(sqlite3 "file:$CHAIN?mode=ro" "SELECT COALESCE(MIN(sequence),-1) FROM chain_entries WHERE session_id='powerloss:1';" 2>/dev/null); minseq=${minseq:--1}
  maxseq=$(sqlite3 "file:$CHAIN?mode=ro" "SELECT COALESCE(MAX(sequence),-1) FROM chain_entries WHERE session_id='powerloss:1';" 2>/dev/null); maxseq=${maxseq:--1}
  drops=$(grep -c '^DROP' "$DLOG" 2>/dev/null || echo 0)
  "$CLI" chain verify --db "$CHAIN" --key "$KEY" --session powerloss:1 >/dev/null 2>&1; verify=$?

  # classify
  local contiguous=0
  [ "$minseq" = 0 ] && [ "$ecount" = "$((maxseq-minseq+1))" ] && [ "$head_seq" = "$maxseq" ] && contiguous=1
  local tag
  if [ "$contiguous" = 1 ]; then
    tag="PASS(atomic/consistent)"
  elif [ "$verify" -eq 0 ]; then
    tag="*** FINDING (silent truncation) ***"
  else
    tag="PASS(inconsistency DETECTED by verify)"
  fi
  printf "  [%-8s a%d] drops=%-5s head_seq=%-5s entries=%-5s seqs=%s..%s verify=%s -> %s\n" \
    "$label" "$a" "$drops" "$head_seq" "$ecount" "$minseq" "$maxseq" "$verify" "$tag"
  echo "$tag" >> "$SCRATCH/../tornwrite-tags.txt"
}

echo "################ TORN-WRITE PROBE (LD_PRELOAD pwrite filter) ################"
echo "shim=$SHIM  N=$N  H=$H  attempts/strategy=$ATTEMPTS"
: > /tmp/tornwrite-tags.txt
# Strategies: WAL-only tail (baseline), whole-chain tail (aggressive),
# MAIN-DB-only (the surgical attempt: let the WAL persist but drop the main-db
# pages a checkpoint writes, trying to leave a head advanced past its entries).
for spec in "wal:chain.db-wal:" "all:chain.db:" "maindb:chain.db:-wal"; do
  IFS=: read -r label match exclude <<<"$spec"
  echo "--- strategy: $label (MATCH='$match' EXCLUDE='${exclude:-}') ---"
  for a in $(seq 1 "$ATTEMPTS"); do run_one "$label" "$match" "$exclude" "$a"; done
done

echo "================================================================"
if grep -q 'FINDING' /tmp/tornwrite-tags.txt; then
  echo "RESULT: at least one SILENT TRUNCATION produced — see FINDING lines above."
else
  na=$(grep -c 'atomic/consistent' /tmp/tornwrite-tags.txt)
  nd=$(grep -c 'DETECTED' /tmp/tornwrite-tags.txt)
  echo "RESULT: NO silent truncation across $((ATTEMPTS*3)) attempts"
  echo "  ($na consistent/atomic, $nd inconsistencies caught by verify)."
  echo "  The chain inherits SQLite WAL atomicity, and the head/entry"
  echo "  completeness check caught every inconsistency it was shown."
fi
echo "================================================================"
rm -rf "$SCRATCH"
