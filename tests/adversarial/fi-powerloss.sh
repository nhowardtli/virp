#!/bin/bash
# fi-powerloss.sh — adversarial test #3. Take the chain writer past the SIGKILL
# ceiling to a real storage cut, on a DISPOSABLE loop-backed filesystem we own
# end to end, and ask the one question SIGKILL-on-tmpfs cannot:
#
#   when writes the daemon believed were durable never reached the platter
#   (power loss / lying disk), does the chain DETECT the lost tail — or does
#   virp chain verify report VALID on a silently shortened chain?
#
# The pass condition is NOT "no data lost". Power loss loses data. It is
# "loss is DETECTED, never silently accepted": the signed per-session head
# asserts a length the surviving entries no longer reach, so verification MUST
# fail. A VALID verdict over a short chain is the finding.
#
# Two rungs (see MEMO-disposable-fs-ceiling.md), selected by $MODE:
#   flakey  (L3, default) dm-flakey drop_writes — writes ack at the syscall,
#           never hit the image. The true power-loss case.
#   error   (L2)          dm-error — every I/O errors. The writer must fail
#           CLOSED (refuse the append) rather than ack a write it cannot persist.
#
# =====================================================================
# HELD FOR REVIEW. This script is destructive at the block layer and is NOT
# run unattended. It requires root (loop/dm/mount/modprobe) via scoped sudo.
# Same contract as include/virp_fault_inject.h, extended to the device:
# dedicated scratch only, unique device names, trap-guaranteed teardown,
# NEVER /var/lib or /run or the production socket. Base commit pinned in the
# transcript per CONVENTIONS.md.
# =====================================================================

set -uo pipefail

MODE="${1:-flakey}"                     # flakey (L3) | error (L2)
SCRATCH="${SCRATCH:-/tmp/claude-powerloss}"   # MUST be disk-backed, not tmpfs
IMG="$SCRATCH/chain-fs.img"
IMG_MB=256                              # ceiling per memo (corpus is single-MB)
MNT="$SCRATCH/mnt"
DM="virp-adv3-flakey-$$"                # unique; never a fixed /dev/mapper name
DMPATH="/dev/mapper/$DM"
D=/opt/virp/build/virp-onode-prod       # prod daemon (built from merged main)
CLI=/opt/virp/build/virp
APPENDS_PRESYNC=200                     # land + fsync before the cut
APPENDS_POSTCUT=200                     # issued after the cut — the lost tail
LOOPDEV=""

# ---- safety fence: refuse to operate anywhere production lives -----------
case "$(readlink -m "$SCRATCH")" in
  /var/*|/run/*|/etc/*|/opt/virp/*|/home/*)
    echo "REFUSING: SCRATCH=$SCRATCH resolves under a protected path"; exit 2;;
esac
mountpoint -q "$(df --output=target "$(dirname "$SCRATCH")" 2>/dev/null | tail -1)" 2>/dev/null
if findmnt -no FSTYPE --target "$(dirname "$SCRATCH")" 2>/dev/null | grep -q tmpfs; then
  echo "REFUSING: $(dirname "$SCRATCH") is tmpfs — fsync there is a formality; use a disk-backed path"; exit 2
fi

# ---- teardown: single trap, idempotent, unwinds in reverse order --------
DPID=""
teardown() {
  [ -n "$DPID" ] && { sudo kill -9 "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; }
  sudo umount "$MNT" 2>/dev/null
  sudo dmsetup remove "$DM" 2>/dev/null
  [ -n "$LOOPDEV" ] && sudo losetup -d "$LOOPDEV" 2>/dev/null
  rm -rf "$SCRATCH"
}
trap teardown EXIT INT TERM

# ---- build the disposable block stack -----------------------------------
echo "################ POWER-LOSS RUN: mode=$MODE ################"
rm -rf "$SCRATCH"; mkdir -p "$SCRATCH" "$MNT"
[ "$MODE" = flakey ] && sudo modprobe dm-flakey
truncate -s "${IMG_MB}M" "$IMG"
LOOPDEV=$(sudo losetup --find --show "$IMG")
echo "loop: $LOOPDEV  image: $IMG (${IMG_MB} MB)"
SECTORS=$(sudo blockdev --getsz "$LOOPDEV")

# Start in a clean pass-through (linear) so mkfs + the pre-sync appends land.
sudo dmsetup create "$DM" --table "0 $SECTORS linear $LOOPDEV 0"
sudo mkfs.ext4 -q -F "$DMPATH"
sudo mount "$DMPATH" "$MNT"
sudo chown "$(id -u):$(id -g)" "$MNT"
CHAIN="$MNT/chain.db"; KEY="$MNT/chain.key"

# ---- isolated daemon on the disposable fs -------------------------------
# Chain key is a raw 32-byte HMAC key (as demo/run.sh:138); O-Key via keygen.
# BOTH must be mode 0600 or the daemon refuses to load them and never binds the
# socket (learned the hard way: the first run created the key at umask 0664, the
# daemon failed to start, zero appends landed, and the verdict then read a
# never-populated chain as "loss detected" — a false pass).
head -c 32 /dev/urandom > "$KEY"; chmod 600 "$KEY"
"$CLI" keygen okey "$MNT/onode.key" >/dev/null 2>&1 || { echo "keygen okey failed"; exit 1; }
chmod 600 "$MNT/onode.key"
printf '[]' > "$MNT/devices.json"; printf '[]' > "$MNT/approvers.json"
start_daemon() {
  "$D" -k "$MNT/onode.key" -s "$MNT/onode.sock" -d "$MNT/devices.json" \
       -c "$CHAIN" -C "$KEY" -a "$MNT/approvals" -A "$MNT/approvers.json" \
       >>"$SCRATCH/daemon.log" 2>&1 &
  DPID=$!
  for _ in $(seq 1 40); do [ -S "$MNT/onode.sock" ] && break; sleep 0.25; done
  if [ ! -S "$MNT/onode.sock" ]; then
    echo "SETUP FAILURE: daemon did not bind $MNT/onode.sock. Daemon log:"
    sed 's/^/    /' "$SCRATCH/daemon.log" 2>/dev/null | tail -20
    exit 3
  fi
}

# Commitment-only fed_observation appends (the oversized shape: no body, so no
# artifacts row — the daemon accepts the bare commitment). Distinct synthetic
# 64-hex hash per index; SESSION fixed so the signed head tracks a length.
append() {  # $1 = index
  local h; h=$(printf '%064x' "$1")
  python3 - "$MNT/onode.sock" "$h" "$1" <<'PY'
import socket,struct,sys
sock,h,i=sys.argv[1],sys.argv[2],sys.argv[3]
j=('{"action":"chain_append","session_id":"powerloss:1",'
   '"artifact_type":"fed_observation","artifact_id":"pl-obs-%s",'
   '"artifact_hash":"%s"}'%(i,h)).encode()
s=socket.socket(socket.AF_UNIX); s.connect(sock)
s.sendall(struct.pack(">I",1+len(j))+b"\x02"+j)
hdr=s.recv(4); n=struct.unpack(">I",hdr)[0]; b=b""
while len(b)<n: b+=s.recv(n-len(b))
sys.exit(0 if n>4 else 1)
PY
}

start_daemon
echo "daemon pid=$DPID on $CHAIN"

# ---- phase 1: land + fsync a durable prefix -----------------------------
for i in $(seq 1 "$APPENDS_PRESYNC"); do append "$i" >/dev/null || echo "presync append $i refused"; done
sync; sudo blockdev --flushbufs "$LOOPDEV"
PRE=$("$CLI" chain tail -n 100000 --db "$CHAIN" 2>/dev/null | grep -c 'pl-obs-')
echo "durable prefix: $PRE entries, synced to the image"
# A power-loss test with nothing durable to lose proves nothing. Abort BEFORE
# the cut so a setup failure can never masquerade as "loss detected".
if [ "$PRE" -eq 0 ]; then
  echo "SETUP FAILURE: no durable prefix landed (daemon/append path broken)."
  echo "Daemon log:"; sed 's/^/    /' "$SCRATCH/daemon.log" 2>/dev/null | tail -20
  exit 3
fi

# ---- phase 2: THE CUT ---------------------------------------------------
if [ "$MODE" = flakey ]; then
  # drop_writes: subsequent writes ack but never reach the image (power loss).
  sudo dmsetup suspend "$DM"
  sudo dmsetup reload "$DM" --table "0 $SECTORS flakey $LOOPDEV 0 0 60 1 drop_writes"
  sudo dmsetup resume "$DM"
  echo "CUT: dm-flakey drop_writes armed — writes now vanish"
else
  sudo dmsetup suspend "$DM"
  sudo dmsetup reload "$DM" --table "0 $SECTORS error"
  sudo dmsetup resume "$DM"
  echo "CUT: dm-error armed — every I/O now errors"
fi

# ---- phase 3: appends into the void, then a hard crash ------------------
refused=0
for i in $(seq $((APPENDS_PRESYNC+1)) $((APPENDS_PRESYNC+APPENDS_POSTCUT))); do
  append "$i" >/dev/null || refused=$((refused+1))
done
echo "post-cut appends refused by the writer: $refused / $APPENDS_POSTCUT"
sudo kill -9 "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; DPID=""

# ---- phase 4: reopen from the IMAGE with cold cache, then verify --------
sudo umount "$MNT" 2>/dev/null
sudo dmsetup remove "$DM" 2>/dev/null
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null   # forget cached writes
# Re-expose the underlying image straight (no flakey): what actually persisted.
sudo dmsetup create "$DM" --table "0 $SECTORS linear $LOOPDEV 0"
sudo mount "$DMPATH" "$MNT"
POST=$("$CLI" chain tail -n 100000 --db "$CHAIN" 2>/dev/null | grep -c 'pl-obs-')
echo "entries surviving on the image after the cut: $POST"

# The signed head is the completeness authority: it records the last sequence
# the chain COMMITTED to. A silent truncation is head.last_sequence claiming
# more than actually survived, with verify none the wiser.
HEADSEQ=$(sqlite3 "file:$CHAIN?mode=ro" \
  "SELECT last_sequence FROM chain_heads WHERE session_id='powerloss:1';" 2>/dev/null)
HEADSEQ=${HEADSEQ:--1}

echo "--- virp chain verify over the recovered chain ---"
"$CLI" chain verify --db "$CHAIN" --key "$KEY" --session powerloss:1
VERIFY=$?

# ---- verdict ------------------------------------------------------------
echo "================================================================"
echo "durable prefix=$PRE  survived=$POST  post-cut-refused=$refused"
echo "signed head last_sequence=$HEADSEQ  verify_exit=$VERIFY  (survived seqs 0..$((POST-1)))"
if [ "$MODE" != flakey ]; then
  echo "L2 (dm-error): the writer should have REFUSED post-cut appends (refused=$refused);"
  echo "               a nonzero refused count with a still-valid pre-cut chain is fail-closed."
elif [ "$PRE" -eq 0 ]; then
  echo "INVALID: no durable prefix (should have aborted in phase 1)."
elif [ "$POST" -lt "$PRE" ]; then
  echo "ANOMALY (not a chain finding): the pre-cut SYNCED prefix did not survive"
  echo "  (survived=$POST < durable=$PRE) — fsync/flushbufs did not persist before"
  echo "  the cut. Retune the sync boundary; the chain layer is not implicated."
elif [ "$POST" -ge "$((PRE+APPENDS_POSTCUT))" ]; then
  echo "INCONCLUSIVE: no tail was lost — drop_writes did not straddle a flush"
  echo "  boundary (all post-cut writes reached the image). Retune sync timing."
elif [ "$HEADSEQ" -ge "$POST" ] && [ "$VERIFY" -eq 0 ]; then
  echo "FINDING: the signed head claims seq $HEADSEQ but only $POST entries survived,"
  echo "  and verify reported VALID — a SILENTLY shortened chain. This is exactly the"
  echo "  SIGKILL-vs-power-loss gap the caveat concedes."
elif [ "$VERIFY" -ne 0 ]; then
  echo "PASS: the storage cut lost the tail and verify FAILED — the truncation is"
  echo "  DETECTED, never silently accepted (head/entry completeness caught it)."
else
  echo "PASS (atomic loss): head and entries reverted together (head=$HEADSEQ,"
  echo "  survived=$POST) — the chain is honestly shorter, verify VALID, and it makes"
  echo "  NO claim to the lost tail. No dangling commitment."
fi
echo "================================================================"
