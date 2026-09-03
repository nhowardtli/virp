#!/usr/bin/env bash
#
# deployed-state.sh — report what THIS node is actually running, as one
# JSON document, and (optionally) land that document on the chain.
#
# Copyright (c) 2026 Third Level IT LLC. All rights reserved.
#
# ─────────────────────────────────────────────────────────────────────
# WHY THIS EXISTS
#
# What is running on a node has lived in DEPLOYED.md prose and in an
# operator's head. That has been wrong three times, and every time it
# was found by accident: a stale ssh alias made a session declare a node
# unreachable; a 43-device fleet existed only on the box and never in
# the repo; the tracked template said nine devices while the box ran
# forty-three. Deployed state should be an observation this system
# produces on a schedule, not a memory someone has to be right about.
#
# This is a REPORTER. It changes nothing, converges nothing, and holds
# no opinion about what the node SHOULD be running — that judgement is
# drift-check.sh's job, deliberately a separate program that never
# touches a node.
#
# ─────────────────────────────────────────────────────────────────────
# WHAT IT READS, AND WHAT IT REFUSES TO READ
#
# Hashes and identifiers only. It reads the device config to COUNT the
# devices and to read the gate policy keys; it never emits a device
# entry, and there is no code path in it that could. It reads
# approvers.json for key_ids; it never emits key bytes — public halves
# belong in deploy/keys/registry.json, secret halves nowhere. It never
# opens /etc/virp/autopilot.env, even running as root.
#
# ─────────────────────────────────────────────────────────────────────
# WHY IT SPLITS COLLECT FROM SUBMIT
#
# The two halves need DIFFERENT identities and neither can do the
# other's job:
#
#   collect  needs root. The daemon sets PR_SET_DUMPABLE=0 as a
#            key-exposure mitigation, which makes /proc/<pid>/exe
#            unreadable even to the daemon's OWN uid. The running-binary
#            hash — the one fact that exposes a hidden rollback, and the
#            reason this tool exists — is root-only as a direct
#            consequence. Verified on virp-lab 2026-09-02: uid 999 gets
#            EACCES on its own daemon's /proc/<pid>/exe.
#
#   submit   must NOT be root. uid 0 is deliberately excluded from
#            socket_allowed_uids; a root client is refused at the
#            peercred gate with "peer uid=0 not in socket_allowed_uids".
#
# So --collect and --submit are separate invocations, and the unit runs
# collection with systemd's `+` prefix (root) and submission as the
# service user — the same idiom virp-onode.service already uses for its
# ExecStartPre render step.
#
# ─────────────────────────────────────────────────────────────────────
# WHY NO NEW GATE CLASSIFIER ROW WAS ADDED
#
# None is needed. The driver classifier governs commands the O-Node runs
# against a DEVICE. This script reads its own node's filesystem locally
# and submits over chain_append, authorised by socket_uid_action_allow /
# socket_uid_chain_append_types, which never enters the classifier. The
# linux driver's deliberate 2026-08-13 hold on growing the GREEN row
# list stays intact, and nothing here asks the gate to police arbitrary
# Linux.
#
# ─────────────────────────────────────────────────────────────────────
# WHAT THE RESULTING CHAIN ENTRY DOES AND DOES NOT PROVE
#
# Two grades, marked per fact in the document:
#
#   attested — the DAEMON minted these about itself. build_id, gate
#              mode, max tier, evidence_required and the per-uid
#              ceilings all appear in the daemon's own node_config/1
#              chain entry, a reserved artifact type GATE 1 forbids any
#              socket client from submitting. Where one exists this
#              document CITES it by hash instead of restating it.
#
#   reported — everything else. Read from this node's filesystem by this
#              script. GATE 2 binds the body to its declared hash and
#              the chain entry carries the node's K_chain HMAC and its
#              position in the hash chain. That proves the daemon
#              received THESE EXACT BYTES at THIS position at THIS time.
#              It does not prove they are true. An attacker with root on
#              the node can lie to this script, and the lie will be
#              faithfully and verifiably chained.
#
# This closes the accident case, not the adversary case. See README.md.
#
# ─────────────────────────────────────────────────────────────────────
# FAILURE POLICY
#
# Loud, never partial. A fact this script expects to read and cannot is
# a hard failure: nothing reaches the output and the exit status is
# non-zero. A fact STRUCTURALLY ABSENT for a node's shape — a node with
# no device template, a daemon too old to mint node_config/1 — is
# recorded as a typed absence WITH A REASON, because "this node has no
# template" is a fact worth chaining while "I could not read the
# template" is a bug.
#
# Exit: 0 ok, 2 collection failed, 3 wrong identity for the mode.
#

set -euo pipefail

PROG="$(basename "$0")"
SELF="$(readlink -f "$0")"

UNIT="virp-onode.service"
SOCKET=""
OUT="-"
IN=""
TREE=""
MODE=""

die()  { printf '%s: %s\n' "$PROG" "$*" >&2; exit 2; }
die3() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 3; }

usage() {
    cat >&2 <<USAGE
usage:
  $PROG --collect [--unit NAME] [--tree PATH] [--out PATH]
        Read this node's state; emit one deployed_state/1 document.
        Must run as root (/proc/<pid>/exe is unreadable otherwise).

  $PROG --submit --in PATH [--unit NAME] [--socket PATH]
        Submit an already-collected document to the local O-Node as a
        chain_append of artifact_type evidence_item. Must NOT be root.
        Prints the daemon's signed receipt as JSON.

  --unit NAME     O-Node unit to describe   (default: $UNIT)
  --tree PATH     deploy tree               (default: auto-detected)
  --out PATH      write here, '-' = stdout  (default: stdout)
  --in PATH       document to submit
  --socket PATH   O-Node socket             (default: the unit's -s flag)
USAGE
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --collect) MODE=collect ;;
        --submit)  MODE=submit ;;
        --unit)    shift; [ $# -gt 0 ] || usage; UNIT="$1" ;;
        --tree)    shift; [ $# -gt 0 ] || usage; TREE="$1" ;;
        --out)     shift; [ $# -gt 0 ] || usage; OUT="$1" ;;
        --in)      shift; [ $# -gt 0 ] || usage; IN="$1" ;;
        --socket)  shift; [ $# -gt 0 ] || usage; SOCKET="$1" ;;
        -h|--help) usage ;;
        *) printf '%s: unknown argument %s\n' "$PROG" "$1" >&2; usage ;;
    esac
    shift
done
[ -n "$MODE" ] || usage

for c in python3 systemctl sha256sum; do
    command -v "$c" >/dev/null 2>&1 || die "required command not found: $c"
done

# ── unit introspection ────────────────────────────────────────────────
# Every path reported below is DERIVED FROM THE UNIT, never hardcoded.
# The two live nodes already disagree about where the device config
# lives — /run/virp/devices.json rendered on one, /etc/virp/devices.json
# static on the other — and a reporter that assumed one shape would
# have reported the other node WRONGLY rather than not at all, which is
# precisely the failure this tool exists to end.
#
# Submission needs only a socket, so when --socket is given it skips
# this entirely. That is not just tidiness: it means the submit half can
# be exercised against a scratch daemon that has no systemd unit at all.

unit_path=""; argv=""; daemon_path=""; devcfg_path=""; chaindb_path=""
socket_path=""; node_id_flag=""; approvers_path=""

introspect_unit() {
    unit_path="$(systemctl show -p FragmentPath --value "$UNIT" 2>/dev/null || true)"
    [ -n "$unit_path" ] && [ -f "$unit_path" ] \
        || die "unit $UNIT has no readable fragment path (is it installed?)"

    # systemd renders ExecStart as a record with several fields; only the
    # argv[] segment is the command line. Parsing the whole record would
    # pick up path=, start_time=[...] and pid=, so isolate argv[] first.
    execstart_raw="$(systemctl show -p ExecStart --value "$UNIT" 2>/dev/null || true)"
    [ -n "$execstart_raw" ] || die "unit $UNIT reports no ExecStart"
    argv="$(printf '%s\n' "$execstart_raw" \
            | sed -n 's/.*argv\[\]=\([^;]*\).*/\1/p')"
    [ -n "$argv" ] || die "could not parse argv[] out of $UNIT's ExecStart"

    # `-x value` out of argv. Absent flag => empty, which callers treat as a
    # typed absence or a hard failure depending on whether the flag is
    # load-bearing.
    unit_flag() {
        printf '%s\n' "$argv" | tr ' ' '\n' | awk -v f="$1" '
            $0 == f { want = 1; next }
            want    { print; exit }'
}

daemon_path="$(printf '%s\n' "$argv" | awk '{print $1}')"
[ -n "$daemon_path" ] || die "could not find the daemon binary in ExecStart"

devcfg_path="$(unit_flag -d)"
chaindb_path="$(unit_flag -c)"
socket_path="$(unit_flag -s)"
node_id_flag="$(unit_flag -n)"
approvers_path="$(unit_flag -A)"
[ -n "$approvers_path" ] || approvers_path="/etc/virp/approvers.json"
[ -n "$SOCKET" ] || SOCKET="$socket_path"
}

# ─────────────────────────────────────────────────────────────────────
# submit
# ─────────────────────────────────────────────────────────────────────
if [ "$MODE" = submit ]; then
    [ -n "$SOCKET" ] || introspect_unit
    [ -n "$IN" ] || die "--submit needs --in PATH"
    [ -r "$IN" ] || die "cannot read document: $IN"
    [ "$(id -u)" != "0" ] || die3 "refusing to submit as root: uid 0 is deliberately excluded from socket_allowed_uids and the daemon would refuse this connection at the peercred gate. Run as the node's service user."
    [ -S "$SOCKET" ] || die "O-Node socket not found: $SOCKET"

    DS_DOC="$IN" DS_SOCK="$SOCKET" exec python3 - <<'PY'
import hashlib, json, os, socket, struct, sys

doc_path = os.environ["DS_DOC"]
sock_path = os.environ["DS_SOCK"]

# Submit the bytes AS COLLECTED. Re-serialising here would put a hash on
# the chain that binds a document nobody ever saw.
body = open(doc_path, "rb").read()
h = hashlib.sha256(body).hexdigest()

try:
    doc = json.loads(body)
    if doc.get("schema") != "deployed_state/1":
        raise ValueError("schema is %r, not deployed_state/1"
                         % doc.get("schema"))
    node_id = doc["node"]["node_id"]
except Exception as e:
    sys.exit("deployed-state: %s is not a deployed_state/1 document: %s"
             % (doc_path, e))

# WHY evidence_item, and not a new type.
#
# artifact_type="observation" WITH a body must carry a v1/v2/v3
# signature (GATE 3). v1 is HMAC under the O-Key, which is the daemon's
# and not this identity's, so an `observation` submission here could
# only be COMMITMENT-ONLY — the document would not be on the chain, only
# its hash, and every reader would correctly grade it UNVERIFIABLE.
#
# A purpose-built `deployed_state` type would mean editing the fixed C
# array in virp_chain_type_is_external_allowed(), rebuilding, and
# redeploying the daemon on every node — far past "build a reporter".
#
# evidence_item is already externally allowed, takes a plain-JSON body
# with no signature requirement, and is semantically honest: a state
# document is evidence. The schema tag inside the body is what makes it
# findable as a deployed_state document.
ARTIFACT_TYPE = "evidence_item"
session_id = "deployed-state:%s" % node_id
artifact_id = "depstate-%s" % h[:16]

req = {
    "action": "chain_append",
    "session_id": session_id,
    "artifact_type": ARTIFACT_TYPE,
    "artifact_id": artifact_id,
    "artifact_hash": h,
}

# The daemon's artifact_content field is 8192 bytes. A body at or past
# that would be stored TRUNCATED, i.e. permanently unverifiable, so an
# oversized document registers commitment-only and SAYS SO rather than
# quietly landing bytes that will never verify.
content = body.decode("utf-8")
stored_body = len(content) < 8192
if stored_body:
    req["artifact_content"] = content

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(60)
try:
    s.connect(sock_path)
    payload = json.dumps(req).encode()
    s.sendall(struct.pack(">I", 1 + len(payload)) + b"\x02" + payload)

    def readn(n):
        buf = b""
        while len(buf) < n:
            c = s.recv(n - len(buf))
            if not c:
                raise IOError("short read from O-Node")
            buf += c
        return buf

    resp = readn(struct.unpack(">I", readn(4))[0])
finally:
    s.close()

# A bare 4-byte frame is a typed error code, not an observation.
if len(resp) == 4:
    sys.exit("deployed-state: O-Node REFUSED the append: error %d "
             "(artifact_type=%s session=%s). Check this uid's "
             "socket_uid_action_allow and socket_uid_chain_append_types."
             % (struct.unpack(">i", resp)[0], ARTIFACT_TYPE, session_id))

# The receipt is a signed v1 observation whose payload is the chain
# entry JSON. The 56-byte wire header is 24 bytes of fields FOLLOWED BY
# the 32-byte HMAC — the HMAC is inside the header, not after it — so
# the payload starts at 56, not at 56+32. Then obs_type/scope/len.
HDR_FIELDS, HMAC_LEN = 24, 32
off = HDR_FIELDS + HMAC_LEN
if len(resp) < off + 4:
    sys.exit("deployed-state: receipt too short to parse (%d bytes)"
             % len(resp))
_t, _sc, dlen = struct.unpack("!BBH", resp[off:off + 4])
entry = json.loads(resp[off + 4: off + 4 + dlen].decode("utf-8"))

print(json.dumps({
    "submitted": True,
    "artifact_type": ARTIFACT_TYPE,
    "artifact_id": artifact_id,
    "artifact_hash": h,
    "session_id": session_id,
    "body_stored": stored_body,
    "body_bytes": len(body),
    "receipt": entry,
}, indent=2, sort_keys=True))
PY
fi

# ─────────────────────────────────────────────────────────────────────
# collect
# ─────────────────────────────────────────────────────────────────────
# Identity is checked BEFORE anything else, so a caller who ran this as
# the wrong user is told that, rather than being handed a confusing
# complaint about systemd from a step that was never going to matter.
[ "$(id -u)" = "0" ] || die3 "--collect must run as root: the daemon sets PR_SET_DUMPABLE=0, so /proc/<pid>/exe — the running-binary hash, the one fact that exposes a hidden rollback — is unreadable to every other uid, this script's own included. Refusing to emit a document without it."

introspect_unit

hash_of() { sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }

main_pid="$(systemctl show -p MainPID --value "$UNIT" 2>/dev/null || echo 0)"
case "$main_pid" in
    ''|*[!0-9]*) die "$UNIT reports a non-numeric MainPID: '$main_pid'" ;;
esac
[ "$main_pid" -gt 0 ] \
    || die "$UNIT has no running MainPID — refusing to report a running binary for a daemon that is not running"

running_exe="$(readlink -f "/proc/$main_pid/exe" 2>/dev/null || true)"
[ -n "$running_exe" ] || die "cannot resolve /proc/$main_pid/exe"
running_sha="$(hash_of "/proc/$main_pid/exe")"
[ -n "$running_sha" ] || die "cannot hash /proc/$main_pid/exe"

installed_sha="$(hash_of "$daemon_path")"
[ -n "$installed_sha" ] || die "cannot hash the installed daemon: $daemon_path"

unit_sha="$(hash_of "$unit_path")"
[ -n "$unit_sha" ] || die "cannot hash the unit file: $unit_path"

proc_start="$(ps -o lstart= -p "$main_pid" 2>/dev/null | sed 's/^ *//;s/ *$//' || true)"
[ -n "$proc_start" ] || die "cannot read the daemon's start time"

# Drop-ins, in the order systemd applies them.
dropins=""
dropin_dir="/etc/systemd/system/$UNIT.d"
if [ -d "$dropin_dir" ]; then
    for f in "$dropin_dir"/*.conf; do
        [ -e "$f" ] || continue
        s="$(hash_of "$f")"
        [ -n "$s" ] || die "cannot hash drop-in: $f"
        dropins="${dropins}$(basename "$f")	$s
"
    done
fi

# The client binary, if this node installs one beside the daemon.
client_path="$(dirname "$daemon_path")/virp-tool"
client_sha=""
client_build=""
if [ -x "$client_path" ]; then
    client_sha="$(hash_of "$client_path")"
    [ -n "$client_sha" ] || die "cannot hash the client: $client_path"
    # `virp-tool version` prints a coredump-filter warning on stderr;
    # stdout's last field is the answer. An older client may not know
    # the verb, which is an absence, not a failure.
    client_build="$("$client_path" version 2>/dev/null | tail -n1 \
                    | awk '{print $NF}' || true)"
fi

# ── deploy tree ───────────────────────────────────────────────────────
# Not derivable from the unit — the unit names installed artifacts, not
# the tree they were built from — so it is auto-detected, and an
# AMBIGUOUS answer is a hard failure rather than a guess. Two candidate
# trees on one node is exactly the situation where picking the wrong one
# produces a confident, wrong report.
tree_reason=""
if [ -z "$TREE" ]; then
    found=""
    for cand in /opt/virp /srv/virp /usr/local/src/virp /root/virp /home/*/virp; do
        [ -d "$cand/.git" ] || continue
        found="${found}${cand}
"
    done
    n="$(printf '%s' "$found" | grep -c . || true)"
    if [ "${n:-0}" -eq 1 ]; then
        TREE="$(printf '%s' "$found" | head -n1)"
    elif [ "${n:-0}" -gt 1 ]; then
        die "ambiguous deploy tree — found $n candidates:
$(printf '%s' "$found" | sed 's/^/    /')
Pass --tree PATH. Guessing here is how a confident wrong report gets made."
    else
        tree_reason="no git checkout found in any known location"
    fi
fi

git_rev=""; git_describe=""; git_branch=""; git_dirty="false"; git_dirty_n="0"
git_remote_refs=""; git_fetched_at=""
if [ -n "$TREE" ]; then
    [ -d "$TREE/.git" ] || die "not a git checkout: $TREE"
    # --no-optional-locks so `status` cannot refresh (i.e. WRITE) the
    # index. A reporter that mutates the tree it reports on is not a
    # reporter, and .git/index is a real file with a real mtime that
    # other tooling reads.
    g() { git --no-optional-locks -c "safe.directory=$TREE" -C "$TREE" "$@"; }
    git_rev="$(g rev-parse HEAD 2>/dev/null || true)"
    [ -n "$git_rev" ] || die "deploy tree $TREE has no readable HEAD"
    git_describe="$(g describe --tags --always --dirty 2>/dev/null || true)"
    git_branch="$(g rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
    git_dirty_n="$(g status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
    [ "${git_dirty_n:-0}" -gt 0 ] && git_dirty="true" || git_dirty="false"
    # Which LOCALLY-KNOWN remote refs contain this commit. This is a
    # local answer: it says the checkout matches a ref this node has
    # fetched at some point, not that it matches origin right now.
    # Fetching would be a write and a network call, and a reporter does
    # neither — so the fetch timestamp travels with the claim and lets
    # the reader judge how stale the answer is.
    git_remote_refs="$(g for-each-ref --format='%(refname:short)' \
                         --contains "$git_rev" refs/remotes 2>/dev/null \
                       | paste -sd, - || true)"
    if [ -f "$TREE/.git/FETCH_HEAD" ]; then
        git_fetched_at="$(date -u -r "$TREE/.git/FETCH_HEAD" \
                          +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
    fi
fi

# ── device config + template ──────────────────────────────────────────
[ -n "$devcfg_path" ] || die "unit $UNIT passes no -d device config path"
[ -r "$devcfg_path" ] || die "device config unreadable: $devcfg_path"
devcfg_sha="$(hash_of "$devcfg_path")"
[ -n "$devcfg_sha" ] || die "cannot hash the device config: $devcfg_path"

# A node either renders its config from a template at daemon start
# (ExecStartPre) or ships a static file. Both are legitimate shapes;
# WHICH ONE THIS NODE IS, is itself a reported fact — and a node whose
# fleet has no tracked source is the exact condition that hid a
# 43-device fleet from the repo for a month.
tmpl_path=""; tmpl_sha=""; devcfg_source="static"
if systemctl show -p ExecStartPre --value "$UNIT" 2>/dev/null \
        | grep -q 'render-devices'; then
    devcfg_source="rendered"
    for cand in /etc/virp/devices.template.json \
                /etc/virp/devices.node2.template.json; do
        [ -r "$cand" ] && { tmpl_path="$cand"; break; }
    done
    [ -n "$tmpl_path" ] \
        || die "the unit renders its device config but no template is on disk — a rendered node with no template is a broken node, not an absence"
    tmpl_sha="$(hash_of "$tmpl_path")"
    [ -n "$tmpl_sha" ] || die "cannot hash the template: $tmpl_path"
fi

self_sha="$(hash_of "$SELF")"

# ─────────────────────────────────────────────────────────────────────
# Assemble. Python owns everything needing JSON or sqlite: the device
# config's policy keys, the approver registry's key_ids, and the
# daemon's own node_config/1 attestation from the chain. Facts cross the
# boundary in the ENVIRONMENT, never interpolated into the source — a
# path with a quote in it must not be able to become code.
# ─────────────────────────────────────────────────────────────────────
if [ "$OUT" = "-" ]; then
    tmp="$(mktemp)"
else
    tmp="$(mktemp "$(dirname "$OUT")/.deployed-state.XXXXXX")"
fi
trap 'rm -f "$tmp"' EXIT

DS_OUT="$tmp" \
DS_UNIT="$UNIT" DS_UNIT_PATH="$unit_path" DS_UNIT_SHA="$unit_sha" \
DS_DROPINS="$dropins" \
DS_DAEMON="$daemon_path" DS_RUNNING_EXE="$running_exe" \
DS_INSTALLED_SHA="$installed_sha" DS_RUNNING_SHA="$running_sha" \
DS_PID="$main_pid" DS_STARTED="$proc_start" \
DS_CLIENT="$client_path" DS_CLIENT_SHA="$client_sha" \
DS_CLIENT_BUILD="$client_build" \
DS_TREE="$TREE" DS_TREE_REASON="$tree_reason" DS_REV="$git_rev" \
DS_DESCRIBE="$git_describe" DS_BRANCH="$git_branch" \
DS_DIRTY="$git_dirty" DS_DIRTY_N="$git_dirty_n" \
DS_REMOTE_REFS="$git_remote_refs" DS_FETCHED_AT="$git_fetched_at" \
DS_DEVCFG="$devcfg_path" DS_DEVCFG_SHA="$devcfg_sha" \
DS_DEVCFG_SOURCE="$devcfg_source" \
DS_TMPL="$tmpl_path" DS_TMPL_SHA="$tmpl_sha" \
DS_CHAINDB="$chaindb_path" DS_APPROVERS="$approvers_path" \
DS_NODE_ID_FLAG="$node_id_flag" DS_SELF_SHA="$self_sha" \
python3 - <<'PY' || die "document assembly failed"
import json, os, sqlite3, sys, time

E = os.environ
def env(k):  return E.get(k, "")
def envn(k): return E.get(k) or None

def fail(msg):
    sys.exit("deployed-state: %s" % msg)

DEVCFG   = env("DS_DEVCFG")
CHAINDB  = env("DS_CHAINDB")
APPROVER = env("DS_APPROVERS")

# ── device config ────────────────────────────────────────────────────
# Only the named policy keys and len(devices) are ever touched. Device
# entries carry credentials; this reads none of them, and `del devices`
# below means no code path after it can reach one. Keys beginning '_'
# are the template's prose annotations, deliberately ignored — the same
# discipline render-devices.sh applies.
try:
    with open(DEVCFG) as f:
        cfg = json.load(f)
except Exception as e:
    fail("device config %s is unreadable or not JSON: %s" % (DEVCFG, e))

devices = cfg.get("devices")
if not isinstance(devices, list):
    fail("device config %s has no 'devices' array" % DEVCFG)
device_count = len(devices)
del devices

def uid_list(v):
    out = []
    for x in v or []:
        try:
            out.append(int(x))
        except (TypeError, ValueError):
            fail("socket_allowed_uids holds a non-numeric entry %r — an "
                 "unrendered template placeholder?" % (x,))
    return sorted(out)

allowed_uids = uid_list(cfg.get("socket_allowed_uids"))
cfg_gate = {
    "default_mode": (cfg.get("gate_default_mode") or "").upper() or None,
    "max_tier": (cfg.get("gate_max_tier") or "").upper() or None,
    "evidence_required": cfg.get("evidence_required"),
    "uid_ceilings": sorted(
        [{"uid": int(k), "ceiling": str(v).upper()}
         for k, v in (cfg.get("socket_uid_tier_ceilings") or {}).items()
         if str(k).isdigit()],
        key=lambda d: d["uid"]),
}
del cfg

# ── approver registry: key_ids only, never key bytes ─────────────────
approvers, approvers_absent = [], None
if os.path.exists(APPROVER):
    try:
        with open(APPROVER) as f:
            entries = json.load(f)
    except Exception as e:
        fail("approver registry %s is unreadable or not JSON: %s"
             % (APPROVER, e))
    if not isinstance(entries, list):
        fail("approver registry %s is not a JSON array" % APPROVER)
    for e in entries:
        approvers.append({
            "key_id": e.get("key_id"),
            "algorithm": e.get("algorithm"),
            "operator": e.get("operator"),
            "enabled": bool(e.get("enabled")),
        })
    approvers.sort(key=lambda d: (d["key_id"] or ""))
else:
    approvers_absent = "no approver registry at %s" % APPROVER

# ── the daemon's own attestation ─────────────────────────────────────
# node_config/1 is minted by the daemon at start under a RESERVED
# artifact type that GATE 1 forbids any socket client from submitting.
# Where one exists it is the authority for build_id and gate posture,
# and this document cites it rather than restating it. Where it does not
# — a daemon predating the feature, as on the home node — that is a
# typed absence and every gate fact drops to 'reported'.
gate = {"attested": False}
if not CHAINDB:
    gate["attestation_absent_reason"] = "the unit passes no -c chain database"
elif not os.path.exists(CHAINDB):
    gate["attestation_absent_reason"] = (
        "chain database %s does not exist" % CHAINDB)
else:
    try:
        db = sqlite3.connect("file:%s?mode=ro" % CHAINDB, uri=True)
        row = db.execute(
            "SELECT e.sequence, e.session_id, e.artifact_id, "
            "       e.artifact_hash, e.timestamp_ns, a.artifact_content "
            "  FROM chain_entries e "
            "  JOIN artifacts a ON a.artifact_id = e.artifact_id "
            "                  AND a.artifact_hash = e.artifact_hash "
            " WHERE e.artifact_type = 'node_config' "
            " ORDER BY e.timestamp_ns DESC LIMIT 1").fetchone()
        db.close()
    except Exception as e:
        fail("chain database %s could not be read: %s" % (CHAINDB, e))
    if row is None:
        gate["attestation_absent_reason"] = (
            "this daemon has never minted a node_config/1 entry — it "
            "predates the feature and cannot attest its own build or "
            "gate posture")
    else:
        seq, sess, aid, ahash, ts_ns, content = row
        try:
            nc = json.loads(content)
        except Exception as e:
            fail("node_config artifact %s is not JSON: %s" % (aid, e))
        gate.update({
            "attested": True,
            "source": "daemon node_config/1",
            "attestation": {
                "artifact_type": "node_config",
                "artifact_id": aid,
                "artifact_hash": ahash,
                "session_id": sess,
                "sequence": seq,
                "recorded_at": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts_ns / 1e9)),
            },
            "build_id": nc.get("build_id"),
            "default_mode": nc.get("gate_default_mode"),
            "max_tier": nc.get("gate_max_tier"),
            "evidence_required": nc.get("evidence_required"),
            "uid_ceilings": nc.get("uid_ceilings"),
            "daemon_node_id": nc.get("node_id"),
        })

if not gate["attested"]:
    gate.update({
        "source": "device config file %s — UNATTESTED" % DEVCFG,
        "build_id": None,
        "default_mode": cfg_gate["default_mode"],
        "max_tier": cfg_gate["max_tier"],
        "evidence_required": cfg_gate["evidence_required"],
        "uid_ceilings": cfg_gate["uid_ceilings"],
    })

# ── facts from the shell half ────────────────────────────────────────
dropins = []
for line in env("DS_DROPINS").splitlines():
    if not line.strip():
        continue
    name, _, sha = line.partition("\t")
    dropins.append({"name": name, "sha256": sha})

node_id = env("DS_NODE_ID_FLAG") or gate.get("daemon_node_id") or ""
if node_id.lower().startswith("0x"):
    node_id = node_id[2:]
node_id = node_id.upper().rjust(8, "0") if node_id else "UNKNOWN"

running, installed = env("DS_RUNNING_SHA"), env("DS_INSTALLED_SHA")
remote_refs = [r for r in env("DS_REMOTE_REFS").split(",") if r]

tree = {
    "path": envn("DS_TREE"),
    "rev": envn("DS_REV"),
    "describe": envn("DS_DESCRIBE"),
    "branch": envn("DS_BRANCH"),
    "dirty": env("DS_DIRTY") == "true",
    "dirty_entries": int(env("DS_DIRTY_N") or 0),
    "remote_refs_containing_head": remote_refs,
    # A LOCAL answer: the checkout matches a ref this node has fetched
    # at some point, not that it matches origin now. The fetch time
    # travels with it so a reader can judge the staleness themselves.
    "matches_known_remote_ref": bool(remote_refs),
    "remote_refs_fetched_at": envn("DS_FETCHED_AT"),
}
if not tree["path"]:
    tree["absent_reason"] = env("DS_TREE_REASON") or "no deploy tree"

doc = {
    "schema": "deployed_state/1",
    "node": {
        "hostname": os.uname().nodename,
        "node_id": node_id,
    },
    "collected": {
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "at_ns": time.time_ns(),
        "by": "deployed-state.sh",
        # null, not "", when the script cannot hash itself — which
        # happens when it is piped in over stdin rather than run from a
        # file. An empty string would read as a hash of nothing.
        "tool_sha256": envn("DS_SELF_SHA"),
    },
    "unit": {
        "name": env("DS_UNIT"),
        "path": env("DS_UNIT_PATH"),
        "sha256": env("DS_UNIT_SHA"),
        "dropins": dropins,
    },
    "daemon": {
        "exec_path": env("DS_DAEMON"),
        "running_exec_path": env("DS_RUNNING_EXE"),
        "installed_sha256": installed,
        "running_sha256": running,
        # Stated outright, never left to a reader to diff two hashes by
        # eye. A node running an older binary than the one on disk is
        # exactly the state that hides a rollback, and it must be
        # impossible to skim past.
        "running_matches_installed": running == installed,
        "pid": int(env("DS_PID")),
        "started_at": env("DS_STARTED"),
    },
    "client": {
        "exec_path": env("DS_CLIENT"),
        "installed_sha256": envn("DS_CLIENT_SHA"),
        "build_id": envn("DS_CLIENT_BUILD"),
    },
    "deploy_tree": tree,
    "device_config": {
        "path": DEVCFG,
        "sha256": env("DS_DEVCFG_SHA"),
        "source": env("DS_DEVCFG_SOURCE"),
        "template_path": envn("DS_TMPL"),
        "template_sha256": envn("DS_TMPL_SHA"),
        "device_count": device_count,
    },
    "gate": gate,
    "socket_allowed_uids": allowed_uids,
    "approvers": approvers,
    "chain": {"db_path": CHAINDB or None},
}
if approvers_absent:
    doc["approvers_absent_reason"] = approvers_absent

# Written whole or not at all: a half-emitted document is worse than a
# loud failure, because it reads exactly like a complete one.
with open(env("DS_OUT"), "w") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
PY

if [ "$OUT" = "-" ]; then
    cat "$tmp"
else
    chmod 0644 "$tmp"
    mv -f "$tmp" "$OUT"
    trap - EXIT
fi
