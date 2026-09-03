#!/bin/bash
#
# check-key-registry.sh — every key_id in deploy/keys/registry.json must
# derive from that entry's own public key bytes.
#
# Copyright (c) 2026 Third Level IT LLC. All rights reserved.
#
# WHY
#
# Two distinct Ed25519 keys both carried the comment 'claude-code@ct211'
# and telling them apart needed a fingerprint sweep across two hosts and
# four containerlab directories. A label is a claim. A key_id derived
# from the bytes is a fact. This check is what makes the registry's ids
# facts rather than a second set of labels — without it, a copy-paste
# slip while adding an entry produces a file that LOOKS authoritative
# and quietly attributes signatures to the wrong key.
#
# It also enforces the two structural invariants that make the file
# usable as a registry at all: key_id is unique, and status is one of
# the two values a verifier knows how to act on.
#
# WHAT IT DOES NOT CHECK
#
# That the registry is COMPLETE. Nothing here can know about a key that
# was never written down — that is the failure mode the registry
# reduces, not one it can detect from inside. Completeness is re-earned
# by sweeping the hosts, which is deployed-state.sh's neighbourhood, not
# this file's.
#
# Reads only. Needs no root, no network, no node.
#
#   --selftest   prove the check can actually fail, against fixtures
#                built in a temp dir. A checker that always passes is
#                indistinguishable from a clean file, which is the
#                failure being fixed one level up.
#
# Exit: 0 clean, 1 a bad entry, 2 usage or unreadable input.
#

set -u

PROG="$(basename "$0")"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGISTRY="$REPO/deploy/keys/registry.json"
SELFTEST=0

while [ $# -gt 0 ]; do
    case "$1" in
        --selftest) SELFTEST=1 ;;
        --registry) shift; REGISTRY="${1:-}" ;;
        -h|--help)
            echo "usage: $PROG [--registry PATH] [--selftest]" >&2; exit 2 ;;
        *) echo "$PROG: unknown argument $1" >&2; exit 2 ;;
    esac
    shift
done

command -v python3 >/dev/null 2>&1 || {
    echo "$PROG: python3 not found" >&2; exit 2; }

verify() {
    KR_FILE="$1" python3 - <<'PY'
import hashlib, json, os, sys

path = os.environ["KR_FILE"]
try:
    with open(path) as f:
        reg = json.load(f)
except Exception as e:
    print("FAIL: %s is unreadable or not JSON: %s" % (path, e))
    sys.exit(2)

keys = reg.get("keys")
if not isinstance(keys, list):
    print("FAIL: %s has no 'keys' array" % path)
    sys.exit(2)
if not keys:
    print("FAIL: %s registers no keys. An empty registry passing green is "
          "the shape of a check that cannot fail." % path)
    sys.exit(2)

VALID_STATUS = {"active", "retired"}
bad = 0
seen = {}

for i, k in enumerate(keys):
    where = k.get("key_id") or "entry %d" % i

    for field in ("key_id", "algorithm", "public_key_hex", "roles",
                  "private_half_host", "valid_from", "status", "note"):
        if field not in k:
            print("FAIL: %s has no '%s'" % (where, field))
            bad += 1

    alg = k.get("algorithm")
    if alg != "ed25519":
        print("FAIL: %s has algorithm %r — this check only knows how to "
              "re-derive ed25519 ids, and passing an algorithm it cannot "
              "check would be the same as not checking it." % (where, alg))
        bad += 1
        continue

    hexs = k.get("public_key_hex", "")
    try:
        raw = bytes.fromhex(hexs)
    except ValueError:
        print("FAIL: %s public_key_hex is not hex" % where)
        bad += 1
        continue
    if len(raw) != 32:
        print("FAIL: %s public_key_hex is %d bytes, not the 32 of a raw "
              "ed25519 public key. A DER SPKI, an ssh wire blob or a "
              "minisign blob wraps those 32 bytes; the registry stores "
              "the bytes themselves, because those are what the id is "
              "taken over." % (where, len(raw)))
        bad += 1
        continue

    derived = hashlib.sha256(raw).hexdigest()[:32]
    declared = k.get("key_id")
    if derived != declared:
        print("FAIL: %s DOES NOT DERIVE FROM ITS OWN PUBLIC KEY" % where)
        print("        declared %s" % declared)
        print("        derived  %s   (sha256(public_key_hex)[0:16])" % derived)
        bad += 1
        continue

    if declared in seen:
        print("FAIL: key_id %s appears twice (entries %d and %d). key_id is "
              "this registry's primary key; a duplicate means either the "
              "same key registered under two roles — which belongs in one "
              "entry with a roles list — or a genuine collision, which "
              "would be a finding about sha256." % (declared, seen[declared], i))
        bad += 1
    seen[declared] = i

    if k.get("status") not in VALID_STATUS:
        print("FAIL: %s has status %r, not one of %s"
              % (where, k.get("status"), sorted(VALID_STATUS)))
        bad += 1

    roles = k.get("roles")
    if not isinstance(roles, list) or not roles:
        print("FAIL: %s roles must be a non-empty list" % where)
        bad += 1

    for field in ("private_half_host", "note"):
        v = k.get(field)
        if not isinstance(v, str) or not v.strip():
            print("FAIL: %s has an empty %s. 'unknown' or 'LOST' is an "
                  "answer; blank is not." % (where, field))
            bad += 1

if bad:
    print()
    print("FAIL: %d problem(s) in %d entr(ies)" % (bad, len(keys)))
    sys.exit(1)

n_active = sum(1 for k in keys if k["status"] == "active")
print("  PASS: %d key(s), every key_id re-derived from its own public key "
      "bytes" % len(keys))
print("        %d active, %d retired, 0 duplicate ids"
      % (n_active, len(keys) - n_active))
sys.exit(0)
PY
}

# ── self-test ─────────────────────────────────────────────────────────
if [ "$SELFTEST" = "1" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    fails=0

    mk() { # mk <file> <python-mutation>
        KR_SRC="$REGISTRY" KR_OUT="$tmp/$1" KR_MUT="$2" python3 - <<'PY'
import json, os
reg = json.load(open(os.environ["KR_SRC"]))
exec(os.environ["KR_MUT"])
json.dump(reg, open(os.environ["KR_OUT"], "w"), indent=2)
PY
    }

    expect_fail() { # expect_fail <file> <label>
        if verify "$tmp/$1" >/dev/null 2>&1; then
            echo "  SELFTEST FAIL: $2 was accepted — the check cannot fail here"
            fails=$((fails + 1))
        else
            echo "  selftest ok: $2 rejected"
        fi
    }

    echo "=== self-testing the key registry check ==="

    # A key_id that does not match its bytes: one hex digit changed.
    mk mutated-id.json 'k=reg["keys"][0]; k["key_id"]=("f" if k["key_id"][0]!="f" else "0")+k["key_id"][1:]'
    expect_fail mutated-id.json "a key_id that does not derive from its bytes"

    # The same key registered twice under different roles.
    mk duplicate.json 'import copy; d=copy.deepcopy(reg["keys"][0]); d["roles"]=["deploy"]; reg["keys"].append(d)'
    expect_fail duplicate.json "a duplicated key_id"

    # Public key bytes swapped between two entries: both ids now wrong.
    mk swapped.json 'a,b=reg["keys"][0],reg["keys"][1]; a["public_key_hex"],b["public_key_hex"]=b["public_key_hex"],a["public_key_hex"]'
    expect_fail swapped.json "public key bytes swapped between two entries"

    # A DER SPKI where the raw key belongs — the encoding mistake most
    # likely to be made by hand, since approvers.json stores keys that way.
    mk der.json 'reg["keys"][0]["public_key_hex"]="302a300506032b6570032100"+reg["keys"][0]["public_key_hex"]'
    expect_fail der.json "a DER-wrapped key where raw bytes belong"

    mk badstatus.json 'reg["keys"][0]["status"]="probably fine"'
    expect_fail badstatus.json "a status outside {active, retired}"

    mk blanknote.json 'reg["keys"][0]["private_half_host"]="   "'
    expect_fail blanknote.json "a blank private_half_host"

    mk empty.json 'reg["keys"]=[]'
    expect_fail empty.json "an empty registry"

    if [ "$fails" -gt 0 ]; then
        echo "SELFTEST FAILED: $fails case(s) the checker did not catch"
        exit 1
    fi
    echo "  selftest passed: the check can fail"
    echo
fi

echo "=== checking $REGISTRY ==="
[ -r "$REGISTRY" ] || { echo "FAIL: cannot read $REGISTRY"; exit 2; }
verify "$REGISTRY"
