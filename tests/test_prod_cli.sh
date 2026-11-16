#!/bin/bash
#
# test_prod_cli.sh — command-line contract of virp-onode-prod that no unit
# test can reach, because it lives in main().
#
# O-Node security review, M21:
#   - a missing -k is FATAL. Without it onode_init() generates an O-Key in
#     memory, so a production node would sign with a key that exists
#     nowhere else and is gone at the next restart.
#   - the usage text no longer claims a key is generated "if the file
#     doesn't exist" (it never was), and documents -O, the observation key
#     that -3 no longer shares with the chain-signing key.
# M26:
#   - main() loads its config with the production loader and does not
#     assign evidence_required afterwards.
#
# Every check here must be answerable by the binary ALONE: no config file,
# no keys, no socket, no root. That is why the -k check sits ahead of the
# options that need privileged files.
#
# usage: test_prod_cli.sh <path-to-virp-onode-prod>
set -u
BIN="${1:?usage: test_prod_cli.sh <virp-onode-prod>}"
fail=0
ok()   { echo "    ok:   $1"; }
bad()  { echo "    FAIL: $1"; fail=1; }

echo
echo "=== virp-onode-prod command-line contract ==="

# ---- a missing -k is fatal, and says why -----------------------------------
out=$("$BIN" -P /nonexistent/policy.json -J /nonexistent/policy.db \
             -d /nonexistent/devices.json 2>&1); rc=$?
if [ "$rc" -ne 0 ] && echo "$out" | grep -q 'requires -k'; then
    ok "no -k: refuses to start and names the missing option"
else
    bad "no -k: expected a fatal error naming -k (rc=$rc)"
fi
if echo "$out" | grep -q 'Generated new O-Key'; then
    bad "no -k: the daemon generated a throwaway O-Key"
else
    ok "no -k: no O-Key was generated"
fi

out=$("$BIN" 2>&1); rc=$?
if [ "$rc" -ne 0 ] && echo "$out" | grep -q 'requires -k'; then
    ok "no arguments at all: the same refusal"
else
    bad "no arguments: expected the -k refusal (rc=$rc)"
fi

# ---- with -k present the NEXT requirement is what is reported --------------
out=$("$BIN" -k /nonexistent/onode.key 2>&1); rc=$?
if [ "$rc" -ne 0 ] && ! echo "$out" | grep -q 'requires -k'; then
    ok "with -k given, the -k refusal does not fire"
else
    bad "with -k given, the daemon still complained about -k (rc=$rc)"
fi

# ---- main() no longer overrules the config (M26) ----------------------------
# "evidence_required": false is refused by the production LOADER
# (load_devices_production — unit-tested in test_onode_review.c). What only
# the source can show is that main() does not force the flag afterwards:
# that override is how a config saying false used to run as true.
SRC="$(dirname "$0")/../src/virp_onode_prod.c"
if grep -Eq 'g_state\.evidence_required[[:space:]]*=' "$SRC"; then
    bad "main() still assigns g_state.evidence_required (the silent override)"
else
    ok "main() does not assign evidence_required after loading the config"
fi
if grep -q 'load_devices_production(&g_state' "$SRC"; then
    ok "main() loads its config through the production loader"
else
    bad "main() does not call load_devices_production()"
fi

# ---- usage text ------------------------------------------------------------
usage=$("$BIN" -h 2>&1)
if echo "$usage" | grep -qi "generates new key"; then
    bad "usage still claims an O-Key is generated"
else
    ok "usage no longer claims an O-Key is generated"
fi
if echo "$usage" | grep -q -- '-k <path>' && echo "$usage" | grep -q 'REQUIRED'; then
    ok "usage marks -k as required"
else
    bad "usage does not mark -k as required"
fi
if echo "$usage" | grep -q -- '-O <path>'; then
    ok "usage documents -O, the observation-signing key"
else
    bad "usage does not document -O"
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== Results: virp-onode-prod command-line contract holds ==="
    echo
    exit 0
fi
echo
echo "=== Results: virp-onode-prod command-line contract FAILED ==="
echo
exit 1
