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
# LOW:
#   - -n and -W are range-checked instead of cast;
#   - the mock daemon (virp-onode) no longer carries an unreachable device
#     loader or the VIRP_ALLOWED_UIDS environment override.
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

# ---- -n and -W are range-checked (LOW) --------------------------------------
# Both used to go through a bare strtoul() and a cast: unparseable -n became
# node id 0, and -W -1 became a grace window of about 136 years.
for bad in zz 0 0x0A 123456789 ""; do
    out=$("$BIN" -k /nonexistent/onode.key -n "$bad" 2>&1); rc=$?
    if [ "$rc" -ne 0 ] && echo "$out" | grep -q -- '-n '; then
        ok "-n '$bad' is refused"
    else
        bad "-n '$bad' was not refused by the option parser (rc=$rc)"
    fi
done
for bad in -1 0 abc 604801 99999999999 1.5; do
    out=$("$BIN" -k /nonexistent/onode.key -K /nonexistent/prev.key -W "$bad" 2>&1); rc=$?
    if [ "$rc" -ne 0 ] && echo "$out" | grep -q -- '-W '; then
        ok "-W '$bad' is refused"
    else
        bad "-W '$bad' was not refused by the option parser (rc=$rc)"
    fi
done
out=$("$BIN" -k /nonexistent/onode.key -n 0A0000D3 -W 900 2>&1)
if echo "$out" | grep -Eq -- 'FATAL: -[nW] '; then
    bad "a valid -n / -W was refused"
else
    ok "a valid -n and -W pass the option parser"
fi

# ---- the mock daemon carries no dead loader and no env allowlist (LOW) ------
MOCK_SRC="$(dirname "$0")/../src/virp_onode_main.c"
if grep -Eq 'getenv\(|json_object|load_devices_json[[:space:]]*\(' "$MOCK_SRC"; then
    bad "virp_onode_main.c still reads the environment or parses a device file"
else
    ok "virp_onode_main.c has no device-file loader and reads no environment"
fi
MOCK_BIN="$(dirname "$BIN")/virp-onode"
if [ -x "$MOCK_BIN" ]; then
    if "$MOCK_BIN" -h 2>&1 | grep -q -- '-d <path>'; then
        bad "the mock daemon's usage still offers -d"
    else
        ok "the mock daemon's usage no longer offers -d"
    fi
    "$MOCK_BIN" -m -n zz >/dev/null 2>&1; rc=$?
    if [ "$rc" -ne 0 ]; then ok "mock daemon: -n zz is refused"
    else bad "mock daemon: -n zz was accepted"; fi
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
