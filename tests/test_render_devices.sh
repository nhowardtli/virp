#!/bin/bash
#
# test_render_devices.sh — deploy/render-devices.sh must FAIL LOUDLY when
# a placeholder the template names is absent from autopilot.env.
#
# Why this is a test and not a code comment: the render is the only thing
# standing between "an operator forgot a credential" and "the daemon
# starts with the literal string ${ZAMMAD_RW_TOKEN} as a bearer token and
# logs an auth failure that reads like a bad credential rather than a bad
# deploy". The script has always claimed to be fatal there; nothing
# asserted it.
#
# Runs the REAL script, with its paths pointed at a sandbox through the
# VIRP_RENDER_* overrides, rather than re-implementing its logic here.
# A test of a transcription proves nothing about the code that runs.
#
# Originates no network contact and touches nothing outside its temp dir:
# in particular it never reads /etc/virp/autopilot.env and never writes
# /run/virp/devices.json.
#
# Copyright (c) 2026 Third Level IT LLC. All rights reserved.

set -u

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/deploy/render-devices.sh"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

run=0
pass=0
check() {   # check <name> <expected-rc> <expected-substring>
    run=$((run + 1))
    printf "  [%d] %s ... " "$run" "$1"
    out="$(VIRP_RENDER_ENV_FILE="$T/env" VIRP_RENDER_TEMPLATE="$T/tmpl.json" \
           VIRP_RENDER_OUT="$T/out.json" bash "$SCRIPT" 2>&1)"
    rc=$?
    if [ "$rc" != "$2" ]; then
        printf "FAIL (rc=%s, expected %s)\n%s\n" "$rc" "$2" "$out"; return
    fi
    if [ -n "$3" ] && ! printf '%s' "$out" | grep -q -- "$3"; then
        printf "FAIL (output missing '%s')\n%s\n" "$3" "$out"; return
    fi
    pass=$((pass + 1)); printf "PASS\n"
}

echo "=== render-devices.sh — missing placeholders are FATAL ==="

cat > "$T/tmpl.json" <<'EOF'
{ "devices": [
  { "hostname": "zammad-ro", "host": "10.0.40.20", "vendor": "zammad",
    "api_token": "${ZAMMAD_RO_TOKEN}" },
  { "hostname": "zammad-rw", "host": "10.0.40.20", "vendor": "zammad",
    "api_token": "${ZAMMAD_RW_TOKEN}",
    "write_ops_allow": "ticket.article.create" }
]}
EOF

printf 'UNRELATED=x\n' > "$T/env"
check "both Zammad tokens missing -> FATAL" 1 "ZAMMAD_RO_TOKEN not set"

printf 'ZAMMAD_RO_TOKEN=ro-sandbox-value\n' > "$T/env"
check "only the RO token set -> FATAL on the RW one" 1 "ZAMMAD_RW_TOKEN not set"

printf 'ZAMMAD_RW_TOKEN=rw-sandbox-value\n' > "$T/env"
check "only the RW token set -> FATAL on the RO one" 1 "ZAMMAD_RO_TOKEN not set"

printf 'ZAMMAD_RO_TOKEN=ro-sandbox-value\nZAMMAD_RW_TOKEN=rw-sandbox-value\n' > "$T/env"
check "both set -> renders" 0 "rendered"

# An empty value is as fatal as an absent one: an empty bearer token is
# not a degraded credential, it is a different request.
printf 'ZAMMAD_RO_TOKEN=\nZAMMAD_RW_TOKEN=rw-sandbox-value\n' > "$T/env"
check "empty RO token -> FATAL (empty is not 'set')" 1 "ZAMMAD_RO_TOKEN not set"

# The rendered file must actually carry the split: only the rw entry may
# name a write operation.
printf 'ZAMMAD_RO_TOKEN=ro-sandbox-value\nZAMMAD_RW_TOKEN=rw-sandbox-value\n' > "$T/env"
VIRP_RENDER_ENV_FILE="$T/env" VIRP_RENDER_TEMPLATE="$T/tmpl.json" \
    VIRP_RENDER_OUT="$T/out.json" bash "$SCRIPT" >/dev/null 2>&1
run=$((run + 1)); printf "  [%d] only the rw entry carries write_ops_allow ... " "$run"
if python3 - "$T/out.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
by = {x["hostname"]: x for x in d["devices"]}
assert "write_ops_allow" not in by["zammad-ro"], "ro entry must name no write op"
assert by["zammad-rw"]["write_ops_allow"] == "ticket.article.create"
assert by["zammad-ro"]["api_token"] != by["zammad-rw"]["api_token"], \
    "the two entries must not share a token"
PY
then pass=$((pass + 1)); printf "PASS\n"; else printf "FAIL\n"; fi

# A placeholder nobody substitutes must not reach the output.
cat > "$T/tmpl.json" <<'EOF'
{ "devices": [ { "hostname": "x", "api_token": "${NEVER_DECLARED_TOKEN}" } ] }
EOF
printf 'ZAMMAD_RO_TOKEN=a\nZAMMAD_RW_TOKEN=b\n' > "$T/env"
check "undeclared placeholder -> FATAL, never rendered literally" 1 "unsubstituted placeholders"

echo ""
echo "=== Results: $pass/$run passed ==="
[ "$pass" = "$run" ]
