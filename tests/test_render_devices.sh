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

# ── IronClaw colo fleet: ${LAB_PASSWORD} / ${LAB_ENABLE} ──────────────
#
# Same contract as the Zammad tokens, asserted separately because these
# are a different pair of names and a tuple entry is easy to add in the
# comment and forget in the code. The panos row is the interesting one:
# PAN-OS has no enable mode, so pa-850 names only ${LAB_PASSWORD} — the
# render must NOT start demanding ${LAB_ENABLE} because other rows use it.
cat > "$T/tmpl.json" <<'EOF'
{ "devices": [
  { "hostname": "pa-850", "host": "198.51.100.10", "vendor": "panos",
    "username": "aiops-svc", "password": "${LAB_PASSWORD}", "port": 22 },
  { "hostname": "ASA-5525", "host": "198.51.100.11", "vendor": "cisco_asa",
    "username": "aiops-svc", "password": "${LAB_PASSWORD}",
    "enable": "${LAB_ENABLE}", "port": 22 },
  { "hostname": "R1", "host": "198.51.100.12", "vendor": "cisco",
    "username": "aiops-svc", "password": "${LAB_PASSWORD}",
    "enable": "${LAB_ENABLE}", "port": 22 }
]}
EOF

printf 'UNRELATED=x\n' > "$T/env"
check "both LAB_* missing -> FATAL" 1 "LAB_PASSWORD not set"

printf 'LAB_PASSWORD=pw-sandbox-value\n' > "$T/env"
check "only LAB_PASSWORD set -> FATAL on LAB_ENABLE" 1 "LAB_ENABLE not set"

printf 'LAB_ENABLE=en-sandbox-value\n' > "$T/env"
check "only LAB_ENABLE set -> FATAL on LAB_PASSWORD" 1 "LAB_PASSWORD not set"

printf 'LAB_PASSWORD=\nLAB_ENABLE=en-sandbox-value\n' > "$T/env"
check "empty LAB_PASSWORD -> FATAL (empty is not 'set')" 1 "LAB_PASSWORD not set"

printf 'LAB_PASSWORD=pw-sandbox-value\nLAB_ENABLE=\n' > "$T/env"
check "empty LAB_ENABLE -> FATAL (empty is not 'set')" 1 "LAB_ENABLE not set"

printf 'LAB_PASSWORD=pw-sandbox-value\nLAB_ENABLE=en-sandbox-value\n' > "$T/env"
check "both set -> renders" 0 "rendered"

# The rendered file must carry the split: the panos row gets the login
# password and NO enable key at all; the enable-capable rows get both, and
# the two credentials must not be the same value.
VIRP_RENDER_ENV_FILE="$T/env" VIRP_RENDER_TEMPLATE="$T/tmpl.json" \
    VIRP_RENDER_OUT="$T/out.json" bash "$SCRIPT" >/dev/null 2>&1
run=$((run + 1)); printf "  [%d] panos row carries no enable; enable rows differ from password ... " "$run"
if python3 - "$T/out.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
by = {x["hostname"]: x for x in d["devices"]}
assert "enable" not in by["pa-850"], "panos row must name no enable"
for h in ("ASA-5525", "R1"):
    assert by[h]["enable"] != by[h]["password"], \
        "%s: enable secret and login password must be distinct credentials" % h
assert by["pa-850"]["password"] == by["R1"]["password"], \
    "fleet shares one login password"
PY
then pass=$((pass + 1)); printf "PASS\n"; else printf "FAIL\n"; fi

# A panos-only template must render without LAB_ENABLE being defined at
# all: the render demands only the placeholders the template NAMES.
cat > "$T/tmpl.json" <<'EOF'
{ "devices": [
  { "hostname": "pa-850", "host": "198.51.100.10", "vendor": "panos",
    "username": "aiops-svc", "password": "${LAB_PASSWORD}", "port": 22 }
]}
EOF
printf 'LAB_PASSWORD=pw-sandbox-value\n' > "$T/env"
check "template naming only LAB_PASSWORD renders without LAB_ENABLE" 0 "rendered"

# A placeholder nobody substitutes must not reach the output.
cat > "$T/tmpl.json" <<'EOF'
{ "devices": [ { "hostname": "x", "api_token": "${NEVER_DECLARED_TOKEN}" } ] }
EOF
printf 'ZAMMAD_RO_TOKEN=a\nZAMMAD_RW_TOKEN=b\n' > "$T/env"
check "undeclared placeholder -> FATAL, never rendered literally" 1 "unsubstituted placeholders"

# ── Annotations: keys beginning with "_" are never rendered ────────────
#
# The bug this pins down: substitution used to run over the raw template
# TEXT, comments included, so the pa-850 _comment explaining that
# ${LAB_ENABLE} must never be loaded rendered WITH the live enable
# secret spelled out in it — and the render DEMANDED LAB_ENABLE from
# autopilot.env although no row named it. Comments are prose: never
# substituted, never scanned for required placeholders, and no secret
# value may ever appear inside one.
cat > "$T/tmpl.json" <<'EOF'
{ "_ironclaw_fleet_note": "fleet shares ${LAB_PASSWORD}; ${LAB_ENABLE} policy note",
  "devices": [
  { "_comment": "no enable mode exists, so ${LAB_ENABLE} must NOT be named on this row",
    "hostname": "pa-850", "host": "198.51.100.10", "vendor": "panos",
    "username": "aiops-svc", "password": "${LAB_PASSWORD}", "port": 22 }
]}
EOF

printf 'LAB_PASSWORD=pw-sandbox-value\n' > "$T/env"
check "placeholder named only in comments -> not demanded" 0 "rendered"

run=$((run + 1)); printf "  [%d] comments pass through unsubstituted; secret lands only in its field ... " "$run"
if python3 - "$T/out.json" <<'PY'
import json, sys
raw = open(sys.argv[1]).read()
d = json.loads(raw)
dev = d["devices"][0]
assert dev["password"] == "pw-sandbox-value"
assert "${LAB_ENABLE}" in dev["_comment"], "comment must keep its literal placeholder"
assert "${LAB_ENABLE}" in d["_ironclaw_fleet_note"]
assert "${LAB_PASSWORD}" in d["_ironclaw_fleet_note"], \
    "no substitution in annotations, even for vars that ARE set"
assert raw.count("pw-sandbox-value") == 1, \
    "the secret may appear exactly once: in the password field"
PY
then pass=$((pass + 1)); printf "PASS\n"; else printf "FAIL\n"; fi

# Placeholders in dict KEYS substitute like values (the live template's
# socket_uid_tier_ceilings maps "${VIRP_NETCLAW_UID}" — a key — to a
# tier; a render that only walks values ships the literal key).
cat > "$T/tmpl.json" <<'EOF'
{ "socket_uid_tier_ceilings": { "${SWITCH_PASS}": "green" },
  "devices": [ { "hostname": "x", "vendor": "linux" } ] }
EOF
printf 'SWITCH_PASS=993\n' > "$T/env"
check "placeholder as a dict key -> substituted" 0 "rendered"
run=$((run + 1)); printf "  [%d] the substituted key is present in the output ... " "$run"
if python3 - "$T/out.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["socket_uid_tier_ceilings"] == {"993": "green"}
PY
then pass=$((pass + 1)); printf "PASS\n"; else printf "FAIL\n"; fi

# Restore the annotations template for the checks below.
cat > "$T/tmpl.json" <<'EOF'
{ "_ironclaw_fleet_note": "fleet shares ${LAB_PASSWORD}; ${LAB_ENABLE} policy note",
  "devices": [
  { "_comment": "no enable mode exists, so ${LAB_ENABLE} must NOT be named on this row",
    "hostname": "pa-850", "host": "198.51.100.10", "vendor": "panos",
    "username": "aiops-svc", "password": "${LAB_PASSWORD}", "port": 22 }
]}
EOF

# Even with the variable defined in the env, a comment naming it must
# not receive the value.
printf 'LAB_PASSWORD=pw-sandbox-value\nLAB_ENABLE=en-secret-value\n' > "$T/env"
VIRP_RENDER_ENV_FILE="$T/env" VIRP_RENDER_TEMPLATE="$T/tmpl.json" \
    VIRP_RENDER_OUT="$T/out.json" bash "$SCRIPT" >/dev/null 2>&1
run=$((run + 1)); printf "  [%d] defined-but-comment-only secret stays out of the render ... " "$run"
if python3 - "$T/out.json" <<'PY'
import json, sys
raw = open(sys.argv[1]).read()
assert "en-secret-value" not in raw, "enable secret leaked into the rendered file"
assert "${LAB_ENABLE}" in json.loads(raw)["devices"][0]["_comment"]
PY
then pass=$((pass + 1)); printf "PASS\n"; else printf "FAIL\n"; fi

# ── a placeholder name containing a DIGIT ────────────────────────────
#
# Regression for a hole found 2026-09-03 while tracking the home node's
# fleet. PLACEHOLDER_RE was [A-Z_]+, so ${VIRP_GNS3_PASSWORD} was
# invisible to BOTH halves of the script: not substituted, and not
# reported by the leftover check either. It would have been written into
# the rendered config verbatim and the daemon would have authenticated
# to 35 routers with the literal string "${VIRP_GNS3_PASSWORD}" — an
# auth failure that reads like a bad credential rather than a bad
# render, which is precisely the failure the FATAL check exists to
# prevent. The guarantee is only ever as wide as the pattern.

cat > "$T/tmpl.json" <<'EOF'
{ "devices": [
  { "hostname": "r1", "host": "10.0.0.55", "vendor": "cisco_ios",
    "password": "${SOME_NAME_WITH_9_DIGITS}" }
]}
EOF
printf 'UNRELATED=x\n' > "$T/env"
# The harness reuses one temp dir, so an earlier PASSING render has left
# an out.json here. Clear it, or the next assertion would pass on a
# stale file rather than on this render's behaviour.
rm -f "$T/out.json"
check "digit-bearing placeholder -> FATAL, not rendered literally" \
      1 "unsubstituted placeholders: SOME_NAME_WITH_9_DIGITS"

run=$((run + 1)); printf "  [%d] ... and no output file was written ... " "$run"
if [ ! -f "$T/out.json" ]; then pass=$((pass + 1)); printf "PASS\n"
else printf "FAIL (a fatal render left a file behind)\n"; fi

echo ""
echo "=== Results: $pass/$run passed ==="
[ "$pass" = "$run" ]
