#!/bin/bash
#
# render-devices.sh — render /run/virp/devices.json from the credential
# env file + the no-secrets template, at virp-onode start.
#
# Runs as root via `ExecStartPre=+` in virp-onode.service (the daemon
# itself runs as the unprivileged `virp` user and only READS the
# rendered file). Secrets never touch persistent storage outside
# /etc/virp/autopilot.env (0600 root), never appear in logs, argv, or
# the shell environment of any other process:
#   - no `set -x`, no echo of values
#   - substitution happens inside python via os.environ
#   - output is 0640 root:virp on the /run tmpfs (gone at shutdown)
#
# Copyright (c) 2026 Third Level IT LLC. All rights reserved.

set -eu

ENV_FILE="/etc/virp/autopilot.env"
TEMPLATE="/etc/virp/devices.template.json"
OUT="/run/virp/devices.json"

umask 027

if [ ! -r "$ENV_FILE" ]; then
    echo "[render-devices] FATAL: $ENV_FILE missing or unreadable" >&2
    exit 1
fi
if [ ! -r "$TEMPLATE" ]; then
    echo "[render-devices] FATAL: $TEMPLATE missing" >&2
    exit 1
fi

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

python3 - "$TEMPLATE" "$OUT" <<'PYEOF'
import json, os, sys

template_path, out_path = sys.argv[1], sys.argv[2]
text = open(template_path).read()

for var in ("WAZUH_USER", "WAZUH_PASS", "LIBRENMS_TOKEN"):
    val = os.environ.get(var)
    if not val:
        print("[render-devices] FATAL: %s not set in autopilot.env" % var,
              file=sys.stderr)
        sys.exit(1)
    text = text.replace("${%s}" % var, json.dumps(val)[1:-1])

json.loads(text)   # must render to valid JSON — fail before the daemon does

with open(out_path, "w") as f:
    f.write(text)
PYEOF

chown root:virp "$OUT"
chmod 0640 "$OUT"
echo "[render-devices] rendered $OUT from $TEMPLATE (secrets from $ENV_FILE, values not logged)"
