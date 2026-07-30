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

# Only substitute placeholders the template actually uses, so a node
# without a peer (or without one of the API devices) does not need every
# variable defined. A placeholder left unsubstituted is FATAL: the daemon
# would otherwise authenticate as the literal "${PEER_USER}" and log an
# auth failure that reads like a bad credential rather than a bad render.
# VIRP_UID resolves the daemon's own uid so socket_allowed_uids can be
# expressed portably in the tracked template instead of hardcoding a number
# that differs per host. The loader accepts uids as strings.
if "${VIRP_UID}" in text:
    import pwd
    os.environ.setdefault("VIRP_UID", str(pwd.getpwnam("virp").pw_uid))

# VIRP_BACKUP_UID is the config-backup runbook's dedicated identity
# (virp-lab only — the node2 template does not name it). Resolved the
# same way as VIRP_UID; if the template names it, the user MUST exist,
# so a missing account fails the render (and the daemon start) loudly
# instead of silently shipping an allowlist that rejects the runbook.
if "${VIRP_BACKUP_UID}" in text:
    import pwd
    os.environ.setdefault("VIRP_BACKUP_UID",
                          str(pwd.getpwnam("virp-backup").pw_uid))

for var in ("VIRP_UID", "VIRP_BACKUP_UID", "WAZUH_USER", "WAZUH_PASS",
            "LIBRENMS_TOKEN", "PEER_USER", "PEER_PASS"):
    placeholder = "${%s}" % var
    if placeholder not in text:
        continue
    val = os.environ.get(var)
    if not val:
        print("[render-devices] FATAL: %s not set in autopilot.env" % var,
              file=sys.stderr)
        sys.exit(1)
    text = text.replace(placeholder, json.dumps(val)[1:-1])

import re as _re
leftover = sorted(set(_re.findall(r"\$\{([A-Z_]+)\}", text)))
if leftover:
    print("[render-devices] FATAL: unsubstituted placeholders: %s"
          % ", ".join(leftover), file=sys.stderr)
    sys.exit(1)

json.loads(text)   # must render to valid JSON — fail before the daemon does

with open(out_path, "w") as f:
    f.write(text)
PYEOF

chown root:virp "$OUT"
chmod 0640 "$OUT"
echo "[render-devices] rendered $OUT from $TEMPLATE (secrets from $ENV_FILE, values not logged)"
