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

# Paths default to the production ones. They are overridable ONLY so the
# FATAL-on-missing-placeholder behaviour can be exercised against this
# script in a sandbox instead of against a copy of it — a test of a
# transcription of the logic proves nothing about the logic that runs.
# The systemd unit passes no overrides, so production is unchanged.
ENV_FILE="${VIRP_RENDER_ENV_FILE:-/etc/virp/autopilot.env}"
TEMPLATE="${VIRP_RENDER_TEMPLATE:-/etc/virp/devices.template.json}"
OUT="${VIRP_RENDER_OUT:-/run/virp/devices.json}"

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
import json, os, re, sys

template_path, out_path = sys.argv[1], sys.argv[2]
with open(template_path) as f:
    data = json.load(f)   # template must be valid JSON before substitution

PLACEHOLDER_RE = re.compile(r"\$\{([A-Z_]+)\}")

# Keys beginning with "_" (_comment, _ironclaw_fleet_note, ...) are
# annotations for humans, and their values are NEVER rendered: a
# placeholder named there is prose ABOUT a credential, not a request for
# one. Substituting inside comments is how a comment explaining that the
# enable secret must not be loaded came to be rendered WITH the live
# secret in it (pa-850, observed 2026-08-09) — and how a placeholder
# named only in prose came to be demanded from autopilot.env. Annotation
# values pass through byte-for-byte and never make a placeholder "used".
def is_annotation_key(k):
    return isinstance(k, str) and k.startswith("_")

def walk_strings(node, fn):
    """Apply fn to every string outside annotation values — dict KEYS
    included: socket_uid_tier_ceilings maps "${VIRP_NETCLAW_UID}" as a
    key to a tier, so keys substitute (and leftover-check) exactly like
    values. Annotation keys themselves are left untouched."""
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            nk = k
            if isinstance(k, str) and not is_annotation_key(k):
                nk = fn(k)
            out[nk] = v if is_annotation_key(k) else walk_strings(v, fn)
        return out
    if isinstance(node, list):
        return [walk_strings(v, fn) for v in node]
    if isinstance(node, str):
        return fn(node)
    return node

used = set()
def collect(s):
    used.update(PLACEHOLDER_RE.findall(s))
    return s
walk_strings(data, collect)

# Only substitute placeholders the template actually uses, so a node
# without a peer (or without one of the API devices) does not need every
# variable defined. A placeholder left unsubstituted is FATAL: the daemon
# would otherwise authenticate as the literal "${PEER_USER}" and log an
# auth failure that reads like a bad credential rather than a bad render.
# VIRP_UID resolves the daemon's own uid so socket_allowed_uids can be
# expressed portably in the tracked template instead of hardcoding a number
# that differs per host. The loader accepts uids as strings.
if "VIRP_UID" in used:
    import pwd
    os.environ.setdefault("VIRP_UID", str(pwd.getpwnam("virp").pw_uid))

# VIRP_BACKUP_UID is the config-backup runbook's dedicated identity
# (virp-lab only — the node2 template does not name it). Resolved the
# same way as VIRP_UID; if the template names it, the user MUST exist,
# so a missing account fails the render (and the daemon start) loudly
# instead of silently shipping an allowlist that rejects the runbook.
if "VIRP_BACKUP_UID" in used:
    import pwd
    os.environ.setdefault("VIRP_BACKUP_UID",
                          str(pwd.getpwnam("virp-backup").pw_uid))

# VIRP_EVIDENCE_UID is the compliance-evidence collector's dedicated
# identity (virp-lab only). Resolved exactly like VIRP_BACKUP_UID: if the
# template names it the user MUST exist, so a missing account fails the
# render (and the daemon start) loudly instead of silently shipping an
# allowlist that rejects the collector.
if "VIRP_EVIDENCE_UID" in used:
    import pwd
    os.environ.setdefault("VIRP_EVIDENCE_UID",
                          str(pwd.getpwnam("virp-evidence").pw_uid))

# VIRP_NETCLAW_UID is the remote requester identity for netclaw
# (virp-lab only): the sshd child serving netclaw's streamlocal
# forward runs as this uid, so it is what SO_PEERCRED presents.
# Resolved exactly like the uids above: if the template names it the
# account MUST exist, so a missing account fails the render (and the
# daemon start) loudly instead of silently shipping an allowlist that
# rejects the remote requester.
if "VIRP_NETCLAW_UID" in used:
    import pwd
    os.environ.setdefault("VIRP_NETCLAW_UID",
                          str(pwd.getpwnam("virp-netclaw").pw_uid))

# VIRP_BROKER_UID is the Stage 1 intent-broker's dedicated identity
# (virp-lab only; see the template's broker note — Stage 1 is
# otherwise still inert). Same rule: named in the template means the
# account must exist, or the render fails loudly.
if "VIRP_BROKER_UID" in used:
    import pwd
    os.environ.setdefault("VIRP_BROKER_UID",
                          str(pwd.getpwnam("virp-broker").pw_uid))

# VIRP_BRIDGE_UID is the NCFED federation bridge's dedicated identity
# (virp-bridge; netclaw only — the bridge process Nexus's local calls
# go through, and the local peer of netclaw's own O-Node). Resolved
# from the passwd db exactly like the other daemon-principal uids: the
# tracked template names it in socket_allowed_uids, so the account must
# exist or the render fails loudly instead of shipping an allowlist
# that silently drops the bridge.
if "VIRP_BRIDGE_UID" in used:
    import pwd
    os.environ.setdefault("VIRP_BRIDGE_UID",
                          str(pwd.getpwnam("virp-bridge").pw_uid))

for var in ("VIRP_UID", "VIRP_BACKUP_UID", "VIRP_EVIDENCE_UID",
            "VIRP_NETCLAW_UID", "VIRP_BROKER_UID", "VIRP_BRIDGE_UID",
            "WAZUH_USER", "WAZUH_PASS",
            "LIBRENMS_TOKEN", "PEER_USER", "PEER_PASS",
            # Zammad carries TWO tokens because it is TWO device entries
            # on one host: zammad-ro holds a read-only token and names no
            # write operation, zammad-rw holds a write-capable token and
            # names exactly ticket.article.create. Splitting the
            # credential is the point — if one token served both entries,
            # write_ops_allow would be the only thing standing between a
            # read-only path and a write, and a single config slip would
            # remove it.
            "ZAMMAD_RO_TOKEN", "ZAMMAD_RW_TOKEN",
            # PBS: the token SECRET is the only true credential here, but
            # the token id, host, certificate fingerprint and datastore
            # allowlist are required the same way. A missing FINGERPRINT
            # must fail the render rather than render a device the driver
            # will then refuse — the operator should learn about it at
            # deploy time, not from a connect failure.
            "PBS_HOST", "PBS_TOKENID", "PBS_TOKEN",
            "PBS_FINGERPRINT", "PBS_DATASTORES", "PBS_SERVERNAME",
            # cat3850-lab (10.0.10.2): the physical switch authenticates
            # with a password and the driver has no key-auth path, so the
            # credential must reach the rendered devices.json. It is NOT
            # inlined in the tracked template, which is world-readable
            # (0644) — unlike the throwaway "frrlab" lab passwords above
            # it, this is a real operator account on physical hardware.
            "SWITCH_PASS",
            # IronClaw colo fleet (pa-850, ASA-5525, srx-300, R1..R35):
            # ONE shared login password and ONE shared enable secret
            # across the fleet, so the template names two placeholders
            # rather than 38 pairs. They are SEPARATE names for the same
            # reason the Zammad tokens are separate: an entry carrying
            # only ${LAB_PASSWORD} reaches operational mode and no
            # further, and that distinction should be visible in the
            # template rather than implied. A vendor with no enable mode
            # (panos) must name only ${LAB_PASSWORD} — naming ${LAB_ENABLE}
            # on such a row loads a secret into the daemon's address space
            # that no driver will ever read.
            "LAB_PASSWORD", "LAB_ENABLE"):
    if var not in used:
        continue
    val = os.environ.get(var)
    if not val:
        print("[render-devices] FATAL: %s not set in autopilot.env" % var,
              file=sys.stderr)
        sys.exit(1)
    placeholder = "${%s}" % var
    # Substitution happens on parsed string VALUES, so the value needs no
    # JSON escaping here — json.dump below escapes on the way out.
    data = walk_strings(data, lambda s: s.replace(placeholder, val))

leftover = set()
def find_leftover(s):
    leftover.update(PLACEHOLDER_RE.findall(s))
    return s
walk_strings(data, find_leftover)
if leftover:
    print("[render-devices] FATAL: unsubstituted placeholders: %s"
          % ", ".join(sorted(leftover)), file=sys.stderr)
    sys.exit(1)

with open(out_path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PYEOF

if [ -z "${VIRP_RENDER_OUT:-}" ]; then
    chown root:virp "$OUT"
    chmod 0640 "$OUT"
fi
echo "[render-devices] rendered $OUT from $TEMPLATE (secrets from $ENV_FILE, values not logged)"
