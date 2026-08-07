#!/usr/bin/env python3
"""
virp_evidence.py — scheduled compliance-evidence collector.

A NO-AI, READ-ONLY automation. For each target device it collects a
defined SET of evidence items; each item is one named read-only command
whose signed output is the evidence for a control. Every result goes
through the VIRP gate as a GREEN read, is O-Key signed by the daemon,
and is chain-registered. Nothing is ever written to a device.

Identity model (enforced at runtime, not assumed from deployment) —
the same contract virp-backup runs under (see virp_config_backup.py):
  - Runs as `virp-evidence`, a dedicated system account that is a
    member of NO key or credential group, and of no group but its own.
    It is NOT root, NOT the daemon user `virp`, and NOT `virp-backup`:
    each automation gets its own identity so one runbook's reach is
    never another's.
  - Before doing anything else, main() PROVES it cannot read the O-Key,
    the chain key, the approver SECRET key, or either credential store
    (autopilot.env, the rendered devices.json). If any of them opens,
    the collector refuses to start (exit 3).
  - It holds no approver key, is not in the approver registry, cannot
    read the approvals store, and contains no approval code path. Its
    entire action vocabulary is `execute` and `chain_append` — pinned
    by test. It is structurally unable to approve anything.
  - Holding no O-Key it cannot verify observation HMACs itself, so it
    stores the raw signed observation bytes and lets a key holder
    verify them later. Under symmetric HMAC signer and verifier are
    inseparable; the least-privilege client is the one that stores
    evidence rather than pretending to check it. `virp-evidence-report`
    is that key holder: it re-verifies every signature and hash at
    render time.

READ-ONLY, structurally:
  - The item list is DATA (evidence-items.json), so adding an item is a
    config edit. Because that file is operator-editable, the collector
    re-derives the linux driver's GREEN row locally and REFUSES to
    submit any command that is not exactly `vtysh -c "show <rest>"`
    with rest limited to [a-z0-9 ./-]. A bad edit cannot turn this into
    a mutation tool: the collector will not even ask. The gate stays the
    authority — this guard only bounds what is ever submitted.
  - Every returned observation is checked to be GREEN DEVICE_OUTPUT.
    A YELLOW/RED tier or an error observation is an alert, never
    silently stored as if it were evidence.

Control mapping is OPERATOR-SUPPLIED (controls.json) and is never
asserted by this tool. An item with no mapping is collected anyway and
flagged `unmapped` — evidence is never dropped for want of a mapping.

Exit codes: 0 clean, 1 one or more alerts (systemd failed-unit signal,
same convention as the autopilot and the backup runbook), 3 identity
check refused to start.

Copyright (c) 2026 Third Level IT LLC. All rights reserved.
"""

import argparse
import base64
import grp
import hashlib
import json
import os
import pwd
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from virp_autopilot import (  # noqa: E402
    OBS_DEVICE_OUTPUT, load_node_config, onode_send, parse_observation,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── Paths / policy constants ───────────────────────────────────────────

EVIDENCE_ROOT = "/var/lib/virp/evidence"
ALERTS_FILE = os.path.join(EVIDENCE_ROOT, "alerts.jsonl")

# Operator-editable data files. /etc/virp is the deployed location; the
# tracked copy under deploy/ is the fallback so a fresh checkout runs.
# Whichever is used is RECORDED (path + sha256) in every result, so a
# report always names the mapping it was produced from.
ITEMS_PATHS = ("/etc/virp/evidence-items.json",
               os.path.join(REPO_ROOT, "deploy", "evidence-items.json"))
CONTROLS_PATHS = ("/etc/virp/controls.json",
                  os.path.join(REPO_ROOT, "deploy", "controls.json"))

# Material this identity must NOT be able to read. If ANY of these opens
# the collector refuses to start (exit 3). approvers.json is deliberately
# absent: it holds public keys only.
SECRET_PATHS = (
    "/etc/virp/keys/onode.key",      # O-Key (symmetric HMAC signer)
    "/etc/virp/keys/chain.key",      # chain HMAC key
    "/etc/virp/keys/approval.key",   # approver SECRET key (operator-only)
    "/etc/virp/autopilot.env",       # device API credentials
    "/run/virp/devices.json",        # rendered device credentials
)

# Accounts this collector must never run as: root, the daemon's own
# service account (which owns the keys), and the OTHER runbook identity
# (whose reach is its own — automations do not share identities).
FORBIDDEN_USERS = ("virp", "virp-backup")
# Groups whose membership grants credential, chain-key, or another
# runbook's evidence-tree reach.
FORBIDDEN_GROUPS = ("virp", "virp-backup")

# The daemon's request buffer is 1024 bytes (virp_onode.c req.command).
MAX_COMMAND_LEN = 900

# ── The GREEN-form guard ───────────────────────────────────────────────
# A local re-derivation of the GREEN row in src/drivers/driver_linux.c
# (linux_gate_classify). This is NOT a second gate — the daemon's
# classifier is the only authority on tier. It is a submission bound:
# because evidence-items.json is operator-editable, the collector must
# be unable to ASK for anything outside its read-only mandate, however
# the file is edited.
#
# Mirrors the C exactly:
#   1. virp_command_check_separators: ; | & ` $( ${ and any control byte
#      are refused anywhere, quoted or not.
#   2. Anchored form: exactly `vtysh -c "<arg>"` — one -c, one quoted
#      argument, the closing quote last, nothing before or after. Two -c
#      flags cannot survive the anchor.
#   3. Whitespace runs collapse and matching is case-insensitive, but
#      abbreviations are NOT expanded: "sh ip os nei" is not "show ...".
#   4. GREEN row: show <rest>, rest limited to [a-z0-9 ./-].

ILLEGAL_SEPARATOR = re.compile(r'[;|&`]|\$[({]|[\x00-\x1f\x7f]')
GREEN_FORM = re.compile(r'^vtysh -c "show( [a-z0-9 ./-]*)?"$')


class NotAReadOnlyCommand(Exception):
    """An item's command is outside the collector's read-only mandate."""


def canonicalize(command):
    """Collapse whitespace runs, trim, lowercase — linux_gate_canon()."""
    return " ".join(command.split()).lower()


def assert_green_form(command):
    """Raise NotAReadOnlyCommand unless `command` is a GREEN vtysh read.

    Returns the canonicalized form on success."""
    if not command or not command.strip():
        raise NotAReadOnlyCommand("empty command")
    if len(command) > MAX_COMMAND_LEN:
        raise NotAReadOnlyCommand(
            "command is %d chars (daemon request limit %d)"
            % (len(command), MAX_COMMAND_LEN))
    m = ILLEGAL_SEPARATOR.search(command)
    if m:
        raise NotAReadOnlyCommand(
            "contains %r — shell metacharacters are refused everywhere, "
            "quoted or not" % m.group(0))
    canon = canonicalize(command)
    if not GREEN_FORM.match(canon):
        raise NotAReadOnlyCommand(
            "not a GREEN read: this collector submits only "
            'vtysh -c "show <rest>" with rest limited to [a-z0-9 ./-]; '
            "got %r" % command)
    return canon


# ── Identity check ─────────────────────────────────────────────────────


def identity_problems(secret_paths=None, euid=None, gids=None):
    """Return the list of reasons this process must NOT run. Empty list
    means the least-privilege contract holds. Pure-ish (paths and ids
    injectable) so tests can exercise every refusal. Defaults resolve at
    call time from the module globals — an import-time default here
    would make a test's rebinding of SECRET_PATHS invisible to main()'s
    bare identity_problems() call."""
    if secret_paths is None:
        secret_paths = SECRET_PATHS
    problems = []
    euid = os.geteuid() if euid is None else euid
    if euid == 0:
        problems.append("running as root (uid 0)")
    for name in FORBIDDEN_USERS:
        try:
            if euid == pwd.getpwnam(name).pw_uid:
                problems.append(
                    "running as another VIRP identity '%s'" % name)
        except KeyError:
            pass
    gids = (os.getgroups() + [os.getegid()]) if gids is None else gids
    for name in FORBIDDEN_GROUPS:
        try:
            if grp.getgrnam(name).gr_gid in gids:
                problems.append(
                    "member of group '%s' (credential/chain reach)" % name)
        except KeyError:
            pass
    for path in secret_paths:
        try:
            with open(path, "rb") as f:
                f.read(1)
            problems.append("can read key/credential material: %s" % path)
        except OSError:
            pass  # unreadable or absent — exactly what we require
    return problems


# ── Item / control loading ─────────────────────────────────────────────


class ConfigError(Exception):
    """The item set or control mapping cannot be used as written."""


def _load_json_first(paths):
    """Load the first readable file from `paths`. Returns
    (data, path, sha256). Raises ConfigError if none opens."""
    tried = []
    for path in paths:
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except OSError as e:
            tried.append("%s (%s)" % (path, e.strerror or e))
            continue
        try:
            return (json.loads(raw.decode("utf-8")), path,
                    hashlib.sha256(raw).hexdigest())
        except (ValueError, UnicodeDecodeError) as e:
            raise ConfigError("%s is not valid JSON: %s" % (path, e))
    raise ConfigError("no readable file among: %s" % ", ".join(tried))


def load_items(paths=ITEMS_PATHS):
    """Load and VALIDATE the evidence item set.

    Every command is checked against the GREEN-form guard here, at load
    time, before any device is contacted — a bad edit fails the whole
    run loudly instead of being discovered item by item mid-collection.
    """
    data, path, sha = _load_json_first(paths)
    items = data.get("items")
    if not isinstance(items, list) or not items:
        raise ConfigError("%s defines no items" % path)
    seen = set()
    out = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise ConfigError("%s item %d is not an object" % (path, i))
        name = item.get("name")
        command = item.get("command")
        if not name or not isinstance(name, str):
            raise ConfigError("%s item %d has no name" % (path, i))
        if name in seen:
            raise ConfigError("%s defines item %r twice" % (path, name))
        seen.add(name)
        if not command or not isinstance(command, str):
            raise ConfigError("%s item %r has no command" % (path, name))
        try:
            assert_green_form(command)
        except NotAReadOnlyCommand as e:
            raise ConfigError("%s item %r: %s" % (path, name, e))
        out.append({
            "name": name,
            "title": item.get("title") or name,
            "command": command,
            "proves": item.get("proves") or "",
            "does_not_prove": item.get("does_not_prove") or "",
            "evidence_gap": item.get("evidence_gap") or None,
        })
    return out, path, sha


def load_controls(paths=CONTROLS_PATHS):
    """Load the operator-supplied control mapping. A MISSING mapping file
    is not fatal: every item then collects as `unmapped`, which is the
    documented behaviour — evidence is never dropped for want of a
    mapping. Returns (mapping, framework, path, sha256)."""
    try:
        data, path, sha = _load_json_first(paths)
    except ConfigError as e:
        return {}, "(no mapping file)", "(none: %s)" % e, ""
    controls = data.get("controls")
    if not isinstance(controls, dict):
        raise ConfigError("%s has no 'controls' object" % path)
    return controls, data.get("framework") or "(unnamed)", path, sha


def control_for(item_name, controls):
    """Return (control_ref_or_None, mapping_status)."""
    ref = controls.get(item_name)
    if not isinstance(ref, dict) or not ref.get("control_id"):
        return None, "unmapped"
    return ({"control_id": ref["control_id"],
             "control_description": ref.get("control_description") or "",
             "framework": ref.get("framework") or ""}, "mapped")


# ── Gate / chain plumbing ──────────────────────────────────────────────


def gate_execute(device, command, send=onode_send):
    raw = send({"action": "execute", "device": device, "command": command})
    return raw, parse_observation(raw)


def chain_register(session_id, artifact_type, artifact_id, body_bytes,
                   send=onode_send):
    """Ask the DAEMON to append a chain entry committing to body_bytes.
    Returns (ok, signed_receipt_bytes, stored_body). Bodies at or past
    the daemon's 8192-byte artifact field would be stored truncated
    (unverifiable), so those register commitment-only."""
    h = hashlib.sha256(body_bytes).hexdigest()
    if artifact_type == "observation":
        content = "base64:" + base64.b64encode(body_bytes).decode()
    else:
        content = body_bytes.decode("utf-8")
    stored_body = len(content) < 8192
    if artifact_type == "observation" and not stored_body:
        # Since the 2026-08-07 re-cut the daemon refuses a body-less
        # "observation" — verified is what that type means. An oversized
        # body registers commitment-only as "external_digest", the type
        # whose name admits the daemon could not verify it.
        artifact_type = "external_digest"
    req = {
        "action": "chain_append",
        "session_id": session_id,
        "artifact_type": artifact_type,
        "artifact_id": artifact_id,
        "artifact_hash": h,
    }
    if stored_body:
        req["artifact_content"] = content
    resp = send(req)
    ok = len(resp) != 4
    return ok, (resp if ok else b""), stored_body


# ── Alerting (journal + local JSONL; log-only by policy) ───────────────


def emit_alert(kind, detail, sink_file=ALERTS_FILE):
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "kind": kind, "detail": detail}
    print("[ALERT] %s: %s" % (kind, detail), file=sys.stderr)
    try:
        os.makedirs(os.path.dirname(sink_file), mode=0o700, exist_ok=True)
        with open(sink_file, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError as e:
        print("[ALERT-SINK-ERROR] %s" % e, file=sys.stderr)
    return rec


# ── Device output handling ─────────────────────────────────────────────


def strip_echo(payload, device, command):
    """The linux driver prefixes every exec result with '<hostname>$
    <command>\\n' (driver_linux.c linux_execute). Remove exactly that
    line so the stored evidence is the device's answer, not our own
    question echoed back."""
    if not payload:
        return ""
    prefix = "%s$ %s\n" % (device, command)
    if payload.startswith(prefix):
        return payload[len(prefix):]
    # Fall back to dropping a first line of the '<device>$ ...' shape.
    first, sep, rest = payload.partition("\n")
    if sep and first.startswith("%s$ " % device):
        return rest
    return payload


# FRR answers an unrecognised command on stdout with a '%' diagnostic and
# still exits successfully, so the GATE sees an ordinary GREEN read and
# the daemon signs it. The signature is valid — the OUTPUT just is not
# evidence of anything. Detect it here or the report would render
# "% Unknown command" as a satisfied control.
DEVICE_DIAGNOSTIC = re.compile(r"^%\s*(unknown command|command incomplete|"
                               r"ambiguous command|incomplete command)",
                               re.IGNORECASE)


def classify_output(text):
    """Return (collection_status, note). The output is stored either way
    — this only labels what was actually received."""
    stripped = (text or "").strip()
    if not stripped:
        return "empty_output", ("the device returned no output for this "
                                "read; nothing was observed to evidence "
                                "the control")
    first = stripped.splitlines()[0].strip()
    if DEVICE_DIAGNOSTIC.match(first):
        return "device_rejected_command", (
            "the device did not recognise this command and answered with a "
            "diagnostic (%r); the observation is validly signed but its "
            "content evidences nothing — fix the command in "
            "evidence-items.json" % first[:120])
    if first.startswith("%"):
        return "device_diagnostic", (
            "the device answered with a diagnostic line (%r) rather than "
            "command output" % first[:120])
    return "ok", ""


# ── Per-item collection ────────────────────────────────────────────────


def collect_item(device, item, session_id, controls, provenance,
                 run_dir, send=onode_send, alerts_file=ALERTS_FILE,
                 now=None):
    """Collect ONE evidence item from ONE device. Returns a result record.

    Never raises for a device- or gate-level problem: every failure mode
    becomes a recorded, alerted result so a bad item cannot silently
    vanish from the evidence set."""
    now = now if now is not None else time.time()
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))
    name = item["name"]
    command = item["command"]
    control, mapping_status = control_for(name, controls)

    rec = {"device": device, "item": name, "ts": ts,
           "collection_method": command, "mapping_status": mapping_status,
           "control_id": control["control_id"] if control else None,
           "status": None, "alerts": []}

    def alert(kind, detail):
        """Alert AND record that this result alerted. The run's exit code
        is derived from this list, not re-inferred from `status`: a chain
        registration that failed leaves status 'ok' (the READ succeeded)
        and would otherwise exit 0 while the evidence never made it into
        the chain."""
        rec["alerts"].append(kind)
        emit_alert(kind, detail, alerts_file)

    # Belt over braces: the item set was validated at load, but never
    # submit a command that has not been re-checked immediately before
    # it goes to the gate.
    try:
        assert_green_form(command)
    except NotAReadOnlyCommand as e:
        rec["status"] = "refused_locally"
        alert("command_refused_locally",
                   {"device": device, "item": name, "command": command,
                    "error": str(e)})
        return rec

    try:
        raw, obs = gate_execute(device, command, send=send)
    except (OSError, IOError) as e:
        rec["status"] = "gate_error"
        alert("gate_error", {"device": device, "item": name,
                                  "error": str(e)})
        return rec

    if "error_code" in obs or obs.get("obs_type") != OBS_DEVICE_OUTPUT:
        rec["status"] = "gate_error"
        alert("gate_error",
              {"device": device, "item": name,
               "error_code": obs.get("error_code"),
               "obs_type": obs.get("obs_type"),
               "payload": (obs.get("payload") or "")[:300]})
        return rec

    tier = obs.get("tier_name")
    if tier != "GREEN":
        # The gate executed something this collector is only ever allowed
        # to submit as a GREEN read. Say so loudly: that is a gate or
        # classifier problem, not a collection success.
        rec["status"] = "non_green_tier"
        alert("non_green_tier",
              {"device": device, "item": name, "command": command,
               "tier": tier,
               "note": "a read-only collector must never receive a "
                       "non-GREEN observation"})
        return rec

    output = strip_echo(obs.get("payload") or "", device, command)
    collection_status, note = classify_output(output)
    rec["status"] = collection_status
    rec["output_sha256"] = hashlib.sha256(output.encode()).hexdigest()

    # 1. Chain-register the SIGNED OBSERVATION (the daemon writes the
    #    entry and returns a signed CHAIN_ENTRY receipt). artifact_id
    #    keeps the canonical obs:<device>:<nanos> shape so the existing
    #    verifier's device extraction works unchanged.
    obs_id = "obs:%s:%d" % (device, int(now * 1e9))
    ok, receipt, stored = chain_register(session_id, "observation", obs_id,
                                         raw, send=send)
    rec["obs_artifact_id"] = obs_id if ok else None
    rec["obs_body_stored"] = stored
    if not ok:
        alert("chain_register_failed",
              {"device": device, "item": name, "artifact_id": obs_id})

    # 2. Chain-register the EVIDENCE RECORD: the metadata that makes the
    #    signed bytes mean something — item, device, timestamp, the exact
    #    command run, the control reference, and the honest caveats. The
    #    report renders from THIS body, so the caveats are bound to the
    #    entry by artifact_hash and cannot drift from the evidence.
    ev_id = "evidence:%s:%s:%d" % (device, name, int(now * 1e9))
    body_obj = {
        "schema": "evidence_item/1",
        "item": name,
        "title": item["title"],
        "device": device,
        "ts": ts,
        "collection_method": command,
        "tier": tier,
        "collection_status": collection_status,
        "collection_note": note,
        "output_sha256": rec["output_sha256"],
        "output_bytes": len(output.encode()),
        "observation": rec["obs_artifact_id"],
        "obs_body_stored": stored,
        "mapping_status": mapping_status,
        "control": control,
        "proves": item["proves"],
        "does_not_prove": item["does_not_prove"],
        "evidence_gap": item["evidence_gap"],
        "items_source": provenance["items_source"],
        "items_sha256": provenance["items_sha256"],
        "controls_source": provenance["controls_source"],
        "controls_sha256": provenance["controls_sha256"],
        "signature_verified_here": False,
        "signature_note": ("this identity holds no O-Key by design; the "
                           "observation HMAC is re-verified at render time "
                           "by virp-evidence-report, which runs as a key "
                           "holder"),
    }
    body = json.dumps(body_obj, sort_keys=True).encode()
    ok2, receipt2, stored2 = chain_register(session_id, "evidence_item",
                                            ev_id, body, send=send)
    rec["evidence_artifact_id"] = ev_id if ok2 else None
    if not ok2:
        alert("chain_register_failed",
              {"device": device, "item": name, "artifact_id": ev_id})

    # 3. Store locally: the record, plus the raw signed bytes for any key
    #    holder to verify independently of the chain.
    ddir = os.path.join(run_dir, device)
    os.makedirs(ddir, mode=0o700, exist_ok=True)
    meta = dict(body_obj,
                session_id=session_id,
                evidence_artifact_id=rec["evidence_artifact_id"],
                signed_observation_b64=base64.b64encode(raw).decode(),
                chain_receipt_b64=base64.b64encode(receipt).decode(),
                evidence_receipt_b64=base64.b64encode(receipt2).decode(),
                output=output)
    with open(os.path.join(ddir, "%s.json" % name), "w") as f:
        json.dump(meta, f, indent=1, sort_keys=True)
        f.write("\n")
    rec["stored"] = os.path.join(ddir, "%s.json" % name)

    # Alerts: an item that did not actually observe anything, and an item
    # nobody has mapped yet, are both operator to-dos and must surface.
    if collection_status != "ok":
        alert("collection_" + collection_status,
              {"device": device, "item": name, "command": command,
               "note": note})
    if mapping_status == "unmapped":
        alert("unmapped_item",
              {"device": device, "item": name,
               "controls_source": provenance["controls_source"],
               "note": ("collected, signed and chain-registered as usual, "
                        "and reported under UNMAPPED; add a mapping for %r "
                        "to clear this" % name)})
    return rec


# ── Run ────────────────────────────────────────────────────────────────


def run(root=None, send=onode_send, alerts_file=None,
        items_paths=ITEMS_PATHS, controls_paths=CONTROLS_PATHS,
        devices=None, now=None):
    """One full collection cycle: every item on every device. root and
    alerts_file resolve at call time (see identity_problems) so tests
    can point the whole evidence tree somewhere disposable."""
    if root is None:
        root = EVIDENCE_ROOT
    if alerts_file is None:
        alerts_file = ALERTS_FILE
    now = now if now is not None else time.time()
    run_ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))
    session_id = "evidence:%s" % time.strftime("%Y-%m-%d", time.gmtime(now))

    try:
        items, items_src, items_sha = load_items(items_paths)
        controls, framework, ctl_src, ctl_sha = load_controls(controls_paths)
    except ConfigError as e:
        emit_alert("config_error", {"error": str(e)}, alerts_file)
        return 1

    provenance = {"items_source": items_src, "items_sha256": items_sha,
                  "controls_source": ctl_src, "controls_sha256": ctl_sha,
                  "framework": framework}

    if devices is None:
        devices = load_node_config().get("frr_nodes") or []
    if not devices:
        emit_alert("config_error", {"error": "no frr_nodes configured"},
                   alerts_file)
        return 1

    run_dir = os.path.join(root, run_ts)
    os.makedirs(run_dir, mode=0o700, exist_ok=True)

    results = []
    alerts = 0
    for device in devices:
        for item in items:
            rec = collect_item(device, item, session_id, controls,
                               provenance, run_dir, send=send,
                               alerts_file=alerts_file)
            print(json.dumps(rec, sort_keys=True))
            results.append(rec)
            # Derived from what actually alerted, not re-inferred from
            # `status`: a failed chain registration leaves status 'ok'
            # (the READ succeeded) and must still fail the unit.
            if rec.get("alerts"):
                alerts += 1

    manifest = {
        "schema": "evidence_run/1",
        "run_ts": run_ts,
        "session_id": session_id,
        "devices": list(devices),
        "items": [i["name"] for i in items],
        "expected_results": len(devices) * len(items),
        "collected_results": len(results),
        "ok": sum(1 for r in results if r["status"] == "ok"),
        "unmapped": sum(1 for r in results
                        if r["mapping_status"] == "unmapped"),
        "alerting_results": alerts,
        "alerts": sorted({k for r in results for k in r.get("alerts", [])}),
        "framework": framework,
        "items_source": items_src, "items_sha256": items_sha,
        "controls_source": ctl_src, "controls_sha256": ctl_sha,
        "results": results,
    }
    with open(os.path.join(run_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1, sort_keys=True)
        f.write("\n")
    print(json.dumps({"run": run_ts, "session": session_id,
                      "expected": manifest["expected_results"],
                      "collected": len(results), "ok": manifest["ok"],
                      "unmapped": manifest["unmapped"],
                      "alerting_results": alerts,
                      "alert_kinds": manifest["alerts"],
                      "manifest": os.path.join(run_dir, "manifest.json")},
                     sort_keys=True))
    return 1 if alerts else 0


def show_plan(items_paths=ITEMS_PATHS, controls_paths=CONTROLS_PATHS):
    """Print what a run WOULD collect, without contacting anything."""
    items, items_src, items_sha = load_items(items_paths)
    controls, framework, ctl_src, ctl_sha = load_controls(controls_paths)
    print("items    : %s (sha256 %s)" % (items_src, items_sha[:16]))
    print("controls : %s (sha256 %s)" % (ctl_src, ctl_sha[:16]))
    print("framework: %s" % framework)
    print()
    for item in items:
        control, status = control_for(item["name"], controls)
        print("  %-26s %-12s %s" % (
            item["name"], status,
            control["control_id"] if control else "(no control mapped)"))
        print("      command   : %s" % item["command"])
        if item["evidence_gap"]:
            print("      GAP       : %s" % item["evidence_gap"])
    return 0


def main(argv=None):
    os.umask(0o077)
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    sub = ap.add_subparsers(dest="mode", required=True)
    sub.add_parser("run", help="one full evidence collection cycle")
    sub.add_parser("check", help="identity check only")
    sub.add_parser("plan", help="show the item set and control mapping")
    args = ap.parse_args(argv)

    problems = identity_problems()
    if problems:
        # stderr/journal only: an over-privileged process must not write
        # into the evidence tree (root-owned droppings would then break
        # the legitimate identity's later runs).
        for p in problems:
            print("[IDENTITY-REFUSED] %s" % p, file=sys.stderr)
        print("refusing to start: this collector must run as a "
              "least-privilege identity", file=sys.stderr)
        return 3
    if args.mode == "check":
        print("identity check passed: no key/credential material readable")
        return 0
    if args.mode == "plan":
        try:
            return show_plan()
        except ConfigError as e:
            print("config error: %s" % e, file=sys.stderr)
            return 1
    return run()


if __name__ == "__main__":
    sys.exit(main())
