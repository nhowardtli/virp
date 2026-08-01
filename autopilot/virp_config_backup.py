#!/usr/bin/env python3
"""
virp_config_backup.py — hourly FRR config backup + drift runbook.

A scheduled, NO-AI automation that demonstrates governed action on
virp-lab. Every device interaction goes through the VIRP gate; the
runbook itself holds no credentials, no signing keys, and no approval
authority.

Identity model (enforced, not aspirational):
  - Runs as `virp-backup`, a dedicated system account that is a member
    of NO key or credential group. It is NOT the daemon user (`virp`)
    and NOT root — main() refuses to start as either.
  - Before doing anything else, main() PROVES it cannot read the O-Key,
    the chain key, the approver secret key, or either credential store
    (autopilot.env, the rendered devices.json). If any of them opens,
    the runbook refuses to start. Least privilege is verified at
    runtime, not assumed from deployment.
  - Because it holds no O-Key, this client cannot verify observation
    HMACs itself. It stores the raw signed observation bytes alongside
    each backup; any key holder (operator, the daily chainwalk) can
    verify them after the fact. This is the deliberate trade the
    autopilot units document: signer and verifier are inseparable under
    symmetric HMAC, so the *least-privilege* client is the one that
    stores evidence rather than pretending to check it.

Per device (frr1-4), each hourly run:
  1. Submits `vtysh -c "show running-config"` through the gate. The
     command classifies GREEN, executes, and returns an O-Key-signed
     observation, which is chain-registered via the daemon's
     chain_append action (the daemon is the chain writer; this client
     supplies only content + commitment).
  2. Stores the returned config as a timestamped backup under
     /var/lib/virp/config-backups/<device>/ (umask 0077 throughout).
  3. Diffs against the device's ESTABLISHED baseline:
       - No baseline yet  → alert "no baseline set". The observed
         config is stored but NEVER silently adopted; baselines come
         only from the explicit `set-baseline` operator command.
       - Identical        → chain-register a `no_drift` record. The
         daemon's signed CHAIN_ENTRY receipt is stored as evidence.
       - Different        → write a drift alert + a unified-diff
         artifact, then FILE A GATE PROPOSAL to restore the baseline by
         submitting the revert command. The revert is a config-mode
         vtysh command, which the linux classifier tiers RED, so the
         ENFORCE gate refuses to execute it and instead files a signed
         proposal (proposal_id returned in the signed rejection). The
         device is NOT touched. A human decides via `virp approve` /
         `virp apply` — this runbook holds no approval key, is not in
         the approver registry, cannot read the approvals store, and
         contains no approval code path, so it is structurally unable
         to approve its own proposals.

Exit codes: 0 clean, 1 one or more alerts (systemd failed-unit signal,
same convention as the autopilot), 3 identity check refused to start.

Copyright (c) 2026 Third Level IT LLC. All rights reserved.
"""

import argparse
import base64
import difflib
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
    ONODE_SOCKET, OBS_DEVICE_OUTPUT, OBS_ERROR, TIER_NAMES,
    load_node_config, onode_send, parse_observation,
)

# ── Paths / policy constants ───────────────────────────────────────────

BACKUP_ROOT = "/var/lib/virp/config-backups"
ALERTS_FILE = os.path.join(BACKUP_ROOT, "alerts.jsonl")

# Material this identity must NOT be able to read. If ANY of these opens
# the runbook refuses to start (exit 3). approvers.json is deliberately
# absent: it holds public keys only.
SECRET_PATHS = (
    "/etc/virp/keys/onode.key",      # O-Key (symmetric HMAC signer)
    "/etc/virp/keys/chain.key",      # chain HMAC key
    "/etc/virp/keys/approval.key",   # approver SECRET key (operator-only)
    "/etc/virp/autopilot.env",       # device API credentials
    "/run/virp/devices.json",        # rendered device credentials
)

# Accounts this runbook must never run as: root, and the daemon's own
# service account (which owns the keys).
FORBIDDEN_USERS = ("virp",)
# Groups whose membership grants credential or chain-key reach.
FORBIDDEN_GROUPS = ("virp",)

SHOW_RUNNING = 'vtysh -c "show running-config"'

# The daemon's request buffer is 1024 bytes (virp_onode.c req.command);
# stay well under it so JSON escaping can never push us over.
MAX_COMMAND_LEN = 900

# Characters the daemon's request-boundary separator guard refuses
# (virp_command_check_separators): `;` `|` `&` backtick, `$(`/`${`, and
# any control byte. We additionally refuse quotes because the revert
# command embeds each line inside -c "...".
ILLEGAL_IN_LINE = re.compile(r'[;|&`"\']|\$[({]|[\x00-\x1f\x7f]')

PROPOSAL_RE = re.compile(r"proposal_id=([0-9a-f]{32})")

# ── Identity check ─────────────────────────────────────────────────────


def identity_problems(secret_paths=SECRET_PATHS, euid=None, gids=None):
    """Return the list of reasons this process must NOT run. Empty list
    means the least-privilege contract holds. Pure-ish (paths and ids
    injectable) so tests can exercise every refusal."""
    problems = []
    euid = os.geteuid() if euid is None else euid
    if euid == 0:
        problems.append("running as root (uid 0)")
    for name in FORBIDDEN_USERS:
        try:
            if euid == pwd.getpwnam(name).pw_uid:
                problems.append("running as the daemon user '%s'" % name)
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


# ── Config normalization / parsing / revert generation ────────────────

_NOISE = ("Building configuration...", "Current configuration:")


def normalize_config(text):
    """Strip vtysh presentation noise, blank lines, and trailing
    whitespace so the diff compares configuration, not formatting."""
    out = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line or line in _NOISE:
            continue
        out.append(line)
    return "\n".join(out) + "\n" if out else ""


class UnrevertableDrift(Exception):
    """The diff cannot be expressed as a safe single revert command."""


def parse_frr(text):
    """Parse an FRR running-config into {block header: [child lines]}.
    Top-level statements are headers with no children. Depth-1 only:
    nested blocks (address-family etc.) make a context unrevertable by
    this generator — the human gets the diff artifact instead."""
    ctxs = {}
    cur = None
    for raw in normalize_config(text).splitlines():
        stripped = raw.strip()
        if not stripped or stripped == "!" or stripped == "end":
            cur = None if stripped in ("!", "end") else cur
            continue
        if raw[0] not in " \t":
            if stripped == "exit":
                cur = None
                continue
            cur = stripped
            ctxs.setdefault(cur, [])
        else:
            if cur is None:
                raise UnrevertableDrift("indented line outside any block: %r"
                                        % stripped)
            if stripped.startswith(("address-family", "exit-address-family")):
                raise UnrevertableDrift("nested block in context %r" % cur)
            ctxs[cur].append(stripped)
    return ctxs


def _flip(line):
    """Revert of an ADDED config line: negate it — or un-negate a 'no'
    form ('no no X' is not FRR syntax)."""
    return line[3:] if line.startswith("no ") else "no " + line


def revert_args(baseline_text, current_text):
    """Config-mode argument list (for vtysh -c chaining) that would take
    `current` back to `baseline`. Raises UnrevertableDrift when the
    change cannot be expressed safely; returns [] when identical."""
    base, cur = parse_frr(baseline_text), parse_frr(current_text)
    args = []
    for header, children in cur.items():
        if header not in base:
            # Whole block (or top-level statement) added → negate it.
            args.append(_flip(header))
            continue
        bset = set(base[header])
        cset = set(children)
        added = [l for l in children if l not in bset]
        removed = [l for l in base[header] if l not in cset]
        if added or removed:
            args.append(header)
            args.extend(_flip(l) for l in added)
            args.extend(removed)
            args.append("exit")
    for header, children in base.items():
        if header not in cur:
            # Whole block removed → re-add it with its children.
            args.append(header)
            args.extend(children)
            if children:
                args.append("exit")
    return args


def build_revert_command(args):
    """Assemble the single gate-submittable revert command, or raise
    UnrevertableDrift when a line would trip the daemon's separator
    guard, needs quoting, or the whole command would exceed the
    daemon's request buffer."""
    for a in args:
        m = ILLEGAL_IN_LINE.search(a)
        if m:
            raise UnrevertableDrift(
                "line %r contains %r, refused by command guards"
                % (a, m.group(0)))
    cmd = "vtysh " + " ".join(
        '-c "%s"' % a for a in ["configure terminal"] + list(args))
    if len(cmd) > MAX_COMMAND_LEN:
        raise UnrevertableDrift(
            "revert command is %d chars (limit %d)" % (len(cmd),
                                                       MAX_COMMAND_LEN))
    return cmd


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
    req = {
        "action": "chain_append",
        "session_id": session_id,
        "artifact_type": artifact_type,
        "artifact_id": artifact_id,
        "artifact_hash": h,
    }
    stored_body = len(content) < 8192
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


# ── Per-device run ─────────────────────────────────────────────────────


def device_dir(device, root=BACKUP_ROOT):
    d = os.path.join(root, device)
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def run_device(device, session_id, root=BACKUP_ROOT, send=onode_send,
               alerts_file=ALERTS_FILE, now=None):
    """One device's backup + drift cycle. Returns a result record; every
    non-clean outcome also emits an alert. NEVER writes baseline.conf —
    baselines are set only by the explicit set-baseline command."""
    now = now if now is not None else time.time()
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))
    ddir = device_dir(device, root)
    rec = {"device": device, "ts": ts, "status": None}

    # 1. Fetch running-config through the gate (GREEN read).
    try:
        raw, obs = gate_execute(device, SHOW_RUNNING, send=send)
    except (OSError, IOError) as e:
        rec["status"] = "gate_error"
        emit_alert("gate_error", {"device": device, "error": str(e)},
                   alerts_file)
        return rec
    if "error_code" in obs or obs.get("obs_type") != OBS_DEVICE_OUTPUT:
        rec["status"] = "gate_error"
        emit_alert("gate_error",
                   {"device": device,
                    "error_code": obs.get("error_code"),
                    "obs_type": obs.get("obs_type"),
                    "payload": (obs.get("payload") or "")[:300]},
                   alerts_file)
        return rec

    config = obs["payload"]
    norm = normalize_config(config)
    rec["config_sha256"] = hashlib.sha256(norm.encode()).hexdigest()

    # 2. Store the timestamped backup + the signed observation bytes.
    conf_path = os.path.join(ddir, "%s.conf" % ts)
    with open(conf_path, "w") as f:
        f.write(config)
    rec["backup"] = conf_path

    # 3. Chain-register the signed observation (daemon writes the entry
    #    and returns a SIGNED chain-entry receipt).
    obs_id = "obs:%s:%d" % (device, int(now * 1e9))
    ok, receipt, stored = chain_register(session_id, "observation", obs_id,
                                         raw, send=send)
    rec["obs_artifact_id"] = obs_id if ok else None
    rec["obs_body_stored"] = stored
    if not ok:
        emit_alert("chain_register_failed",
                   {"device": device, "artifact_id": obs_id}, alerts_file)

    meta = {"device": device, "ts": ts, "session_id": session_id,
            "command": SHOW_RUNNING, "tier": obs.get("tier_name"),
            "config_sha256": rec["config_sha256"],
            "obs_artifact_id": rec["obs_artifact_id"],
            "obs_body_stored": stored,
            "signed_observation_b64": base64.b64encode(raw).decode(),
            "chain_receipt_b64": base64.b64encode(receipt).decode(),
            "signature_verified_here": False,
            "signature_note": ("this identity holds no O-Key by design; "
                               "verify with virp-tool inspect as a key "
                               "holder, or rely on the daily chainwalk")}

    # 4. Baseline comparison.
    baseline_path = os.path.join(ddir, "baseline.conf")
    if not os.path.exists(baseline_path):
        rec["status"] = "no_baseline"
        emit_alert("no_baseline",
                   {"device": device, "backup": conf_path,
                    "note": ("config recorded but NOT adopted as baseline; "
                             "establish one with: virp_config_backup.py "
                             "set-baseline %s --from latest" % device)},
                   alerts_file)
        _write_meta(ddir, ts, dict(meta, status="no_baseline"))
        return rec

    with open(baseline_path) as f:
        baseline_raw = f.read()
    baseline_norm = normalize_config(baseline_raw)
    rec["baseline_sha256"] = hashlib.sha256(baseline_norm.encode()).hexdigest()

    if baseline_norm == norm:
        # 5a. No drift → signed, chain-registered no-drift record.
        nodrift_id = "nodrift:%s:%d" % (device, int(now * 1e9))
        body = json.dumps({"schema": "config_nodrift/1", "device": device,
                           "ts": ts,
                           "baseline_sha256": rec["baseline_sha256"],
                           "observed_sha256": rec["config_sha256"],
                           "observation": rec["obs_artifact_id"]},
                          sort_keys=True).encode()
        ok, receipt2, _ = chain_register(session_id, "no_drift", nodrift_id,
                                         body, send=send)
        rec["status"] = "no_drift"
        rec["nodrift_artifact_id"] = nodrift_id if ok else None
        if not ok:
            emit_alert("chain_register_failed",
                       {"device": device, "artifact_id": nodrift_id},
                       alerts_file)
        _write_meta(ddir, ts, dict(meta, status="no_drift",
                                   baseline_sha256=rec["baseline_sha256"],
                                   nodrift_artifact_id=rec.get(
                                       "nodrift_artifact_id"),
                                   nodrift_receipt_b64=base64.b64encode(
                                       receipt2).decode()))
        return rec

    # 5b. DRIFT. Artifact + alert + restore proposal. Never touch the
    # device: the only thing submitted is the revert command, which the
    # gate classifies RED and refuses-and-proposes.
    diff = "".join(difflib.unified_diff(
        baseline_norm.splitlines(keepends=True),
        norm.splitlines(keepends=True),
        fromfile="baseline/%s" % device, tofile="observed/%s@%s" % (device, ts)))
    diff_path = os.path.join(ddir, "drift-%s.diff" % ts)
    with open(diff_path, "w") as f:
        f.write(diff)
    rec["status"] = "drift"
    rec["diff"] = diff_path

    proposal_id, revert_cmd, revert_note = None, None, None
    try:
        args = revert_args(baseline_raw, config)
        revert_cmd = build_revert_command(args)
    except UnrevertableDrift as e:
        revert_note = ("no restore proposal filed — %s; a human must "
                       "restore from the diff artifact" % e)

    if revert_cmd is not None:
        try:
            rraw, robs = gate_execute(device, revert_cmd, send=send)
            if robs.get("obs_type") == OBS_ERROR:
                m = PROPOSAL_RE.search(robs.get("payload") or "")
                if m:
                    proposal_id = m.group(1)
                else:
                    revert_note = ("gate refused the revert but no "
                                   "proposal_id was returned: %s"
                                   % (robs.get("payload") or "")[:200])
            else:
                # Must be unreachable: config-mode vtysh classifies RED.
                # If it ever executes, say so loudly — that is a gate
                # failure, not a runbook success.
                revert_note = ("UNEXPECTED: revert command EXECUTED "
                               "(obs_type=0x%02x) — gate did not refuse a "
                               "config-mode command" % robs.get("obs_type", 0))
                emit_alert("gate_policy_violation",
                           {"device": device, "command": revert_cmd,
                            "note": revert_note}, alerts_file)
        except (OSError, IOError) as e:
            revert_note = "proposal submission failed: %s" % e

    drift_id = "drift:%s:%d" % (device, int(now * 1e9))
    body = json.dumps({"schema": "config_drift/1", "device": device,
                       "ts": ts,
                       "baseline_sha256": rec["baseline_sha256"],
                       "observed_sha256": rec["config_sha256"],
                       "observation": rec["obs_artifact_id"],
                       "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
                       "restore_proposal_id": proposal_id,
                       "note": revert_note}, sort_keys=True).encode()
    ok, _, _ = chain_register(session_id, "drift_alert", drift_id, body,
                              send=send)
    rec["drift_artifact_id"] = drift_id if ok else None
    rec["restore_proposal_id"] = proposal_id

    emit_alert("config_drift",
               {"device": device, "diff": diff_path,
                "baseline_sha256": rec["baseline_sha256"],
                "observed_sha256": rec["config_sha256"],
                "restore_proposal_id": proposal_id,
                "restore_command": revert_cmd,
                "note": revert_note or
                ("restore proposal filed; a human must approve within the "
                 "proposal TTL (virp approve %s && virp apply %s) or "
                 "reject by letting it expire" % (proposal_id, proposal_id))},
               alerts_file)
    _write_meta(ddir, ts, dict(meta, status="drift", diff=diff_path,
                               baseline_sha256=rec["baseline_sha256"],
                               restore_proposal_id=proposal_id,
                               restore_command=revert_cmd,
                               drift_artifact_id=rec["drift_artifact_id"],
                               note=revert_note))
    return rec


def _write_meta(ddir, ts, meta):
    with open(os.path.join(ddir, "%s.meta.json" % ts), "w") as f:
        json.dump(meta, f, indent=1, sort_keys=True)
        f.write("\n")


# ── Modes ──────────────────────────────────────────────────────────────


def run(root=BACKUP_ROOT, send=onode_send, alerts_file=ALERTS_FILE):
    session_id = "config-backup:%s" % time.strftime("%Y-%m-%d", time.gmtime())
    cfg = load_node_config()
    devices = cfg.get("frr_nodes") or []
    if not devices:
        emit_alert("config_error", {"error": "no frr_nodes configured"},
                   alerts_file)
        return 1
    alerts = 0
    for device in devices:
        rec = run_device(device, session_id, root=root, send=send,
                         alerts_file=alerts_file)
        print(json.dumps(rec, sort_keys=True))
        if rec["status"] != "no_drift":
            alerts += 1
    return 1 if alerts else 0


def set_baseline(device, source, root=BACKUP_ROOT, send=onode_send):
    """EXPLICIT operator adoption of a previously recorded backup as the
    device baseline. The only code path that writes baseline.conf."""
    ddir = os.path.join(root, device)
    if not os.path.isdir(ddir):
        print("error: no backups yet for %s — run the runbook first"
              % device, file=sys.stderr)
        return 1
    if source == "latest":
        backups = sorted(f for f in os.listdir(ddir)
                         if f.endswith(".conf") and f != "baseline.conf")
        if not backups:
            print("error: no backups recorded for %s" % device,
                  file=sys.stderr)
            return 1
        source = backups[-1]
    src_path = os.path.join(ddir, source)
    if not os.path.isfile(src_path):
        print("error: backup %s not found under %s" % (source, ddir),
              file=sys.stderr)
        return 1
    with open(src_path) as f:
        content = f.read()
    sha = hashlib.sha256(normalize_config(content).encode()).hexdigest()
    with open(os.path.join(ddir, "baseline.conf"), "w") as f:
        f.write(content)
    prov = {"schema": "config_baseline_set/1", "device": device,
            "source_backup": source, "baseline_sha256": sha,
            "set_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "set_by_uid": os.geteuid()}
    with open(os.path.join(ddir, "baseline.meta.json"), "w") as f:
        json.dump(prov, f, indent=1, sort_keys=True)
        f.write("\n")
    bl_id = "baseline:%s:%d" % (device, time.time_ns())
    body = json.dumps(prov, sort_keys=True).encode()
    session_id = "config-backup:%s" % time.strftime("%Y-%m-%d", time.gmtime())
    ok, _, _ = chain_register(session_id, "baseline_set", bl_id, body,
                              send=send)
    print("baseline set for %s from %s (sha256 %s)%s"
          % (device, source, sha,
             "" if ok else " — WARNING: chain registration failed"))
    return 0 if ok else 1


def main(argv=None):
    os.umask(0o077)
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    sub = ap.add_subparsers(dest="mode", required=True)
    sub.add_parser("run", help="hourly backup + drift cycle")
    sub.add_parser("check", help="identity check only")
    sb = sub.add_parser("set-baseline",
                        help="operator: adopt a recorded backup as baseline")
    sb.add_argument("device")
    sb.add_argument("--from", dest="source", default="latest",
                    help="backup filename, or 'latest' (default)")
    args = ap.parse_args(argv)

    problems = identity_problems()
    if problems:
        # stderr/journal only: an over-privileged process must not write
        # into the backup tree (root-owned droppings would then break
        # the legitimate identity's later runs).
        for p in problems:
            print("[IDENTITY-REFUSED] %s" % p, file=sys.stderr)
        print("refusing to start: this runbook must run as a "
              "least-privilege identity", file=sys.stderr)
        return 3
    if args.mode == "check":
        print("identity check passed: no key/credential material readable")
        return 0
    if args.mode == "set-baseline":
        return set_baseline(args.device, args.source)
    return run()


if __name__ == "__main__":
    sys.exit(main())
