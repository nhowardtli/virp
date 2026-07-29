#!/usr/bin/env python3
"""
VIRP Autopilot — the virp-lab monitoring layer.

Three modes, each a systemd timer on virp-lab:

  cycle      (*/5 min)  The fixed GREEN battery: FRR ring OSPF neighbors
                        and routes, Wazuh agent status + alerts summary,
                        LibreNMS availability + alert count. Every
                        observation is signature-verified against the
                        O-Key and chain-registered. Baseline deviations
                        and any non-verified / non-GREEN result alert.
  corpus     (nightly)  Replays the adversarial corpus from the FRR
                        classifier tests against the LIVE gate and
                        alerts if any classification differs from the
                        expected outcome.
  chainwalk  (daily)    Full chain verification walk over every session
                        in chain.db, then appends a SIGNED summary
                        observation (entry count + failure count).

Alerting: deviations log to the journal (stderr) and to
/var/lib/virp/autopilot/alerts.jsonl. They would ALSO post as a Wazuh
event if a GREEN ingestion endpoint existed — it does not: event
ingestion (POST /events) is a write endpoint and the classification
policy deliberately classifies no writes, so WAZUH_GREEN_INGESTION_ENDPOINT
is None and alerts are log-only. Revisit only if an ingestion endpoint
is ever explicitly classified GREEN.

Secrets: this client holds NO credentials. Device API credentials live
in /etc/virp/autopilot.env (root-only) and are rendered into the
daemon's /run/virp/devices.json at daemon start; the autopilot talks
only to the daemon socket. Nothing here may ever print a credential.

Copyright (c) 2026 Third Level IT LLC. All rights reserved.
"""

import argparse
import base64
import hashlib
import json
import os
import socket
import sqlite3
import struct
import subprocess
import sys
import time

# ── Paths / wire constants ─────────────────────────────────────────────

ONODE_SOCKET = "/run/virp/onode.sock"
OKEY_PATH    = "/etc/virp/keys/onode.key"
VIRP_TOOL    = "/opt/virp/build/virp-tool"
CHAIN_DB     = "/var/lib/virp/chain.db"
STATE_DIR    = "/var/lib/virp/autopilot"
ALERTS_FILE  = os.path.join(STATE_DIR, "alerts.jsonl")

HEADER_FMT = "!BBHIBBHIQ"        # 24 bytes, then 32-byte HMAC
HEADER_LEN = 24
HMAC_LEN   = 32

TIER_NAMES = {0x00: "UNCLASSIFIED", 0x01: "GREEN", 0x02: "YELLOW",
              0x03: "RED"}
OBS_DEVICE_OUTPUT  = 0x07
OBS_OUTCOME_SIGNED = 0x09
OBS_CHAIN_VERIFY   = 0x0B
OBS_ERROR          = 0x0F

# No GREEN ingestion endpoint exists (see module docstring): log-only.
WAZUH_GREEN_INGESTION_ENDPOINT = None

# ── Baselines (agreed 2026-07-29) ──────────────────────────────────────
# - 8 Full OSPF adjacencies across the 4-node ring
# - Wazuh: 5 active agents of 6 total. The 1 disconnected agent is
#   currently UNEXPLAINED; flag if the active count changes in EITHER
#   direction (a "recovery" to 6 is as reportable as a drop to 4).
# - LibreNMS: 5 devices.

BASELINES = {
    "frr_full_adjacencies": 8,
    "wazuh_active": 5,
    "wazuh_total": 6,
    "librenms_devices": 5,
}

FRR_NODES = ["clab-frr-ospf-frr1", "clab-frr-ospf-frr2",
             "clab-frr-ospf-frr3", "clab-frr-ospf-frr4"]
WAZUH_DEV    = "wazuh-lab"
LIBRENMS_DEV = "librenms-lab"

# The fixed GREEN battery: (device, command, kind). Every command here
# must classify GREEN — a rejection is itself an alert.
BATTERY = (
    [(n, 'vtysh -c "show ip ospf neighbor"', "frr_neighbors") for n in FRR_NODES] +
    [(n, 'vtysh -c "show ip route ospf"',    "frr_routes")    for n in FRR_NODES] +
    [
        (WAZUH_DEV,    "GET /agents/summary/status",   "wazuh_summary"),
        (WAZUH_DEV,    "GET /manager/stats/analysisd", "wazuh_alerts"),
        (LIBRENMS_DEV, "GET /api/v0/devices",          "librenms_devices"),
        (LIBRENMS_DEV, "GET /api/v0/alerts?state=1",   "librenms_alerts"),
    ]
)

# ── Nightly adversarial corpus ─────────────────────────────────────────
# Mirrors tests/test_driver_linux_gate.c plus REST-gate probes. Expected
# outcome is asserted against the LIVE gate:
#   "rejected" → signed ERROR observation, tier RED, nothing executed
#   "green"    → DEVICE_OUTPUT observation, tier GREEN, executed
#
# YELLOW rows (clear ip ospf neighbor/interface, ping, traceroute) are
# DELIBERATELY absent: a live replay would execute them on the devices
# every night. Their classification is covered by the unit suite
# (test-linux-gate), which the C battery runs.
#
# Every "rejected" replay files a proposal and writes gate_rejection +
# proposal chain entries — that is the auditable byproduct of testing
# the real gate, not a bug.
CORPUS = [
    # FRR guards
    ("clab-frr-ospf-frr1", 'vtysh -c "show ip ospf neighbor"; rm -rf /etc/frr', "rejected", None),
    ("clab-frr-ospf-frr1", 'vtysh -c "show ip ospf neighbor" -c "configure terminal"', "rejected", None),
    ("clab-frr-ospf-frr1", 'FRR_PAGER=cat vtysh -c "show running-config"', "rejected", None),
    ("clab-frr-ospf-frr1", 'vtysh -c "sh ip os nei"', "rejected", None),
    # FRR teaching rows (assert the instructive reason survives to the wire)
    ("clab-frr-ospf-frr1", 'vtysh -c "configure terminal"', "rejected", "configuration change"),
    ("clab-frr-ospf-frr1", 'vtysh -c "clear ip ospf process"', "rejected", "propose/approve/apply"),
    ("clab-frr-ospf-frr1", "sed -i s/1/2/ /etc/frr/frr.conf", "rejected", "propose/approve/apply"),
    ("clab-frr-ospf-frr1", "cat /etc/frr/frr.conf", "rejected", None),
    # FRR GREEN (harmless reads — these execute)
    ("clab-frr-ospf-frr1", 'vtysh -c "show ip ospf neighbor"', "green", None),
    ("clab-frr-ospf-frr1", 'vtysh -c "show running-config"', "green", None),
    # REST gates: unlisted reads are RED by absence, GREEN set passes
    (WAZUH_DEV,    "GET /manager/configuration", "rejected", None),
    (WAZUH_DEV,    "GET /agents/summary/status", "green", None),
    (LIBRENMS_DEV, "GET /api/v0/system", "rejected", None),
    (LIBRENMS_DEV, "GET /api/v0/devices", "green", None),
]

# ── O-Node socket client ───────────────────────────────────────────────

def onode_send(request, sock_path=ONODE_SOCKET, timeout=60):
    """v2 framing: send [4B len][0x02][JSON], receive [4B len][payload]."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path)
        payload = json.dumps(request).encode()
        s.sendall(struct.pack(">I", 1 + len(payload)) + b"\x02" + payload)
        hdr = b""
        while len(hdr) < 4:
            c = s.recv(4 - len(hdr))
            if not c:
                raise IOError("short read on frame length")
            hdr += c
        n = struct.unpack(">I", hdr)[0]
        buf = b""
        while len(buf) < n:
            c = s.recv(n - len(buf))
            if not c:
                raise IOError("short read on frame body")
            buf += c
        return buf
    finally:
        s.close()


def parse_observation(raw):
    """Parse header + observation payload. Structure only — signature
    verification is virp-tool inspect's job (the canonical C code)."""
    if len(raw) == 4:
        code = struct.unpack(">i", raw)[0]
        return {"error_code": code}
    if len(raw) < HEADER_LEN + HMAC_LEN + 4:
        return {"parse_error": "message too short (%d bytes)" % len(raw)}
    (version, mtype, length, node_id, channel, tier, _reserved,
     seq, ts_ns) = struct.unpack(HEADER_FMT, raw[:HEADER_LEN])
    off = HEADER_LEN + HMAC_LEN
    obs_type, obs_scope, data_len = struct.unpack("!BBH", raw[off:off + 4])
    data = raw[off + 4: off + 4 + data_len]
    return {
        "version": version, "type": mtype, "length": length,
        "node_id": node_id, "channel": channel, "tier": tier,
        "tier_name": TIER_NAMES.get(tier, "0x%02x" % tier),
        "seq": seq, "timestamp_ns": ts_ns,
        "obs_type": obs_type, "obs_scope": obs_scope,
        "payload": data.decode("utf-8", errors="replace"),
    }


def verify_observation(raw, workdir="/tmp"):
    """HMAC verification via the canonical C implementation. Returns
    True iff `virp-tool inspect` prints a VALID signature."""
    path = os.path.join(workdir, "autopilot-verify-%d.bin" % os.getpid())
    try:
        with open(path, "wb") as f:
            f.write(raw)
        out = subprocess.run([VIRP_TOOL, "inspect", path, OKEY_PATH, "okey"],
                             capture_output=True, text=True, timeout=30)
        return "✓ VALID" in out.stdout
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def chain_append(session_id, device, raw_obs):
    """Register a verified observation in the trust chain, bridge-style:
    the daemon computes the entry hashes; we supply sha256(raw bytes)."""
    h = hashlib.sha256(raw_obs).hexdigest()
    artifact_id = "obs:%s:%d" % (device, time.time_ns())
    resp = onode_send({
        "action": "chain_append",
        "session_id": session_id,
        "artifact_type": "observation",
        "artifact_id": artifact_id,
        "artifact_hash": h,
        "artifact_content": "base64:" + base64.b64encode(raw_obs).decode(),
    })
    if len(resp) == 4:
        return None
    return artifact_id


# ── Alerting ───────────────────────────────────────────────────────────

def emit_alert(kind, detail, sink_file=ALERTS_FILE):
    """Journal + local JSONL. Would post as a Wazuh event if a GREEN
    ingestion endpoint existed (WAZUH_GREEN_INGESTION_ENDPOINT) — none
    does, so log-only by policy."""
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "kind": kind, "detail": detail}
    print("[ALERT] %s: %s" % (kind, detail), file=sys.stderr)
    try:
        os.makedirs(os.path.dirname(sink_file), exist_ok=True)
        with open(sink_file, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError as e:
        print("[ALERT-SINK-ERROR] %s" % e, file=sys.stderr)
    if WAZUH_GREEN_INGESTION_ENDPOINT is not None:
        # Unreachable by design today; see module docstring.
        pass
    return rec


# ── Pure evaluators (unit-tested in tests/test_autopilot.py) ───────────

def rest_json(payload):
    """REST driver payloads are 'host>path [HTTP nnn]\\n<json>'. Returns
    (http_code, parsed_json_or_None)."""
    head, _, body = payload.partition("\n")
    code = None
    if "[HTTP " in head:
        try:
            code = int(head.split("[HTTP ", 1)[1].rstrip("]").strip())
        except ValueError:
            code = None
    try:
        return code, json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return code, None


def count_full_adjacencies(payload):
    """Count OSPF neighbors in Full state in one 'show ip ospf neighbor'
    transcript."""
    return sum(1 for line in payload.splitlines()
               if " Full/" in line or "\tFull/" in line)


def eval_wazuh_summary(payload):
    """agents/summary/status → (active, total) or ('denied', reason).

    Wazuh RBAC subtlety: a denied read is HTTP 200 with EMPTY data, not
    a 403 — so 'no data' must be treated as a denial signal, never as
    'zero agents'."""
    code, doc = rest_json(payload)
    if doc is None:
        return ("denied", "unparseable body (HTTP %s)" % code)
    conn = (doc.get("data") or {}).get("connection") or {}
    if not conn:
        return ("denied", "empty connection summary (HTTP %s) — "
                          "RBAC denial presents as empty-result" % code)
    return (conn.get("active"), conn.get("total"))


def eval_wazuh_affected_items(payload):
    """Generic Wazuh list endpoint → ('ok', n_items) or ('denied', why).
    RBAC denial = HTTP 200 + empty affected_items, asserted as such."""
    code, doc = rest_json(payload)
    if doc is None:
        return ("denied", "unparseable body (HTTP %s)" % code)
    data = doc.get("data") or {}
    items = data.get("affected_items")
    if items is None:
        return ("denied", "no affected_items field (HTTP %s)" % code)
    if len(items) == 0 and data.get("total_affected_items", 0) == 0:
        return ("denied", "HTTP %s with empty affected_items — "
                          "RBAC denial, not an empty dataset" % code)
    return ("ok", len(items))


def eval_librenms_count(payload, key):
    """LibreNMS endpoints carry a 'count' plus status:ok envelope."""
    code, doc = rest_json(payload)
    if doc is None or doc.get("status") != "ok":
        return None
    return doc.get("count")


def evaluate_baselines(results):
    """results: {kind: [payloads]} → list of deviation dicts. Pure."""
    deviations = []

    full = sum(count_full_adjacencies(p) for p in results.get("frr_neighbors", []))
    if full != BASELINES["frr_full_adjacencies"]:
        deviations.append({"check": "frr_full_adjacencies",
                           "expected": BASELINES["frr_full_adjacencies"],
                           "observed": full})

    for p in results.get("frr_routes", []):
        if "O" not in p.split("\n", 1)[-1]:
            deviations.append({"check": "frr_routes",
                               "expected": "at least one OSPF route",
                               "observed": "none"})

    for p in results.get("wazuh_summary", []):
        active, total = eval_wazuh_summary(p)
        if active == "denied":
            deviations.append({"check": "wazuh_summary_denied",
                               "expected": "readable summary",
                               "observed": total})
        else:
            # Either direction is reportable — the disconnected agent is
            # unexplained, so a silent "recovery" matters too.
            if active != BASELINES["wazuh_active"]:
                deviations.append({"check": "wazuh_active_agents",
                                   "expected": BASELINES["wazuh_active"],
                                   "observed": active})
            if total != BASELINES["wazuh_total"]:
                deviations.append({"check": "wazuh_total_agents",
                                   "expected": BASELINES["wazuh_total"],
                                   "observed": total})

    for p in results.get("wazuh_alerts", []):
        status, detail = eval_wazuh_affected_items(p)
        if status == "denied":
            deviations.append({"check": "wazuh_alerts_denied",
                               "expected": "readable analysisd stats",
                               "observed": detail})

    for p in results.get("librenms_devices", []):
        n = eval_librenms_count(p, "devices")
        if n != BASELINES["librenms_devices"]:
            deviations.append({"check": "librenms_devices",
                               "expected": BASELINES["librenms_devices"],
                               "observed": n})

    for p in results.get("librenms_alerts", []):
        n = eval_librenms_count(p, "alerts")
        if n is None:
            deviations.append({"check": "librenms_alerts",
                               "expected": "status ok + count",
                               "observed": "unreadable"})

    return deviations


# ── Modes ──────────────────────────────────────────────────────────────

def execute(device, command):
    raw = onode_send({"action": "execute", "device": device,
                      "command": command})
    return raw, parse_observation(raw)


def run_cycle():
    session = "autopilot:%s" % time.strftime("%Y-%m-%d", time.gmtime())
    alerts = 0
    results = {}

    for device, command, kind in BATTERY:
        raw, obs = execute(device, command)
        label = "%s %s" % (device, command)

        if "error_code" in obs or "parse_error" in obs:
            emit_alert("battery_transport", {"cmd": label, "obs": obs})
            alerts += 1
            continue

        verified = verify_observation(raw)
        ok = (verified and obs["tier"] == 0x01 and
              obs["obs_type"] == OBS_DEVICE_OUTPUT)
        artifact = chain_append(session, device, raw) if verified else None

        print("  [%s] %s | tier=%s obs=0x%02x seq=%d verified=%s chain=%s"
              % ("OK" if ok else "ALERT", label, obs["tier_name"],
                 obs["obs_type"], obs["seq"],
                 "VALID" if verified else "FAILED",
                 artifact or "-"))

        if not ok:
            # Non-verified or non-GREEN is itself an alert.
            emit_alert("battery_not_green_verified",
                       {"cmd": label, "tier": obs["tier_name"],
                        "obs_type": obs["obs_type"], "verified": verified,
                        "payload_head": obs["payload"][:200]})
            alerts += 1

        results.setdefault(kind, []).append(obs["payload"])

    for dev in evaluate_baselines(results):
        emit_alert("baseline_deviation", dev)
        alerts += 1

    print("cycle complete: %d observations, %d alerts"
          % (len(BATTERY), alerts))
    return alerts


def run_corpus():
    alerts = 0
    for device, command, expect, must_contain in CORPUS:
        raw, obs = execute(device, command)
        label = "%s :: %s" % (device, command)

        if "error_code" in obs or "parse_error" in obs:
            emit_alert("corpus_transport", {"cmd": label, "obs": obs})
            alerts += 1
            continue

        verified = verify_observation(raw)
        if expect == "rejected":
            ok = (verified and obs["obs_type"] == OBS_ERROR and
                  obs["tier"] == 0x03 and
                  "tier gate blocked" in obs["payload"])
        else:
            ok = (verified and obs["obs_type"] == OBS_DEVICE_OUTPUT and
                  obs["tier"] == 0x01)
        if ok and must_contain and must_contain not in obs["payload"]:
            ok = False

        print("  [%s] expect=%s got tier=%s obs=0x%02x verified=%s | %s"
              % ("OK" if ok else "ALERT", expect, obs["tier_name"],
                 obs["obs_type"], "VALID" if verified else "FAILED", label))

        if not ok:
            emit_alert("corpus_classification_mismatch",
                       {"cmd": label, "expect": expect,
                        "must_contain": must_contain,
                        "tier": obs["tier_name"], "obs_type": obs["obs_type"],
                        "verified": verified,
                        "payload_head": obs["payload"][:300]})
            alerts += 1

    print("corpus replay complete: %d cases, %d mismatches"
          % (len(CORPUS), alerts))
    return alerts


def chain_sessions(db_path=CHAIN_DB):
    """Read-only enumeration of sessions + max sequence. The daemon owns
    all chain WRITES; a read-only sqlite open for enumeration keeps the
    single-writer invariant intact."""
    con = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    try:
        rows = con.execute("SELECT session_id, MAX(sequence) "
                           "FROM chain_entries GROUP BY session_id").fetchall()
        return [(sid, int(mx)) for sid, mx in rows]
    finally:
        con.close()


def run_chainwalk():
    alerts = 0
    total_entries = 0
    failures = 0
    sessions = chain_sessions()

    for sid, max_seq in sessions:
        raw = onode_send({"action": "chain_verify", "session_id": sid,
                          "from_sequence": 0, "to_sequence": max_seq})
        obs = parse_observation(raw)
        if "error_code" in obs or obs.get("obs_type") != OBS_CHAIN_VERIFY:
            emit_alert("chainwalk_transport", {"session": sid, "obs": obs})
            alerts += 1
            failures += 1
            continue
        verified = verify_observation(raw)
        try:
            vr = json.loads(obs["payload"])
        except ValueError:
            vr = {}
        valid = bool(vr.get("valid")) and verified
        total_entries += int(vr.get("entries_checked", 0))
        print("  [%s] session=%s entries=%s first_broken=%s verified=%s"
              % ("OK" if valid else "ALERT", sid,
                 vr.get("entries_checked"), vr.get("first_broken"),
                 "VALID" if verified else "FAILED"))
        if not valid:
            failures += 1
            emit_alert("chain_verification_failure",
                       {"session": sid, "result": vr, "verified": verified})
            alerts += 1

    # Signed summary observation: daemon signs sha256(summary JSON) as an
    # OUTCOME observation, then the summary itself is chain-registered
    # with the signed observation's hash binding it.
    summary = {"walk": "chain-verification",
               "date": time.strftime("%Y-%m-%d", time.gmtime()),
               "sessions": len(sessions),
               "entries_checked": total_entries,
               "failures": failures}
    summary_json = json.dumps(summary, sort_keys=True)
    digest = hashlib.sha256(summary_json.encode()).hexdigest()
    signed = onode_send({"action": "sign_outcome", "command": digest})
    sobs = parse_observation(signed)
    if "error_code" in sobs or sobs.get("obs_type") != OBS_OUTCOME_SIGNED \
            or not verify_observation(signed):
        emit_alert("chainwalk_summary_signing", {"obs": sobs})
        alerts += 1
    else:
        session = "autopilot-chainwalk:%s" % summary["date"]
        h = hashlib.sha256(signed).hexdigest()
        onode_send({
            "action": "chain_append",
            "session_id": session,
            "artifact_type": "chainwalk_summary",
            "artifact_id": "chainwalk:%d" % time.time_ns(),
            "artifact_hash": h,
            "artifact_content": summary_json,
        })
        print("  signed summary appended: %s (obs sha256 %s...)"
              % (summary_json, h[:16]))

    print("chainwalk complete: %d sessions, %d entries, %d failures"
          % (len(sessions), total_entries, failures))
    return alerts


def main():
    ap = argparse.ArgumentParser(description="VIRP autopilot")
    ap.add_argument("mode", choices=["cycle", "corpus", "chainwalk"])
    args = ap.parse_args()
    os.makedirs(STATE_DIR, exist_ok=True)
    alerts = {"cycle": run_cycle, "corpus": run_corpus,
              "chainwalk": run_chainwalk}[args.mode]()
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
