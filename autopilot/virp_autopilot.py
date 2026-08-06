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
  comparator (*/10 min) Diffs THIS node's latest published observations
                        against the PEER node's for the shared targets
                        (LibreNMS device count, Wazuh active/total,
                        peer liveness) and alerts on any disagreement.
                        Disagreement between independent observers is
                        the finding. See the honest-v1 federation note
                        above run_comparator().

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
#
# RULE: every baseline here MUST be measured with the EXACT API query the
# battery below issues — same path, same query string. A baseline taken
# with a different query form is not a baseline for this loop, it is a
# number about a different question, and the mismatch surfaces as a
# permanent false deviation that trains people to ignore the alert.
#
# This rule was written the hard way. librenms_devices was originally 5,
# measured with a filtered query, while the loop counts unfiltered
# inventory (/api/v0/devices) and sees 6 — flagging every cycle for a
# fleet that had not changed. Measured 2026-07-29 through this daemon:
#
#   /api/v0/devices               → 6   (what the loop uses: inventory)
#   /api/v0/devices?type=all      → 6   (identical to unfiltered)
#   /api/v0/devices?type=up       → 5   ← where the 5 came from
#   /api/v0/devices?type=down     → 1   (proxmox01)
#
# So the 5 was an AVAILABILITY figure, not an inventory figure, and the
# single device accounting for the gap is **proxmox01**, which LibreNMS
# currently reports as down (all six devices predate 2026-07-29; nothing
# was added). Note also that ?type=network and ?type=server both return
# 6 here — LibreNMS does not filter on those values the way the name
# suggests, which is exactly why the query string must be copied
# verbatim from the battery rather than reasoned about.
#
# Baselines:
# - 8 Full OSPF adjacencies across the 4-node ring
# - Wazuh: 5 active agents of 6 total. The 1 disconnected agent is
#   currently UNEXPLAINED; flag if the active count changes in EITHER
#   direction (a "recovery" to 6 is as reportable as a drop to 4).
# - LibreNMS: 6 devices in inventory, per /api/v0/devices unfiltered.
#   This tracks INVENTORY only. Availability is deliberately not
#   baselined here yet: proxmox01 being down means an availability
#   baseline of 6-up would alert immediately, and 5-up would bake a
#   current outage into the definition of healthy. Decide the intent
#   before adding it.

BASELINES = {
    "frr_full_adjacencies": 8,
    "wazuh_active": 5,
    "wazuh_total": 6,
    "librenms_devices": 6,
}

FRR_NODES = ["clab-frr-ospf-frr1", "clab-frr-ospf-frr2",
             "clab-frr-ospf-frr3", "clab-frr-ospf-frr4"]
WAZUH_DEV    = "wazuh-lab"
LIBRENMS_DEV = "librenms-lab"
PBS_DEV      = "pbs-lab"

# ── Per-node identity / topology ───────────────────────────────────────
# /etc/virp/autopilot-node.json lets one client serve both nodes:
#   {"node": "virp-node2", "frr_nodes": [],
#    "peer_device": "virp-lab-peer", "peer_node": "virp-lab"}
# Absent file → virp-lab's historical shape (4 FRR nodes, no peer), so
# an un-migrated deployment keeps behaving exactly as before.
NODE_CONFIG_PATH = "/etc/virp/autopilot-node.json"

# Peer probes — EXACTLY the exact-match GREEN rows in driver_linux.c.
# Any drift here classifies RED and alerts, which is the intended
# failure mode: the classifier is the authority, not this list.
PEER_CMD_LIVENESS   = "systemctl is-active virp-onode"
PEER_CMD_CHAIN_HEAD = ("/opt/virp/build/virp-tool chain tail -n 1 "
                       "--db /var/lib/virp/chain.db")
PEER_CMD_PUBLISHED  = "cat /var/lib/virp/autopilot/published.json"

PUBLISHED_FILE = os.path.join(STATE_DIR, "published.json")

# A peer summary older than this is stale — 3 missed 5-minute cycles.
PEER_STALE_SEC = 900


def load_node_config(path=NODE_CONFIG_PATH):
    cfg = {"node": "virp-lab", "frr_nodes": list(FRR_NODES),
           "peer_device": None, "peer_node": None}
    try:
        with open(path) as f:
            cfg.update(json.load(f))
    except (OSError, ValueError):
        pass
    return cfg


def build_battery(cfg):
    """The fixed GREEN battery: (device, command, kind). Every command
    here must classify GREEN — a rejection is itself an alert."""
    frr = cfg.get("frr_nodes") or []
    battery = (
        [(n, 'vtysh -c "show ip ospf neighbor"', "frr_neighbors") for n in frr] +
        [(n, 'vtysh -c "show ip route ospf"',    "frr_routes")    for n in frr] +
        [
            (WAZUH_DEV,    "GET /agents/summary/status",   "wazuh_summary"),
            (WAZUH_DEV,    "GET /manager/stats/analysisd", "wazuh_alerts"),
            (LIBRENMS_DEV, "GET /api/v0/devices",          "librenms_devices"),
            (LIBRENMS_DEV, "GET /api/v0/alerts?state=1",   "librenms_alerts"),
        ]
    )
    # PBS typed operations. The command is a canonical typed op, not a
    # path — see docs/DRIVER-TYPED-OPS.md. The datastore name comes from
    # node config rather than a literal, because it is also constrained
    # by the per-device allowlist in devices.json and the two must agree.
    # Gated on config exactly like peer_device: a node without a PBS
    # device must not probe one. node2 has no PBS entry in its devices
    # template, and an ungated row there would alert every cycle.
    pbs_dev = cfg.get("pbs_device")
    if pbs_dev:
        battery += [
            (pbs_dev, "pbs op=backup.version.read",    "pbs_version"),
            (pbs_dev, "pbs op=backup.datastore.usage", "pbs_datastore_usage"),
            (pbs_dev, "pbs op=backup.verify.tasks",    "pbs_verify_tasks"),
        ]
        pbs_store = cfg.get("pbs_datastore")
        if pbs_store:
            battery += [
                (pbs_dev, "pbs op=backup.snapshots.list store=%s" % pbs_store,
                 "pbs_snapshots"),
            ]

    peer = cfg.get("peer_device")
    if peer:
        battery += [
            (peer, PEER_CMD_LIVENESS,   "peer_liveness"),
            (peer, PEER_CMD_CHAIN_HEAD, "peer_chain_head"),
        ]
    return battery


NODE = load_node_config()
BATTERY = build_battery(NODE)

# ── Nightly adversarial corpus ─────────────────────────────────────────
# Mirrors tests/test_driver_linux_gate.c plus REST-gate probes. Expected
# outcome is asserted against the LIVE gate:
#   "separator" → signed ERROR, tier UNCLASSIFIED, refused by the
#                 daemon's request-boundary separator policy BEFORE
#                 device lookup or classification (virp_onode.c). This
#                 is the OUTER layer of a two-layer defense; the
#                 classifier's own guard is the inner one (unit-tested).
#                 Asserting the layer precisely means a regression that
#                 demotes this to a weaker layer still fails here.
#   "rejected"  → signed ERROR observation, tier RED, gate-blocked,
#                 nothing executed
#   "green"     → DEVICE_OUTPUT observation, tier GREEN, executed
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
    ("clab-frr-ospf-frr1", 'vtysh -c "show ip ospf neighbor"; rm -rf /etc/frr', "separator", "illegal separator"),
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
    # ── PBS typed operations: one row per REFUSAL CLASS ────────────────
    # The unit suites cover these offline; these rows assert the same
    # refusals survive all the way to the live gate, with their teaching
    # reasons intact. Ordered as in the grammar doc.
    #   unknown op / no write op exists at any tier
    (PBS_DEV, "pbs op=backup.verify.run", "rejected", "RED by absence"),
    (PBS_DEV, "pbs op=backup.snapshots.delete store=colo-backups", "rejected",
     "RED by absence"),
    #   prefix creep, both directions. NOTE the two reasons differ and
    #   that distinction is deliberate: an UPPERCASE suffix fails the op-id
    #   CHARSET check (lowercase only) before the table is ever consulted,
    #   while a lowercase suffix is well-formed and fails the TABLE lookup.
    #   Asserting the precise reason keeps the two layers distinguishable —
    #   the live replay caught this expectation being wrong on 2026-07-31.
    (PBS_DEV, "pbs op=backup.version.readX", "rejected", "illegal byte"),
    (PBS_DEV, "pbs op=backup.version.readx", "rejected", "unknown operation id"),
    (PBS_DEV, "pbs op=backup.version.rea", "rejected", "unknown operation id"),
    #   separator policy — refused at the daemon boundary, before the driver
    (PBS_DEV, "pbs op=backup.version.read; rm -rf /", "separator",
     "illegal separator"),
    (PBS_DEV, "pbs op=backup.version.read | cat /etc/shadow", "separator",
     "illegal separator"),
    #   value charset: path traversal, query smuggling, URL fragment
    (PBS_DEV, "pbs op=backup.snapshots.list store=../../etc/passwd",
     "rejected", "illegal byte"),
    (PBS_DEV, "pbs op=backup.snapshots.list store=colo-backups?typefilter=all",
     "rejected", "illegal byte"),
    (PBS_DEV, "pbs op=backup.snapshots.list store=colo-backups#frag",
     "rejected", "illegal byte"),
    #   canonical-form violations
    (PBS_DEV, "pbs op=backup.snapshots.list store=a store=b", "rejected",
     "duplicate parameter"),
    (PBS_DEV, "pbs op=backup.snapshots.list abc=1 store=colo-backups",
     "rejected", "ascending key order"),
    (PBS_DEV, "pbs op=backup.version.read store=colo-backups", "rejected",
     "not declared for this operation"),
    (PBS_DEV, "pbs op=backup.snapshots.list", "rejected",
     "required parameter missing"),
    (PBS_DEV, "pbs op=BACKUP.VERSION.READ", "rejected", None),
    (PBS_DEV, "pbs  op=backup.version.read", "rejected", None),
    (PBS_DEV, "pbs op=backup.verify.tasks typefilter=all", "rejected",
     "not declared for this operation"),
    #   op-in-param smuggling
    (PBS_DEV, "pbs op=backup.version.read op=backup.verify.run", "rejected",
     "duplicate parameter"),
    #   GREEN control — the cheapest of the four, harmless to replay
    (PBS_DEV, "pbs op=backup.version.read", "green", None),
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
    the daemon computes the entry hashes; we supply sha256(raw bytes).

    Bodies at or past the daemon's 8192-byte artifact_content field would
    be stored TRUNCATED, and a truncated body cannot hash to the
    commitment the entry carries. Those register commitment-only: the
    entry and its hash over the FULL signed message are recorded, no body
    is stored, and a verifier honestly reports "no body retained" instead
    of a body that fails binding. virp_evidence.py and
    virp_config_backup.py have always done this; this client did not, so
    it submitted oversized bodies that the daemon silently truncated
    (2,211 such bodies are in the chain, all librenms). Since the daemon
    began binding submitted bodies to their declared hash on 2026-08-06,
    an oversized submission is refused outright and the observation loses
    its chain entry entirely — hence this guard."""
    h = hashlib.sha256(raw_obs).hexdigest()
    artifact_id = "obs:%s:%d" % (device, time.time_ns())
    req = {
        "action": "chain_append",
        "session_id": session_id,
        "artifact_type": "observation",
        "artifact_id": artifact_id,
        "artifact_hash": h,
    }
    content = "base64:" + base64.b64encode(raw_obs).decode()
    if len(content) < 8192:
        req["artifact_content"] = content
    resp = onode_send(req)
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


def shell_output(payload):
    """Linux-driver payloads are 'host$ <command>\\n<output>'. Return the
    output with the echoed command line removed."""
    _, _, body = payload.partition("\n")
    return body.strip()


def eval_peer_liveness(payload):
    """systemctl is-active virp-onode → True iff the peer daemon is
    active. Anything else (inactive/failed/unknown/empty) is False."""
    return shell_output(payload) == "active"


def eval_peer_chain_head(payload):
    """Parse `virp chain tail -n 1` into {session, seq, entry_hash}.

    Columns: SESSION SEQ TYPE ARTIFACT_ID ENTRY_HASH PREV_HASH. Returns
    None if no data row is present."""
    for line in shell_output(payload).splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[0] != "SESSION" and parts[1].isdigit():
            return {"session": parts[0], "seq": int(parts[1]),
                    "entry_hash": parts[4]}
    return None


def count_full_adjacencies(payload):
    """Count OSPF neighbors in Full state in one 'show ip ospf neighbor'
    transcript."""
    return sum(1 for line in payload.splitlines()
               if " Full/" in line or "\tFull/" in line)


def eval_wazuh_summary(payload):
    """agents/summary/status → (active, total) or ('denied', reason).

    Wazuh RBAC denial has TWO shapes and neither is a 403 on this
    endpoint:
      - endpoint-level denial → a real HTTP 403 (seen on
        /manager/stats/analysisd for a tightly-scoped credential)
      - resource-level filtering → HTTP 200 with an EMPTY result. On
        this endpoint that presents as a present-but-all-zero connection
        block (total == 0), which must NEVER be read as "the manager has
        zero agents". virp-node2's credential does exactly this.
    """
    code, doc = rest_json(payload)
    if doc is None:
        return ("denied", "unparseable body (HTTP %s)" % code)
    conn = (doc.get("data") or {}).get("connection") or {}
    if not conn:
        return ("denied", "empty connection summary (HTTP %s) — "
                          "RBAC denial presents as empty-result" % code)
    active, total = conn.get("active"), conn.get("total")
    if not total:
        return ("denied", "HTTP %s with total=0 agents — resource-level "
                          "RBAC filtering, not an agentless manager" % code)
    return (active, total)


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

    # FRR adjacencies are only a baseline for nodes that actually observe
    # the ring. An agentless node with no FRR devices must not be told it
    # is missing 8 adjacencies it was never asked to watch.
    if results.get("frr_neighbors"):
        full = sum(count_full_adjacencies(p)
                   for p in results["frr_neighbors"])
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
            # ONE unobservable finding, not a pair of bogus count
            # deviations: a credential that cannot see agents has not
            # observed "0 active of 0".
            deviations.append({"check": "wazuh_unobservable",
                               "expected": "readable agent summary",
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

    # Peer health — only evaluated on nodes that have a peer configured.
    for p in results.get("peer_liveness", []):
        if not eval_peer_liveness(p):
            deviations.append({"check": "peer_daemon_liveness",
                               "expected": "active",
                               "observed": shell_output(p) or "(no output)"})

    for p in results.get("peer_chain_head", []):
        if eval_peer_chain_head(p) is None:
            deviations.append({"check": "peer_chain_head",
                               "expected": "one chain entry row",
                               "observed": "unparseable"})

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

    try:
        pub = publish_summary(results, alerts)
        print("  published: %s" % json.dumps(pub["observed"], sort_keys=True))
    except OSError as e:
        emit_alert("publish_failed", {"error": str(e)})
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
        if expect == "separator":
            # Outer layer: refused at the request boundary, so the
            # command was never classified — UNCLASSIFIED is the honest
            # tier here, not a classification failure.
            ok = (verified and obs["obs_type"] == OBS_ERROR and
                  obs["tier"] == 0x00 and
                  "illegal separator" in obs["payload"])
        elif expect == "rejected":
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


def chain_head(db_path=CHAIN_DB):
    """Latest chain entry on THIS node, read-only (the daemon owns all
    writes). Shape matches eval_peer_chain_head() so local and peer
    heads are directly comparable."""
    try:
        con = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    except sqlite3.Error:
        return None
    try:
        row = con.execute("SELECT session_id, sequence, chain_entry_hash "
                          "FROM chain_entries ORDER BY id DESC "
                          "LIMIT 1").fetchone()
    except sqlite3.Error:
        return None
    finally:
        con.close()
    if not row:
        return None
    return {"session": row[0], "seq": int(row[1]), "entry_hash": row[2]}


def publish_summary(results, alerts):
    """Write this node's view of the shared targets so the PEER can read
    it through its one exact-match GREEN row and diff it. 0644 on
    purpose: the peer's probe account only needs to read it, and it
    carries no secrets — measured counts and our own chain head only."""
    def first(kind, fn, default=None):
        vals = results.get(kind) or []
        if not vals:
            return default
        try:
            return fn(vals[0])
        except Exception:
            return default

    # Publish None — never 0 — when the credential cannot observe agents,
    # so the peer's comparator reports a missing-value disagreement
    # instead of a fabricated "0 active vs 5 active".
    active_total = first("wazuh_summary", eval_wazuh_summary, (None, None))
    active, total = active_total if isinstance(active_total, tuple) \
        else (None, None)
    if active == "denied":
        active, total = None, None

    summary = {
        "node": NODE.get("node"),
        "published_at": int(time.time()),
        "chain_head": chain_head(),
        "alerts": alerts,
        "observed": {
            "librenms_devices": first("librenms_devices",
                                      lambda p: eval_librenms_count(p, "devices")),
            "librenms_alerts": first("librenms_alerts",
                                     lambda p: eval_librenms_count(p, "alerts")),
            "wazuh_active": active,
            "wazuh_total": total,
            "frr_full_adjacencies": sum(
                count_full_adjacencies(p)
                for p in results.get("frr_neighbors", [])) or None,
        },
    }
    tmp = PUBLISHED_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(summary, f, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, PUBLISHED_FILE)
    os.chmod(PUBLISHED_FILE, 0o644)
    return summary


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
        # chain_verify_session: the daemon derives the range from the
        # SIGNED head record, not from a caller-supplied to_sequence.
        # The old form derived max_seq from the same database being
        # audited, so a truncated DB shrank the asserted range along
        # with the evidence and the walk could not see the loss.
        raw = onode_send({"action": "chain_verify_session",
                          "session_id": sid})
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
        # Cross-check: the head's committed length must reach at least as
        # far as the entries this walker can SEE. head < visible max means
        # the head lagged or was replaced — alert either way. (head >
        # visible is not checkable from here; the daemon's completeness
        # rule already caught missing entries.)
        head_to = vr.get("to_sequence")
        if valid and head_to is not None and int(head_to) < max_seq:
            valid = False
            vr["local_note"] = ("head commits to %s but %s entries "
                                "visible locally" % (head_to, max_seq))
        total_entries += int(vr.get("entries_checked", 0))
        print("  [%s] session=%s entries=%s first_broken=%s verified=%s%s"
              % ("OK" if valid else "ALERT", sid,
                 vr.get("entries_checked"), vr.get("first_broken"),
                 "VALID" if verified else "FAILED",
                 (" detail=%r" % vr["error_detail"])
                 if vr.get("error_detail") else ""))
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


# ── Comparator: two independent observers, diffed ──────────────────────
#
# HONEST-v1 NOTE (federation). VIRP signs observations with HMAC-SHA256
# under each node's own O-Key, and the wire header carries no sig_alg
# field, so there is NO asymmetric observation signing and a peer's
# O-Key must never leave the peer. This node therefore CANNOT verify the
# peer's signature on the peer's own observations. What it can do — and
# what this comparator does — is read the peer's report through the tier
# gate and sign, with ITS OWN O-Key, an observation of what the peer
# reported, cross-referencing both chain heads.
#
# The auditable claim is exactly:
#   "node A observed, and signed, that node B reported head X at time T"
# NOT:
#   "node A verified node B's signature."
# Real cross-node verification needs asymmetric observation signing, a
# peer public-key registry, and a foreign-entry import path — none of
# which exist in the repo today (virp_federation.c is an Ed25519
# keypair library used by the approval flow).

COMPARED_KEYS = ("librenms_devices", "wazuh_active", "wazuh_total")


def compare_views(mine, theirs, now, stale_sec=PEER_STALE_SEC):
    """Pure diff of two published summaries. Returns a list of
    disagreement dicts. Disagreement between independent observers IS
    the finding — that is the whole point of the second node."""
    findings = []

    if theirs is None:
        findings.append({"check": "peer_summary_unreadable",
                         "detail": "no parseable peer summary"})
        return findings

    age = now - int(theirs.get("published_at") or 0)
    if age > stale_sec:
        findings.append({"check": "peer_summary_stale",
                         "peer_age_sec": age, "limit_sec": stale_sec})

    if mine is None:
        findings.append({"check": "local_summary_missing",
                         "detail": "this node has published no summary yet"})
        return findings

    mo = mine.get("observed") or {}
    to = theirs.get("observed") or {}
    for key in COMPARED_KEYS:
        a, b = mo.get(key), to.get(key)
        if a is None or b is None:
            # One observer having no value is itself a disagreement about
            # observability — never silently treated as "equal".
            findings.append({"check": "observer_disagreement_missing_value",
                             "target": key,
                             "local": a, "peer": b})
        elif a != b:
            findings.append({"check": "observer_disagreement",
                             "target": key,
                             "local": a, "peer": b})

    return findings


def run_comparator():
    alerts = 0
    peer_dev = NODE.get("peer_device")
    if not peer_dev:
        print("no peer_device configured in %s — nothing to compare"
              % NODE_CONFIG_PATH)
        return 0

    now = int(time.time())
    session = "autopilot-comparator:%s" % time.strftime("%Y-%m-%d",
                                                        time.gmtime())

    # Our own view: a local file read (same host, no device involved).
    try:
        with open(PUBLISHED_FILE) as f:
            mine = json.load(f)
    except (OSError, ValueError):
        mine = None

    # The peer's view + liveness + chain head, each through the gate.
    peer_reads = {}
    for kind, command in (("peer_liveness", PEER_CMD_LIVENESS),
                          ("peer_chain_head", PEER_CMD_CHAIN_HEAD),
                          ("peer_published", PEER_CMD_PUBLISHED)):
        raw, obs = execute(peer_dev, command)
        if "error_code" in obs or "parse_error" in obs:
            emit_alert("comparator_transport",
                       {"cmd": command, "obs": obs})
            alerts += 1
            peer_reads[kind] = None
            print("  [ALERT] %-16s transport failure: %s" % (kind, obs))
            continue

        verified = verify_observation(raw)
        green = obs["tier"] == 0x01 and obs["obs_type"] == OBS_DEVICE_OUTPUT
        ok = verified and green
        artifact = chain_append(session, peer_dev, raw) if verified else None

        print("  [%s] %-16s tier=%s obs=0x%02x verified=%s chain=%s"
              % ("OK" if ok else "ALERT", kind, obs["tier_name"],
                 obs["obs_type"], "VALID" if verified else "FAILED",
                 artifact or "-"))

        if not ok:
            # A peer probe that is refused or unverified means we have NO
            # trustworthy reading of the peer — an alert in its own right,
            # distinct from "the peer disagrees with us".
            emit_alert("comparator_probe_not_green_verified",
                       {"cmd": command, "tier": obs["tier_name"],
                        "obs_type": obs["obs_type"], "verified": verified,
                        "payload_head": obs["payload"][:200]})
            alerts += 1
            peer_reads[kind] = None
            continue

        peer_reads[kind] = obs["payload"]

    # Peer daemon liveness.
    live_payload = peer_reads.get("peer_liveness")
    peer_live = eval_peer_liveness(live_payload) if live_payload else False
    if not peer_live:
        emit_alert("peer_daemon_not_active",
                   {"peer": NODE.get("peer_node"),
                    "observed": shell_output(live_payload) if live_payload
                                else "(unreachable / refused)"})
        alerts += 1
    print("  peer_live=%s" % peer_live)

    # Chain heads, cross-referenced (the honest-v1 federation step).
    local_head = chain_head()
    peer_head = (eval_peer_chain_head(peer_reads["peer_chain_head"])
                 if peer_reads.get("peer_chain_head") else None)
    print("  local_head=%s" % (json.dumps(local_head) if local_head else "-"))
    print("  peer_head =%s" % (json.dumps(peer_head) if peer_head else "-"))

    # The view diff.
    try:
        theirs = json.loads(peer_reads["peer_published"]
                            .partition("\n")[2]) \
            if peer_reads.get("peer_published") else None
    except (ValueError, AttributeError):
        theirs = None

    findings = compare_views(mine, theirs, now)
    for f in findings:
        emit_alert("comparator_" + f["check"], f)
        alerts += 1
    if not findings:
        print("  views agree on: %s" % ", ".join(COMPARED_KEYS))

    # Sign + chain-register the comparator verdict, carrying BOTH heads.
    verdict = {
        "comparator": "cross-node",
        "node": NODE.get("node"),
        "peer": NODE.get("peer_node"),
        "at": now,
        "peer_live": peer_live,
        "local_chain_head": local_head,
        "peer_chain_head": peer_head,
        "compared": {k: {"local": (mine or {}).get("observed", {}).get(k),
                         "peer": (theirs or {}).get("observed", {}).get(k)}
                     for k in COMPARED_KEYS},
        "disagreements": findings,
        "verification_note": ("peer report observed and signed under THIS "
                              "node's O-Key; peer signature not verifiable "
                              "(no asymmetric observation signing in VIRP)"),
    }
    verdict_json = json.dumps(verdict, sort_keys=True)
    digest = hashlib.sha256(verdict_json.encode()).hexdigest()
    signed = onode_send({"action": "sign_outcome", "command": digest})
    sobs = parse_observation(signed)
    if "error_code" in sobs or sobs.get("obs_type") != OBS_OUTCOME_SIGNED \
            or not verify_observation(signed):
        emit_alert("comparator_verdict_signing", {"obs": sobs})
        alerts += 1
    else:
        onode_send({
            "action": "chain_append",
            "session_id": session,
            "artifact_type": "comparator_verdict",
            "artifact_id": "comparator:%d" % time.time_ns(),
            "artifact_hash": hashlib.sha256(signed).hexdigest(),
            "artifact_content": verdict_json,
        })
        print("  signed verdict appended (obs sha256 %s...)"
              % hashlib.sha256(signed).hexdigest()[:16])

    print("comparator complete: %d disagreements, %d alerts"
          % (len(findings), alerts))
    return alerts


def main():
    ap = argparse.ArgumentParser(description="VIRP autopilot")
    ap.add_argument("mode", choices=["cycle", "corpus", "chainwalk",
                                     "comparator"])
    args = ap.parse_args()
    os.makedirs(STATE_DIR, exist_ok=True)
    alerts = {"cycle": run_cycle, "corpus": run_corpus,
              "chainwalk": run_chainwalk,
              "comparator": run_comparator}[args.mode]()
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
