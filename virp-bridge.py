#!/usr/bin/env python3
"""
VIRP Demo Bridge — TCP:9998 JSON API to VIRP O-Node.

Accepts JSON requests on TCP port 9998, proxies them through VIRPClient
to the O-Node unix socket, returns JSON responses with HMAC verification
metadata.

Request format:
  {"command": "show version", "hostname": "R1"}

Optional fields: host, vendor, tier (informational only — O-Node resolves
device by hostname from its own device registry).

Response format:
  {
    "verdict": "VERIFIED",
    "hmac_hex": "ab12cd...",
    "chain_seq": 42,
    "raw_output": "Cisco IOS Software ...",
    "timestamp": "2026-03-09T14:30:00.123456Z",
    "latency_ms": 1234.5,
    "device": "R1",
    "command": "show version",
    "trust_tier": "GREEN",
    "node_id": "0x01010101"
  }

Copyright (c) 2026 Third Level IT LLC. All rights reserved.
"""

import hashlib
import hmac as hmac_mod
import json
import sqlite3
import logging
import os
import secrets
import socket as sock_mod
import socketserver
import struct
import sys
import time
from datetime import datetime, timezone

# Single source of truth — device registry
from device_registry import (
    all_device_metadata,
    device_metadata,
    get_device_list_for_prompt,
    load_devices,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [virp-bridge] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("virp-bridge")

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9998
MAX_REQUEST_SIZE = 524288

ONODE_SOCKET = "/tmp/virp-onode.sock"
OKEY_PATH = "/root/virp/keys/onode.key"
ONODE_TIMEOUT = 30.0

# v2 socket framing — must match daemon handle_client()
VIRP_FRAME_VERSION = 0x02
ONODE_MAX_REQUEST_SIZE = 24576

# VIRP binary protocol constants
HEADER_SIZE = 56
HEADER_FMT = ">BBHIBBHIQ32s"
OBS_HDR_FMT = ">BBH"
OBS_HDR_SIZE = 4
HMAC_OFFSET = 24
HMAC_SIZE = 32

TIER_NAMES = {0x01: "GREEN", 0x02: "YELLOW", 0x03: "RED", 0xFF: "BLACK"}

# Load O-Key once at startup
with open(OKEY_PATH, "rb") as _f:
    OKEY = _f.read(32)
assert len(OKEY) == 32, f"O-Key must be 32 bytes, got {len(OKEY)}"
log.info("O-Key loaded from %s", OKEY_PATH)


def _recv_exact(s, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("O-Node closed socket prematurely")
        buf += chunk
    return buf


def onode_send(request: dict) -> bytes:
    """Send a JSON request to the O-Node over v2 framing, return raw response payload.

    Wire send:     [4-byte BE len][0x02 version][JSON]
    Wire receive:  [4-byte BE len][payload]  — returned value is payload only.
    """
    s = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
    s.settimeout(ONODE_TIMEOUT)
    try:
        s.connect(ONODE_SOCKET)

        payload = json.dumps(request).encode()
        frame_len = 1 + len(payload)
        if frame_len > ONODE_MAX_REQUEST_SIZE:
            raise ValueError(
                f"request frame {frame_len} bytes exceeds "
                f"ONODE_MAX_REQUEST_SIZE ({ONODE_MAX_REQUEST_SIZE})"
            )
        s.sendall(struct.pack("!I", frame_len) + bytes([VIRP_FRAME_VERSION]) + payload)

        raw_len = _recv_exact(s, 4)
        (resp_len,) = struct.unpack("!I", raw_len)
        if resp_len == 0:
            return b""
        return _recv_exact(s, resp_len)
    finally:
        s.close()


# Session handshake state (module-level, one session per bridge process)
_session_active = False
_session_id = None
_client_nonce = None
_server_nonce = None


def onode_handshake():
    """Perform VIRP session handshake with the O-Node."""
    global _session_active, _session_id, _client_nonce, _server_nonce

    _client_nonce = secrets.token_hex(8)
    client_id = f"virp-bridge-{os.getpid()}"

    # Step 1: SESSION_HELLO
    log.info("Handshake: sending SESSION_HELLO")
    resp = onode_send({
        "action": "session_hello",
        "client_id": client_id,
        "versions": "2,1",
        "algorithms": "1",
        "client_nonce": _client_nonce,
        "supported_channels": 3,
    })

    if len(resp) == 4:
        code = struct.unpack(">I", resp)[0]
        log.error("SESSION_HELLO rejected: error %d", code)
        return

    ack = json.loads(resp.decode("utf-8"))
    _session_id = ack.get("session_id")
    _server_nonce = ack.get("server_nonce")

    if not _session_id or not _server_nonce:
        log.error("HELLO_ACK missing session_id or server_nonce")
        _session_id = None
        return

    if ack.get("client_nonce") != _client_nonce:
        log.error("HELLO_ACK client_nonce mismatch")
        _session_id = None
        return

    log.info(
        "Handshake: HELLO_ACK received, session_id=%s, version=%s",
        _session_id, ack.get("selected_version"),
    )

    # Step 2: SESSION_BIND
    log.info("Handshake: sending SESSION_BIND")
    resp = onode_send({
        "action": "session_bind",
        "client_id": client_id,
        "session_id": _session_id,
        "client_nonce": _client_nonce,
        "server_nonce": _server_nonce,
    })

    if len(resp) == 4:
        code = struct.unpack(">I", resp)[0]
        log.error("SESSION_BIND rejected: error %d", code)
        _session_id = None
        return

    bind_resp = json.loads(resp.decode("utf-8"))
    if bind_resp.get("active"):
        _session_active = True
        log.info("Handshake complete — session ACTIVE, session_id=%s", _session_id)
    else:
        log.error("SESSION_BIND did not reach ACTIVE: %s", bind_resp)
        _session_id = None


def onode_request(device: str, command: str) -> bytes:
    """Send JSON request to O-Node, return raw binary response."""
    return onode_send({
        "action": "execute", "device": device, "command": command,
    })


def verify_hmac(msg: bytes) -> bool:
    """Verify HMAC-SHA256: covers [0:24] + [56:] — skips hmac field [24:56]."""
    if len(msg) < HEADER_SIZE:
        return False
    received = msg[HMAC_OFFSET:HMAC_OFFSET + HMAC_SIZE]
    sign_data = msg[:HMAC_OFFSET] + msg[HMAC_OFFSET + HMAC_SIZE:]
    computed = hmac_mod.new(OKEY, sign_data, hashlib.sha256).digest()
    return hmac_mod.compare_digest(received, computed)


def parse_response(raw: bytes, device: str, command: str):
    """Parse raw VIRP binary into a dict. Returns (dict, error_string)."""
    if len(raw) == 0:
        return None, "O-Node returned empty response"
    if len(raw) == 4:
        code = struct.unpack(">I", raw)[0]
        return None, f"O-Node error code {code}"
    if len(raw) < HEADER_SIZE:
        return None, f"response too short ({len(raw)} bytes)"

    hmac_ok = verify_hmac(raw)
    hmac_hex = raw[HMAC_OFFSET:HMAC_OFFSET + HMAC_SIZE].hex()

    (version, msg_type, length, node_id,
     channel, tier, reserved, seq_num,
     timestamp_ns, _hmac_bytes) = struct.unpack(HEADER_FMT, raw[:HEADER_SIZE])

    # Parse observation sub-header
    payload = raw[HEADER_SIZE:]
    output_data = b""
    if len(payload) >= OBS_HDR_SIZE:
        _obs_type, _obs_scope, obs_length = struct.unpack(
            OBS_HDR_FMT, payload[:OBS_HDR_SIZE]
        )
        output_data = payload[OBS_HDR_SIZE:OBS_HDR_SIZE + obs_length]

    try:
        output_str = output_data.decode("utf-8")
    except UnicodeDecodeError:
        output_str = output_data.decode("latin-1")

    ts = datetime.fromtimestamp(
        timestamp_ns / 1e9, tz=timezone.utc
    ).isoformat()

    return {
        "verdict": "VERIFIED" if hmac_ok else "HMAC_FAILED",
        "hmac_hex": hmac_hex,
        "chain_seq": seq_num,
        "raw_output": output_str,
        "timestamp": ts,
        "latency_ms": 0,
        "device": device,
        "command": command,
        "trust_tier": TIER_NAMES.get(tier, f"UNKNOWN({tier})"),
        "channel": "OBSERVATION" if channel == 0x01 else f"CHANNEL({channel})",
        "node_id": f"0x{node_id:08X}",
    }, None



CHAIN_DB = "/var/lib/virp/chain.db"

def chain_session():
    try:
        conn = sqlite3.connect(f"file://{CHAIN_DB}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT session_id, MIN(timestamp_ns) AS first_ts, MAX(timestamp_ns) AS last_ts, COUNT(*) AS entry_count FROM chain_entries GROUP BY session_id ORDER BY first_ts DESC LIMIT 1")
        row = cur.fetchone()
        result = dict(row) if row else {"session_id": "none", "state": "UNBOUND", "entry_count": 0}
        if row: result["state"] = "BOUND"
        conn.close()
        return result
    except Exception as e:
        return {"error": str(e), "session_id": "error", "state": "ERROR"}

def chain_entries(limit=200):
    try:
        conn = sqlite3.connect(f"file://{CHAIN_DB}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT id, session_id, sequence, artifact_type, artifact_id, substr(chain_hmac,1,12) as hmac_short, chain_hmac, timestamp_ns, artifact_hash, previous_entry_hash, chain_entry_hash FROM chain_entries ORDER BY timestamp_ns DESC LIMIT ?", (limit,))
        entries = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT COUNT(*) FROM chain_entries")
        total = cur.fetchone()[0]
        conn.close()
        return {"entries": entries, "total": total}
    except Exception as e:
        return {"error": str(e), "entries": [], "total": 0}

def chain_verify():
    try:
        conn = sqlite3.connect(f"file://{CHAIN_DB}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT id, chain_entry_hash, previous_entry_hash FROM chain_entries ORDER BY id ASC")
        rows = cur.fetchall()
        conn.close()
        if not rows:
            return {"valid": False, "entries_checked": 0, "error": "no entries"}
        checked = 0
        for i, row in enumerate(rows):
            if i > 0 and row["previous_entry_hash"] != rows[i-1]["chain_entry_hash"]:
                return {"valid": False, "entries_checked": checked, "first_broken": row["id"]}
            checked += 1
        return {"valid": True, "entries_checked": checked, "first_broken": -1}
    except Exception as e:
        return {"valid": False, "entries_checked": 0, "error": str(e)}

def chain_export():
    try:
        conn = sqlite3.connect(f"file://{CHAIN_DB}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM chain_entries ORDER BY id ASC")
        entries = [dict(r) for r in cur.fetchall()]
        conn.close()
        return {"entries": entries, "total": len(entries)}
    except Exception as e:
        return {"error": str(e), "entries": [], "total": 0}


def chain_register(hmac_hex, device, command_text, tier="GREEN", node_id=0):
    """Register an observation HMAC in chain.db for later verification.

    Called by the dashboard after onode_execute() returns a valid HMAC.
    This bridges the gap between the O-Node's in-memory HMAC generation
    and the chain.db audit trail.
    """
    import time as _time
    try:
        conn = sqlite3.connect(CHAIN_DB)
        cur = conn.cursor()

        session_id = _session_id or "dashboard-obs"
        now_ns = int(_time.time() * 1e9)

        # Get previous entry hash and next sequence for chain linking
        cur.execute(
            "SELECT chain_entry_hash, sequence FROM chain_entries "
            "WHERE session_id = ? ORDER BY sequence DESC LIMIT 1",
            (session_id,),
        )
        prev = cur.fetchone()
        prev_hash = prev[0] if prev else "0" * 64
        next_seq = (prev[1] + 1) if prev else 0

        # Compute chain entry hash (SHA-256 of key fields)
        entry_data = f"{session_id}:{hmac_hex}:{device}:{now_ns}"
        entry_hash = hashlib.sha256(entry_data.encode()).hexdigest()

        # Artifact hash from command content
        artifact_hash = hashlib.sha256(
            (command_text or "").encode()
        ).hexdigest()

        artifact_id = f"obs:{device}:{int(_time.time())}"

        cur.execute(
            "INSERT INTO chain_entries "
            "(session_id, sequence, chain_entry_hash, previous_entry_hash, "
            " timestamp_ns, monotonic_ns, artifact_type, artifact_id, "
            " artifact_hash, signer_node_id, chain_hmac) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (session_id, next_seq, entry_hash, prev_hash,
             now_ns, now_ns, "observation", artifact_id,
             artifact_hash, node_id, hmac_hex),
        )

        # Also store artifact content for the verify service
        cur.execute(
            "INSERT OR IGNORE INTO artifacts "
            "(artifact_id, artifact_type, artifact_content, artifact_hash, "
            " session_id, created_at_ns) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (artifact_id, "observation",
             f"{device}#{command_text}", artifact_hash,
             session_id, now_ns),
        )

        conn.commit()
        conn.close()
        log.info("chain_register: %s device=%s cmd=%s", hmac_hex[:12], device, command_text[:40])
        return {"registered": True, "chain_hmac": hmac_hex[:12]}
    except Exception as e:
        log.error("chain_register failed: %s", e)
        return {"registered": False, "error": str(e)}

class BridgeHandler(socketserver.StreamRequestHandler):
    """Handle one JSON request per TCP connection."""

    def handle(self):
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        try:
            raw = self.rfile.read(MAX_REQUEST_SIZE)
            if not raw:
                self._send_error(400, "empty request")
                return

            try:
                req = json.loads(raw)
            except json.JSONDecodeError as e:
                self._send_error(400, f"invalid JSON: {e}")
                return

            command = req.get("command")
            if command == "chain_session":
                self._send_json(200, chain_session()); return
            if command == "chain_entries":
                self._send_json(200, chain_entries(req.get("limit", 200))); return
            if command == "chain_verify":
                self._send_json(200, chain_verify()); return
            if command == "chain_export":
                self._send_json(200, chain_export()); return
            if command == "chain_register":
                hmac_val = req.get("hmac", "")
                device = req.get("device", "")
                cmd = req.get("cmd", "")
                tier = req.get("tier", "GREEN")
                node_id = req.get("node_id", 0)
                if not hmac_val or not device:
                    self._send_error(400, "chain_register requires 'hmac' and 'device'")
                    return
                self._send_json(200, chain_register(hmac_val, device, cmd, tier, node_id))
                return

            # ── Device registry queries (single source of truth) ──
            if command == "device_list":
                metadata = all_device_metadata()
                self._send_json(200, {
                    "devices": metadata,
                    "total": len(metadata),
                }); return
            if command == "device_info":
                target = req.get("hostname") or req.get("device")
                if not target:
                    self._send_error(400, "device_info requires 'hostname'")
                    return
                meta = device_metadata(target)
                if not meta:
                    self._send_error(404, f"device '{target}' not in registry")
                    return
                self._send_json(200, meta); return
            if command == "device_prompt":
                self._send_json(200, {
                    "prompt_fragment": get_device_list_for_prompt(),
                }); return

            hostname = req.get("hostname") or req.get("device")
            if not command or not hostname:
                self._send_error(400, "missing 'command' and/or 'hostname'")
                return

            log.info("%s -> %s: %s", peer, hostname, command)

            t0 = time.monotonic()
            try:
                raw_resp = onode_request(hostname, command)
            except (OSError, sock_mod.timeout) as e:
                self._send_error(502, f"O-Node unreachable: {e}")
                return

            latency_ms = (time.monotonic() - t0) * 1000

            result, err = parse_response(raw_resp, hostname, command)
            if err:
                self._send_error(502, err)
                return

            if result["verdict"] == "HMAC_FAILED":
                self._send_error(403, f"HMAC verification failed (hmac={result['hmac_hex'][:16]}...)")
                return

            result["latency_ms"] = round(latency_ms, 1)
            self._send_json(200, result)
            log.info(
                "%s <- %s: seq=%d tier=%s hmac=%s... %.0fms",
                peer, hostname, result["chain_seq"], result["trust_tier"],
                result["hmac_hex"][:16], latency_ms,
            )

        except Exception as e:
            log.exception("unhandled error from %s", peer)
            self._send_error(500, f"internal error: {e}")

    def _send_json(self, status, obj):
        body = json.dumps(obj, indent=2) + "\n"
        self.wfile.write(body.encode("utf-8"))
        self.wfile.flush()

    def _send_error(self, status, message):
        log.warning("error %d: %s", status, message)
        self._send_json(status, {"error": message, "status": status})


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    log.info("VIRP Demo Bridge starting on %s:%d", LISTEN_HOST, LISTEN_PORT)
    log.info("O-Node socket: %s", ONODE_SOCKET)

    # Perform session handshake before accepting client requests
    try:
        onode_handshake()
    except Exception as e:
        log.warning("Session handshake failed (O-Node may not be running): %s", e)
        log.warning("Will operate without session — observations still HMAC-verified")

    server = ThreadedTCPServer((LISTEN_HOST, LISTEN_PORT), BridgeHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
