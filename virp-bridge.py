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
import logging
import socket as sock_mod
import socketserver
import struct
import sys
import time
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [virp-bridge] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("virp-bridge")

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9998
MAX_REQUEST_SIZE = 8192

ONODE_SOCKET = "/tmp/virp-onode.sock"
OKEY_PATH = "/root/virp/keys/onode.key"
ONODE_TIMEOUT = 30.0

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


def onode_request(device: str, command: str) -> bytes:
    """Send JSON request to O-Node, return raw binary response."""
    s = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
    s.settimeout(ONODE_TIMEOUT)
    try:
        s.connect(ONODE_SOCKET)
        payload = json.dumps({
            "action": "execute", "device": device, "command": command,
        }).encode()
        s.sendall(payload)
        s.shutdown(sock_mod.SHUT_WR)
        chunks = []
        while True:
            c = s.recv(65536)
            if not c:
                break
            chunks.append(c)
        return b"".join(chunks)
    finally:
        s.close()


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
    server = ThreadedTCPServer((LISTEN_HOST, LISTEN_PORT), BridgeHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
