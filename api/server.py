#!/usr/bin/env python3
"""
VIRP Appliance API Server
REST API wrapping virp-onode for consumption by any automation platform.
"""

import asyncio
import hashlib
import hmac
import json
import os
import socket
import struct
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VIRP_SOCKET = os.environ.get("VIRP_SOCKET", "/tmp/virp-onode.sock")
VIRP_KEY_PATH = os.environ.get("VIRP_KEY_PATH", "/etc/virp/keys/onode.key")
DEVICES_PATH = os.environ.get("VIRP_DEVICES", "/etc/virp/devices.json")
WEB_DIR = os.environ.get("VIRP_WEB_DIR", "/opt/virp-appliance/web")
API_TOKEN = os.environ.get("VIRP_API_TOKEN", "")  # Optional bearer token

# VIRP protocol constants
VIRP_HEADER_SIZE = 56
VIRP_HMAC_SIZE = 32
VIRP_KEY_SIZE = 32
VIRP_VERSION = 0x01
VIRP_TYPE_OBSERVATION = 0x01
VIRP_TYPE_HELLO = 0x02
VIRP_TYPE_PROPOSAL = 0x10
VIRP_TYPE_APPROVAL = 0x11
VIRP_TYPE_INTENT_ADV = 0x20
VIRP_TYPE_INTENT_WD = 0x21
VIRP_TYPE_HEARTBEAT = 0x30
VIRP_TYPE_TEARDOWN = 0xF0
VIRP_CHANNEL_OC = 0x01
VIRP_CHANNEL_IC = 0x02

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

observation_log = []  # In-memory log (POC — production would use SQLite/Postgres)
MAX_LOG_SIZE = 1000
appliance_start_time = time.time()
key_material = None
key_fingerprint = None


# ---------------------------------------------------------------------------
# Key Management
# ---------------------------------------------------------------------------

def load_okey():
    """Load the O-Key for HMAC verification."""
    global key_material, key_fingerprint
    try:
        with open(VIRP_KEY_PATH, "rb") as f:
            data = f.read()
        # Key file is exactly 32 bytes of raw key material (no prefix)
        if len(data) != VIRP_KEY_SIZE:
            raise ValueError(f"Expected {VIRP_KEY_SIZE}-byte key, got {len(data)} bytes")
        key_material = data
        key_fingerprint = hashlib.sha256(key_material).hexdigest()[:16]
        return True
    except FileNotFoundError:
        print(f"[WARN] O-Key not found at {VIRP_KEY_PATH} — running in demo mode")
        return False
    except Exception as e:
        print(f"[ERROR] Failed to load O-Key: {e}")
        return False


# ---------------------------------------------------------------------------
# VIRP Message Parsing
# ---------------------------------------------------------------------------

def parse_virp_message(msg: bytes) -> dict:
    """Parse a binary VIRP message into structured data.

    Wire format (56-byte header, packed, all multi-byte fields big-endian):
      [0]     uint8   version
      [1]     uint8   type
      [2-3]   uint16  length (total message size including header)
      [4-7]   uint32  node_id
      [8]     uint8   channel
      [9]     uint8   tier
      [10-11] uint16  reserved
      [12-15] uint32  seq_num
      [16-23] uint64  timestamp_ns
      [24-55] uint8[32] HMAC-SHA256
    Payload follows at offset 56.
    """
    if len(msg) < VIRP_HEADER_SIZE:
        raise ValueError(f"Message too short: {len(msg)} bytes (min {VIRP_HEADER_SIZE})")

    # Parse 56-byte header
    (version, msg_type, length, node_id,
     channel, tier, reserved,
     seq_num, timestamp_ns) = struct.unpack_from("!BBHI BBHI Q", msg, 0)
    received_hmac = msg[24:56]

    # Extract payload (everything after the 56-byte header)
    payload_len = length - VIRP_HEADER_SIZE
    if payload_len < 0:
        raise ValueError(f"Invalid length field: {length} < header size {VIRP_HEADER_SIZE}")
    payload = msg[VIRP_HEADER_SIZE:VIRP_HEADER_SIZE + payload_len]

    # Verify HMAC if key is loaded
    # HMAC covers bytes [0:24] (header before HMAC) + bytes [56:] (payload)
    # The 32-byte HMAC field at [24:56] is excluded from the hash input
    verified = False
    if key_material:
        sign_buf = msg[0:24] + msg[56:56 + payload_len]
        computed = hmac.new(key_material, sign_buf, hashlib.sha256).digest()
        verified = hmac.compare_digest(computed, received_hmac)

    tier_names = {0x01: "GREEN", 0x02: "YELLOW", 0x03: "RED", 0x04: "BLACK"}
    type_names = {
        0x01: "OBSERVATION", 0x02: "HELLO", 0x10: "PROPOSAL",
        0x11: "APPROVAL", 0x20: "INTENT_ADVERTISE", 0x21: "INTENT_WITHDRAW",
        0x30: "HEARTBEAT", 0xF0: "TEARDOWN",
    }

    # Convert nanosecond timestamp to seconds for ISO formatting
    timestamp_sec = timestamp_ns / 1_000_000_000

    # For OBSERVATION messages, parse sub-header to extract the data
    obs_text = ""
    if msg_type == VIRP_TYPE_OBSERVATION and len(payload) >= 4:
        # Observation sub-header: obs_type(1) + obs_scope(1) + obs_length(2 BE)
        obs_length = struct.unpack_from("!H", payload, 2)[0]
        obs_text = payload[4:4 + obs_length].decode("utf-8", errors="replace")
    elif len(payload) > 0:
        obs_text = payload.decode("utf-8", errors="replace")

    return {
        "version": version,
        "type": type_names.get(msg_type, f"UNKNOWN(0x{msg_type:02x})"),
        "channel": "OBSERVATION" if channel == VIRP_CHANNEL_OC else f"INTENT({channel})",
        "trust_tier": tier_names.get(tier, f"UNKNOWN({tier})"),
        "sequence": seq_num,
        "node_id": node_id,
        "timestamp": timestamp_sec,
        "timestamp_ns": timestamp_ns,
        "timestamp_iso": datetime.fromtimestamp(timestamp_sec, tz=timezone.utc).isoformat(),
        "payload_length": payload_len,
        "payload": obs_text,
        "hmac_hex": received_hmac.hex(),
        "verified": verified,
        "raw_size": len(msg),
    }


# ---------------------------------------------------------------------------
# virp-onode Client
# ---------------------------------------------------------------------------

def onode_execute(device: str, command: str, timeout: float = 30.0) -> dict:
    """Send a command to virp-onode and return parsed observation."""
    request = json.dumps({
        "action": "execute",
        "device": device,
        "command": command,
    }).encode("utf-8")

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect(VIRP_SOCKET)

        # Send raw JSON (no length prefix - onode expects raw recv)
        sock.sendall(request)

        # Receive raw response - onode sends either:
        #   - A full VIRP message (56+ bytes) on success
        #   - A 4-byte error code on failure
        chunks = []
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
        msg = b"".join(chunks)

        if len(msg) == 0:
            raise ConnectionError("Empty response from onode")
        if len(msg) == 4:
            err_code = struct.unpack("!I", msg)[0]
            raise ConnectionError(f"onode error code: {err_code}")

        return parse_virp_message(msg)

    except FileNotFoundError:
        raise ConnectionError(f"virp-onode socket not found at {VIRP_SOCKET}")
    except socket.timeout:
        raise TimeoutError(f"Timeout waiting for response from {device}")
    finally:
        sock.close()


def _recv_exact(sock, n: int) -> bytes:
    """Receive exactly n bytes."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed prematurely")
        buf += chunk
    return buf


# ---------------------------------------------------------------------------
# Device Registry
# ---------------------------------------------------------------------------

def load_devices() -> dict:
    """Load device registry from config file."""
    try:
        with open(DEVICES_PATH) as f:
            raw = json.load(f)
        # Handle VIRP source format: {"devices": [{"hostname": "R1", ...}]}
        if isinstance(raw, dict) and "devices" in raw and isinstance(raw["devices"], list):
            result = {}
            for d in raw["devices"]:
                name = d.get("hostname", d.get("name", "unknown"))
                result[name] = {
                    "host": d.get("host", ""),
                    "driver": "cisco" if d.get("vendor", "").startswith("cisco") else d.get("driver", "unknown"),
                    "username": d.get("username", ""),
                    "password": d.get("password", ""),
                    "enable": d.get("enable", ""),
                }
            return result
        return raw
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid devices.json: {e}")
        return {}


# ---------------------------------------------------------------------------
# API Models
# ---------------------------------------------------------------------------

class ObserveRequest(BaseModel):
    device: str
    command: str
    timeout: Optional[float] = 30.0


class SweepRequest(BaseModel):
    commands: Optional[list[str]] = None
    devices: Optional[list[str]] = None
    timeout: Optional[float] = 30.0


class DeviceAddRequest(BaseModel):
    name: str
    host: str
    driver: str = "cisco"
    username: str = ""
    password: str = ""
    enable: str = ""


# ---------------------------------------------------------------------------
# Auth Middleware
# ---------------------------------------------------------------------------

async def check_auth(request: Request):
    """Simple bearer token auth (if configured)."""
    if not API_TOKEN:
        return  # No auth configured
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {API_TOKEN}":
        raise HTTPException(status_code=401, detail="Invalid or missing API token")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_okey()
    print(f"[VIRP] Appliance API starting")
    print(f"[VIRP] Socket: {VIRP_SOCKET}")
    print(f"[VIRP] Key fingerprint: {key_fingerprint or 'NONE (demo mode)'}")
    print(f"[VIRP] Devices config: {DEVICES_PATH}")
    yield
    print("[VIRP] Appliance API shutting down")


app = FastAPI(
    title="VIRP Appliance",
    description="Verified Infrastructure Response Protocol — Network Trust Anchor",
    version="0.1.0-poc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    """Appliance health check."""
    onode_alive = os.path.exists(VIRP_SOCKET)
    devices = load_devices()
    uptime = time.time() - appliance_start_time

    return {
        "status": "healthy" if onode_alive else "degraded",
        "onode_socket": onode_alive,
        "key_loaded": key_material is not None,
        "key_fingerprint": key_fingerprint,
        "devices_registered": len(devices),
        "observations_logged": len(observation_log),
        "uptime_seconds": int(uptime),
        "version": "0.1.0-poc",
        "protocol_version": VIRP_VERSION,
    }


@app.get("/api/devices")
async def list_devices():
    """List all registered devices."""
    devices = load_devices()
    result = []
    for name, config in devices.items():
        result.append({
            "name": name,
            "host": config.get("host", ""),
            "driver": config.get("driver", "unknown"),
            "virp_supported": config.get("driver") == "cisco",  # POC: only Cisco for now
        })
    return {"devices": result, "total": len(result)}


@app.post("/api/observe")
async def observe(req: ObserveRequest):
    """Execute a command on a device and return a signed VIRP observation."""
    await check_auth(Request)

    devices = load_devices()
    if req.device not in devices:
        raise HTTPException(status_code=404, detail=f"Device '{req.device}' not registered")

    device_info = devices[req.device]
    if device_info.get("driver") != "cisco":
        raise HTTPException(
            status_code=400,
            detail=f"Device '{req.device}' uses driver '{device_info.get('driver')}' — only 'cisco' is VIRP-supported in POC"
        )

    try:
        obs = onode_execute(req.device, req.command, req.timeout)
    except ConnectionError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except TimeoutError as e:
        raise HTTPException(status_code=504, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Observation failed: {e}")

    # Log it
    log_entry = {
        "id": str(uuid.uuid4()),
        "device": req.device,
        "command": req.command,
        "verified": obs["verified"],
        "trust_tier": obs["trust_tier"],
        "timestamp": obs["timestamp_iso"],
        "payload_length": obs["payload_length"],
        "sequence": obs["sequence"],
        "logged_at": datetime.now(timezone.utc).isoformat(),
    }
    observation_log.append(log_entry)
    if len(observation_log) > MAX_LOG_SIZE:
        observation_log.pop(0)

    return {
        "observation": obs,
        "device": req.device,
        "command": req.command,
    }


@app.post("/api/sweep")
async def sweep(req: SweepRequest):
    """Run a topology sweep across all (or selected) devices."""
    devices = load_devices()
    target_devices = req.devices or [
        name for name, cfg in devices.items() if cfg.get("driver") == "cisco"
    ]
    commands = req.commands or [
        "show ip bgp summary",
        "show ip route",
        "show ip ospf neighbor",
        "show ip interface brief",
    ]

    results = []
    errors = []

    for device in target_devices:
        if device not in devices:
            errors.append({"device": device, "error": "Not registered"})
            continue
        if devices[device].get("driver") != "cisco":
            errors.append({"device": device, "error": "Not VIRP-supported (POC: Cisco only)"})
            continue

        device_results = []
        for cmd in commands:
            try:
                obs = onode_execute(device, cmd, req.timeout)
                device_results.append({
                    "command": cmd,
                    "verified": obs["verified"],
                    "trust_tier": obs["trust_tier"],
                    "payload_length": obs["payload_length"],
                    "output": obs["payload"],
                    "sequence": obs["sequence"],
                })

                # Log each observation
                observation_log.append({
                    "id": str(uuid.uuid4()),
                    "device": device,
                    "command": cmd,
                    "verified": obs["verified"],
                    "trust_tier": obs["trust_tier"],
                    "timestamp": obs["timestamp_iso"],
                    "payload_length": obs["payload_length"],
                    "sequence": obs["sequence"],
                    "logged_at": datetime.now(timezone.utc).isoformat(),
                })

            except Exception as e:
                device_results.append({
                    "command": cmd,
                    "error": str(e),
                    "verified": False,
                })

        results.append({
            "device": device,
            "observations": device_results,
            "all_verified": all(r.get("verified", False) for r in device_results),
        })

    # Trim log
    while len(observation_log) > MAX_LOG_SIZE:
        observation_log.pop(0)

    total_obs = sum(len(r["observations"]) for r in results)
    verified_count = sum(
        1 for r in results
        for o in r["observations"]
        if o.get("verified", False)
    )

    return {
        "sweep": {
            "devices_scanned": len(results),
            "total_observations": total_obs,
            "verified": verified_count,
            "failed": total_obs - verified_count,
            "errors": errors,
        },
        "results": results,
    }


@app.get("/api/observations")
async def get_observations(limit: int = 50, device: Optional[str] = None):
    """Get recent observation log."""
    logs = observation_log
    if device:
        logs = [l for l in logs if l.get("device") == device]
    return {
        "observations": list(reversed(logs[-limit:])),
        "total": len(logs),
    }


@app.get("/api/key")
async def key_info():
    """Public key information (fingerprint only — never expose key material)."""
    return {
        "key_loaded": key_material is not None,
        "fingerprint": key_fingerprint,
        "channel": "OBSERVATION",
        "algorithm": "HMAC-SHA256",
        "key_path": VIRP_KEY_PATH,
    }


@app.post("/api/devices/add")
async def add_device(req: DeviceAddRequest):
    """Add a device to the registry."""
    devices = load_devices()
    devices[req.name] = {
        "host": req.host,
        "driver": req.driver,
        "username": req.username,
        "password": req.password,
        "enable": req.enable,
    }
    with open(DEVICES_PATH, "w") as f:
        json.dump(devices, f, indent=2)
    return {"status": "added", "device": req.name}


@app.delete("/api/devices/{name}")
async def remove_device(name: str):
    """Remove a device from the registry."""
    devices = load_devices()
    if name not in devices:
        raise HTTPException(status_code=404, detail=f"Device '{name}' not found")
    del devices[name]
    with open(DEVICES_PATH, "w") as f:
        json.dump(devices, f, indent=2)
    return {"status": "removed", "device": name}


# ---------------------------------------------------------------------------
# Serve web UI (if present)
# ---------------------------------------------------------------------------

web_path = Path(WEB_DIR)
if web_path.exists():
    app.mount("/", StaticFiles(directory=str(web_path), html=True), name="web")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8470, log_level="info")
