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
DEVICES_PATH = os.environ.get("VIRP_DEVICES", "/etc/virp/devices.json")  # legacy fallback
WEB_DIR = os.environ.get("VIRP_WEB_DIR", "/opt/virp-appliance/web")
API_TOKEN = os.environ.get("VIRP_API_TOKEN", "")  # Optional bearer token

# Single source of truth — device registry
try:
    import device_registry as _dr
    _HAVE_REGISTRY = True
except ImportError:
    _HAVE_REGISTRY = False

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


ONODE_MAX_BATCH = 16  # Must match ONODE_MAX_BATCH in virp_onode.h


def _batch_execute_chunk(chunk: list[dict], timeout: float) -> list[dict]:
    """Send a single batch_execute request (up to ONODE_MAX_BATCH commands)."""
    request = json.dumps({
        "action": "batch_execute",
        "commands": chunk,
    }).encode("utf-8")

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect(VIRP_SOCKET)
        sock.sendall(request)
        sock.shutdown(socket.SHUT_WR)

        # Read 4-byte result count
        raw_count = _recv_exact(sock, 4)
        count = struct.unpack("!I", raw_count)[0]

        results = []
        for i in range(count):
            raw_len = _recv_exact(sock, 4)
            msg_len = struct.unpack("!I", raw_len)[0]
            msg = _recv_exact(sock, msg_len)

            device = chunk[i]["device"] if i < len(chunk) else f"device_{i}"
            command = chunk[i]["command"] if i < len(chunk) else "unknown"

            if msg_len == 4:
                err_code = struct.unpack("!I", msg)[0]
                results.append({
                    "device": device, "command": command,
                    "error": f"onode error code: {err_code}",
                })
            else:
                obs = parse_virp_message(msg)
                obs["device"] = device
                obs["command"] = command
                results.append(obs)

        return results

    except FileNotFoundError:
        raise ConnectionError(f"virp-onode socket not found at {VIRP_SOCKET}")
    except socket.timeout:
        raise TimeoutError("Timeout waiting for batch response")
    finally:
        sock.close()


def onode_batch_execute(commands_list: list[dict], timeout: float = 30.0) -> list[dict]:
    """Execute commands in parallel using O-Node batch_execute (pthread).

    Automatically chunks into groups of ONODE_MAX_BATCH (16) to stay
    within the O-Node's per-request thread limit. Each chunk runs its
    devices in parallel; chunks are sent sequentially.

    Args:
        commands_list: [{"device": "R1", "command": "show version"}, ...]
        timeout: socket timeout in seconds

    Returns:
        list of parsed observation dicts, one per command (order preserved)
    """
    results = []
    for i in range(0, len(commands_list), ONODE_MAX_BATCH):
        chunk = commands_list[i:i + ONODE_MAX_BATCH]
        results.extend(_batch_execute_chunk(chunk, timeout))
    return results


# ---------------------------------------------------------------------------
# Device Registry
# ---------------------------------------------------------------------------

_VENDOR_TO_DRIVER = {
    "cisco_ios": "cisco",
    "cisco_asa": "cisco_asa",
    "fortinet": "fortigate",
    "panos": "panos",
    "linux": "linux",
    "juniper": "juniper",
    "windows": "windows",
    "proxmox": "proxmox",
    "wazuh": "wazuh",
}


def load_devices() -> dict:
    """Load device registry.

    Uses the canonical devices.yaml via device_registry if available,
    falling back to the legacy devices.json for backward compat.
    Returns dict keyed by hostname with host/driver fields.
    """
    if _HAVE_REGISTRY:
        result = {}
        for name, d in _dr.get_enabled_devices().items():
            vendor = d.get("vendor", "")
            result[name] = {
                "host": d.get("host", ""),
                "driver": _VENDOR_TO_DRIVER.get(vendor, vendor),
                "vendor": vendor,
                "platform": d.get("platform", ""),
                "type": d.get("type", ""),
                "trust_tier": d.get("trust_tier", "YELLOW"),
                "collector": d.get("collector", "none"),
                "tags": d.get("tags", []),
            }
        return result

    # Legacy fallback — read from devices.json
    try:
        with open(DEVICES_PATH) as f:
            raw = json.load(f)
        if isinstance(raw, dict) and "devices" in raw and isinstance(raw["devices"], list):
            result = {}
            for d in raw["devices"]:
                name = d.get("hostname", d.get("name", "unknown"))
                result[name] = {
                    "host": d.get("host", ""),
                    "driver": "cisco" if d.get("vendor", "").startswith("cisco") else d.get("driver", "unknown"),
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
        entry = {
            "name": name,
            "host": config.get("host", ""),
            "driver": config.get("driver", "unknown"),
            "virp_supported": config.get("driver") in ("cisco", "fortigate", "panos", "cisco_asa"),
        }
        # Include richer metadata from device_registry when available
        if _HAVE_REGISTRY:
            entry["platform"] = config.get("platform", "")
            entry["type"] = config.get("type", "")
            entry["trust_tier"] = config.get("trust_tier", "YELLOW")
            entry["tags"] = config.get("tags", [])
        result.append(entry)
    return {"devices": result, "total": len(result), "source": "devices.yaml" if _HAVE_REGISTRY else "devices.json"}


@app.post("/api/observe")
async def observe(req: ObserveRequest):
    """Execute a command on a device and return a signed VIRP observation."""
    await check_auth(Request)

    devices = load_devices()
    if req.device not in devices:
        raise HTTPException(status_code=404, detail=f"Device '{req.device}' not registered")

    device_info = devices[req.device]
    _SUPPORTED_DRIVERS = {"cisco", "fortigate", "panos", "cisco_asa", "linux", "wazuh"}
    if device_info.get("collector", "ssh") == "none":
        raise HTTPException(
            status_code=400,
            detail=f"Device '{req.device}' has collector=none — not observable via SSH"
        )
    if device_info.get("driver") not in _SUPPORTED_DRIVERS:
        raise HTTPException(
            status_code=400,
            detail=f"Device '{req.device}' uses driver '{device_info.get('driver')}' — not VIRP-supported"
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
    """Run a topology sweep across all (or selected) devices.

    Uses O-Node batch_execute for parallel execution across devices.
    Each command is batched across all target devices simultaneously.
    """
    devices = load_devices()
    _SWEEP_DRIVERS = {"cisco", "fortigate", "panos", "cisco_asa", "linux", "wazuh"}
    target_devices = req.devices or [
        name for name, cfg in devices.items()
        if cfg.get("driver") in _SWEEP_DRIVERS and cfg.get("collector", "ssh") != "none"
    ]
    commands = req.commands or [
        "show ip bgp summary",
        "show ip route",
        "show ip ospf neighbor",
        "show ip interface brief",
    ]

    errors = []
    valid_devices = []
    for device in target_devices:
        if device not in devices:
            errors.append({"device": device, "error": "Not registered"})
        elif devices[device].get("driver") not in _SWEEP_DRIVERS:
            errors.append({"device": device, "error": f"Driver '{devices[device].get('driver')}' not supported"})
        else:
            valid_devices.append(device)

    # Collect per-device results
    device_results = {d: [] for d in valid_devices}

    # Batch each command across all devices in parallel
    for cmd in commands:
        batch_cmds = [{"device": d, "command": cmd} for d in valid_devices]
        try:
            batch_results = onode_batch_execute(batch_cmds, req.timeout)
            for obs in batch_results:
                dev = obs.get("device", "unknown")
                if "error" in obs:
                    device_results.get(dev, []).append({
                        "command": cmd,
                        "error": obs["error"],
                        "verified": False,
                    })
                else:
                    device_results.get(dev, []).append({
                        "command": cmd,
                        "verified": obs.get("verified", False),
                        "trust_tier": obs.get("trust_tier", "UNKNOWN"),
                        "payload_length": obs.get("payload_length", 0),
                        "output": obs.get("payload", ""),
                        "sequence": obs.get("sequence", 0),
                    })

                    observation_log.append({
                        "id": str(uuid.uuid4()),
                        "device": dev,
                        "command": cmd,
                        "verified": obs.get("verified", False),
                        "trust_tier": obs.get("trust_tier", "UNKNOWN"),
                        "timestamp": obs.get("timestamp_iso", ""),
                        "payload_length": obs.get("payload_length", 0),
                        "sequence": obs.get("sequence", 0),
                        "logged_at": datetime.now(timezone.utc).isoformat(),
                    })
        except Exception as e:
            # Fallback: if batch fails, record error for all devices
            for d in valid_devices:
                device_results[d].append({
                    "command": cmd,
                    "error": str(e),
                    "verified": False,
                })

    # Trim log
    while len(observation_log) > MAX_LOG_SIZE:
        observation_log.pop(0)

    results = []
    for d in valid_devices:
        obs_list = device_results[d]
        results.append({
            "device": d,
            "observations": obs_list,
            "all_verified": all(r.get("verified", False) for r in obs_list),
        })

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
            "mode": "batch_execute",
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
    """Add a device to the registry.

    NOTE: During migration, this writes to the legacy devices.json.
    The canonical source is /root/virp/devices.yaml — edit that file
    for permanent additions.
    """
    if _HAVE_REGISTRY and _dr.get_device(req.name):
        raise HTTPException(
            status_code=409,
            detail=f"Device '{req.name}' already exists in devices.yaml. "
                   f"Edit /root/virp/devices.yaml to modify it."
        )
    # Legacy fallback: write to devices.json
    try:
        with open(DEVICES_PATH) as f:
            raw = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        raw = {}
    raw[req.name] = {
        "host": req.host,
        "driver": req.driver,
    }
    with open(DEVICES_PATH, "w") as f:
        json.dump(raw, f, indent=2)
    return {
        "status": "added",
        "device": req.name,
        "warning": "Added to legacy devices.json. For permanent changes, edit /root/virp/devices.yaml",
    }


@app.delete("/api/devices/{name}")
async def remove_device(name: str):
    """Remove a device from the registry."""
    if _HAVE_REGISTRY and _dr.get_device(name):
        raise HTTPException(
            status_code=409,
            detail=f"Device '{name}' is defined in devices.yaml. "
                   f"Edit /root/virp/devices.yaml to remove it."
        )
    # Legacy fallback
    try:
        with open(DEVICES_PATH) as f:
            raw = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        raise HTTPException(status_code=404, detail=f"Device '{name}' not found")
    if name not in raw:
        raise HTTPException(status_code=404, detail=f"Device '{name}' not found")
    del raw[name]
    with open(DEVICES_PATH, "w") as f:
        json.dump(raw, f, indent=2)
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
