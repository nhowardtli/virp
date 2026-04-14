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
import re
import socket
import struct
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
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
VIRP_ALLOW_PY_FALLBACK = os.environ.get("VIRP_ALLOW_PY_FALLBACK", "") == "1"

# CORS: pinned origin allowlist (comma-separated). CT 210 is the canonical
# tli-ops-center frontend; CT 211 is this appliance's own UI mount.
_DEFAULT_ORIGINS = "http://10.0.0.210,http://10.0.0.211"
VIRP_ALLOWED_ORIGINS = [
    o.strip() for o in os.environ.get("VIRP_ALLOWED_ORIGINS", _DEFAULT_ORIGINS).split(",")
    if o.strip()
]

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
_virp_bridge = None  # VIRPBridge instance for C-based HMAC verification

# Observation payload cache — stores raw signed output for content fidelity checks.
# Key: (device, sequence) → {"payload": str, "verified": bool, "timestamp": float}
_obs_payload_cache: dict[tuple[str, int], dict] = {}
_OBS_CACHE_MAX = 500


def _cache_observation(device: str, sequence: int, payload: str,
                       verified: bool, timestamp: float = 0.0):
    """Store a raw observation payload for content fidelity gate lookups."""
    _obs_payload_cache[(device, sequence)] = {
        "payload": payload,
        "verified": verified,
        "timestamp": timestamp or time.time(),
    }
    while len(_obs_payload_cache) > _OBS_CACHE_MAX:
        _obs_payload_cache.pop(next(iter(_obs_payload_cache)))


def _get_latest_cached(device: str) -> Optional[dict]:
    """Get the most recent cached observation for a device."""
    latest = None
    for (d, seq), entry in _obs_payload_cache.items():
        if d == device and (latest is None or seq > latest[0]):
            latest = (seq, entry)
    return latest[1] if latest else None


# ---------------------------------------------------------------------------
# Key Management
# ---------------------------------------------------------------------------

def load_okey():
    """Load the O-Key for HMAC verification.

    Primary path: load via VIRPBridge (C library).
    Fallback: raw Python hmac — only if VIRP_ALLOW_PY_FALLBACK=1.
    """
    global key_material, key_fingerprint, _virp_bridge
    try:
        with open(VIRP_KEY_PATH, "rb") as f:
            data = f.read()
        if len(data) != VIRP_KEY_SIZE:
            raise ValueError(f"Expected {VIRP_KEY_SIZE}-byte key, got {len(data)} bytes")
        key_material = data
        key_fingerprint = hashlib.sha256(key_material).hexdigest()[:16]
    except FileNotFoundError:
        print(f"[WARN] O-Key not found at {VIRP_KEY_PATH} — running in demo mode")
        return False
    except Exception as e:
        print(f"[ERROR] Failed to load O-Key: {e}")
        return False

    # Try to initialize the C bridge for HMAC verification
    try:
        from virp_bridge import VIRPBridge
        _virp_bridge = VIRPBridge(key_path=VIRP_KEY_PATH)
        print(f"[VIRP] C bridge loaded for HMAC verification")
    except Exception as e:
        _virp_bridge = None
        if VIRP_ALLOW_PY_FALLBACK:
            print(f"[WARN] C bridge unavailable ({e}), using Python HMAC fallback")
        else:
            print(f"[ERROR] C bridge unavailable ({e}) and VIRP_ALLOW_PY_FALLBACK!=1")
    return True


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

    # Extract payload — validate length against both header size and actual buffer
    if length < VIRP_HEADER_SIZE:
        raise ValueError(f"Declared length {length} < header size {VIRP_HEADER_SIZE}")
    if length > len(msg):
        raise ValueError(f"Declared length {length} > actual message size {len(msg)}")
    payload_len = length - VIRP_HEADER_SIZE
    payload = msg[VIRP_HEADER_SIZE:VIRP_HEADER_SIZE + payload_len]

    # Verify HMAC — prefer C library, fall back to Python only if allowed
    verified = False
    if _virp_bridge is not None:
        verified = _virp_bridge.verify_observation(msg)
    elif key_material and VIRP_ALLOW_PY_FALLBACK:
        print("[WARN] Using Python HMAC fallback — set up C bridge to eliminate drift risk")
        sign_buf = msg[0:24] + msg[56:56 + payload_len]
        computed = hmac.new(key_material, sign_buf, hashlib.sha256).digest()
        verified = hmac.compare_digest(computed, received_hmac)

    tier_names = {0x01: "GREEN", 0x02: "YELLOW", 0x03: "RED", 0xFF: "BLACK"}
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
# Observation Gate: Content Fidelity Verification
# ---------------------------------------------------------------------------
#
# Pass 1 (existing): HMAC verification — did signed data come back?
# Pass 2 (new):      Content fidelity — does the AI's response accurately
#                     reflect what the signed data actually says?
#
# Claim types cross-referenced:
#   - Numeric counts:    "N running VMs" vs actual count in signed output
#   - Universal claims:  "all interfaces up" vs exceptions in signed output
#   - IP addresses:      IPs in AI text must appear in signed observation
# ---------------------------------------------------------------------------

# ── Claim extraction patterns ──

_COUNT_PATTERN = re.compile(
    r'\b(\d+)\s+'
    r'(running|active|up|down|idle|established|stopped|failed|configured|'
    r'enabled|disabled|healthy|unhealthy|online|offline|connected|'
    r'disconnected|listening|blocked|open|closed|reachable|unreachable)\s+'
    r'(VMs?|virtual\s+machines?|interfaces?|neighbors?|sessions?|routes?|'
    r'policies|rules?|users?|processes|services?|containers?|nodes?|'
    r'peers?|connections?|ports?|instances?|members?|devices?|tunnels?|'
    r'zones?|vlans?|prefixes|adjacencies|circuits?)',
    re.IGNORECASE
)

_ALL_NONE_PATTERN = re.compile(
    r'\b(all|every|each|no|none|zero)\s+\S+(?:\s+\S+){0,4}?\s+'
    r'(?:are|is|have|has|were|was|show|report)\s+'
    r'(up|down|running|active|established|healthy|online|offline|'
    r'stopped|failed|inactive|idle|connected|disconnected|'
    r'unreachable|reachable|operational|degraded)',
    re.IGNORECASE
)

_IP_PATTERN = re.compile(
    r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b'
)

_STATUS_ANTONYMS = {
    "up": ["down", "administratively down", "err-disabled", "not connect"],
    "down": ["up"],
    "running": ["stopped", "halted", "failed", "exited", "dead", "inactive"],
    "stopped": ["running", "active"],
    "active": ["inactive", "standby", "failed"],
    "established": ["idle", "active", "connect", "opensent", "openconfirm"],
    "healthy": ["unhealthy", "degraded", "failed", "critical"],
    "online": ["offline", "unreachable"],
    "connected": ["disconnected", "unreachable"],
    "reachable": ["unreachable"],
    "operational": ["degraded", "failed", "down"],
}


def _count_in_raw(raw_output: str, qualifier: str) -> int:
    """Count data lines containing a qualifier word in device output.

    Skips empty lines and separator lines (----, ====, etc.).
    Returns 0 if qualifier not found anywhere.
    """
    pattern = re.compile(r'\b' + re.escape(qualifier) + r'\b', re.IGNORECASE)
    count = 0
    for line in raw_output.strip().splitlines():
        stripped = line.strip()
        if not stripped or re.match(r'^[-=~+#*]+$', stripped):
            continue
        if pattern.search(stripped):
            count += 1
    return count


def _check_universal_claim(raw_output: str, quantifier: str,
                           status: str) -> Optional[dict]:
    """Check an all/none claim against raw output.

    Returns mismatch details if contradicted, None if supported.
    """
    status_lower = status.lower()
    is_universal = quantifier.lower() in ("all", "every", "each")
    is_negation = quantifier.lower() in ("no", "none", "zero")

    anti = _STATUS_ANTONYMS.get(status_lower, [])
    lines = raw_output.strip().splitlines()

    if is_universal and anti:
        for line in lines:
            ll = line.lower()
            for a in anti:
                if a in ll and re.search(r'\d', line):
                    return {
                        "quantifier": quantifier,
                        "claimed_status": status,
                        "contradiction": line.strip()[:150],
                        "detail": f"'{quantifier}...{status}' contradicted — "
                                  f"found '{a}' in signed data",
                    }
    elif is_negation:
        pattern = re.compile(r'\b' + re.escape(status_lower) + r'\b',
                             re.IGNORECASE)
        for line in lines:
            if pattern.search(line) and re.search(r'\d', line):
                return {
                    "quantifier": quantifier,
                    "claimed_status": status,
                    "contradiction": line.strip()[:150],
                    "detail": f"'{quantifier}...{status}' contradicted — "
                              f"found '{status}' in signed data",
                }
    return None


def _find_device_scope(text: str, match_pos: int,
                       device_names: list[str],
                       window: int = 300) -> Optional[str]:
    """Find which device a claim is about based on proximity in the AI text."""
    start = max(0, match_pos - window)
    end = min(len(text), match_pos + window)
    context = text[start:end].lower()
    claim_offset = match_pos - start

    closest = None
    closest_dist = float("inf")
    for name in device_names:
        idx = context.find(name.lower())
        if idx >= 0:
            dist = abs(idx - claim_offset)
            if dist < closest_dist:
                closest_dist = dist
                closest = name
    return closest


def check_content_fidelity(ai_response: str,
                           observations: list[dict]) -> dict:
    """Cross-reference AI claims against raw signed observation payloads.

    Args:
        ai_response:  The AI-generated text to verify.
        observations: List of dicts with at least "device" and "payload" keys.

    Returns:
        {"passed": bool, "mismatches": [...], "verified": int, "unchecked": int}
    """
    mismatches = []
    verified = 0
    unchecked = 0

    if not observations:
        return {"passed": True, "mismatches": [], "verified": 0, "unchecked": 0}

    device_payloads = {}
    for obs in observations:
        dev = obs.get("device", "")
        pay = obs.get("payload", "")
        if dev and pay:
            # Concatenate if multiple observations per device (e.g., multi-command)
            device_payloads[dev] = device_payloads.get(dev, "") + "\n" + pay

    all_payload = "\n".join(device_payloads.values()).strip()
    if not all_payload:
        return {"passed": True, "mismatches": [], "verified": 0, "unchecked": 0}

    device_names = list(device_payloads.keys())

    # ── Check 1: Numeric count claims ──
    for m in _COUNT_PATTERN.finditer(ai_response):
        claimed = int(m.group(1))
        qualifier = m.group(2)
        noun = m.group(3)

        # Scope to the relevant device if possible
        scoped_dev = _find_device_scope(ai_response, m.start(), device_names)
        target_payload = (device_payloads.get(scoped_dev, all_payload)
                          if scoped_dev else all_payload)

        raw_count = _count_in_raw(target_payload, qualifier)
        if raw_count == 0:
            unchecked += 1
            continue

        # Allow ±1 tolerance for header-line ambiguity
        min_actual = max(0, raw_count - 1)
        max_actual = raw_count
        if claimed < min_actual or claimed > max_actual:
            mismatches.append({
                "type": "count",
                "claim": m.group(0),
                "claimed": claimed,
                "signed_range": [min_actual, max_actual],
                "raw_lines": raw_count,
                "qualifier": qualifier,
                "noun": noun,
                "device": scoped_dev,
                "detail": (f"AI claimed {claimed} {qualifier} {noun} — "
                           f"signed data shows {min_actual}-{max_actual}"),
            })
        else:
            verified += 1

    # ── Check 2: Universal / negation claims ──
    for m in _ALL_NONE_PATTERN.finditer(ai_response):
        quantifier = m.group(1)
        status = m.group(2)

        scoped_dev = _find_device_scope(ai_response, m.start(), device_names)
        target_payload = (device_payloads.get(scoped_dev, all_payload)
                          if scoped_dev else all_payload)

        contradiction = _check_universal_claim(target_payload, quantifier, status)
        if contradiction:
            mismatches.append({
                "type": "universal",
                "claim": m.group(0),
                "device": scoped_dev,
                **contradiction,
            })
        else:
            verified += 1

    # ── Check 3: IP addresses ──
    ai_ips = set(_IP_PATTERN.findall(ai_response))
    payload_text = all_payload  # IPs checked against all signed data

    for ip in ai_ips:
        base_ip = ip.split("/")[0]
        octets = base_ip.split(".")
        if len(octets) != 4:
            continue
        try:
            if not all(0 <= int(o) <= 255 for o in octets):
                continue
        except ValueError:
            continue
        # Skip non-routable / broadcast / link-local noise
        if base_ip in ("0.0.0.0", "255.255.255.255", "127.0.0.1"):
            continue

        if base_ip in payload_text or ip in payload_text:
            verified += 1
        else:
            mismatches.append({
                "type": "ip_address",
                "claim": ip,
                "detail": (f"IP {ip} in AI response not found "
                           f"in any signed observation payload"),
            })

    return {
        "passed": len(mismatches) == 0,
        "mismatches": mismatches,
        "verified": verified,
        "unchecked": unchecked,
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


class GateRequest(BaseModel):
    """Observation Gate request — verify AI response against signed data."""
    response: str                               # AI-generated text
    observations: Optional[list[dict]] = None   # Full obs dicts (device + payload)
    device_refs: Optional[list[str]] = None     # Alternative: look up cached payloads


# ---------------------------------------------------------------------------
# Auth Middleware
# ---------------------------------------------------------------------------

async def check_auth(request: Request):
    """FastAPI dependency: bearer token auth (if configured).

    Use via `dependencies=[Depends(check_auth)]` on route decorators.
    When VIRP_API_TOKEN is unset, auth is a no-op (POC/dev mode).
    """
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
    allow_origins=VIRP_ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["authorization", "content-type"],
)


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    """Appliance health check. Intentionally public — used by monitors/load balancers."""
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


@app.get("/api/devices", dependencies=[Depends(check_auth)])
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


@app.post("/api/observe", dependencies=[Depends(check_auth)])
async def observe(req: ObserveRequest):
    """Execute a command on a device and return a signed VIRP observation."""
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

    # Cache payload for content fidelity gate
    _cache_observation(
        device=req.device,
        sequence=obs.get("sequence", 0),
        payload=obs.get("payload", ""),
        verified=obs.get("verified", False),
        timestamp=obs.get("timestamp", 0.0),
    )

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


@app.post("/api/sweep", dependencies=[Depends(check_auth)])
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
                    _cache_observation(
                        device=dev,
                        sequence=obs.get("sequence", 0),
                        payload=obs.get("payload", ""),
                        verified=obs.get("verified", False),
                        timestamp=obs.get("timestamp", 0.0),
                    )
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


@app.get("/api/observations", dependencies=[Depends(check_auth)])
async def get_observations(limit: int = 50, device: Optional[str] = None):
    """Get recent observation log."""
    logs = observation_log
    if device:
        logs = [l for l in logs if l.get("device") == device]
    return {
        "observations": list(reversed(logs[-limit:])),
        "total": len(logs),
    }


@app.post("/api/gate", dependencies=[Depends(check_auth)])
async def observation_gate(req: GateRequest):
    """Observation Gate — verify AI response fidelity against signed data.

    Two-pass verification:
      Pass 1: Device reference — did signed observations come back for
              every device the AI mentions?  (existing HMAC check)
      Pass 2: Content fidelity — does the AI's text accurately reflect
              what the signed data actually says?  (new)

    Tags returned:
      [OBSERVATION GATE: VERIFIED]          — both passes clear
      [OBSERVATION GATE: UNVERIFIED]        — no signed data for a referenced device
      [OBSERVATION GATE: CONTENT MISMATCH]  — signed data contradicts AI claims
    """
    checks = []
    tags = []

    # ── Resolve observations ──
    # Caller can pass full observation dicts OR device names (we look up cached).
    observations = list(req.observations or [])

    if req.device_refs:
        obs_devices_seen = {o.get("device") for o in observations}
        for dev in req.device_refs:
            if dev in obs_devices_seen:
                continue
            cached = _get_latest_cached(dev)
            if cached:
                observations.append({
                    "device": dev,
                    "payload": cached["payload"],
                    "verified": cached["verified"],
                })

    # ── Pass 1: Device reference check ──
    devices = load_devices()
    referenced_devices: set[str] = set()
    response_lower = req.response.lower()

    for name in devices:
        if name.lower() in response_lower:
            referenced_devices.add(name)
    if req.device_refs:
        referenced_devices.update(req.device_refs)

    obs_by_device = {}
    for o in observations:
        d = o.get("device", "")
        if d:
            obs_by_device[d] = o

    for device in sorted(referenced_devices):
        obs = obs_by_device.get(device)
        if obs and obs.get("verified", False):
            checks.append({
                "pass": 1,
                "type": "device_reference",
                "device": device,
                "status": "VERIFIED",
                "detail": "Signed observation present and HMAC-verified",
            })
        elif obs:
            checks.append({
                "pass": 1,
                "type": "device_reference",
                "device": device,
                "status": "UNVERIFIED",
                "detail": "Observation present but HMAC verification failed",
            })
            tags.append(f"[OBSERVATION GATE: UNVERIFIED — {device}]")
        else:
            checks.append({
                "pass": 1,
                "type": "device_reference",
                "device": device,
                "status": "UNVERIFIED",
                "detail": "No signed observation for this device",
            })
            tags.append(f"[OBSERVATION GATE: UNVERIFIED — {device}]")

    # ── Pass 2: Content fidelity (only verified observations) ──
    verified_obs = [o for o in observations if o.get("verified", False)]

    if verified_obs:
        fidelity = check_content_fidelity(req.response, verified_obs)

        if not fidelity["passed"]:
            for mm in fidelity["mismatches"]:
                checks.append({
                    "pass": 2,
                    "type": "content_fidelity",
                    "status": "CONTENT_MISMATCH",
                    **mm,
                })
            tags.append("[OBSERVATION GATE: CONTENT MISMATCH]")
        else:
            checks.append({
                "pass": 2,
                "type": "content_fidelity",
                "status": "VERIFIED",
                "claims_verified": fidelity["verified"],
                "claims_unchecked": fidelity["unchecked"],
            })

    # ── Determine overall gate result ──
    has_unverified = any(c.get("status") == "UNVERIFIED" for c in checks)
    has_mismatch = any(c.get("status") == "CONTENT_MISMATCH" for c in checks)

    if not has_unverified and not has_mismatch and checks:
        tags.append("[OBSERVATION GATE: VERIFIED]")

    return {
        "gate_pass": not has_unverified and not has_mismatch,
        "tags": tags,
        "checks": checks,
        "summary": {
            "devices_referenced": len(referenced_devices),
            "observations_available": len(observations),
            "verified_observations": len(verified_obs),
            "content_mismatches": sum(
                1 for c in checks if c.get("status") == "CONTENT_MISMATCH"
            ),
        },
    }


@app.get("/api/key")
async def key_info():
    """Intentionally public — fingerprint-only info, never exposes key material."""
    return {
        "key_loaded": key_material is not None,
        "fingerprint": key_fingerprint,
        "channel": "OBSERVATION",
        "algorithm": "HMAC-SHA256",
        "key_path": VIRP_KEY_PATH,
    }


@app.post("/api/devices/add", dependencies=[Depends(check_auth)])
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


@app.delete("/api/devices/{name}", dependencies=[Depends(check_auth)])
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
