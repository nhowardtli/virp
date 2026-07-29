#!/usr/bin/env python3
"""
VIRP Appliance API Server
REST API wrapping virp-onode for consumption by any automation platform.
"""

import asyncio
import collections
import fcntl
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import socket
import struct
import tempfile
import threading
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
from pydantic import BaseModel, ConfigDict, field_validator

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VIRP_SOCKET = os.environ.get("VIRP_SOCKET", "/run/virp/onode.sock")
VIRP_KEY_PATH = os.environ.get("VIRP_KEY_PATH", "/etc/virp/keys/onode.key")
# devices.json lives under /var/lib/virp (service-user writable) rather
# than /etc/virp (root-owned, immutable config). Operators can point
# VIRP_DEVICES elsewhere; see deploy/virp-onode.service for the
# systemd StateDirectory convention.
DEVICES_PATH = os.environ.get("VIRP_DEVICES", "/var/lib/virp/devices.json")
WEB_DIR = os.environ.get("VIRP_WEB_DIR", "/opt/virp-appliance/web")
API_TOKEN = os.environ.get("VIRP_API_TOKEN", "")  # Optional bearer token
VIRP_ALLOW_PY_FALLBACK = os.environ.get("VIRP_ALLOW_PY_FALLBACK", "") == "1"

# Drivers that the VIRP daemon actually knows how to talk to. This
# list is authoritative for /api/devices/add; anything else is
# rejected with 400. Keep in sync with _VENDOR_TO_DRIVER above and
# the C-side virp_vendor enum.
VIRP_ALLOWED_DRIVERS = frozenset({
    "cisco", "cisco_asa", "fortigate", "panos",
    "linux", "juniper", "windows", "proxmox", "wazuh",
})

# RFC 1123-ish strict hostname: labels of 1-63 chars, letters/digits/
# hyphens, no leading/trailing hyphen, total length capped at 253.
# Rejects shell metacharacters, spaces, and anything json.dump would
# have to escape weirdly later.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

# Serializes every devices.json read-modify-write. threading.Lock (not
# asyncio.Lock) because an asyncio.Lock binds to a specific event loop,
# and uvicorn + TestClient both spin up independent loops per-worker /
# per-test which would deadlock a shared asyncio.Lock. threading.Lock
# handles the async-worker-thread case cleanly since FastAPI runs
# sync-looking code on a threadpool. For multi-process uvicorn
# deployments, fcntl.flock on the tempfile-then-rename path below
# provides cross-process safety as well.
_devices_lock = threading.Lock()

_audit_log = logging.getLogger("virp.audit")
if not _audit_log.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter(
        "%(asctime)s [virp.audit] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    ))
    _audit_log.addHandler(_handler)
    _audit_log.setLevel(logging.INFO)

# CORS: pinned origin allowlist (comma-separated). Defaults to empty —
# no CORS middleware is installed unless VIRP_ALLOWED_ORIGINS is set. The
# canonical frontends (CT 210 tli-ops-center, CT 211 this appliance UI)
# are configured via systemd/docker env, not baked in, so dev environments
# don't accidentally inherit a production allowlist.
VIRP_ALLOWED_ORIGINS = [
    o.strip() for o in os.environ.get("VIRP_ALLOWED_ORIGINS", "").split(",")
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

# Upper bound on a single framed VIRP message accepted by the API. The
# wire length field is uint16 so the protocol ceiling is 65535; the
# onode's own request buffer is 24KB. 32KB gives headroom for legitimate
# long `show` outputs while refusing anything suspiciously oversized
# before we start dereferencing the length field.
VIRP_MAX_FRAME = 32768
VIRP_VERSION = 0x01
# Wire-level socket framing (distinct from VIRP_VERSION, which is the
# version field in the VIRP message header). v2 framing is:
#   [4-byte BE length][1-byte frame version = 0x02][JSON payload]
# The daemon rejects unframed (v1) requests with VIRP_ERR_PROTOCOL_VERSION.
VIRP_FRAME_VERSION = 0x02
ONODE_MAX_REQUEST_SIZE = 24576
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

MAX_LOG_SIZE = 1000
#
# IN-MEMORY ONLY — not a durable audit trail
# ------------------------------------------
# observation_log is a best-effort rolling window of the last
# MAX_LOG_SIZE entries. It exists so /api/observations and the
# heartbeat counter can surface recent activity without reaching into
# the signed chain. It is NOT the source of truth, is NOT durable
# across process restarts, and provides NO guarantees under concurrent
# writers beyond what deque.append offers (which is thread-safe for
# single appends and bounded by maxlen).
#
# Production auditing goes through the signed trust chain at
# src/virp_chain.c (SQLite-backed, HMAC-chained, survives restart).
# Query /api/observations only for operator visibility / dashboards,
# never as a compliance artifact.
#
observation_log = collections.deque(maxlen=MAX_LOG_SIZE)

appliance_start_time = time.time()
key_material = None
key_fingerprint = None
_virp_bridge = None  # VIRPBridge instance for C-based HMAC verification

# ---------------------------------------------------------------------------
# Key Management
# ---------------------------------------------------------------------------

def _check_key_file_permissions(path: str) -> Optional[str]:
    """
    Mirror the C-side virp_key_load_file gate. Returns None if the
    file is safe to open, or a human-readable refusal reason. Uses
    os.lstat so a symlink is caught before any read, and os.stat on
    the resolved path so the real target's mode is also validated.
    Runs BEFORE opening the file — there is still a theoretical TOCTOU
    between stat and open, but the daemon's /etc/virp tree is
    root-owned and the service-user only has write access to the
    directories it manages, so the racer would already have the
    capability to plant the key itself.
    """
    try:
        lst = os.lstat(path)
    except FileNotFoundError:
        return None  # Caller handles "not found" separately
    if os.path.islink(path):
        return (f"key file {path} is a symlink — refusing to follow "
                f"(mirror of C O_NOFOLLOW gate)")

    st = os.stat(path)   # After lstat says it's not a symlink, stat==lstat
    mode = st.st_mode & 0o777
    if mode & 0o077:
        return (f"key file {path} has insecure mode 0o{mode:o} — "
                f"refusing to load. Run: chmod 0600 {path}")
    if st.st_uid != os.geteuid():
        return (f"key file {path} is owned by uid={st.st_uid}, "
                f"expected {os.geteuid()} — refusing to load")
    if not stat_is_regular(st.st_mode):
        return f"key file {path} is not a regular file"
    return None


def stat_is_regular(mode: int) -> bool:
    # os.path.S_ISREG exists only via the `stat` module — inline to
    # avoid an extra import at module scope.
    import stat as _stat
    return _stat.S_ISREG(mode)


def load_okey():
    """Load the O-Key for HMAC verification.

    Primary path: load via VIRPBridge (C library).
    Fallback: raw Python hmac — only if VIRP_ALLOW_PY_FALLBACK=1.

    Before reading, the file must be mode 0400/0600 and owned by the
    current euid, matching the C daemon's enforcement so the API
    server cannot accidentally load a key file that the daemon would
    refuse (or, worse, that someone else on the box has already been
    able to read).
    """
    global key_material, key_fingerprint, _virp_bridge

    refusal = _check_key_file_permissions(VIRP_KEY_PATH)
    if refusal:
        print(f"[ERROR] {refusal}")
        return False

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

def _parse_error(reason: str) -> dict:
    """Return a dict shaped like parse_virp_message's success return but with
    the observation marked unparseable. Callers treat `parse_error` truthiness
    and `verified: False` as a hard reject — such frames never enter the
    observation log or reach the Observation Gate as verified. Keys used by
    the /api/observe handler are present with safe defaults so a reject path
    doesn't KeyError downstream."""
    now_iso = datetime.now(timezone.utc).isoformat()
    return {
        "parse_error": reason,
        "verified": False,
        "type": "PARSE_ERROR",
        "observation": "",
        "payload": "",
        "payload_length": 0,
        "sequence": 0,
        "trust_tier": "UNKNOWN",
        "timestamp": 0.0,
        "timestamp_ns": 0,
        "timestamp_iso": now_iso,
        "node_id": 0,
        "channel": "UNKNOWN",
    }


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

    Size validation is defensive: the 16-bit length field is attacker-
    controlled before HMAC verification, so we refuse any frame larger
    than VIRP_MAX_FRAME or that lies about its own length before we
    dereference the payload slice. Parse errors are returned as dicts
    with `parse_error` set rather than raised, so callers handle them
    uniformly with HMAC failures.
    """
    if len(msg) < VIRP_HEADER_SIZE:
        return _parse_error(
            f"Message too short: {len(msg)} bytes (min {VIRP_HEADER_SIZE})"
        )

    # Parse 56-byte header
    (version, msg_type, length, node_id,
     channel, tier, reserved,
     seq_num, timestamp_ns) = struct.unpack_from("!BBHI BBHI Q", msg, 0)
    received_hmac = msg[24:56]

    # Hard cap: reject pathological length fields before any slicing.
    if length > VIRP_MAX_FRAME:
        return _parse_error(
            f"Declared length {length} exceeds VIRP_MAX_FRAME {VIRP_MAX_FRAME}"
        )
    # Lower bound: length must at least cover the header.
    if length < VIRP_HEADER_SIZE:
        return _parse_error(
            f"Declared length {length} < header size {VIRP_HEADER_SIZE}"
        )
    # Consistency: the buffer we actually received must hold the claim.
    if len(msg) < length:
        return _parse_error(
            f"Buffer {len(msg)} bytes < declared length {length}"
        )
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
# virp-onode Client
# ---------------------------------------------------------------------------

def _recv_exact(sock, n: int) -> bytes:
    """Receive exactly n bytes, looping over partial reads."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed prematurely")
        buf += chunk
    return buf


def _send_framed_request(sock: socket.socket, request_obj: dict) -> None:
    """Serialize request_obj as JSON and send it as a v2 framed message.

    Wire format:  [4-byte BE length][1-byte VIRP_FRAME_VERSION][JSON]
    Length covers (version byte + JSON), not the prefix itself.
    """
    payload = json.dumps(request_obj).encode("utf-8")
    frame_len = 1 + len(payload)
    if frame_len > ONODE_MAX_REQUEST_SIZE:
        raise ValueError(
            f"request frame {frame_len} bytes exceeds "
            f"ONODE_MAX_REQUEST_SIZE ({ONODE_MAX_REQUEST_SIZE})"
        )
    header = struct.pack("!I", frame_len) + bytes([VIRP_FRAME_VERSION])
    sock.sendall(header + payload)


def _recv_framed_response(sock: socket.socket) -> bytes:
    """Read a v2 framed response: [4-byte BE length][payload]. Returns payload."""
    raw_len = _recv_exact(sock, 4)
    length = struct.unpack("!I", raw_len)[0]
    if length == 0:
        return b""
    return _recv_exact(sock, length)


def onode_execute(device: str, command: str, timeout: float = 30.0) -> dict:
    """Send a command to virp-onode and return parsed observation."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect(VIRP_SOCKET)
        _send_framed_request(sock, {
            "action": "execute",
            "device": device,
            "command": command,
        })
        msg = _recv_framed_response(sock)

        if len(msg) == 0:
            raise ConnectionError("Empty response from onode")
        # A 4-byte payload inside the outer frame is an error code, not
        # a VIRP header — distinguish it from a truncated observation.
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


ONODE_MAX_BATCH = 16  # Must match ONODE_MAX_BATCH in virp_onode.h


def _batch_execute_chunk(chunk: list[dict], timeout: float) -> list[dict]:
    """Send a single batch_execute request (up to ONODE_MAX_BATCH commands).

    Response format (inside the outer framed payload):
      [4-byte BE count]
      [4-byte BE msg_len_1][msg_1]
      [4-byte BE msg_len_2][msg_2]
      ...
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect(VIRP_SOCKET)
        _send_framed_request(sock, {
            "action": "batch_execute",
            "commands": chunk,
        })

        batch_payload = _recv_framed_response(sock)
        if len(batch_payload) < 4:
            raise ConnectionError(
                f"batch response too short: {len(batch_payload)} bytes"
            )

        count = struct.unpack_from("!I", batch_payload, 0)[0]
        off = 4

        results = []
        for i in range(count):
            if off + 4 > len(batch_payload):
                raise ConnectionError("batch response truncated at len prefix")
            msg_len = struct.unpack_from("!I", batch_payload, off)[0]
            off += 4
            if off + msg_len > len(batch_payload):
                raise ConnectionError("batch response truncated at payload")
            msg = batch_payload[off:off + msg_len]
            off += msg_len

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
    """
    Minimal device identity. Credentials MUST go through the separate
    credential store (see deploy/README → credential layout) — never
    through this API, which would persist them in a plaintext JSON
    file readable by anything in the virp group. `extra='forbid'`
    causes pydantic to reject requests that carry `password` /
    `enable` / `username` / any other unexpected key with a 422.
    """
    model_config = ConfigDict(extra="forbid")

    name: str
    host: str
    driver: str = "cisco"

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        if not v or not _HOSTNAME_RE.match(v):
            raise ValueError("name must be a valid hostname label")
        return v

    @field_validator("host")
    @classmethod
    def _validate_host(cls, v: str) -> str:
        if not v:
            raise ValueError("host is required")
        # Accept a literal IPv4 / IPv6 address...
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            pass
        # ...or a strict DNS hostname.
        if _HOSTNAME_RE.match(v):
            return v
        raise ValueError("host must be a valid IP address or hostname")

    @field_validator("driver")
    @classmethod
    def _validate_driver(cls, v: str) -> str:
        if v not in VIRP_ALLOWED_DRIVERS:
            allowed = ", ".join(sorted(VIRP_ALLOWED_DRIVERS))
            raise ValueError(f"driver must be one of: {allowed}")
        return v




# ---------------------------------------------------------------------------
# Auth Middleware
# ---------------------------------------------------------------------------

def _request_identity(request: Request) -> str:
    """
    Best-effort identity string for audit log lines. With bearer-token
    auth there is no per-user identity, so we log:
      - the sha256-prefixed fingerprint of the presented token (never
        the token itself), and
      - the client IP from the socket + X-Forwarded-For when present.
    Future: swap in a real token→principal lookup once the token
    store lands.
    """
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[len("Bearer "):]
        fp = hashlib.sha256(token.encode("utf-8", "ignore")).hexdigest()[:12]
        token_id = f"token:{fp}"
    else:
        token_id = "token:none"

    client = request.client.host if request.client else "?"
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        client = f"{client} via {xff.split(',')[0].strip()}"

    return f"{token_id} from {client}"


def _read_then_write_devices(path: str, mutate) -> dict:
    """
    Read the devices.json at `path`, call mutate(raw_dict) to update it,
    then atomically replace the file. Steps:

      1. Acquire a process-level threading.Lock  (prevents intra-proc race).
      2. Take an fcntl.LOCK_EX on a sidecar `.lock` file (cross-proc).
      3. Read current devices.json, invoke mutate().
      4. Write into a tempfile in the same directory, fsync it.
      5. os.replace() the tempfile onto the target (atomic rename).
      6. fsync the enclosing directory so the rename is durable.

    Returns the mutated dict. Propagates whatever mutate() raises.
    """
    parent = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(parent, exist_ok=True)
    lock_path = os.path.join(parent, ".devices.lock")

    with _devices_lock:
        # Open + hold an exclusive flock on the sidecar across the entire
        # read-modify-write. The separate file means concurrent readers
        # of devices.json itself are never blocked.
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o640)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)

            try:
                with open(path) as f:
                    raw = json.load(f)
                if not isinstance(raw, dict):
                    raw = {}
            except (FileNotFoundError, json.JSONDecodeError):
                raw = {}

            mutate(raw)

            fd, tmp_path = tempfile.mkstemp(
                prefix=".devices-", suffix=".json.tmp", dir=parent
            )
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(raw, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.chmod(tmp_path, 0o640)
                os.replace(tmp_path, path)

                dfd = os.open(parent, os.O_DIRECTORY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except Exception:
                try:
                    os.unlink(tmp_path)
                except FileNotFoundError:
                    pass
                raise

            return raw
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)


async def check_auth(request: Request):
    """FastAPI dependency: bearer token auth (if configured).

    Use via `dependencies=[Depends(check_auth)]` on route decorators.
    When VIRP_API_TOKEN is unset, auth is a no-op (POC/dev mode).
    Comparison is constant-time so a valid-length wrong token cannot be
    learned byte-by-byte from response-time differences.
    """
    if not API_TOKEN:
        return  # No auth configured
    auth = request.headers.get("Authorization", "")
    expected = f"Bearer {API_TOKEN}"
    if not hmac.compare_digest(auth, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing API token")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

def _probe_coredump_filter() -> None:
    """
    On Linux, /proc/self/coredump_filter decides which VM areas land
    in a core dump. Bit 0 (anonymous private) and bit 2 (anonymous
    shared) cover the pages that hold a loaded key. Warn the operator
    if either is set — the C daemon calls prctl(PR_SET_DUMPABLE, 0),
    but the Python API server has no equivalent and falls back to
    relying on the filter + rlimit/coredumpctl config.
    """
    try:
        with open("/proc/self/coredump_filter") as f:
            filt = int(f.read().strip(), 16)
    except (FileNotFoundError, ValueError):
        return  # Not Linux, or /proc unavailable

    if filt & 0b0101:   # bit 0 (anon private) or bit 2 (anon shared)
        print(
            f"[WARN] /proc/self/coredump_filter=0x{filt:x} includes "
            f"anonymous pages — a core dump of this process could "
            f"expose loaded key material. Consider setting "
            f"coredump_filter to 0 or running under a systemd unit "
            f"with LimitCORE=0."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    _probe_coredump_filter()
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

if VIRP_ALLOWED_ORIGINS:
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

    # Log it. deque(maxlen=...) drops the oldest automatically; no
    # manual trim, no O(n) pop(0) — and the bound is enforced by the
    # container, not by a racy length check.
    observation_log.append({
        "id": str(uuid.uuid4()),
        "device": req.device,
        "command": req.command,
        "verified": obs["verified"],
        "trust_tier": obs["trust_tier"],
        "timestamp": obs["timestamp_iso"],
        "payload_length": obs["payload_length"],
        "sequence": obs["sequence"],
        "logged_at": datetime.now(timezone.utc).isoformat(),
    })

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

    # (No manual trim — deque(maxlen=MAX_LOG_SIZE) bounds itself.)

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
    """
    Return recent in-memory observations (see note on observation_log).
    Snapshot the deque to a list BEFORE slicing/iterating so a
    concurrent append does not raise RuntimeError mid-iteration and
    the snapshot is consistent with the `total` we report back.
    """
    snapshot = list(observation_log)
    if device:
        snapshot = [l for l in snapshot if l.get("device") == device]
    return {
        "observations": list(reversed(snapshot[-limit:])),
        "total": len(snapshot),
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
async def add_device(req: DeviceAddRequest, request: Request):
    """Add a device to the registry.

    Inputs are validated on the pydantic model (hostname-shape name,
    IP-or-hostname host, allowlisted driver, no credential fields).
    The read-modify-write is serialized under _devices_lock and
    committed via tmpfile+fsync+os.replace, so concurrent callers and
    mid-write crashes cannot leave a torn file.

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

    identity = _request_identity(request)

    def _apply(raw: dict) -> None:
        raw[req.name] = {"host": req.host, "driver": req.driver}

    # Offload the blocking file I/O to a thread so we don't stall the
    # event loop. The thread still serializes via _devices_lock + flock.
    await asyncio.to_thread(_read_then_write_devices, DEVICES_PATH, _apply)

    _audit_log.info(
        "device.add name=%s host=%s driver=%s by=%s",
        req.name, req.host, req.driver, identity,
    )
    return {
        "status": "added",
        "device": req.name,
        "warning": "Added to legacy devices.json. For permanent changes, edit /root/virp/devices.yaml",
    }


@app.delete("/api/devices/{name}", dependencies=[Depends(check_auth)])
async def remove_device(name: str, request: Request):
    """Remove a device from the registry. Same locking + atomic-write
    guarantees as add_device."""
    if _HAVE_REGISTRY and _dr.get_device(name):
        raise HTTPException(
            status_code=409,
            detail=f"Device '{name}' is defined in devices.yaml. "
                   f"Edit /root/virp/devices.yaml to remove it."
        )

    identity = _request_identity(request)

    class _NotFound(Exception):
        pass

    def _apply(raw: dict) -> None:
        if name not in raw:
            raise _NotFound()
        del raw[name]

    try:
        await asyncio.to_thread(_read_then_write_devices, DEVICES_PATH, _apply)
    except _NotFound:
        raise HTTPException(status_code=404, detail=f"Device '{name}' not found")

    _audit_log.info("device.remove name=%s by=%s", name, identity)
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
    # Default to loopback; operators must opt in to external exposure by
    # setting VIRP_BIND_HOST (e.g. 0.0.0.0) — usually behind a reverse
    # proxy that terminates TLS and adds the bearer token.
    bind_host = os.environ.get("VIRP_BIND_HOST", "127.0.0.1")
    uvicorn.run(app, host=bind_host, port=8470, log_level="info")
