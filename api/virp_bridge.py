"""
virp_bridge.py — Python ctypes bridge to libvirp.so

All VIRP operations go through the C library. No Python reimplementation.

Provides:
  - Observation building and signing via virp_build_observation()
  - Signature verification via virp_verify()
  - Key management via virp_key_load_file() / virp_key_init()

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import ctypes
import ctypes.util
import os
import logging
from enum import IntEnum
from typing import Optional

logger = logging.getLogger(__name__)


# ── VIRP enums (must match C headers in virp.h / virp_driver.h) ────

class Transport(IntEnum):
    REST = 0   # FG_TRANSPORT_REST
    SSH = 1    # FG_TRANSPORT_SSH
    AUTO = 2   # FG_TRANSPORT_AUTO

class TrustTier(IntEnum):
    GREEN = 0x01   # VIRP_TIER_GREEN — passive, no approval
    YELLOW = 0x02  # VIRP_TIER_YELLOW — active, single approval
    RED = 0x03     # VIRP_TIER_RED — critical; single enrolled-approver signature (same mechanism as YELLOW); m-of-n quorum is roadmap, not implemented
    BLACK = 0xFF   # VIRP_TIER_BLACK — forbidden

class KeyType(IntEnum):
    OKEY = 1   # VIRP_KEY_TYPE_OKEY — signs OC messages
    RKEY = 2   # VIRP_KEY_TYPE_RKEY — signs IC messages
    CHAIN = 3  # VIRP_KEY_TYPE_CHAIN

class MsgType(IntEnum):
    OBSERVATION = 0x01  # VIRP_MSG_OBSERVATION

class ObsType(IntEnum):
    DEVICE_OUTPUT = 0x07  # VIRP_OBS_DEVICE_OUTPUT

class ObsScope(IntEnum):
    LOCAL = 0x01  # VIRP_SCOPE_LOCAL


# ── Protocol constants ─────────────────────────────────────────────

VIRP_HEADER_SIZE = 56
VIRP_HMAC_SIZE = 32
VIRP_KEY_SIZE = 32
VIRP_MAX_MESSAGE_SIZE = 65536


# ── Labels for the ops center UI ──────────────────────────────────

TIER_LABELS = {
    TrustTier.GREEN: "green",
    TrustTier.YELLOW: "yellow",
    TrustTier.RED: "red",
    TrustTier.BLACK: "black",
}

TRANSPORT_LABELS = {
    Transport.REST: "rest",
    Transport.SSH: "ssh",
    Transport.AUTO: "auto",
}


# ── C struct for virp_signing_key_t ────────────────────────────────

class VIRPKey(ctypes.Structure):
    """Mirrors virp_key_t: 32-byte key + bool loaded."""
    _fields_ = [
        ("key", ctypes.c_uint8 * VIRP_KEY_SIZE),
        ("loaded", ctypes.c_bool),
    ]

class VIRPSigningKey(ctypes.Structure):
    """Mirrors virp_signing_key_t: key + type + fingerprint."""
    _fields_ = [
        ("key", VIRPKey),
        ("type", ctypes.c_int),
        ("fingerprint", ctypes.c_uint8 * VIRP_HMAC_SIZE),
    ]


class VIRPHeader(ctypes.Structure):
    """Mirrors virp_header_t (packed, 56 bytes) — host-order after
    virp_header_deserialize()."""
    _pack_ = 1
    _fields_ = [
        ("version", ctypes.c_uint8),
        ("type", ctypes.c_uint8),
        ("length", ctypes.c_uint16),
        ("node_id", ctypes.c_uint32),
        ("channel", ctypes.c_uint8),
        ("tier", ctypes.c_uint8),
        ("reserved", ctypes.c_uint16),
        ("seq_num", ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
        ("hmac", ctypes.c_uint8 * VIRP_HMAC_SIZE),
    ]


class VIRPObservationHdr(ctypes.Structure):
    """Mirrors virp_observation_t (packed, 4 bytes)."""
    _pack_ = 1
    _fields_ = [
        ("obs_type", ctypes.c_uint8),
        ("obs_scope", ctypes.c_uint8),
        ("obs_length", ctypes.c_uint16),
    ]


# ── Library loader ─────────────────────────────────────────────────

def _load_libvirp() -> ctypes.CDLL:
    """
    Load libvirp.so. Raises RuntimeError if not found.
    No fallback — the C library is mandatory.
    """
    # Module-relative: api/virp_bridge.py → ../build/libvirp.so. Resolves
    # to wherever the repo is checked out so callers don't need to install
    # into /opt or /usr. Kept in the list alongside the legacy /opt path
    # so existing deployments still work.
    _repo_build = os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "build", "libvirp.so")
    )
    search_paths = [
        os.environ.get("VIRP_LIB_PATH", ""),
        _repo_build,
        "/opt/virp/build/libvirp.so",
        "/usr/local/lib/libvirp.so",
        "/usr/lib/libvirp.so",
    ]

    # Also try ctypes.util
    found = ctypes.util.find_library("virp")
    if found:
        search_paths.insert(0, found)

    for path in search_paths:
        if path and os.path.exists(path):
            try:
                lib = ctypes.CDLL(path)
                logger.info(f"Loaded libvirp from {path}")
                return lib
            except OSError as e:
                logger.warning(f"Failed to load {path}: {e}")

    raise RuntimeError(
        "libvirp.so not found. Build with: cd /opt/virp && make CISCO=1 FORTIGATE=1"
    )


# ── Bridge class ───────────────────────────────────────────────────

class VIRPBridge:
    """
    Python bridge to the VIRP C library.

    All routing and signing goes through C. No Python fallback.
    """

    def __init__(self, key_path: Optional[str] = None):
        self._lib = _load_libvirp()
        self._setup_ctypes()
        self._signing_key = None

        if key_path:
            self.load_key(key_path)

        logger.info("VIRP bridge loaded (native C library)")

    def _setup_ctypes(self):
        """Define C function signatures for ctypes."""
        lib = self._lib

        # TODO(2026-04-12): fg_route_command and FG_ROUTE_TABLE_SIZE are not
        # yet implemented in libvirp.so. fg_route_table_full.c exists but has
        # no function, no header, and is not in LIB_OBJS. Re-add bindings
        # once the C side is integrated.

        # ── Key management ──
        # virp_error_t virp_key_init(virp_signing_key_t *sk,
        #     virp_key_type_t type, const uint8_t key_bytes[32])
        lib.virp_key_init.argtypes = [
            ctypes.POINTER(VIRPSigningKey),
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_uint8),
        ]
        lib.virp_key_init.restype = ctypes.c_int

        # virp_error_t virp_key_load_file(virp_signing_key_t *sk,
        #     virp_key_type_t type, const char *path)
        lib.virp_key_load_file.argtypes = [
            ctypes.POINTER(VIRPSigningKey),
            ctypes.c_int,
            ctypes.c_char_p,
        ]
        lib.virp_key_load_file.restype = ctypes.c_int

        # void virp_key_destroy(virp_signing_key_t *sk)
        lib.virp_key_destroy.argtypes = [ctypes.POINTER(VIRPSigningKey)]
        lib.virp_key_destroy.restype = None

        # ── Observation building (includes signing) ──
        # virp_error_t virp_build_observation(uint8_t *buf, size_t buf_len,
        #     size_t *out_len, uint32_t node_id, uint32_t seq_num,
        #     uint8_t obs_type, uint8_t obs_scope,
        #     const uint8_t *data, uint16_t data_len,
        #     const virp_signing_key_t *sk)
        lib.virp_build_observation.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),     # buf
            ctypes.c_size_t,                     # buf_len
            ctypes.POINTER(ctypes.c_size_t),     # out_len
            ctypes.c_uint32,                     # node_id
            ctypes.c_uint32,                     # seq_num
            ctypes.c_uint8,                      # obs_type
            ctypes.c_uint8,                      # obs_scope
            ctypes.POINTER(ctypes.c_uint8),      # data
            ctypes.c_uint16,                     # data_len
            ctypes.POINTER(VIRPSigningKey),       # sk
        ]
        lib.virp_build_observation.restype = ctypes.c_int

        # ── Signature verification ──
        # virp_error_t virp_verify(virp_context_t *ctx,
        #     const uint8_t *msg, size_t msg_len,
        #     const virp_signing_key_t *sk)
        lib.virp_verify.argtypes = [
            ctypes.c_void_p,                    # ctx (unused, pass NULL)
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(VIRPSigningKey),
        ]
        lib.virp_verify.restype = ctypes.c_int

        # ── Message parsing (C parse path — no Python reimplementation) ──
        # virp_error_t virp_header_deserialize(virp_header_t *hdr,
        #     const uint8_t *buf, size_t buf_len)
        lib.virp_header_deserialize.argtypes = [
            ctypes.POINTER(VIRPHeader),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
        ]
        lib.virp_header_deserialize.restype = ctypes.c_int

        # virp_error_t virp_header_validate(const virp_header_t *hdr)
        lib.virp_header_validate.argtypes = [ctypes.POINTER(VIRPHeader)]
        lib.virp_header_validate.restype = ctypes.c_int

        # virp_error_t virp_parse_observation(const uint8_t *payload,
        #     size_t payload_len, virp_observation_t *obs,
        #     const uint8_t **data, uint16_t *data_len)
        lib.virp_parse_observation.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(VIRPObservationHdr),
            ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
            ctypes.POINTER(ctypes.c_uint16),
        ]
        lib.virp_parse_observation.restype = ctypes.c_int

        # ── Raw HMAC ──
        # void virp_hmac_sha256(const uint8_t key[32],
        #     const uint8_t *data, size_t data_len, uint8_t out[32])
        lib.virp_hmac_sha256.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
        ]
        lib.virp_hmac_sha256.restype = None

        # FG_ROUTE_TABLE_SIZE removed — see TODO above

    # ── Key management ─────────────────────────────────────────────

    def load_key(self, path: str, key_type: int = KeyType.OKEY):
        """Load a signing key from a file via the C library."""
        sk = VIRPSigningKey()
        err = self._lib.virp_key_load_file(
            ctypes.byref(sk),
            ctypes.c_int(key_type),
            path.encode("utf-8"),
        )
        if err != 0:
            raise RuntimeError(f"virp_key_load_file failed: error {err}")
        self._signing_key = sk

    def init_key(self, key_bytes: bytes, key_type: int = KeyType.OKEY):
        """Initialize a signing key from raw bytes via the C library."""
        if len(key_bytes) != VIRP_KEY_SIZE:
            raise ValueError(f"Key must be {VIRP_KEY_SIZE} bytes, got {len(key_bytes)}")
        sk = VIRPSigningKey()
        key_buf = (ctypes.c_uint8 * VIRP_KEY_SIZE)(*key_bytes)
        err = self._lib.virp_key_init(
            ctypes.byref(sk),
            ctypes.c_int(key_type),
            key_buf,
        )
        if err != 0:
            raise RuntimeError(f"virp_key_init failed: error {err}")
        self._signing_key = sk

    # ── Observation signing ────────────────────────────────────────

    def build_signed_observation(self, device_output: bytes,
                                  node_id: int, seq_num: int,
                                  obs_type: int = ObsType.DEVICE_OUTPUT,
                                  obs_scope: int = ObsScope.LOCAL) -> bytes:
        """
        Build a signed VIRP observation message via the C library.

        Takes raw device output, wraps it in the VIRP wire format with
        a proper header + observation sub-header, and signs it with
        HMAC-SHA256 using the loaded O-Key.

        Returns the complete signed message as bytes.
        """
        if self._signing_key is None:
            raise RuntimeError("No signing key loaded. Call load_key() or init_key() first.")

        buf = (ctypes.c_uint8 * VIRP_MAX_MESSAGE_SIZE)()
        out_len = ctypes.c_size_t(0)

        data_len = len(device_output)
        if data_len > 65535:
            raise ValueError(f"Device output too large: {data_len} bytes (max 65535)")

        data_buf = (ctypes.c_uint8 * data_len)(*device_output)

        err = self._lib.virp_build_observation(
            buf,
            ctypes.c_size_t(VIRP_MAX_MESSAGE_SIZE),
            ctypes.byref(out_len),
            ctypes.c_uint32(node_id),
            ctypes.c_uint32(seq_num),
            ctypes.c_uint8(obs_type),
            ctypes.c_uint8(obs_scope),
            data_buf,
            ctypes.c_uint16(data_len),
            ctypes.byref(self._signing_key),
        )

        if err != 0:
            raise RuntimeError(f"virp_build_observation failed: error {err}")

        return bytes(buf[:out_len.value])

    # ── Signature verification ─────────────────────────────────────

    def verify_observation(self, msg: bytes) -> bool:
        """
        Verify the HMAC-SHA256 signature on a VIRP message using the C library.
        Returns True if valid, False if invalid.
        """
        if self._signing_key is None:
            raise RuntimeError("No signing key loaded. Call load_key() or init_key() first.")

        msg_buf = (ctypes.c_uint8 * len(msg))(*msg)
        err = self._lib.virp_verify(
            None,                               # ctx — unused by virp_verify
            msg_buf,
            ctypes.c_size_t(len(msg)),
            ctypes.byref(self._signing_key),
        )
        return err == 0

    # ── Message parsing ────────────────────────────────────────────

    def parse_observation(self, msg: bytes) -> dict:
        """
        Parse a signed v1 OBSERVATION message via the C library and
        return its header fields and payload — decoded from the message
        bytes only.

        Does NOT verify the signature; call verify_observation() first.
        Raises ValueError on any structural inconsistency: bad header,
        wrong message type, declared length not matching the actual
        message size, or an observation length that does not account
        for every payload byte (virp_parse_observation itself does not
        bounds-check obs_length, so that is enforced here).
        """
        if len(msg) < VIRP_HEADER_SIZE + 4:
            raise ValueError(f"message too short ({len(msg)} bytes)")

        buf = (ctypes.c_uint8 * len(msg))(*msg)
        hdr = VIRPHeader()
        err = self._lib.virp_header_deserialize(
            ctypes.byref(hdr), buf, ctypes.c_size_t(len(msg)))
        if err != 0:
            raise ValueError(f"virp_header_deserialize failed: error {err}")

        err = self._lib.virp_header_validate(ctypes.byref(hdr))
        if err != 0:
            raise ValueError(f"virp_header_validate failed: error {err}")

        if hdr.type != MsgType.OBSERVATION:
            raise ValueError(f"not an OBSERVATION message (type 0x{hdr.type:02x})")
        if hdr.length != len(msg):
            raise ValueError(
                f"declared length {hdr.length} != actual message size {len(msg)}")

        payload_len = len(msg) - VIRP_HEADER_SIZE
        payload_buf = (ctypes.c_uint8 * payload_len)(*msg[VIRP_HEADER_SIZE:])
        obs = VIRPObservationHdr()
        data_ptr = ctypes.POINTER(ctypes.c_uint8)()
        data_len = ctypes.c_uint16(0)
        err = self._lib.virp_parse_observation(
            payload_buf, ctypes.c_size_t(payload_len),
            ctypes.byref(obs), ctypes.byref(data_ptr), ctypes.byref(data_len))
        if err != 0:
            raise ValueError(f"virp_parse_observation failed: error {err}")

        if obs.obs_length != payload_len - 4:
            raise ValueError(
                f"observation length {obs.obs_length} does not match "
                f"payload size {payload_len - 4}")

        payload = bytes(payload_buf[4:4 + obs.obs_length]) if obs.obs_length else b""

        return {
            "version": hdr.version,
            "type": hdr.type,
            "node_id": hdr.node_id,
            "channel": hdr.channel,
            "tier": hdr.tier,
            "seq_num": hdr.seq_num,
            "timestamp_ns": hdr.timestamp_ns,
            "obs_type": obs.obs_type,
            "obs_scope": obs.obs_scope,
            "payload": payload,
        }

    def __del__(self):
        if hasattr(self, '_signing_key') and self._signing_key is not None:
            self._lib.virp_key_destroy(ctypes.byref(self._signing_key))
