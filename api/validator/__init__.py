"""
Response validator client — CT 210 side.

Talks to virp-onode over the Unix socket (or the virp-socat TCP proxy at
10.0.0.211:9999) and invokes the validate_turn action implemented in
src/virp_onode.c. The validator itself (src/virp_validator.c) runs on
CT 211 alongside the O-Node and the chain.db — that's the trust
boundary CT 210 cannot cross.

Wire contract matches ONODE_ACTION_VALIDATE_TURN (= 13):

  Request (framed JSON, same envelope as every other onode action):
    {
      "action": "validate_turn",
      "session_id": "<fallback, used if the embedded manifest.session_id
                     is missing/unparseable>",
      "prose": "<the exact prose bytes the AI layer is about to emit>",
      "manifest": {<sidecar — see docs/VALIDATOR-MANIFEST-CONTRACT.md>}
    }

  Response: a signed VIRP OBSERVATION (type=0x01, tier=GREEN) whose
  obs_type == VIRP_OBS_VALIDATION_DECISION (0x10). The observation
  payload is UTF-8 JSON:
    {
      "decision": "pass" | "warn" | "block",
      "turn_violation": <int, see Violation enum below>,
      "chain_sequence": <int>,
      "chain_entry_hash": "<64-hex>",
      "artifact_hash": "<64-hex>",
      "assertions": [{"decision": "...", "violation": <int>}, ...]
    }

A missing, empty, or malformed manifest does NOT return an error frame —
the dispatcher commits a MANIFEST_MISSING / MANIFEST_MALFORMED BLOCK to
chain.db and returns the signed decision anyway. There is no fail-open
path by design.

Copyright 2026 Third Level IT LLC.
"""

# ---------------------------------------------------------------------------
# TODO — mandatory O-Key signature verification
#
# validate_turn() currently accepts bridge= as an optional parameter for
# HMAC verification of the signed observation response. This means a
# caller that forgets to pass bridge= will trust whatever CT 211 claims,
# unverified.
#
# Target state: the O-Key's public fingerprint is pinned on CT 210 (see
# server.py:key_info()), validate_turn rejects any response whose
# signature does not verify against the pinned fingerprint, and the
# bridge= parameter becomes non-optional.
#
# Not done now because it requires deciding where O-Key fingerprint
# material lives on CT 210 and how it's rotated. Revisit before the
# validator moves to production-enforcing mode (i.e. before CT 210's AI
# layer is required to emit manifests).
# ---------------------------------------------------------------------------

import hashlib
import json
import os
import socket
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional


# Defaults mirror api/server.py so the same env overrides apply.
VIRP_SOCKET = os.environ.get("VIRP_SOCKET", "/tmp/virp-onode.sock")
VIRP_FRAME_VERSION = 0x02
ONODE_MAX_REQUEST_SIZE = 24576
VIRP_HEADER_SIZE = 56
VIRP_OBS_VALIDATION_DECISION = 0x10


# -- Enums mirroring include/virp_validator.h ------------------------------

class Decision(IntEnum):
    PASS = 0
    WARN = 1
    BLOCK = 2


class Violation(IntEnum):
    NONE = 0
    NO_EVIDENCE_STATE_READ = 1
    NO_EVIDENCE_STATE_CHANGE = 2
    EVIDENCE_NOT_IN_TURN = 3
    EVIDENCE_NOT_IN_CHAIN = 4
    UNKNOWN_CLAIM_TYPE = 5
    PROSE_HASH_MISMATCH = 6
    MANIFEST_MALFORMED = 7
    MANIFEST_TOO_LARGE = 8
    MANIFEST_MISSING = 9


# -- Manifest construction helpers -----------------------------------------

@dataclass
class Assertion:
    """One per device-state claim the AI makes in this turn's prose.

    `evidence_ref` is the 64-hex SHA-256 of an artifact the O-Node
    produced this turn. Set to None for explicit "no evidence"; the
    contract requires either a real ref OR an explicit None, never a
    missing field (though the C parser is lenient and accepts both).
    """
    device: str
    claim_type: str  # "state_read" | "state_change" | "config_change"
    evidence_ref: Optional[str] = None

    def to_manifest(self) -> dict:
        return {
            "device": self.device,
            "claim_type": self.claim_type,
            "evidence_ref": self.evidence_ref,
        }


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_manifest(session_id: str,
                   prose: str,
                   tool_call_refs: list,
                   assertions: list) -> dict:
    """Construct the manifest sidecar dict in the exact shape the C
    parser expects. `tool_call_refs` must be a list of 64-hex strings;
    `assertions` is a list of Assertion."""
    return {
        "session_id": session_id,
        "prose_hash": sha256_hex(prose.encode("utf-8")),
        "tool_call_refs": list(tool_call_refs),
        "assertions": [a.to_manifest() for a in assertions],
    }


# -- Socket framing (matches api/server.py) --------------------------------

def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed prematurely")
        buf += chunk
    return buf


def _send_framed(sock, obj: dict) -> None:
    payload = json.dumps(obj).encode("utf-8")
    frame_len = 1 + len(payload)
    if frame_len > ONODE_MAX_REQUEST_SIZE:
        raise ValueError(
            f"request frame {frame_len} exceeds "
            f"ONODE_MAX_REQUEST_SIZE ({ONODE_MAX_REQUEST_SIZE})"
        )
    header = struct.pack("!I", frame_len) + bytes([VIRP_FRAME_VERSION])
    sock.sendall(header + payload)


def _recv_framed(sock) -> bytes:
    raw = _recv_exact(sock, 4)
    length = struct.unpack("!I", raw)[0]
    if length == 0:
        return b""
    return _recv_exact(sock, length)


def _parse_observation(msg: bytes):
    """Minimal VIRP observation parser — validates length fields,
    extracts obs_type, JSON body, and HMAC. Returns a tuple of
    (obs_type, body_bytes, hmac_hex)."""
    if len(msg) < VIRP_HEADER_SIZE + 4:
        raise ValueError(f"response too short: {len(msg)} bytes")
    (_ver, _msg_type, length, _nid, _channel, _tier, _rsv, _seq, _ts
     ) = struct.unpack_from("!BBHI BBHI Q", msg, 0)
    if length != len(msg):
        raise ValueError(
            f"declared length {length} does not match received {len(msg)}"
        )
    hmac_hex = msg[24:56].hex()
    payload = msg[VIRP_HEADER_SIZE:]
    if len(payload) < 4:
        raise ValueError("observation payload too short")
    obs_type = payload[0]
    obs_length = struct.unpack_from("!H", payload, 2)[0]
    body = payload[4:4 + obs_length]
    return obs_type, body, hmac_hex


# -- Result --------------------------------------------------------------

@dataclass
class ValidationResult:
    decision: Decision
    turn_violation: Violation
    chain_sequence: int
    chain_entry_hash: str
    artifact_hash: str
    per_assertion: list   # [(Decision, Violation), ...]
    signature_hex: str
    verified: bool        # True only if an HMAC-capable bridge was supplied

    def banner(self) -> Optional[str]:
        """Return a short banner string for non-PASS decisions.

        Per the locked UX: non-PASS attaches a banner, never censors the
        prose. BLOCK still returns only a banner here — the caller
        decides whether to additionally withhold the prose.
        """
        if self.decision == Decision.PASS:
            return None
        if self.decision == Decision.WARN:
            return (
                f"[VIRP VALIDATOR WARN] one or more claims lack evidence "
                f"(chain seq {self.chain_sequence})"
            )
        reason = self.turn_violation.name
        if reason == "NONE":
            # Turn-wide was clean, so the BLOCK came from an assertion.
            # Surface the first offender.
            for d, v in self.per_assertion:
                if d == Decision.BLOCK:
                    reason = v.name
                    break
        return (
            f"[VIRP VALIDATOR BLOCK] {reason} "
            f"(chain seq {self.chain_sequence})"
        )


# -- Main entry point ----------------------------------------------------

def validate_turn(session_id: str,
                  prose: str,
                  manifest: dict,
                  socket_path: str = VIRP_SOCKET,
                  timeout: float = 15.0,
                  bridge=None) -> ValidationResult:
    """Call the O-Node's validate_turn action and return the decision.

    `bridge`: optional object implementing `.verify_observation(msg) -> bool`
    (e.g. an api.virp_bridge.VIRPBridge with the O-Key loaded). When
    provided, ValidationResult.verified reflects the HMAC check. Without
    a bridge, .verified is False and the caller must rely on the chain
    commit (chain_sequence / chain_entry_hash) for durability.
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(socket_path)
        _send_framed(sock, {
            "action": "validate_turn",
            "session_id": session_id,
            "prose": prose,
            "manifest": manifest,
        })
        raw = _recv_framed(sock)
    finally:
        sock.close()

    if len(raw) == 0:
        raise ConnectionError("empty response from onode")
    if len(raw) == 4:
        err_code = struct.unpack("!I", raw)[0]
        raise ConnectionError(f"onode error code: {err_code}")

    obs_type, body, hmac_hex = _parse_observation(raw)
    if obs_type != VIRP_OBS_VALIDATION_DECISION:
        raise ValueError(
            f"unexpected obs_type 0x{obs_type:02x}; "
            f"expected 0x{VIRP_OBS_VALIDATION_DECISION:02x}"
        )

    decision = json.loads(body.decode("utf-8"))

    verified = False
    if bridge is not None:
        try:
            verified = bool(bridge.verify_observation(raw))
        except Exception:
            verified = False

    per = [
        (Decision[a["decision"].upper()], Violation(int(a["violation"])))
        for a in decision.get("assertions", [])
    ]

    return ValidationResult(
        decision=Decision[decision["decision"].upper()],
        turn_violation=Violation(int(decision["turn_violation"])),
        chain_sequence=int(decision["chain_sequence"]),
        chain_entry_hash=decision["chain_entry_hash"],
        artifact_hash=decision["artifact_hash"],
        per_assertion=per,
        signature_hex=hmac_hex,
        verified=verified,
    )


def attach_banner(prose: str,
                  result: ValidationResult,
                  allow_blocked_prose: bool = False) -> str:
    """Apply the validator's decision to the outbound prose.

    - PASS: prose returned unchanged, no banner.
    - WARN: banner prepended, prose retained.
    - BLOCK: banner only. Prose is suppressed at the library level so
      that a caller who forgets to check result.decision still fails
      closed rather than leaking a fabrication.
    - BLOCK with allow_blocked_prose=True: banner + prose. Use only for
      audit or debugging contexts where seeing what was blocked is the
      point.
    """
    banner = result.banner()
    if banner is None:
        return prose
    if result.decision == Decision.BLOCK and not allow_blocked_prose:
        return banner
    return f"{banner}\n\n{prose}"


__all__ = [
    "Decision",
    "Violation",
    "Assertion",
    "ValidationResult",
    "sha256_hex",
    "build_manifest",
    "validate_turn",
    "attach_banner",
    "VIRP_OBS_VALIDATION_DECISION",
]
