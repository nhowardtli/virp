# VIRP Wire Format Specification
**Version:** 0.4  
**Author:** Nate Howard, Third Level IT LLC  
**Contact:** nhoward@thirdlevelit.com  
**Repository:** https://github.com/nhowardtli/virp  
**Full RFC:** VIRP-SPEC-RFC-v2.md (draft-howard-virp-02)

---

## Purpose

This document is a minimal, self-contained description of the VIRP wire format sufficient to write an independent O-Node client in any language. It does not require reading the full RFC.

VIRP (Verified Infrastructure Response Protocol) is a two-channel cryptographic protocol for signing and verifying AI-collected infrastructure observations. This document covers message framing, HMAC computation, trust tiers, and the Unix socket protocol.

---

## 1. Transport

The O-Node exposes a Unix domain socket (default: `/tmp/virp-onode.sock`).

Clients connect, send a request frame, and receive a response frame. One request per connection is the simplest model. The O-Node supports up to 8 concurrent clients (`ONODE_MAX_CLIENTS=8`).

---

## 2. Message Frame

All VIRP messages share a common binary header followed by a variable-length payload.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    version    |   msg_type    |    channel    |  trust_tier   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          sequence                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          node_id                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       timestamp_ns (high 32)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       timestamp_ns (low 32)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       payload_length                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    hmac[0..31] (32 bytes)                     |
|                                                               |
|                                                               |
|                                                               |
|                                                               |
|                                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    payload (variable)                         |
|                         ...                                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Header size:** 56 bytes  
**HMAC field:** 32 bytes (bytes 24–55)  
**Payload:** immediately follows header, length given by `payload_length`

### Field Definitions

| Field | Size | Type | Description |
|-------|------|------|-------------|
| version | 1 byte | uint8 | Protocol version. Current: `0x01` |
| msg_type | 1 byte | uint8 | Message type (see Section 3) |
| channel | 1 byte | uint8 | `0x01` = OBSERVATION, `0x02` = INTENT |
| trust_tier | 1 byte | uint8 | `0x00`=GREEN, `0x01`=YELLOW, `0x02`=RED, `0x03`=BLACK |
| sequence | 4 bytes | uint32 BE | Monotonic sequence number, per node, no gaps |
| node_id | 4 bytes | uint32 BE | O-Node identifier |
| timestamp_ns | 8 bytes | uint64 BE | Unix nanosecond timestamp at collection time |
| payload_length | 4 bytes | uint32 BE | Length of payload in bytes |
| hmac | 32 bytes | bytes | HMAC-SHA256 (see Section 4) |

---

## 3. Message Types

```
0x01  OBSERVATION       Raw device output, signed by O-Node
0x02  OBSERVATION_ACK   Acknowledgment of received observation
0x03  HEARTBEAT         O-Node liveness signal
0x04  ERROR             Error response
0x05  SIGN_REQUEST      Client requests O-Node to sign a payload
0x06  SIGN_RESPONSE     O-Node returns signed message
0x07  VERIFY_REQUEST    Client requests O-Node to verify a message
0x08  VERIFY_RESPONSE   O-Node returns verification result
0x09  OUTCOME_SIGNED    Signed before/after outcome record
0x10  PROPOSAL          Intent channel: proposed configuration change
0x11  APPROVAL          Intent channel: human-authorized approval
0x12  REJECTION         Intent channel: rejected proposal
```

---

## 4. HMAC Computation

The HMAC is computed over the first 24 bytes of the header (everything before the HMAC field) concatenated with the payload.

```
HMAC-SHA256(key, header[0:24] || payload)
```

Where `||` denotes concatenation.

**Key material:** 32 bytes of random data, loaded from a file at O-Node startup (default: `/etc/virp/keys/onode.key`). The key never leaves the O-Node process.

**Verification:** A client cannot verify an observation without access to the key. This is intentional — the O-Node is the sole verification authority. Clients send `VERIFY_REQUEST` messages to ask the O-Node to verify.

---

## 5. Trust Tiers

| Tier | Value | Meaning | Default Action |
|------|-------|---------|----------------|
| GREEN | 0x00 | Read-only, non-destructive | Auto-execute |
| YELLOW | 0x01 | Potentially impactful | Require acknowledgment |
| RED | 0x02 | Configuration change | Require approval + change record |
| BLACK | 0x03 | Destructive / irreversible | No execution path exists |

BLACK tier operations are structurally absent. There is no code path that executes a BLACK-tier message. The tier exists only to classify and reject.

---

## 6. Channel Separation

VIRP enforces strict two-channel separation at the message level:

- **OBSERVATION channel (0x01):** Carries signed facts about infrastructure state. The AI receives observations but cannot inject into this channel.
- **INTENT channel (0x02):** Carries proposals from the AI. Intent messages are never treated as observations regardless of content.

Channel-key binding is enforced before HMAC computation. A message signed on the OBSERVATION channel cannot be replayed as an INTENT message — the HMAC will not verify because the channel byte differs.

---

## 7. Unix Socket Protocol

### Simple sign-and-return flow

```
Client                          O-Node
  |                               |
  |-- connect() ----------------> |
  |-- SIGN_REQUEST (payload) ---> |
  |                               | (computes HMAC, assigns sequence+timestamp)
  |<-- SIGN_RESPONSE ------------ |
  |-- close() ------------------> |
```

### Verify flow

```
Client                          O-Node
  |                               |
  |-- connect() ----------------> |
  |-- VERIFY_REQUEST (message) -> |
  |                               | (recomputes HMAC, checks sequence)
  |<-- VERIFY_RESPONSE ---------- |
  |    (verified: bool,           |
  |     reason: string) --------- |
  |-- close() ------------------> |
```

### Python example (minimal client)

```python
import socket
import struct
import hmac
import hashlib
import time

HEADER_FORMAT = ">BBBBIIQi"  # version, msg_type, channel, tier, seq, node_id, ts_ns, payload_len
HEADER_SIZE = 56  # includes 32-byte HMAC field

def send_sign_request(sock_path, payload: bytes) -> bytes:
    """Send payload to O-Node for signing, return signed message bytes."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(sock_path)
        
        # Build SIGN_REQUEST (msg_type=0x05)
        header_pre_hmac = struct.pack(
            ">BBBBII",
            0x01,        # version
            0x05,        # msg_type: SIGN_REQUEST
            0x01,        # channel: OBSERVATION
            0x00,        # trust_tier: GREEN
            0,           # sequence (O-Node assigns)
            0,           # node_id (O-Node assigns)
        )
        ts_ns = time.time_ns()
        header_pre_hmac += struct.pack(">Q", ts_ns)
        header_pre_hmac += struct.pack(">I", len(payload))
        
        # Placeholder HMAC (O-Node will compute real one)
        request = header_pre_hmac + b'\x00' * 32 + payload
        s.sendall(request)
        
        # Read response
        response = s.recv(65536)
        return response

def verify_message(message: bytes, key: bytes) -> bool:
    """Verify HMAC of a signed VIRP message."""
    header_pre_hmac = message[:24]
    payload_len = struct.unpack(">I", message[20:24])[0]
    received_hmac = message[24:56]
    payload = message[56:56 + payload_len]
    
    expected_hmac = hmac.new(key, header_pre_hmac + payload, hashlib.sha256).digest()
    return hmac.compare_digest(received_hmac, expected_hmac)
```

---

## 8. Sequence Numbers

Sequence numbers are monotonic, per-node, and must have no gaps. A gap in sequence numbers invalidates the chain from that point forward.

- Genesis sequence: 1
- Each signed message increments by exactly 1
- Sequence numbers are assigned by the O-Node, not the client
- Replay detection: a message with a sequence number ≤ the last seen sequence is rejected

---

## 9. Observation Freshness (TTL)

VIRP guarantees authenticity, not freshness. A valid HMAC on stale data is still stale data. Consumers should enforce TTLs appropriate to their observation type:

| Observation Type | Recommended TTL |
|-----------------|-----------------|
| BGP adjacency state | 30 seconds |
| Interface state | 30 seconds |
| Routing table | 45 seconds |
| OSPF adjacency | 30 seconds |
| Firewall policy | 300 seconds |
| CPU/Memory | 20 seconds |

Core/distribution devices should use shorter TTLs (0.5x multiplier) than access devices.

---

## 10. Implementing a Minimal O-Node Client

A conforming client must:

1. Connect to the Unix socket at the configured path
2. Send well-formed VIRP frames with correct byte order (big-endian)
3. Accept signed SIGN_RESPONSE frames from the O-Node
4. Never attempt to self-sign observations (no key access)
5. Send VERIFY_REQUEST to the O-Node for all verification operations
6. Respect trust tier gating (do not execute RED-tier operations without approval)

A conforming client must not:

1. Modify the HMAC field of received messages
2. Replay messages across sessions without re-signing
3. Execute BLACK-tier operations under any circumstances
4. Treat INTENT channel messages as OBSERVATION channel messages

---

## 11. Test Vectors

The following test vectors can be used to validate a VIRP implementation.

### Observation signing

```
Key (hex):    0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
Payload:      "show ip interface brief\nGigabitEthernet0/0 is up"
version:      0x01
msg_type:     0x01 (OBSERVATION)
channel:      0x01 (OBSERVATION)
trust_tier:   0x00 (GREEN)
sequence:     0x00000001
node_id:      0x00000001
timestamp_ns: 0x0000000000000000 (use 0 for test vector)
payload_len:  0x00000031 (49 bytes)

Expected HMAC: (compute with: HMAC-SHA256(key, header[0:24] || payload))
```

---

## 12. Known Limitations

- Single O-Node: no chain replication between nodes. Failover for RED-tier operations requires chain DB sync (not yet implemented).
- HMAC-SHA256 is symmetric: cross-organizational verification requires sharing the key. Ed25519 asymmetric signing is planned for Trust Federation (Primitive 7).
- No hardware attestation of the O-Node itself. The observation is only as trustworthy as the host running the O-Node.

---

## 13. Further Reading

- Full RFC: `draft-howard-virp-02` (VIRP-SPEC-RFC-v2.md in the repository)
- Reference implementation: https://github.com/nhowardtli/virp
- IronClaw (reference consumer): https://github.com/nhowardtli/ironclaw
- DOI: Published on Zenodo

---

*This document is intentionally minimal. If something is unclear, open an issue at https://github.com/nhowardtli/virp/issues — implementation questions improve this spec.*
