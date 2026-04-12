VIRP Observation Flow — End to End

Query: "What is R1's uptime?"
Step 1 — You or the AI sends a request to the bridge (CT 210, port 9998)
￼
json
POST http://localhost:9998
{
  "hostname": "R1",
  "command": "show version"
}
virp-bridge.py receives this on CT 210.

Step 2 — Bridge checks session state
Before doing anything, virp_session_require_active() is called in C.

￼
c
if (g_virp_session.state != VIRP_SESSION_ACTIVE)
    return VIRP_ERR_SESSION_INVALID;
If no active session exists — meaning HELLO/HELLO_ACK/SESSION_BIND haven't completed — the request dies here. The AI gets nothing.

If session is ACTIVE, it also checks:

￼
c
if (!g_virp_session.session_key_valid)
    return VIRP_ERR_SESSION_INVALID;
The derived session key must exist. No session key, no observations.

Step 3 — Bridge sends JSON request to O-Node over Unix socket
CT 210 opens a TCP connection to CT 211 port 9999 (the socat bridge), which forwards to /tmp/virp-onode.sock.

￼
json
{
  "action": "execute",
  "device": "R1",
  "command": "show version"
}
This crosses the trust boundary. CT 210 has zero credentials. It just asked CT 211 to do the work.

Step 4 — O-Node looks up R1 in devices.json
On CT 211, the O-Node finds R1:

￼
json
{
  "hostname": "R1",
  "ip": "10.0.0.50",
  "device_id": 1,
  "type": "cisco_ios",
  "username": "virp-agent",
  "password": "changeme"
}
```

`device_id: 1` — this stable UUID goes into the signed header. Not the hostname string. If R1 gets renamed, the UUID doesn't change.

---

### Step 5 — C executor opens SSH to R1

`driver_cisco.c` opens an SSH session to `10.0.0.50` using libssh2:
```
SSH connect → authenticate → exec channel → "show version" → read output → close
```

Raw output comes back something like:
```
Cisco IOS Software, Version 15.2(4)M
Router uptime is 3 days, 14 hours, 22 minutes
System image file is "flash:c2900-universalk9-mz.SPA.152-4.M"
...
Step 6 — Command is canonicalized and hashed
Before signing, the command string is normalized:

￼
c
virp_canonicalize_command("show version", canon, sizeof(canon));
// result: "show version"
SHA256("show version") → command_hash = 7c2b4d3a...
This is what goes into the header. Proves exactly which command produced this output.

Step 7 — v2 observation header is built
￼
c
virp_obs_header_v2_t hdr = {
    .version      = 2,
    .channel      = VIRP_CHANNEL_OBS,
    .tier         = GREEN,           // show version is read-only
    .node_id      = 0x00000001,      // this O-Node's identity
    .timestamp_ns = 1741823422917384, // nanoseconds since epoch
    .seq_num      = 4882,            // next in chain
    .session_id   = {0xf8,0x4c,...}, // from the active session
    .device_id    = 1,               // R1's stable UUID
    .command_hash = {0x7c,0x2b,...}, // SHA-256 of "show version"
    .payload_len  = 847,             // bytes of device output
};
```

---

### Step 8 — HMAC is computed with the session key

The session key was derived at handshake time:
```
session_key = HKDF(
    master_key,
    salt = SHA-256(HELLO || HELLO_ACK || SESSION_BIND),
    info = generation counter
)
Now it signs:

￼
c
HMAC_SHA256(
    session_key,     // derived key — master key is NOT used directly
    &hdr,            // entire v2 header
    payload,         // raw "show version" output
    → signature[32]  // da383afe...c18
)
The master key never touched this. A key that was derived from this specific negotiated session signed this specific observation.

Step 9 — Observation is appended to chain.db
SQLite on CT 211:

￼
sql
INSERT INTO chain (seq, timestamp_ns, device_id, command_hash, 
                   session_id, hmac, payload)
VALUES (4882, 1741823422917384, 1, '7c2b4d3a...', 
        'f84c1a3e...', 'da383afe...', '<raw output>');
Tamper-evident. Every 100 entries a milestone hash is written that covers all previous entries.

Step 10 — Binary VIRP message sent back to bridge
CT 211 sends the signed binary observation back over the socket to CT 210.

Step 11 — Bridge calls C library to verify
On CT 210, virp_ctypes_verify_observation() is called via ctypes:

￼
c
virp_validate_message(raw, len, &session_key, &hdr);
virp_parse_observation(raw + HEADER_SIZE, ...);
If HMAC doesn't verify — observation is rejected. The AI never sees it.

If it verifies — the bridge builds the JSON response:

￼
json
{
  "verdict": "VERIFIED",
  "chain_seq": 4882,
  "trust_tier": "GREEN",
  "session_id": "f84c1a3e229d4b8b...",
  "node_id": "0x00000001",
  "device_id": "0x00000001",
  "command_hash": "7c2b4d3a...",
  "timestamp": "2026-03-11T14:30:22.917384Z",
  "latency_ms": 1843.2,
  "raw_output": "Cisco IOS Software...\nRouter uptime is 3 days, 14 hours, 22 minutes\n..."
}
Step 12 — AI reads the verified observation
The AI now sees R1's uptime. It knows:

This output was collected by O-Node 0x00000001
From device 0x00000001 (R1)
In response to exactly "show version"
At 2026-03-11T14:30:22
In session f84c1a3e...
Signed with a key that only existed for this session
Chain position 4882 — nothing was skipped
R1 uptime is 3 days, 14 hours, 22 minutes.

And that claim is cryptographically provable.
