
# VIRP — Verified Infrastructure Response Protocol

**Cryptographic trust primitives for AI agents operating on real infrastructure.**

When an AI agent tells you your firewall policy is misconfigured, can you prove it actually checked? When it says a BGP session is established, did it read that from a real device or fabricate it from training data? When it claims a config change succeeded, where's the evidence?

VIRP makes every agent claim verifiable. Not with prompts. Not with guardrails. With cryptography.

---

## What VIRP Does

VIRP is an open protocol that signs every device observation at the point of collection, before the AI ever sees it. A dedicated process — the O-Node — connects to your network devices, captures raw output, and signs it with HMAC-SHA256. The AI agent receives pre-signed data. It can reason about what the device returned. It cannot forge it, modify it, or fabricate it, because it never holds the signing key.

This is not a policy. It is a code path. Unsigned data cannot enter the observation channel.

```
Agent: "FortiGate policy 2 allows all traffic with no AV/IPS."

VIRP: Here's the signed observation. HMAC da383afe...c18.
      Chain seq 1, session 3b579a43. Verify it yourself.
```

## Why This Exists

During development of a production AI operations platform, we watched an AI generate complete firewall policies with valid UUIDs that didn't exist on any device, report security threats from RFC 5737 documentation addresses, and propose routing changes based on fabricated OSPF adjacency states. Every output was technically plausible. None of it was real.

Prompt engineering didn't fix it. Output validation didn't fix it. The AI bypassed every behavioral guardrail by generating fabricated output directly in its response text, never invoking the signed execution path.

VIRP is the structural fix.

## Architecture

```
┌─────────────────────┐         ┌─────────────────────┐
│   AI Node (CT 210)  │         │   O-Node (CT 211)   │
│                     │  intent │                     │
│  OpenClaw Gateway   │────────>│  VIRP C Library     │
│  Agent + LLM        │         │  Device Credentials │
│                     │<────────│  Signing Keys       │
│  Zero credentials   │  signed │  Chain Database     │
│  Zero signing keys  │   obs   │  C Executor (SSH)   │
└─────────────────────┘         └──────────┬──────────┘
                                           │ SSH
                        ┌──────────────────┼──────────────────┐
                        │                  │                  │
                   ┌────┴────┐      ┌──────┴──────┐    ┌─────┴─────┐
                   │ Cisco   │      │  FortiGate  │    │  PA-850   │
                   │ IOS/ASA │      │    200G     │    │  PAN-OS   │
                   └─────────┘      └─────────────┘    └───────────┘
```

The AI agent is smart enough to build its own drivers. The architecture makes sure it doesn't have to be trusted to.

## Transport Agnostic

VIRP signs observations, not packets. The protocol doesn't care whether the O-Node reached the device over SSH, a REST API, or a cloud SDK call. If an agent claims your S3 bucket is public, your Kubernetes pod is healthy, or your SaaS tenant is configured correctly — VIRP provides the same cryptographic proof.

Five drivers ship today (Cisco IOS, FortiOS, PAN-OS, ASA, Linux). The driver interface is the same for a CLI command over SSH and a JSON response from a cloud API. The trust boundary doesn't change with the transport.

## Beyond Networking

VIRP's trust primitives are not specific to network infrastructure. Any domain where AI agents make claims about real-world system state faces the same verification problem.

**Healthcare** — An AI reviews patient monitoring data and recommends a dosage change. VIRP can sign the raw telemetry at the point of collection, proving the agent's recommendation is based on actual readings, not hallucinated vitals. Every clinical decision has a cryptographic evidence trail.

**Aviation** — An AI agent reports that an aircraft system passed a maintenance check. Signed observations prove the diagnostic tool returned those specific readings. The evidence-gated verdict means the system will not clear an aircraft when sensor data is missing or degraded — it reports "evidence limited" instead of guessing.

**Defense and Critical Infrastructure** — Autonomous systems operating in contested environments need tamper-proof proof of what they observed and what actions they took. The signed observation chain provides non-repudiable audit logs. Federation (Primitive 6) allows verification across organizational boundaries without sharing signing keys.

**Industrial Control and Energy** — SCADA and ICS environments where an AI agent reporting false sensor readings could cause physical harm. VIRP ensures the agent's claims about pressure, temperature, or flow rates are backed by signed readings from the actual sensor, not inferred from a model.

The trust model is the same everywhere: separate observation from reasoning, sign at the point of collection, and never let the AI hold the signing key. The driver changes. The cryptography doesn't.

## Seven Trust Primitives

VIRP defines seven primitives. Together they form a complete trust layer for agentic infrastructure operations.

| # | Primitive | What It Does | Status |
|---|-----------|-------------|--------|
| P1 | **Signed Observation** | Every device output HMAC-signed at point of collection. Agent never holds the key. | Production |
| P2 | **Evidence-Gated Verdict** | System refuses conclusions when evidence is degraded. "I don't know" beats a guess. | Production |
| P3 | **Continuous Attestation** | Ongoing signed health monitoring, not point-in-time snapshots. | Planned |
| P4 | **Reversible Action Proof** | Before/after signed snapshots with cryptographic rollback capability. | Planned |
| P5 | **Device Identity Binding** | Observations anchored to hardware serial numbers and firmware fingerprints. | Next |
| P6 | **Cross-Domain Federation** | Ed25519 asymmetric signatures for multi-tenant verification without shared secrets. | Implemented |
| P7 | **Tamper-Evident Logging** | SQLite-backed chain with HMAC linkage, auto-milestones, and crash recovery. | Implemented |

## Trust Tiers

Every command is classified at the O-Node level — not by the AI:

| Tier | Approval | Example |
|------|----------|---------|
| **GREEN** | None — agent executes freely | `show version`, `show route`, `show access-list` |
| **YELLOW** | Flagged for review | `description`, SNMP community changes |
| **RED** | Human approval required | ACL changes, routing policy, firewall rules |
| **BLACK** | Blocked unconditionally | `write erase`, `reload`, uplink shutdown |

BLACK tier commands are rejected in C before they reach the network. The agent cannot override this regardless of how it's prompted.

## What's In The Box

**C Library (libvirp)** — ~8,500 lines of production C compiled with `-Wall -Wextra -Werror -pedantic -std=c11`. No dynamic allocation in the crypto path. Constant-time HMAC comparison. Explicit key zeroing with volatile to defeat compiler optimization.

**Five Vendor Drivers:**
- `driver_cisco.c` — Cisco IOS (tested on 35 routers + SW-3850)
- `driver_fortigate.c` — FortiOS (tested on FortiGate-200G, SSH + REST dual-path)
- `driver_panos.c` — Palo Alto PAN-OS (tested on PA-850)
- `driver_asa.c` — Cisco ASA (tested on ASA-5525, native driver with enable mode persistence)
- `driver_linux.c` — Linux/SSH (servers, SIEM, hypervisors)

**Go Implementation** — 2,700+ lines with C interoperability tests. Same wire format, independent implementation.

**Trust Chain** — SQLite-backed with transactional sequencing, auto-milestones every 100 entries, and crash recovery. Every observation is chained with monotonic sequence numbers and nanosecond timestamps.

**Federation** — Ed25519 via libsodium with `sodium_mlock()` on secret keys. Verify observations from remote O-Nodes without holding their signing keys.

**700+ test assertions** across unit tests, integration tests, interop tests, and a fuzz harness.

## Security Model

VIRP uses a layered trust model designed for the threat profile of agentic AI:

**Local trust (Primitives 1-5):** HMAC-SHA256 between the O-Node and devices. The AI agent never holds the signing key. The O-Node is architecturally isolated — separate container, separate credentials, separate keys. Forgery requires compromising the O-Node itself, which the agent cannot reach.

**Federation trust (Primitive 6):** Ed25519 asymmetric signatures for cross-domain verification. A remote NOC or customer can verify observation chains using only the O-Node's public key. Verify without forge.

**Channel separation:** O-Keys can only sign Observation Channel messages. R-Keys can only sign Intent Channel messages. This binding is enforced in code (`check_channel_key_binding`), not in configuration. A key that signs observations physically cannot sign intents, and vice versa.

The HMAC layer is intentionally scoped to the single-node trust boundary where performance matters. Ed25519 wraps it for external verification where non-repudiation matters. This is the same layered approach used in TLS (symmetric session keys inside asymmetric handshakes).

## Production Results

These numbers are from live hardware, not simulations:

- **40 devices** under active VIRP management across 5 vendor platforms
- **35-router scale test** — 13 autonomous systems, full BGP topology, all observations HMAC-verified in under 60 seconds
- **Per-device latency** — 2-4 seconds including SSH connect, command execution, signing, and chain write
- **FortiGate security audit** — 15 real findings (overly permissive policies, HTTP on management, cleartext DNS, factory certs), zero false positives, every finding backed by signed device output
- **ASA driver** — 1,800+ lines of C, 86 unit tests, 14 live SSH tests, built and validated against hardware in a single session
- **Zero fabricated findings** — the architecture makes fabrication impossible, not unlikely

## Quick Start

### Build

```bash
# Core library only
make

# With all drivers
make CISCO=1 FORTIGATE=1 PANOS=1 ASA=1 LINUX=1

# Production O-Node binary
make CISCO=1 FORTIGATE=1 PANOS=1 ASA=1 LINUX=1 prod

# Run tests
make test                    # Core protocol tests
make test-onode              # O-Node tests
make test-chain              # Trust chain tests
make test-federation         # Ed25519 federation tests
make test-asa                # ASA driver tests (requires ASA=1)
make all-tests               # Everything
```

### Dependencies

```
libcrypto (OpenSSL)    — HMAC-SHA256, SHA-256
libsodium              — Ed25519 federation signatures
libsqlite3             — Trust chain database
libssh2                — SSH device drivers (1.11+ for curve25519)
libjson-c              — Production O-Node config parsing
libcurl                — FortiGate REST API driver (optional)
```

### Deploy

```bash
# Generate signing keys
./build/virp-tool keygen -o /etc/virp/keys/onode.key

# Configure devices
cp devices-r35.json /etc/virp/devices.json

# Start the O-Node
./build/virp-onode-prod \
    -k /etc/virp/keys/onode.key \
    -s /tmp/virp-onode.sock \
    -d /etc/virp/devices.json \
    -c /var/lib/virp/chain.db \
    -C /etc/virp/keys/chain.key

# Verify an observation
./build/virp-tool verify -k /etc/virp/keys/onode.key -f observation.bin
```

See `deploy/virp-onode.service` for the systemd unit.

## Wire Format

56-byte fixed header, network byte order:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |     Type      |            Length              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Node ID                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Channel    |     Tier      |           Reserved            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Sequence Number                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Timestamp (nanoseconds)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                      HMAC-SHA256 (32 bytes)                   |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Full wire format specification: [VIRP-WIRE-FORMAT.md](VIRP-WIRE-FORMAT.md)

## Protocol Specification

The formal protocol specification is published as an Internet-Draft:

- **RFC Draft:** draft-howard-virp-02
- **DOI:** Zenodo registered
- **Specification:** [VIRP-SPEC-RFC-v2.md](VIRP-SPEC-RFC-v2.md)
- **Paper:** [VIRP-Paper-arXiv.pdf](VIRP-Paper-arXiv.pdf)

## Project Structure

```
virp/
├── include/                    # C headers — protocol, drivers, crypto
│   ├── virp.h                  # Core protocol definitions (338 lines)
│   ├── virp_crypto.h           # Signing and verification API
│   ├── virp_chain.h            # Trust chain API
│   ├── virp_federation.h       # Ed25519 federation API
│   ├── virp_driver.h           # Driver abstraction layer
│   ├── virp_driver_asa.h       # ASA driver header
│   ├── virp_driver_cisco.h     # Cisco IOS driver header
│   ├── virp_driver_fortigate.h # FortiGate driver header
│   └── driver_panos.h          # PAN-OS driver header
├── src/                        # C implementation
│   ├── virp_crypto.c           # HMAC-SHA256, key management (256 lines)
│   ├── virp_message.c          # Message serialization (920 lines)
│   ├── virp_onode.c            # O-Node core logic (990 lines)
│   ├── virp_chain.c            # Trust chain with SQLite (776 lines)
│   ├── virp_federation.c       # Ed25519 federation (212 lines)
│   ├── virp_onode_prod.c       # Production O-Node with device config
│   └── drivers/
│       ├── driver_cisco.c      # Cisco IOS — 35 routers tested
│       ├── driver_fortigate.c  # FortiOS — SSH + REST dual-path
│       ├── driver_asa.c        # Cisco ASA — native enable mode handling
│       ├── driver_linux.c      # Linux/SSH
│       └── driver_mock.c       # Mock driver for testing
├── implementations/
│   └── go/                     # Go implementation (2,700+ lines)
├── tests/
│   ├── test_virp.c             # Core protocol tests
│   ├── test_chain.c            # Trust chain tests
│   ├── test_federation.c       # Federation tests
│   ├── test_driver_asa.c       # ASA driver tests (86 assertions)
│   ├── test_onode.c            # O-Node tests
│   ├── fuzz_virp.c             # Fuzz harness
│   └── virp_sweep.c            # Multi-device sweep test
├── api/                        # Python integration layer
├── deploy/                     # Systemd service units
├── VIRP-SPEC-RFC-v2.md         # Formal protocol specification
├── VIRP-WIRE-FORMAT.md         # Wire format specification
└── Makefile                    # Build system with per-driver flags
```

## Maturity

| Milestone | Status |
|-----------|--------|
| Protocol specification | Published (draft-howard-virp-02) |
| C reference implementation | Production (8,500+ lines) |
| Go implementation | Complete (2,700+ lines) |
| C/Go interoperability | Tested |
| Multi-vendor drivers | 5 platforms, hardware-tested |
| Trust chain with persistence | Production (SQLite) |
| Ed25519 federation | Implemented |
| Test coverage | 700+ assertions + fuzz harness |
| External security review | In progress |
| Independent deployment | Seeking collaborators |

## Contributing

VIRP is Apache 2.0. Contributions welcome:

- **Infrastructure engineers** — test VIRP against your devices, report what breaks
- **Security researchers** — audit the crypto, challenge the trust model
- **Driver authors** — Juniper, Arista, Meraki, cloud APIs all need drivers
- **Protocol designers** — review the RFC draft, propose improvements

If you want to validate VIRP independently, the Go implementation exists specifically for that purpose. Build both, run the interop tests, and verify the wire format matches.

## Contact

Nathan M. Howard
Third Level IT LLC
nhoward@thirdlevelit.com

---

*"A responsible system does not guess when evidence is absent. It says: I don't know, and here's why."*
