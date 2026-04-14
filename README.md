# VIRP — Verified Infrastructure Response Protocol

**Cryptographically verifiable observations from real infrastructure. Signed at collection. Chained. Independently auditable.**

> *Reality speaks first, inside a bound session.*

VIRP is an open protocol for proving that an observation of a network device — a routing table, a firewall policy, a BGP session state, a running config — was actually read from that device, at a known time, by an authorized collector, and has not been altered since. It puts signed infrastructure state on the same footing that Certificate Transparency put TLS certificates on: tamper-evident, session-bound, and independently verifiable by any party that holds the verification key.

If you have ever had to answer *"prove this is what the device actually said"* — to an auditor, to a post-mortem, to a regulator, or to yourself at 3am — VIRP is for you.

---

## What VIRP Does

A dedicated process — the **O-Node** — connects to your devices, captures raw output, and signs it with HMAC-SHA256 at the point of collection. Every signed observation is appended to a session-scoped hash chain with monotonic sequence numbers, transactional commits, and periodic milestones. Consumers receive pre-signed artifacts and can verify them independently. The signing key never leaves the O-Node. The chain is crash-safe. The session is transcript-bound.

```
Observation:
  verdict:       VERIFIED
  HMAC:          da383afe...c18
  chain_seq:     4882
  session_id:    f84c1a3e...
  device_id:     0x00000002  (FW-01)
  command_hash:  7c2b4d3a... (show firewall policy 2)
  timestamp:     2026-03-11T14:30:22.917384Z

  Verify it yourself.
```

This is not a policy. It is a code path. A consumer that cannot produce a valid HMAC and chain entry cannot produce a valid observation — because it never holds the signing key.

---

## Why This Exists

Every monitoring pipeline, audit tool, and infrastructure agent implicitly trusts the process that produced its data. Syslog trusts the forwarder. SIEM trusts the collector. Rancid trusts the cron job. The running-config in your Git repo trusts whatever wrote it. None of these chains of trust are cryptographic, and none of them survive a hostile or buggy collector.

VIRP removes the implicit trust and replaces it with a signature you can verify.

The immediate motivation came from AI agents operating on live infrastructure. During development of IronClaw (an agent built on top of VIRP), we observed an LLM generating firewall policies with valid-looking UUIDs that did not exist, reporting threats from RFC 5737 documentation addresses, and proposing routing changes based on fabricated OSPF adjacency states. Every output was technically plausible. None of it was real. Prompt engineering, output validation, and behavioral guardrails did not fix it — the model simply generated plausible-looking device state directly in its response text without invoking any signed path.

The fix is structural: if the only trustworthy observations are the ones carrying a valid HMAC and chain entry, a consumer that cannot produce one cannot lie convincingly. The same logic applies far beyond AI. It applies to any system whose output you are being asked to trust.

---

## Who It's For

VIRP is useful anywhere an infrastructure observation needs to be provable rather than assumed.

| Use case | What VIRP gives you |
|---|---|
| **Audit & compliance** (PCI-DSS, SOC 2, HIPAA, NERC CIP) | End-to-end cryptographic chain of custody from device to auditor, with no implicit trust in the collection pipeline |
| **Forensics & post-mortem** | Tamper-evident record of device state at a known time, resistant to retroactive rewriting |
| **Change management** | Signed before/after comparisons that cannot be fabricated by a compromised operator account |
| **Multi-party operations** (MSPs, co-managed networks) | Cross-tenant verification via Ed25519 federation — the operator and the auditor can be different organizations |
| **Monitoring integrity** | Detects tampering in the monitoring path itself, closing a known blind spot between device and SIEM |
| **AI agents on live infrastructure** | Agents cannot fabricate device state, because they never hold the signing key |

VIRP sits in the transparency-log lineage alongside RFC 6962 / RFC 9162 Certificate Transparency and RFC 3161 timestamping. The same shape — append-only, hash-chained, independently verifiable, domain-separated keys — applied to a different artifact class: infrastructure observations instead of TLS certificates.

---

## Architecture

```
┌─────────────────────┐      ┌─────────────────────┐
│   Consumer          │      │   O-Node            │
│   (any verifier)    │      │                     │
│                     │─────▶│  VIRP C Library     │
│  SIEM / audit tool /│      │  Device Credentials │
│  AI agent / CLI /   │◀─────│  Signing Keys       │
│  compliance scanner │      │  Chain Database     │
└─────────────────────┘      └──────────┬──────────┘
                                        │ SSH
                             ┌──────────┼──────────┐
                         Cisco IOS  FortiGate   PA-850   …
```

The consumer never holds credentials or signing keys. The O-Node never executes consumer-supplied code. All observations cross the boundary as signed, sequenced, session-bound artifacts.

### Four Walls

The reference deployment enforces isolation between the consumer and the infrastructure with four structural walls:

| Wall | Mechanism | Enforcement |
|---|---|---|
| 1 | Consumer has no network route to devices | Network topology |
| 2 | Device ACLs accept SSH from O-Node IP only | Device config |
| 3 | O-Node socket locked to authorized processes | Unix socket perms + peer credentials |
| 4 | O-Node process sandboxed via Linux Landlock + seccomp-bpf | Kernel LSM |

Walls 1–3 isolate credentials and control the call path. Wall 4 contains post-exploitation: if a driver parser bug, an SSH library CVE, or an attacker-controlled device banner ever yields code execution inside the O-Node, the kernel still refuses access to anything outside the declared ruleset — no arbitrary filesystem reads, no unexpected outbound sockets, no pivot to the chain database outside the allowed path. A compromised O-Node can still produce a wrong observation, but the blast radius is bounded at "wrong data in chain" rather than "wrong data plus key exfiltration plus lateral movement."

On Linux the reference implementation uses Landlock (kernel ≥ 5.13, network restrictions ≥ 6.7) and seccomp-bpf. On other platforms, `pledge`/`unveil` (OpenBSD) and Capsicum (FreeBSD) are suitable equivalents. The protocol specification is OS-agnostic; implementations SHOULD apply OS-level mandatory access controls to the O-Node process.

---

## Seven Trust Primitives

| # | Name | What It Does | Status |
|---|---|---|---|
| P1 | Verified Observation | Device output HMAC-signed at collection | Production |
| P2 | Tiered Authorization | Command classification enforced below the consumer | Production |
| P3 | Verified Intent | Signed proposals before execution | Implemented |
| P4 | Verified Outcome | Before/after signed comparison | Implemented |
| P5 | Baseline Memory | Deviation detection from signed history | Implemented |
| P6 | Trust Chain | SQLite-backed, tamper-evident, crash-safe | Implemented |
| P7 | Trust Federation | Ed25519 cross-tenant verification | Implemented |

Formal verification of P1 (signing + counter monotonicity) in Tamarin and ProVerif lives under `proofs/`. Handshake and chain properties are in progress.

---

## Quick Start

```bash
# Dependencies
sudo apt install -y build-essential git \
  libssl-dev libsodium-dev libsqlite3-dev \
  libssh2-1-dev libcurl4-openssl-dev libjson-c-dev

# Build
git clone https://github.com/nhowardtli/virp.git && cd virp
make CISCO=1 FORTIGATE=1 PANOS=1 ASA=1 LINUX=1
make CISCO=1 FORTIGATE=1 PANOS=1 ASA=1 LINUX=1 prod

# Test
make all-tests
make test-session
make test-session-key

# Deploy
./build/virp-tool keygen -o /etc/virp/keys/onode.key
./build/virp-onode-prod \
  -k /etc/virp/keys/onode.key \
  -s /tmp/virp-onode.sock \
  -d /etc/virp/devices.json \
  -c /var/lib/virp/chain.db
```

Systemd unit: `deploy/virp-onode.service`

---

## Production Results

Tested on real hardware:

- 40 devices under active VIRP management
- 35-router BGP topology, full verification under 60 seconds
- FortiGate policy audit: 15 real findings, zero false positives
- Fabrication is prevented by the protocol design, assuming the O-Node is trusted and uncompromised
- Linux Landlock + seccomp-bpf enforced in the reference deployment; sandbox entry is tested negatively (post-sandbox attempts to read `/etc/passwd`, bind unauthorized sockets, and write outside the chain directory all fail closed)

---

## What's In The Box

- **C library (libvirp)** — ~14,500 lines, C11, `-Wall -Wextra -Werror -pedantic`
- **Vendor drivers** — Cisco IOS, FortiOS, PAN-OS, Cisco ASA, Juniper, Wazuh, Linux, plus a mock driver for CI
- **Go implementation** — independent reimplementation, identical wire format, C↔Go interop tested
- **Python verifier** — standalone tool for auditors to verify chains without the C library
- **Session handshake** — HELLO / HELLO_ACK / SESSION_BIND state machine with transcript binding
- **HKDF-derived session keys** — domain-separated per key type; master key never signs runtime observations directly
- **Trust chain** — SQLite-backed, canonical JSON, transactional sequencing, auto-milestones every 100 entries
- **Federation** — Ed25519 via libsodium
- **OS sandbox** — Linux Landlock + seccomp-bpf in the reference O-Node
- **Test suite** — unit, integration, C↔Go interop, libFuzzer harness, negative-path session tests, black-box per-vendor driver tests
- **Formal models** — Tamarin and ProVerif for P1 under `proofs/`
- **clang-tidy audit** — candid inventory of all findings in `AUDIT-clang-tidy.md`

---

## Documentation

| Topic | Location |
|---|---|
| How a query becomes a signed observation | [Wiki: Observation Flow](../../wiki/Observation-Flow-End-to-End) |
| Session handshake deep dive | [Wiki: Session Establishment](../../wiki/Session-Establishment) |
| Wire format v1 and v2 | [Wiki: Wire Format Reference](../../wiki/Wire-Format-Reference) |
| Security architecture (The Cage) | [Wiki: The Cage](../../wiki/The-Cage-Security-Architecture) |
| Hardened KVM deployment | [Wiki: KVM Deployment](../../wiki/KVM-Hardened-Deployment) |
| Threat model | [Wiki: Threat Model](../../wiki/Threat-Model) |
| Trust tiers explained | [Wiki: Trust Tiers](../../wiki/Trust-Tiers) |
| Adding devices | [Wiki: Device Onboarding](../../wiki/Device-Onboarding) |
| FAQ | [Wiki: FAQ](../../wiki/FAQ) |
| Protocol specification | `VIRP-SPEC-RFC-v2.md` |
| Wire format specification | `VIRP-WIRE-FORMAT.md` |

---

## Protocol Specification

- **RFC Draft:** `draft-howard-virp-02`
- **IETF RATS:** submitted
- **Zenodo DOI:** registered
- **License:** Apache 2.0

---

## Related: IronClaw

IronClaw is an AI agent for network operations that consumes VIRP observations. It is the project that originally motivated VIRP, and it demonstrates one application of the protocol — but VIRP is not an AI project, and VIRP does not depend on IronClaw. Any consumer that can verify an HMAC and walk a hash chain can use VIRP: a SIEM, an audit tool, a compliance scanner, a CLI, a bespoke Python script for a regulator. IronClaw lives in a separate repository and is developed independently.

---

## Contributing

Infrastructure engineers · Security researchers · Auditors and compliance practitioners · Driver authors (Juniper, Arista, Meraki, cloud APIs) · Protocol designers · Formal-methods folks interested in extending the Tamarin/ProVerif models to the handshake and chain

**Nathan M. Howard** — Third Level IT LLC — nhoward@thirdlevelit.com

---

> *A responsible system does not guess when evidence is absent.*
> *It says: I don't know, and here's why.*
