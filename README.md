# VIRP — Verified Intent Routing Protocol

**Cryptographic trust primitives for agentic infrastructure operations.**

-----

## The Problem

AI systems managing infrastructure fabricate data. Not occasionally — routinely. During development of a production AI operations platform, we observed an AI generate complete firewall policies with valid UUIDs that didn’t exist on any device, report security threats from RFC 5737 documentation addresses, and propose routing changes based on fabricated OSPF adjacency states. Every output was technically plausible. None of it was real.

Prompt engineering didn’t fix this. Output validation didn’t fix this. The AI bypassed every behavioral guardrail by generating fabricated output directly in its response text, never invoking the signed execution path.

VIRP is the structural fix.

-----

## The Solution

VIRP separates observation from reasoning at the protocol level. A dedicated process (the O-Node) collects device output via SSH, signs it with HMAC-SHA256 at the point of collection, and serves it to the AI layer. The AI can reason about signed data. It cannot forge it, modify it, or fabricate it — because it does not hold the signing key.

This is not a policy. It is a code path. The HMAC function is never reached for unsigned data.

-----

## Seven Trust Primitives

VIRP defines seven primitives that together form a complete trust layer for AI agents operating on real infrastructure.

### 1. Verified Observation ✓

The AI never touches the device. The O-Node collects raw output, signs it with HMAC-SHA256, and serves pre-signed data to the AI. The signing key exists only in O-Node process memory. Fabricated data has no valid signature.

### 2. Tiered Authorization ✓

Every command is classified at the O-Node level — not by the AI:

|Tier  |Name     |Approval               |Example               |
|------|---------|-----------------------|----------------------|
|GREEN |Passive  |None (auto-execute)    |`show ip bgp summary` |
|YELLOW|Active   |Single operator        |`ping`, `traceroute`  |
|RED   |Critical |m-of-n operators       |`interface shutdown`  |
|BLACK |Forbidden|Structurally impossible|`erase startup-config`|

BLACK tier commands have no message type, no approval path, no override. The absence is structural.

### 3. Verified Intent

Every proposed change is a formal, signed object referencing specific observations by HMAC. Includes evidence references, impact assessment, and pre-planned rollback. No evidence → no proposal. Stale evidence → rejected.

### 4. Verified Outcome

Automatic post-change observation. The system re-collects signed observations after every approved change and compares before/after state. If the outcome doesn’t match the intent, the pre-planned rollback triggers. Closed-loop operations.

### 5. Baseline Memory

The AI learns “normal” from accumulated signed observations over time. Alerts on verified deviation, not thresholds. The baseline is built from HMAC-signed data — the AI cannot hallucinate what normal looks like. Silence means health. A message means something actually changed.

### 6. Trust Chain

Every action produces a signed artifact referencing the previous artifact by HMAC. Observation → Intent → Approval → Execution → Outcome. Each link verifiable. Tampering with any link breaks the chain. Blockchain-grade integrity without blockchain.

### 7. Trust Federation

Ed25519 asymmetric signatures for multi-tenant deployments. Each O-Node holds its own private key. Verifiers hold only public keys. An MSP can reason across 15 clients — verifying everything, forging nothing. Compromise of one node doesn’t compromise others.

-----

## Architecture

```
┌──────────────────────────────────────┐
│         Managed Devices              │
│   Cisco  ·  Fortinet  ·  Palo Alto  │
└──────────────┬───────────────────────┘
               │ SSH
               ▼
┌──────────────────────────────────────┐
│            O-Node                    │
│                                      │
│   Collects device output             │
│   Signs with HMAC-SHA256 (O-Key)     │
│   Enforces trust tiers               │
│   Serves signed observations         │
│                                      │
│   Key NEVER accessible to AI layer   │
└──────────────┬───────────────────────┘
               │ Signed VIRP Messages
               ▼
┌──────────────────────────────────────┐
│            R-Node (AI)               │
│                                      │
│   Consumes signed observations       │
│   Reasons about infrastructure       │
│   Proposes changes (signed, R-Key)   │
│   CANNOT forge observations          │
│   CANNOT bypass trust tiers          │
└──────────────┬───────────────────────┘
               │ Proposals
               ▼
┌──────────────────────────────────────┐
│         Human Approval               │
│                                      │
│   Reviews structured Intent objects  │
│   Verifies evidence references       │
│   Approves or rejects per tier       │
└──────────────────────────────────────┘
```

-----

## Demo Workflow

```
1. Engineer asks:  "Are all BGP neighbors healthy across the network?"

2. O-Node:         Connects to 35 devices via SSH
                   Collects raw output from each
                   Signs every response with HMAC-SHA256
                   Returns signed observations

3. AI (R-Node):    Receives pre-signed data
                   Analyzes BGP state across 13 autonomous systems
                   Identifies failed sessions, maps topology gaps
                   Assesses redundancy — all grounded in verified data

4. Result:         Full topology analysis in under 60 seconds
                   Every data point cryptographically verified
                   AI cannot fabricate what devices said

5. If change needed:
   AI constructs:  Signed Intent → evidence refs → rollback plan
   Human reviews:  Structured proposal, not chat text
   Upon approval:  O-Node executes, then re-observes
   System verifies: Before/after comparison, both signed
```

-----

## Status

|Primitive              |Status        |Detail                                 |
|-----------------------|--------------|---------------------------------------|
|1. Verified Observation|**Done**      |6,800 lines of C, 87 tests passing     |
|2. Tiered Authorization|**Done**      |GREEN/YELLOW/RED/BLACK enforced        |
|3. Verified Intent     |In development|Formal proposal structure              |
|4. Verified Outcome    |Designed      |Closed-loop verification               |
|5. Baseline Memory     |Next priority |Deviation detection from signed history|
|6. Trust Chain         |Designed      |Cryptographic audit trail              |
|7. Trust Federation    |Specified     |Ed25519 multi-tenant (RFC appendix)    |

-----

## Specification

The protocol is formally specified in **draft-howard-virp-01** (2,278 lines), including wire format, message types, channel-key binding, threat model, formal security properties, conformance requirements, and Ed25519 extension path.

-----

## Multi-Vendor Support

|Vendor          |Protocol|Status     |
|----------------|--------|-----------|
|Cisco IOS/IOS-XE|SSH     |Implemented|
|Fortinet FortiOS|SSH     |Implemented|
|Palo Alto PAN-OS|SSH/API |In progress|
|Juniper Junos   |SSH     |Planned    |
|Arista EOS      |SSH     |Planned    |
|Linux           |SSH     |Planned    |
|Windows         |WinRM   |Planned    |

-----

## Quick Start

```bash
# Clone the repository
git clone https://github.com/nhowardtli/virp.git
cd virp

# Build
make

# Run tests
make test

# Generate signing keys
./virp-tool keygen -o /etc/virp/okey.bin -c OC
./virp-tool keygen -o /etc/virp/rkey.bin -c IC

# Start the O-Node
./virp-onode -k /etc/virp/okey.bin -d devices.json -s /tmp/virp-onode.sock
```

-----

## License

Apache License 2.0

-----

## Author

**Nate Howard**
Third Level IT LLC
nhoward@thirdlevelit.com
[thirdlevel.ai](https://thirdlevel.ai)