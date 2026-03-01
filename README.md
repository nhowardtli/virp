# VIRP — Verified Intent Routing Protocol

**A next-generation network control protocol designed for AI-native infrastructure.**

VIRP is the first routing protocol where trust is a protocol primitive, not an afterthought. Unlike BGP and OSPF — which were designed for a world where every participant runs deterministic code — VIRP is designed for a world where network participants might be AI systems capable of generating plausible but false information.

VIRP makes fabrication structurally impossible.

## The Problem

Traditional routing protocols trust their peers implicitly. BGP believes whatever routes a neighbor advertises. OSPF trusts that link-state advertisements reflect reality. This works when every participant is deterministic software. It breaks when AI enters the control plane.

An AI managing network infrastructure can hallucinate device output, fabricate metrics, or propose changes based on imagined state. Existing protocols have no mechanism to detect or prevent this.

## The Solution

VIRP separates the network into two cryptographically isolated channels:

- **Observation Channel (OC)** — Carries signed measurements of real network state. Every message is signed with an O-Key that only hardened observer processes can access. Facts only.

- **Intent Channel (IC)** — Carries proposals and intent from reasoning systems. Signed with R-Keys. Opinions, subject to verification and approval.

An AI (R-Node) can reason about observations and propose changes. It **cannot** forge an observation. The signing keys are structurally separated — the code enforces this at the function level, not through policy.

## Key Properties

| Property | Guarantee |
|---|---|
| Channel separation | O-Keys sign OC only, R-Keys sign IC only. Code enforces at signing time. |
| Evidence required | Proposals must reference signed observations. Zero-evidence proposals are rejected. |
| BLACK tier | Destructive operations (key deletion, approval bypass) don't exist in the message format. |
| Tamper detection | HMAC-SHA256 on every message. Constant-time comparison prevents timing attacks. |
| No dynamic allocation | Fixed buffers throughout. Deterministic execution. |

## Trust Tiers

| Tier | Name | Approval | Examples |
|---|---|---|---|
| GREEN | Passive | None | Read forwarding tables, measure latency |
| YELLOW | Active | Single human or automated | Inject routes, modify metrics |
| RED | Critical | Multiple humans | Decommission peers, modify security zones |
| BLACK | Forbidden | Impossible — not in protocol | Delete keys, bypass approval, disable observers |

## Architecture

```
┌──────────────────────────────────────────────────┐
│                   VIRP Node                       │
│                                                   │
│  ┌─────────────┐          ┌─────────────────┐    │
│  │   O-Node    │          │     R-Node      │    │
│  │  (Observer) │          │   (Reasoning)   │    │
│  │             │          │                 │    │
│  │  Measures   │◄────────►│   Proposes      │    │
│  │  Signs      │  VIRP    │   Analyzes      │    │
│  │  Verifies   │ Messages │   Decides       │    │
│  │             │          │                 │    │
│  │  [O-Key]    │          │   [R-Key]       │    │
│  └─────────────┘          └─────────────────┘    │
│                                                   │
│  O-Key NEVER accessible to R-Node                 │
│  R-Key NEVER used on Observation Channel          │
└──────────────────────────────────────────────────┘
```

## Building

```bash
# Requirements: gcc, make, libssl-dev (OpenSSL)
sudo apt install build-essential libssl-dev

# Extract and build
tar xzf virp-v0.1.tar.gz
cd virp
make

# Run test suite
make test
```

## Test Suite

27 tests proving every structural guarantee:

```
[Structural Guarantees]
  test_header_size                                             [PASS]
  test_black_tier_rejected                                     [PASS]
  test_black_tier_validation                                   [PASS]
  test_okey_signs_oc                                           [PASS]
  test_okey_cannot_sign_ic                                     [PASS]
  test_rkey_signs_ic                                           [PASS]
  test_rkey_cannot_sign_oc                                     [PASS]
  test_proposal_requires_evidence                              [PASS]

[HMAC Integrity]
  test_hmac_detects_tamper                                     [PASS]
  test_hmac_detects_header_tamper                              [PASS]
  test_wrong_key_fails_verify                                  [PASS]

[Channel-Type Consistency]
  test_observation_on_ic_rejected                              [PASS]
  test_proposal_on_oc_rejected                                 [PASS]
  test_heartbeat_on_ic_rejected                                [PASS]
  test_teardown_on_both_channels                               [PASS]

[Round-Trip Serialization]
  test_observation_round_trip                                  [PASS]
  test_proposal_round_trip                                     [PASS]
  test_heartbeat_round_trip                                    [PASS]
  test_approval_round_trip                                     [PASS]
  test_intent_advertise_round_trip                             [PASS]
  test_intent_withdraw_round_trip                              [PASS]
  test_hello_round_trip                                        [PASS]

[Key Management]
  test_key_generate_and_destroy                                [PASS]
  test_key_save_and_load                                       [PASS]

[Edge Cases]
  test_null_pointers                                           [PASS]
  test_buffer_too_small                                        [PASS]
  test_reserved_nonzero_rejected                               [PASS]

Results: 27/27 passed
```

## Project Structure

```
virp/
├── include/
│   ├── virp.h            # Protocol constants, structures, message types
│   ├── virp_crypto.h     # HMAC signing, key management, verification
│   └── virp_message.h    # Message building, parsing, validation API
├── src/
│   ├── virp_crypto.c     # Crypto implementation with channel-key binding
│   └── virp_message.c    # Serialization, construction, validation
├── tests/
│   └── test_virp.c       # 27 tests covering all structural guarantees
└── Makefile
```

## Roadmap

- [x] **Phase 1** — Message library (wire format, signing, validation)
- [ ] **Phase 2** — O-Node daemon (Unix socket listener, device command execution)
- [ ] **Phase 3** — Device drivers (Cisco IOS, FortiGate, Juniper, Palo Alto)
- [ ] **Phase 4** — R-Node integration (AI backend speaks VIRP)
- [ ] **Phase 5** — Peer protocol (TCP transport, HELLO, trust verification, ESTABLISHED)
- [ ] **Phase 6** — Bridge node (VIRP-to-BGP translation for legacy networks)

## Origin

VIRP was born from building the TLI AI Operations Center — a platform where AI manages real production network infrastructure across Cisco, Fortinet, and Linux systems. Every design decision in this protocol was informed by a real problem encountered in production:

- **Channel separation** came from an AI fabricating device output
- **Evidence requirements** came from an AI proposing changes based on imagined state
- **The BLACK tier** came from an AI attempting to clear BGP on routers nobody asked it to touch
- **HMAC signing** came from needing to prove which output was measured vs. generated

The protocol also draws inspiration from NetClaw by John Capobianco and Sean Mahoney, which demonstrated AI agents as first-class BGP speakers — and raised the question of what a purpose-built protocol for AI-native networking would look like.

## License

Copyright (c) 2026 Third Level IT LLC. All rights reserved.

Proprietary. Published for review and comment. Implementation rights reserved pending formal licensing.
