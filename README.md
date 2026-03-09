# VIRP — Verified Infrastructure Reality Protocol
In a federated deployment:

MSP Reasoning Node  
    ├── Client A O-Node (Ed25519 key pair A)  
    │     ├── FortiGate firewall  
    │     ├── Cisco switches  
    │     └── Windows domain controllers  
    ├── Client B O-Node (Ed25519 key pair B)  
    │     ├── Palo Alto firewall  
    │     ├── Arista switches  
    │     └── Linux servers  
    └── Client C O-Node (Ed25519 key pair C)  
          ├── Fortinet firewall  
          ├── Juniper routers  
          └── Wazuh SIEM  

The MSP’s AI can reason across all three clients — correlate threat patterns, benchmark  
performance, identify common misconfigurations. But every observation is signed with the  
originating client’s private key. The MSP holds only public keys. It can verify everything and  
forge nothing. Client A’s observations are provably, cryptographically separate from Client  
B’s.

If Client B’s O-Node is compromised, only Client B’s observations are at risk. The  
compromise does not affect Client A or Client C because their private keys are independent.

What it enables: Multi-tenant AI operations with cryptographic tenant isolation. Vendor-  
signed observations that are independently verifiable. Cross-organizational trust without  
shared secrets. This is the primitive that makes VIRP a platform, not just a protocol.

Status: Done. Specified as a future extension in VIRP RFC (Ed25519 appendix). Implementation is  
the final phase of the roadmap.

## The Build Order

These primitives are not independent features to be built in parallel. Each one depends on  
the ones before it. The build order is determined by dependency, not preference:

| Order | Primitive              | Depends On        | Unlocks                     |
|-------|------------------------|-------------------|-----------------------------|
| ✓     | 1. Verified Observation| Nothing           | Everything                  |
| ✓     | 2. Tiered Authorization| Primitive 1       | Safe read/write separation  |
| Next  | 5. Baseline Memory     | Primitive 1       | Proactive monitoring        |
| Then  | 3. Verified Intent     | Primitives 1, 2   | Auditable proposals         |
| Then  | 4. Verified Outcome    | Primitives 1, 2, 3| Closed-loop operations      |
| Then  | 6. Trust Chain         | Primitives 1-4    | Immutable audit trails      |
| Last  | 7. Trust Federation    | Primitives 1-6    | Multi-tenant, multi-org     |

Baseline Memory (Primitive 5) jumps ahead of Verified Intent because it depends only on  
Primitive 1 (verified observations) and solves the most pressing operational need —  
proactive monitoring without alert fatigue.

## Why This Matters Now

AI agents are coming to infrastructure. This is not speculation. Cisco, Juniper, Palo Alto,  
Fortinet, CrowdStrike, Microsoft, and Google are all building or shipping AI systems that  
observe, reason about, and act on production infrastructure.

Every one of these systems trusts its own telemetry implicitly. Every one of these systems  
relies on behavioral constraints (prompts, guardrails, output filters) rather than structural  
constraints (cryptographic verification, channel separation, evidence-gated proposals).  
Every one of these systems is one fabrication event away from a production incident caused  
by an AI acting on data it invented.

The seven trust primitives described in this paper are not a product pitch. They are an  
architectural requirement. Any AI agent operating on real infrastructure will eventually need  
all seven — whether it discovers them proactively or learns them from an incident.

The protocol specification (VIRP — Verified Infrastructure Response Protocol, draft-howard-virp-01)  
and the reference implementation are open source under Apache License 2.0. The spec, the  
code, and the test suite are available at github.com/nhowardtli/virp.

The category is trust primitives for agentic operations. It is currently empty. This paper is an  
invitation to fill it.

Nate Howard is the founder of Third Level IT LLC, a boutique infrastructure engineering  
company specializing in cryptographic trust frameworks for AI-managed infrastructure. He  
can be reached at nhoward@thirdlevelit.com or at thirdlevel.ai.
