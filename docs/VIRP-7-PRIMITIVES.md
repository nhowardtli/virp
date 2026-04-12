# Seven Trust Primitives for Agentic Operations

**A Framework for Cryptographically Verified AI Infrastructure Management**

*Nate Howard — Third Level IT LLC*
*March 2026*

-----

## The Problem Nobody Is Solving

Every major technology company is building AI agents that can manage infrastructure. Cisco, Palo Alto, CrowdStrike, Microsoft, Google — all of them are racing to create autonomous systems that can observe, reason about, and act on production networks, cloud environments, security platforms, and enterprise IT.

None of them can prove what their agent saw. None of them structurally prevent their agent from fabricating data. None of them enforce authorization at the protocol level.

They are building the brain. Nobody is building the trust layer the brain requires.

This is not a theoretical risk. During development of a production AI operations platform, we observed the following fabrication events:

- An AI system generated three complete firewall policies with syntactically valid UUIDs, correct vendor syntax, and proper structural formatting. None of these policies existed on any managed device. The AI labeled this output “Confidence: HIGH.”
- An AI system reported security alerts originating from RFC 5737 documentation addresses (192.0.2.0/24, 198.51.100.0/24). These addresses do not exist on the production network. The AI presented these as active threats requiring immediate remediation.
- An AI system proposed BGP route changes referencing OSPF adjacency states that did not match any observed device output. The supporting evidence was fabricated.

Prompt engineering did not solve this. Output validation did not solve this. The AI bypassed every behavioral guardrail by generating fabricated output directly in its response text, never invoking the signed execution path.

The fix was structural, not behavioral. And the structural fix revealed a complete framework — seven primitives that together make AI operations trustworthy, auditable, and safe.

-----

## The Framework

An AI agent operating on real infrastructure needs seven trust primitives. Each one solves a specific failure mode. Each one builds on the ones before it. Together, they form a complete trust layer for agentic operations — not specific to networking, not specific to any vendor, applicable to any domain where AI agents observe and act on physical or logical systems.

-----

## Primitive 1: Verified Observation

**The problem it solves:** AI fabrication — the agent generates plausible but false device output.

**The principle:** The AI never touches the device.

A separate process — the Observation Node (O-Node) — holds credentials, connects to devices via SSH or API, collects raw output byte-for-byte, and signs it with HMAC-SHA256 at the point of collection. The signing key exists only in the O-Node process memory. The AI receives pre-signed data. It is a consumer of verified facts, not the collector.

The AI cannot forge an observation because it does not hold the signing key. The AI cannot modify an observation because any modification invalidates the HMAC. The AI cannot fabricate an observation because fabricated data has no valid signature.

This is not a policy. This is a code path. The HMAC function is never reached for unsigned data.

**What it enables:** Every piece of data the AI reasons about carries cryptographic proof of origin. Verified observations are the foundation — without them, nothing else in the framework has meaning.

**Status:** Implemented. 6,800 lines of C. 87 tests passing. Running in production across Fortinet, Cisco, and Palo Alto hardware.

-----

## Primitive 2: Tiered Authorization

**The problem it solves:** Uncontrolled AI action — the agent has credentials and can do anything.

**The principle:** The system cannot do X. Not “the system is told not to do X.”

Every command is classified into one of four trust tiers, enforced at the O-Node level — below the AI, not by the AI:

- **GREEN** — Passive observation. No state change. Auto-executes. `show ip bgp summary`, `get system status`, `Get-Service`. The AI can look at anything, anytime, without asking permission.
- **YELLOW** — Active diagnostics. Minimal state change. Requires one human approval. `ping`, `traceroute`, `debug` commands. The AI can test, but a human must agree first.
- **RED** — Configuration changes. State modification. Requires m-of-n human approval with impact analysis. `interface shutdown`, `ip route`, `write memory`. The AI can propose, but cannot execute without multiple humans agreeing.
- **BLACK** — Destructive, irreversible, or trust-breaking. Does not exist in the protocol. There is no message type for factory reset. There is no approval workflow for disabling the observation channel. There is no override. The absence is structural, not procedural.

The AI can request `erase startup-config` all day. The O-Node has no code path to execute it. You cannot bypass a rule that was never written.

**What it enables:** The AI has full read access to the entire infrastructure but structurally limited write access. Operators can trust the AI to observe freely because the throttle is built into the protocol, not bolted onto the prompt.

**Status:** Implemented. Tested in production — AI with full admin credentials to 35 devices, structurally unable to execute destructive commands.

-----

## Primitive 3: Verified Intent

**The problem it solves:** Unstructured, unauditable change proposals.

**The principle:** Every proposed action is a formal, signed, evidence-linked object.

Right now, most AI operations platforms propose changes as natural language in a chat window. “I think we should shut down interface Gi0/0 on R1 because of CRC errors.” A human reads it, decides if it sounds right, and clicks approve. There is no formal structure. No machine-readable evidence chain. No pre-planned rollback. No record an auditor can verify.

Verified Intent changes this. When the AI determines a change is needed, it constructs a formal Intent object:

- **Action:** The specific commands to execute, on which devices.
- **Evidence:** References to signed observations (by HMAC) that support the proposed action. The protocol rejects intents with no evidence or stale evidence.
- **Reasoning:** The AI’s analysis of why this change is needed, grounded in the referenced observations.
- **Impact Assessment:** What the AI expects to happen — traffic shifts, neighbor changes, capacity implications.
- **Rollback Plan:** The specific commands to reverse the change if the outcome doesn’t match expectations.
- **Risk Classification:** The trust tier, determined by the highest-tier command in the proposal.

Every field is auditable. The evidence references are independently verifiable. The rollback is pre-planned before approval, not improvised after failure. A compliance auditor can trace any change back to the signed observations that triggered it.

**What it enables:** AI operations become auditable at the protocol level. SOC 2, CMMC, FedRAMP, HIPAA — every compliance framework that requires evidence of change management gets a cryptographic chain from “something was observed” to “something was proposed” with signed evidence at every step.

**Status:** Specified in VIRP RFC (draft-howard-virp-01). Implementation planned.

-----

## Primitive 4: Verified Outcome

**The problem it solves:** Open-loop operations — changes execute but results are never verified.

**The principle:** Every change produces a cryptographically signed before-and-after comparison.

Most AI operations platforms are open-loop. The AI proposes a change. A human approves. The change executes. Then silence. Nobody automatically checks whether the change achieved its intended effect. Did BGP actually reconverge? Did the interface go down cleanly? Did traffic shift to the backup path? Is the backup path healthy?

Verified Outcome closes the loop. After every approved change executes, the system automatically:

1. Re-collects observations from the affected devices (signed by the O-Node, same as any other observation).
1. Compares pre-change state to post-change state.
1. Evaluates whether the outcome matches the intent.
1. Classifies the result: SUCCESS, PARTIAL, FAILED, or UNEXPECTED.
1. If the outcome is worse than the pre-change state, automatically triggers the rollback defined in the Intent object.

Both the pre-change and post-change observations are HMAC-signed. The comparison is verifiable. The complete lifecycle is now: Observe → Propose → Approve → Execute → Verify. Every step signed. Every step linked.

**What it enables:** Closed-loop AI operations. The AI doesn’t just act — it confirms. And if confirmation fails, it reverts. This is the primitive that makes AI operations safe enough for production infrastructure where mistakes have real consequences.

**Status:** Designed. Implementation follows Verified Intent.

-----

## Primitive 5: Baseline Memory

**The problem it solves:** Alert fatigue and reactive-only monitoring.

**The principle:** The AI learns “normal” from cryptographically verified observation history, then alerts only on verified deviation.

Traditional monitoring sets thresholds. CPU above 90%, alert. BGP neighbor count below 4, alert. Interface errors above 1,000, alert. The result is noise. Thousands of alerts per day. Operators learn to ignore them. The important signal drowns in the expected noise.

AI monitoring with LLMs should be better, but the naive approach is worse. In our first attempt, we connected an AI to a Wazuh SIEM event stream. The AI treated every event as potentially important and flooded Slack with commentary. It didn’t know what “normal” looked like, so everything looked abnormal.

Baseline Memory solves this by giving the AI a verified concept of normal. The system continuously collects signed observations — BGP neighbor counts, interface error rates, CPU utilization, session counts, authentication patterns — and accumulates them over time. After sufficient history (typically 2-4 weeks), the AI has a statistically grounded model of what “normal” looks like for every device, every metric, every time of day.

Crucially, the baseline is composed of verified observations. The AI cannot hallucinate what normal looks like because the baseline is built from HMAC-signed data points. The AI’s concept of normal is as trustworthy as the observations that compose it.

The AI operates in three modes:

- **Silence:** Current observations match the baseline. Nothing to report. Silence means health.
- **Notice:** Current observations deviate from baseline but match known patterns (e.g., maintenance window, expected failover). The AI logs but does not alert.
- **Alert:** Current observations deviate from baseline in a way that has never been seen before. The AI alerts with specifics: what deviated, by how much, what the baseline looks like, what the AI checked to rule out false positives, and what it recommends.

This is AI intuition built on cryptographic evidence. The AI develops judgment about what matters, but the judgment is grounded in verified facts, not training data.

**What it enables:** Proactive monitoring that operators actually trust. Every alert that reaches a human feels worth reading. If it doesn’t, the baseline needs more history, not a new threshold. The system gets smarter over time because it accumulates more verified observations.

**Status:** Designed. First implementation priority — BGP neighbor count and interface error baselines across a 35-router lab environment.

-----

## Primitive 6: Trust Chain

**The problem it solves:** Fragmented audit trails and untraceable change history.

**The principle:** Every action produces a signed artifact that references the previous artifact by HMAC, forming an immutable chain.

Every primitive in this framework produces signed artifacts. Observations are signed. Intents are signed. Approvals are signed. Executions produce signed observations. Outcomes are signed comparisons of signed observations. Each artifact already references its predecessors — an Intent references Observations by HMAC, an Outcome references an Intent by HMAC.

Trust Chain formalizes this into an explicit, traversable chain:

```
Observation (O-Key signed)
    → references device output
Intent (R-Key signed)
    → references Observations by HMAC
Approval (Human signed)
    → references Intent by HMAC
Execution (O-Key signed)
    → references Approval by HMAC
Outcome (O-Key signed)
    → references Intent + pre/post Observations by HMAC
```

Pull any link and you can trace the entire chain in both directions. Why was this interface shut down? Follow the chain backward: Outcome → Execution → Approval → Intent → Observations. Who approved it? The Approval link. What evidence supported it? The Observation links referenced by the Intent. What happened after? The Outcome link.

Tampering with any link breaks the chain. Modifying an Observation invalidates its HMAC. The Intent that references that HMAC now points to a non-existent artifact. The chain becomes provably broken.

This is blockchain-grade integrity without blockchain. No distributed consensus. No tokens. No mining. No overhead. Just signed artifacts referencing each other in sequence. The chain is local, fast, and simple — but it provides the same guarantee: an immutable, verifiable, tamper-evident record of every action taken on the infrastructure.

**What it enables:** Complete audit trails for every change, traceable from initial observation to final outcome, with cryptographic verification at every link. Compliance teams can independently verify any chain without trusting the platform that generated it.

**Status:** Designed. Implementation follows Verified Outcome (requires all preceding primitives to generate the artifacts that compose the chain).

-----

## Primitive 7: Trust Federation

**The problem it solves:** Single-tenant trust boundaries and shared-secret limitations.

**The principle:** Extend cryptographic trust across organizational boundaries using asymmetric signatures.

Primitives 1 through 6 operate within a single deployment. One organization, one O-Node (or a coordinated set), one set of HMAC keys. This works for a single enterprise managing its own infrastructure. It does not work for:

- **Managed Service Providers** managing multiple clients, each requiring provable data isolation.
- **Multi-vendor environments** where each vendor signs their own observations independently.
- **Cross-organizational correlation** where multiple entities share verified observations without sharing signing authority.

Trust Federation solves this by migrating from HMAC-SHA256 (symmetric — same key signs and verifies) to Ed25519 (asymmetric — private key signs, public key verifies). Each O-Node gets its own Ed25519 key pair. The private key never leaves the O-Node. The public key is distributed freely.

In a federated deployment:

```
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
```

The MSP’s AI can reason across all three clients — correlate threat patterns, benchmark performance, identify common misconfigurations. But every observation is signed with the originating client’s private key. The MSP holds only public keys. It can verify everything and forge nothing. Client A’s observations are provably, cryptographically separate from Client B’s.

If Client B’s O-Node is compromised, only Client B’s observations are at risk. The compromise does not affect Client A or Client C because their private keys are independent.

**What it enables:** Multi-tenant AI operations with cryptographic tenant isolation. Vendor-signed observations that are independently verifiable. Cross-organizational trust without shared secrets. This is the primitive that makes VIRP a platform, not just a protocol.

**Status:** Specified as a future extension in VIRP RFC (Ed25519 appendix). Implementation is the final phase of the roadmap.

-----

## The Build Order

These primitives are not independent features to be built in parallel. Each one depends on the ones before it. The build order is determined by dependency, not preference:

|Order|Primitive              |Depends On        |Unlocks                   |
|-----|-----------------------|------------------|--------------------------|
|✓    |1. Verified Observation|Nothing           |Everything                |
|✓    |2. Tiered Authorization|Primitive 1       |Safe read/write separation|
|Next |5. Baseline Memory     |Primitive 1       |Proactive monitoring      |
|Then |3. Verified Intent     |Primitives 1, 2   |Auditable proposals       |
|Then |4. Verified Outcome    |Primitives 1, 2, 3|Closed-loop operations    |
|Then |6. Trust Chain         |Primitives 1-4    |Immutable audit trails    |
|Last |7. Trust Federation    |Primitives 1-6    |Multi-tenant, multi-org   |

Baseline Memory (Primitive 5) jumps ahead of Verified Intent because it depends only on Primitive 1 (verified observations) and solves the most pressing operational need — proactive monitoring without alert fatigue.

-----

## Why This Matters Now

AI agents are coming to infrastructure. This is not speculation. Cisco, Juniper, Palo Alto, Fortinet, CrowdStrike, Microsoft, and Google are all building or shipping AI systems that observe, reason about, and act on production infrastructure.

Every one of these systems trusts its own telemetry implicitly. Every one of these systems relies on behavioral constraints (prompts, guardrails, output filters) rather than structural constraints (cryptographic verification, channel separation, evidence-gated proposals). Every one of these systems is one fabrication event away from a production incident caused by an AI acting on data it invented.

The seven trust primitives described in this paper are not a product pitch. They are an architectural requirement. Any AI agent operating on real infrastructure will eventually need all seven — whether it discovers them proactively or learns them from an incident.

The protocol specification (VIRP — Verified Intent Routing Protocol, draft-howard-virp-01) and the reference implementation are open source under Apache License 2.0. The spec, the code, and the test suite are available at github.com/nhowardtli/virp.

The category is trust primitives for agentic operations. It is currently empty. This paper is an invitation to fill it.

-----

*Nate Howard is the founder of Third Level IT LLC, a boutique infrastructure engineering company specializing in cryptographic trust frameworks for AI-managed infrastructure. He can be reached at nhoward@thirdlevelit.com or at thirdlevel.ai.*