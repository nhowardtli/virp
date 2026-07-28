<p align="center">
  <img alt="License: Apache 2.0" src="https://img.shields.io/badge/License-Apache_2.0-blue.svg">
  <img alt="C11" src="https://img.shields.io/badge/C-11-00599C?logo=c&logoColor=white">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white">
  <img alt="IETF Draft" src="https://img.shields.io/badge/IETF-draft--howard--virp--05-orange">
  <img alt="Status" src="https://img.shields.io/badge/Status-Production-success">
</p>

> **VIRP does not let AI speak first. Reality speaks first, inside a bound session.**

# VIRP — Verified Infrastructure Response Protocol

**Cryptographic trust primitives for AI agents operating on real infrastructure.**

When an AI agent tells you your firewall policy is misconfigured, can you prove it actually checked?

When it says a BGP session is established, did it read that from a real device — or fabricate it?

When it claims a config change succeeded, where is the evidence?

**VIRP makes every agent claim verifiable. Not with prompts. Not with guardrails. With cryptography.**

---

## What VIRP Does

VIRP is an open protocol that signs every device observation at the point of collection, before the AI ever sees it.

A dedicated process — the **O-Node** — connects to your network devices, captures raw output, and signs it with HMAC-SHA256. The AI agent receives pre-signed data. It can reason about what the device returned. It cannot forge it, modify it, or fabricate it — because it never holds the signing key.

This is not a policy. It is a code path.

```
Agent: "FortiGate policy 2 allows all traffic with no AV/IPS."

VIRP:
  verdict:       VERIFIED
  HMAC:          da383afe...c18
  chain_seq:     4882
  session_id:    f84c1a3e...
  device_id:     0x00000002  (FW-01)
  command_hash:  7c2b4d3a...  (show firewall policy 2)
  timestamp:     2026-03-11T14:30:22.917384Z

  Verify it yourself.
```

---

## Why This Exists

During development of IronClaw, we observed an AI system:

- Generating firewall policies with valid UUIDs that did not exist
- Reporting threats from RFC 5737 documentation addresses
- Proposing routing changes based on fabricated OSPF adjacency states

Every output was technically plausible. None of it was real.

Prompt engineering, output validation, and behavioral guardrails did not fix it. The AI fabricated output directly in its response text without invoking the signed execution path.

**VIRP is the structural fix.**

---

## Architecture

```
┌─────────────────────┐      ┌─────────────────────┐
│   AI Node (CT 210)  │      │   O-Node (CT 211)   │
│                     │      │                     │
│  Agent + LLM        │─────▶│  VIRP C Library     │
│                     │      │  Device Credentials │
│  Zero credentials   │      │  Signing Keys       │
│  Zero signing keys  │◀─────│  Chain Database     │
└─────────────────────┘      └──────────┬──────────┘
                                        │ SSH
                             ┌──────────┼──────────┐
                         Cisco IOS  FortiGate   PA-850
```

**The Cage** — three structural walls enforce isolation:

| Wall | Mechanism |
|---|---|
| 1 | AI node has no network route to devices |
| 2 | Device ACLs accept SSH from O-Node IP only |
| 3 | O-Node socket locked to authorized processes |

---

## Seven Trust Primitives

| # | Name | What It Does | Status | Evidence |
|---|---|---|---|---|
| P1 | Verified Observation | Device output HMAC-signed at collection | Production | tested |
| P2 | Tiered Authorization | Command classification enforced below AI | Production | tested — see caveats below |
| P3 | Verified Intent | Signed proposals before execution | Implemented | tested |
| P4 | Verified Outcome | Before/after signed comparison | Implemented | tested |
| P5 | Baseline Memory | Deviation detection from signed history | Implemented | untested — no suite covers deviation detection |
| P6 | Trust Chain | SQLite tamper-evident chain | Implemented | tested (logic); production-chain integrity unestablished, see below |
| P7 | Trust Federation | Ed25519 cross-tenant verification | Implemented | tested (crypto only); no multi-tenant deployment exists — federation *operation* is aspirational |

**Production** primitives have accumulated operational history across real deployments. **Implemented** primitives are complete, tested, and exercised in integration runs, but have not yet accumulated equivalent production hours.

> **Gate scope.** The tier gate accepts one command per request. Separator
> characters (newline, `;`, `|`, `&`, backtick, `$(`, `${`) are rejected
> fleet-wide, so CLI display filters such as `show run | include bgp` do
> not work, and multi-line/config-mode payloads are unsupported through
> the single-command path. The `linux` and `wazuh` drivers have no
> classifier and execute unclassified under the SHADOW overrides they run
> with in production. See [`SECURITY.md`](SECURITY.md) §Command Gate —
> Explicit Scope Limits.

---

## Operational Status

VIRP has been running continuously on production infrastructure since March 2026.

Each item below is tagged with its evidence status:
**[tested]** implemented and covered by a checked-in test or machine proof;
**[untested]** implemented but with no automated coverage;
**[aspirational]** intended, not yet built.

- **66 days of continuous operation** at time of this writing *[untested — uptime is observed, not asserted by any check]*
- **2,024 cryptographically linked chain artifacts** across 81 sessions *[untested — a count from a one-time export, not reproduced by a test]*
- **35-router BGP topology**: full verification under 60 seconds *[untested — a one-time measurement; no benchmark in the suite]*
- **FortiGate audit**: 15 findings on real hardware, zero false positives *[untested — a one-time manual audit]*

**Chain integrity.** A previous version of this section claimed "99.9%
chain integrity (verified against full export)". That number has been
removed rather than explained, because it could not be substantiated and
because the metric is a category error: a hash-linked chain is valid or
it is not — a 0.1% failure rate in a structure where each entry commits
to its predecessor means every entry after the first break is
unverifiable, not that 99.9% of it is good. The one recorded verification
in this tree, from 2026-04-24, returned `valid:false first_broken:2`
(snapshot preserved as `chain.db.broken-2026-04-24`). Chain verification
logic itself is covered by `tests/test_chain.c` (genesis, sequential
linking, tamper detection, crash recovery) and
`tests/test_chain_concurrency.c` *[tested]*; what is **not** established
is any integrity figure for the production chain. Re-establishing that
needs a fresh `virp chain verify` against the live database, reported as
pass/fail with the first broken sequence if any.

Fabrication is prevented by protocol design, assuming the O-Node is uncompromised *[tested — see `docs/VIRP-CLAIMS.md` Appendix A, C5–C8 and C16]*. See [`SECURITY.md`](SECURITY.md) for the full trust boundary analysis, including known open work on TCP-path mutual authentication.

---

## Quick Start

```bash
# Dependencies (Debian/Ubuntu)
sudo apt install -y build-essential git \
  libssl-dev libsodium-dev libsqlite3-dev \
  libssh2-1-dev libcurl4-openssl-dev libjson-c-dev

# Clone and build
git clone https://github.com/nhowardtli/virp.git && cd virp
make CISCO=1 FORTIGATE=1 PANOS=1 ASA=1 LINUX=1
make CISCO=1 FORTIGATE=1 PANOS=1 ASA=1 LINUX=1 prod

# Test
make all-tests
make test-session
make test-session-key

# Generate a signing key and start the O-Node
./build/virp-tool keygen -o /etc/virp/keys/onode.key
./build/virp-onode-prod \
  -k /etc/virp/keys/onode.key \
  -s /tmp/virp-onode.sock \
  -d /etc/virp/devices.json \
  -c /var/lib/virp/chain.db
```

Systemd unit file: [`deploy/virp-onode.service`](deploy/virp-onode.service)

---

## What's In The Box

- **C library (libvirp)** — 13,743 source lines + 2,867 header lines, C11, `-Wall -Wextra -Werror -pedantic`
- **Go implementation** — 2,739 lines, identical wire format, interop-tested against the C reference
- **Vendor drivers** — Cisco IOS, FortiOS, PAN-OS, Cisco ASA, Juniper, Linux, Wazuh
- **Session handshake** — `SESSION_HELLO` / `SESSION_HELLO_ACK` / `SESSION_BIND` state machine with HKDF-derived session keys
- **Trust chain** — SQLite-backed, tamper-evident, crash-safe
- **Federation** — Ed25519 via libsodium for cross-tenant artifact verification
- **101 test cases** across 23 files: 71 C unit + integration tests, 30 Python end-to-end and parity tests, plus libFuzzer harness, concurrency tests, and live-hardware tests
- **Integrations** — Prometheus exporter, NetBox sync

---

## FAQ

**Won't a sufficiently advanced AI just learn not to fabricate?**
No. Fabrication is a structural failure mode: the model generates output in response text without invoking the signed execution path. No amount of training prevents a language model from producing plausible-sounding text. VIRP makes the difference between "text that looks like an observation" and "an observation" cryptographically distinguishable. The fix is not at the model layer.

**Why not just hash the device output after the fact?**
Because the question is not "did this bytestring get tampered with after we recorded it?" — it is "did this bytestring come from a real device?" Hashing after the AI sees the data lets the AI insert the data. VIRP signs at the point of collection, in a process the AI cannot reach, with a key the AI cannot read.

**How is this different from agent observability or tracing platforms?**
Observability tools record what the agent claimed to do. VIRP records what was cryptographically verified to have happened. Tracing tells you the agent said it ran `show firewall policy 2`. VIRP tells you the device responded, here is the signed response, here is its position in the tamper-evident chain.

**Is the O-Node a single point of compromise?**
Yes, and intentionally so. The O-Node is the trust boundary; you harden it the way you would harden a HSM or a credential vault. VIRP's job is to compress the trust surface from "everywhere the AI can reach" down to "one process you can audit." That is a manageable problem. The original is not.

**Can I use VIRP without the rest of IronClaw?**
Yes. VIRP is a protocol and a reference implementation. IronClaw is one consumer of it. Any agent, dashboard, or automation system can be a VIRP consumer — the wire format is documented in [`docs/VIRP-WIRE-FORMAT.md`](docs/VIRP-WIRE-FORMAT.md).

---

## Documentation

| Topic | Location |
|---|---|
| Protocol specification | [`docs/VIRP-SPEC-RFC-v2.md`](docs/VIRP-SPEC-RFC-v2.md) |
| Wire format reference | [`docs/VIRP-WIRE-FORMAT.md`](docs/VIRP-WIRE-FORMAT.md) |
| The seven trust primitives | [`docs/VIRP-7-PRIMITIVES.md`](docs/VIRP-7-PRIMITIVES.md) |
| AI trust stack model | [`docs/AI-TRUST-STACK.md`](docs/AI-TRUST-STACK.md) |
| Observation flow end-to-end | [`docs/VIRP-OBSERVATION-FLOW.md`](docs/VIRP-OBSERVATION-FLOW.md) |
| Validator manifest contract | [`docs/VALIDATOR-MANIFEST-CONTRACT.md`](docs/VALIDATOR-MANIFEST-CONTRACT.md) |
| Threat model and trust boundaries | [`SECURITY.md`](SECURITY.md) |
| Contributing | [`CONTRIBUTING.md`](CONTRIBUTING.md) |

---

## Protocol Specification

- **IETF Draft:** `draft-howard-virp-05` (drafts -01 through -05 submitted)
- **Formal verification:** (1) injective agreement (every accepted v2
  observation corresponds to exactly one signing) and key secrecy
  (master O-Key and derived session keys) are machine-verified in
  ProVerif 2.05; the model and raw output are checked in at
  [`proofs/virp_obs_v2.pv`](proofs/virp_obs_v2.pv) and
  [`proofs/virp_obs_v2.out`](proofs/virp_obs_v2.out), re-runnable via
  `make proofs`. (2) The proof holds under a stated trace restriction
  matching `virp_seqstore_accept()`; that store's correctness is
  demonstrated by the replay negative tests in `tests/test_obs_v2.c`,
  including persistence across verifier restart. (3) Timestamp
  freshness is test-verified only (`test_stale_observation_rejected`),
  not modeled. There is no Tamarin model — that is future work. The
  proofs cover the v2 observation path only; `draft-howard-virp-05`
  §16.1 still cites the older, broader claim and needs the same
  correction in its next revision.
- **License:** Apache 2.0

---

## Contributing

We are particularly interested in:

- Infrastructure engineers running VIRP against production fleets
- Security researchers attacking the protocol
- Driver authors for Juniper, Arista, Meraki, and cloud APIs
- Protocol designers working on the IETF drafts

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for setup, code standards, and the new-driver checklist. Security issues: see [`SECURITY.md`](SECURITY.md).

---

## Contact

**Nathan M. Howard** — Third Level IT LLC — `nhoward@thirdlevelit.com`

---

> *A responsible system does not guess when evidence is absent.*
> *It says: I don't know, and here's why.*
