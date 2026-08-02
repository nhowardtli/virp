<p align="center">
  <img alt="License: Apache 2.0" src="https://img.shields.io/badge/License-Apache_2.0-blue.svg">
  <img alt="C11" src="https://img.shields.io/badge/C-11-00599C?logo=c&logoColor=white">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white">
  <img alt="IETF Draft" src="https://img.shields.io/badge/IETF-draft--howard--virp--06-orange">
  <img alt="Status" src="https://img.shields.io/badge/Status-Research_Prototype-orange">
</p>

> **VIRP does not let AI speak first. Reality speaks first, inside a bound session.**

# VIRP — Verified Infrastructure Response Protocol

**Authenticated evidence for infrastructure automation.**

When an AI agent tells you your firewall policy is misconfigured, can you prove it actually checked?

When it says a BGP session is established, did it read that from a real device — or fabricate it?

When it claims a config change succeeded, where is the evidence?

**VIRP authenticates operation records under an explicit collector trust model — not with prompts, not with guardrails, with cryptography. It does not establish that a device is honest or that every AI statement is true.**

---

## What VIRP Does

VIRP is an open protocol that authenticates every device observation at the point of collection, before the AI ever sees it.

A dedicated process — the **O-Node** — connects to your network devices, captures raw output, and authenticates it with an HMAC-SHA256 tag. The AI agent receives pre-authenticated data. It can reason about what the device returned. It cannot forge it, modify it, or fabricate it — because it never holds the authentication key.

This is not a policy. It is a code path.

> **Scope caveat — body-to-command correspondence.** The signature binds
> command, device and session to the bytes the O-Node read. It does
> **not** currently guarantee that those bytes are the device's response
> to that command on the SSH drivers: stale buffered output, a
> concurrent watchdog probe, or driver wrapper echoes can enter the body
> before signing, and one such mismatch was observed live on 2026-07-29
> (a signed `show system resources` observation carrying
> `show system info` output). See
> [`SECURITY.md`](SECURITY.md) §Observation-Body Integrity.

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

## Reproducible Demo

Clone, install the build dependencies, run. No hardware, no credentials, no
network access (Debian/Ubuntu):

```bash
git clone https://github.com/nhowardtli/virp
cd virp
sudo apt install -y build-essential libssl-dev libsodium-dev \
     libsqlite3-dev libssh2-1-dev libcurl4-openssl-dev libjson-c-dev
./demo/run.sh
```

The demo runs the reference collector against a deterministic **simulated
target** and asserts nine security behaviors end to end: a GREEN operation
executes and its record verifies; a tampered record fails verification; a
RED operation is blocked and a proposal is filed; an Ed25519 approval signed
outside the collector executes the change once; approval reuse, expiry, and
absence are refused with typed errors; an unknown operation fails closed;
and every chain session verifies from its own genesis. On an independent
verifier machine with the dependencies already installed, it ran 9/9 from a
fresh clone in 15 seconds; a first run that also installs dependencies and
compiles takes about two minutes. The target is simulated, so the demo
establishes protocol behavior, not device truth. Containerized alternative
and details: [`demo/README.md`](demo/README.md).

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

Names and numbering follow §5 of `draft-howard-virp-06`, which is authoritative.

| # | Name | What It Does | Status | Evidence |
|---|---|---|---|---|
| P1 | Observation Integrity | Device output HMAC-authenticated at collection | Production | tested (authentication-tag validity); body-to-command correspondence not guaranteed on SSH drivers — one live mismatch observed 2026-07-29, see `SECURITY.md` §Observation-Body Integrity |
| P2 | Two-Channel Separation | Observation (read) and Intent (write) channels separated, bound to distinct key roles | Implemented | tested — a message authenticated with the other channel's key is refused |
| P3 | Intent Gating | Command classification enforced below the AI; signed proposals before execution | Production | tested — see gate-scope caveats below |
| P4 | Outcome Verification | Before/after authenticated comparison | Implemented | tested |
| P5 | Baseline Memory | Deviation detection from authenticated history | Implemented | untested — no suite covers deviation detection |
| P6 | Multi-Vendor Normalization | Normalized observation schema across vendor drivers | Implemented | per-driver unit tests; no published cross-vendor live transcript |
| P7 | Agent Containment | Requesting process treated as an untrusted principal; containment enforced externally | Specified | the three-layer cage above is the enforcement design; not yet fully demonstrated |

Two supporting mechanisms underpin the primitives without being primitives
themselves: the SQLite tamper-evident **trust chain** (logic tested;
production-chain integrity unestablished, see below) and per-node Ed25519
**federation keys** (crypto tested; no multi-tenant deployment exists —
federation *operation* is aspirational).

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
**[unreproduced measurement]** a one-time observation, not re-derived by
any check;
**[aspirational]** intended, not yet built.

- **66 days of continuous operation** at time of this writing *[unreproduced measurement — uptime is observed, not asserted by any check]*
- **2,024 cryptographically linked chain artifacts** across 81 sessions *[unreproduced measurement — a count from a one-time export]*
- **35-router BGP topology**: full verification under 60 seconds *[unreproduced measurement — one-time timing; no benchmark in the suite]*
- **FortiGate audit**: 15 findings on real hardware, zero false positives *[unreproduced measurement — a one-time manual audit]*

**Chain integrity — verified 2026-07-28, read-only.** A previous version
of this section claimed "99.9% chain integrity (verified against full
export)". That figure is removed: it could not be substantiated, and the
metric is a category error for a hash-linked structure, where each entry
commits to its predecessor. What follows replaces it.

The `valid:false first_broken:2` result recorded on 2026-04-24 was a
**verifier bug, not chain corruption**. `virp-bridge.py:chain_verify()`
walks `ORDER BY id ASC` — globally — and compares each row's
`previous_entry_hash` to the previous row's hash. The chain is
*per-session*: `virp_chain_verify()` walks `(session_id, sequence)` and
every session begins at sequence 0 with
`SHA256("VIRP_CHAIN_GENESIS:" || session_id)`. With two or more sessions
present, the global walk necessarily breaks at the second session's
genesis entry. Reproduced exactly on all three databases below.

Verified per-session, read-only, no daemon restart:

| Database | Entries | Sessions | Result |
|---|---|---|---|
| Live `/var/lib/virp/chain.db` | 3,009 | 169 | **162/169 sessions fully hash-linked**; 7 broken |
| Export `chain.db.export-20260614-2156` | 2,465 | 125 | 118/125 valid; same 7 broken |
| Snapshot `chain.db.broken-2026-04-24` | 1,265 | 38 | 31/38 valid; same 7 broken |

The 7 failures are **writer-convention mismatches, not tamper evidence**.
Five sessions carry an all-zero `previous_entry_hash` at sequence 0 — a
second writer (the Python bridge) using zeros for "no predecessor"
instead of the derived genesis; one carries a third, foreign genesis
value; one has non-contiguous sequence allocation. Six of the seven break
at their *first* entry, which is the signature of a genesis convention,
not of modification. The same 7 break identically across all three
databases. Entry-count ratios overstate the spread: one long-running
bridge session (`dashboard-obs`) accounts for 1,065 of the 1,776 entries
in broken sessions.

**All three approval sessions verify clean** — `approval:R1` (15 entries,
the 2026-07-23 live-proof session), `approval:SW-3850` (10),
`approval:R21` (1). The PROPOSAL → APPROVAL → OUTCOME evidence in
[`docs/LIVE-PROOF-2026-07-23.md`](docs/LIVE-PROOF-2026-07-23.md) holds
under correct per-session verification.

**Narrowed 2026-07-29 (static review):** "fully hash-linked" above
means internal link consistency, not completeness. The per-session C
verifier (`chain_verify_locked`) reports `valid:true` when its walk
ends without checking it reached the session's recorded tail — deleting
the newest K entries of a session still verifies valid, and a zero-row
session verifies valid. The 2026-07-28 result therefore does not rule
out deletion of trailing entries. Additionally, the bridge's
`chain_verify()` checks only the unkeyed `chain_entry_hash` links and
never verifies the keyed `chain_hmac`, so a keyless attacker with DB
write access can produce a chain the operator-facing API reports valid.
See `SECURITY.md` §Verifier Limitations.

**Fixed 2026-08-01, merged to `main` and deployed (running commit
`b6e9602c`):** the C verifier's tail-truncation and zero-row
acceptance. Range verification now
enforces completeness, and a signed per-session head record
(`chain_heads`, HMAC'd with K_chain, updated transactionally with
every append) authenticates chain LENGTH — `virp_chain_verify_session`
/ daemon action `chain_verify_session` detect tail deletion, head
deletion, and keyless head forgery. See `SECURITY.md` §Verifier
Limitations for the mechanism and its trust boundary (a K_chain holder
can still rewrite history; external anchoring remains future work).

**Still open:** the bridge's global-walk verifier (`virp-bridge.py`,
consumer side, not in this repository) is unfixed, so that
operator-facing `chain_verify` API still reports `valid:false` on any
multi-session database and never verifies `chain_hmac`; and the
two-writer genesis divergence is unresolved. Chain *logic* is covered
by `tests/test_chain.c` (genesis, sequential linking, tamper
detection, crash recovery, tail-truncation, zero-row, head-record
attacks, backfill) and `tests/test_chain_concurrency.c` *[tested]*.

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
  -s /run/virp/onode.sock \
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
Observability tools record what the agent claimed to do. VIRP records what was cryptographically verified to have happened. Tracing tells you the agent said it ran `show firewall policy 2`. VIRP tells you the device responded, here is the signed response, here is its position in the tamper-evident chain. (One honest narrowing: "the signed response" means the bytes the O-Node read and signed for that command — on the SSH drivers, body-to-command correspondence is not currently guaranteed; see `SECURITY.md` §Observation-Body Integrity.)

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

- **IETF Draft:** `draft-howard-virp-06` (revisions -00 through -06 submitted)
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
  proofs cover the v2 observation path only; `draft-howard-virp-06`
  §16.1 scopes its evidence claim to match (the -05 text carried the
  older, broader claim).
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
