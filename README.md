<p align="center">
  <img alt="License: Apache 2.0" src="https://img.shields.io/badge/License-Apache_2.0-blue.svg">
  <img alt="C11" src="https://img.shields.io/badge/C-11-00599C?logo=c&logoColor=white">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white">
  <img alt="IETF Draft" src="https://img.shields.io/badge/IETF-draft--howard--virp--06-orange">
  <img alt="Status" src="https://img.shields.io/badge/Status-Research_Prototype-orange">
</p>

# VIRP: Verified Infrastructure Response Protocol

AI agents operating on infrastructure fabricate device state. VIRP puts a
signing daemon (the O-Node) between the agent and the devices: the agent
holds no credentials and no keys, every command is classified against
fail-closed per-vendor allowlists, commands above the configured tier
require an Ed25519-signed human approval that the daemon can verify but
cannot mint, and every device response is authenticated at capture.
Anything the agent then claims about a device that no authenticated
observation supports can be flagged.

The claim ceiling, stated once: VIRP produces authenticated, append-only
operation records under an explicit collector trust model, plus an
experimental gate that checks agent claims against those records. It
does not establish that a device told the truth, and it does not defend
a record against whoever holds the relevant key or controls the
collector.

---

## What is proven and what is not

**Implemented and tested.** The record layer. Observations are
HMAC-SHA256 authenticated inside the O-Node before the caller sees them.
Chain entries are hash-linked per session, each carries a keyed HMAC,
and a signed per-session head record makes tail deletion detectable.
Commands above the tier ceiling are refused with a typed, authenticated
rejection and a filed proposal; they execute only after an approval
signed outside the daemon verifies against an enrolled approver key,
bound to the command hash and device, with a 300 second TTL and
single-use consumption. All of this runs in `make all-tests` and in the
in-tree demo (see below). Evidence for each piece is tagged line by line
in [`SECURITY.md`](SECURITY.md).

**Implemented, not wired into the daemon.** Ed25519 observation signing
(wire version 3). The library builds and verifies v3 observations and
`virp-tool obs-verify` checks one with only the public key. The chain
registration path verifies a v3 body when an observation-signing key is
loaded. But neither shipped daemon binary loads such a key, nothing in
the execute path emits v3, a producer is never required to use v3, and a
downgrade to v1/v2 is never refused. Status: **implemented in the
library, optional, not enforced.** Verified by: `grep obskey
src/virp_onode_prod.c src/virp_onode_main.c` returns nothing;
`tests/test_onode.c` sets `obskey_loaded` by hand.

**Experimental.** The check of agent claims against the record. Two
pieces exist:

- `api/virp_verify.py`, in this tree, verifies a structured claim
  (subject, predicate, value, cited observation) against a corpus of
  authenticated observations and returns VERIFIED, CONTRADICTED,
  UNVERIFIABLE, INCOMPLETE or STALE. It reads payload, timestamp and
  sequence from the verified bytes only. It needs the O-Key, so it is a
  key-holder tool. Spec: [`docs/VIRP-CLAIMS.md`](docs/VIRP-CLAIMS.md).
  Tests: `tests/test_virp_verify.py`.
- The Observation Gate, which scans an agent's free text for device
  claims with no matching tool call and for numbers or addresses that
  disagree with cached observation payloads, is **not in this
  repository**. It lives in the IronClaw consumer
  (`github.com/nhowardtli/ironclaw`, `virp_observation_gate.py`). In the
  copy checked on 2026-08-21 it returns a `flagged` result; it does not
  refuse. The companion data-envelope check in that consumer has a
  `STRICT_MODE`, the environment flag `DATA_ENVELOPE_STRICT=1`. It is
  off by default, and with it off a context that carries device data
  without a collector status is a logged warning, not an error. This
  layer is pattern matching over text, not cryptography, and it is not
  enforcement-grade.

**Specified only.** Role separation into observer, executor and policy
nodes (draft-06 §10); external anchoring of chain heads (§17.4);
cross-administrative-domain federation (§17.5); an EXECUTION_INTENT
record for the crash window between device I/O and the OUTCOME append
(`docs/virp-audit-design-proposals.md`). None of these exist in code.

**Formal analysis.** ProVerif 2.05 proves O-Key secrecy, session-key
secrecy and injective agreement for the v2 observation path, under a
stated trace restriction for the replay store. Freshness is not modeled.
The v1 path and v3 are not modeled. No Tamarin model exists.
[`proofs/README.md`](proofs/README.md); `make proofs` (not run here:
ProVerif is not installed on this host).

---

## Validation

- Independent validation by a NATO NCIA engineer on production Cisco
  hardware: 9/9 HMAC-verified observations. The issues found were filed
  publicly and fixed: legacy KEX negotiation on older IOS (#5, commit
  `d6a986a`), the ASA driver missing from the dev binary (#6,
  `e675b8d`), and a segfault on a device at `enable=0` (#7, regression
  test in `tests/test_onode.c`). Filed 2026-06-02, closed 2026-08-16.
- IETF: `draft-howard-virp` revisions -00 through -06 submitted as an
  individual Internet-Draft; -06 is dated 1 August 2026. -06 specifies
  the v1 and v2 observation formats only. Its Appendix A records the
  claims walked back from -05, including the removal of per-observation
  Ed25519. v3 is ahead of the specification and is -07 material
  ([`docs/DRAFT07-NOTES.md`](docs/DRAFT07-NOTES.md)).
- Ongoing formal-methods engagement with TU Dresden on the ProVerif
  model and the replay-counter restriction, and a routing-area review of
  -03 that prompted a reframing of the draft. Both are acknowledged in
  draft-06 §21.

---

## Verify it yourself

What a verifier can check depends on which key they hold.

| Record | Who can verify today | How |
|---|---|---|
| v1 observation (the execute-path default) | Holder of the O-Key | `api/virp_verify.py`, `report/verify.py`, `virp-tool inspect` |
| v2 session observation | Holder of the derived session key | `virp_verify_observation_v2` in `src/virp_crypto.c` |
| v3 observation | Anyone with the public key | `virp-tool obs-verify <pubkey> <obs_file>`; but see above: nothing emits v3 yet |
| Chain entry hash and per-session link | Anyone with the database | `report/verify.py` (reports the keyed checks as UNCHECKED, not as passes) |
| Chain entry HMAC and signed head | Holder of K_chain | `virp chain verify --db PATH --key PATH`; `report/verify.py` with the key |
| Approval record | Anyone with the approver's public key | `src/virp_approval.c`; approver registry `docs/APPROVAL-FLOW.md` |

So: a third party without the O-Key can check chain linkage and approval
signatures but cannot verify that an observation body came from the
O-Node. Under HMAC the verify key is the forge key. v3 Ed25519 is the
path to public verification of observations, with the status stated
above. One more limit: a commitment-only chain entry (hash, no body) is
accepted by design and grades UNVERIFIABLE in the verifier field, but
`report/virp_report.py` currently rolls that up as PASS. That gap is
pinned as an expected failure in `tests/test_commitment_only_grading.py`
so that fixing it forces this text to change.

---

## The demo, described honestly

`./demo/run.sh` is a deny-side demonstration against a simulated target
(`src/drivers/driver_mock.c`). No device, credential or network is
involved. It observes nine behaviors: a GREEN operation executes and
its record verifies; a modified record fails verification; a RED
operation is refused and a proposal is filed; an approval signed outside
the collector lets the exact approved operation execute once; reusing
the approval fails; an unknown operation fails closed; and every chain
session verifies from its own genesis. Run here on 2026-08-22 from this
tree: `9/9 security behaviors observed`, exit 0.

It shows what the daemon refuses and what it records. It does not show
an agent fabricating, because the agent-side flagging lives in the
consumer gate described above, and it does not show a device telling the
truth, because no device is present. There is no write-path autonomy
demo, because the implementation does not have one: every write above
the ceiling waits for a human signature.

---

## Architecture

```
 requesting process             O-Node (sole credential holder)          devices
 (agent, API, CLI)
 no credentials         Unix socket, SO_PEERCRED uid allowlist
 no keys        ------> classify -> gate -> execute -> authenticate ----> SSH / HTTPS
                <------ authenticated observation or typed refusal
                        chain.db (per-session hash link, K_chain HMAC,
                        signed head), proposals, approvals
```

- **Sole credential holder.** Device credentials are rendered into the
  daemon's config at start from a root-only environment file; the
  daemon runs as an unprivileged service user
  ([`deploy/virp-onode.service`](deploy/virp-onode.service)). The
  socket is mode 0660 and every `accept()` checks the peer uid against
  a startup allowlist. That socket is the trust boundary; a v1 request
  needs no handshake, so whoever can deliver bytes can submit, and
  unauthenticated TCP in front of the socket is not a boundary
  (SECURITY.md §Trust Boundaries).
- **Tier classification.** Each driver supplies a `route_command`
  table. A command is one of GREEN, YELLOW, RED or BLACK, or
  UNCLASSIFIED when no row matches. The gate refuses UNCLASSIFIED and
  refuses anything above the ceiling (`gate_max_tier`, default YELLOW).
  GREEN executes and is recorded. YELLOW executes under the default
  ceiling and needs approval if the ceiling is set to GREEN. RED needs
  approval under the default ceiling. Matching is case-sensitive and the
  exact classified bytes are the bytes executed; separators (`;`, `|`,
  `&`, newline, backtick, `$(`) are refused before classification, which
  also means CLI display filters are refused.
- **BLACK.** Refused under ENFORCE, never filed as a proposal, never
  approvable (`src/virp_onode.c`, the apply and propose branches), and
  rejected by the wire format so no observation can carry it. One
  caveat a reader should know: the gate has a SHADOW mode, a per-driver
  config override that logs and proceeds, and under SHADOW a BLACK
  verdict is logged but not blocked (SECURITY.md §4.7, open). The
  shipped default is ENFORCE for every driver.
- **Per-identity tier ceiling.** `socket_uid_tier_ceilings` in the prod
  config maps a connecting uid to a ceiling that can only tighten the
  node-wide one (`onode_effective_max_tier`). A separate
  `socket_uid_action_allow` map restricts which socket actions a uid may
  call at all.
- **Authenticated observations.** v1 HMAC-SHA256 under the O-Key is
  what the execute path produces. v2 binds session, device, sequence
  and command digest under an HKDF session key and needs the
  HELLO/ACK/BIND handshake. v3 adds Ed25519 (status above).
- **Chain.** SQLite, append-only by convention, one hash chain per
  session from a derived genesis, each entry HMAC'd with K_chain, a
  signed head record per session, and a completeness check so a
  truncated range never verifies. Externally submitted observation
  bodies must carry a valid signature or the append is refused; unknown
  artifact types are refused. A K_chain holder can still rewrite
  history; anchoring outside the collector is specified only.
- **Approvals.** The daemon holds only approver public keys. The
  approver signs a 72 byte canonical payload (proposal id, command hash,
  device node id, timestamp, TTL) with Ed25519 or ECDSA P-256, from a
  software key or a PKCS#11 token. The hardware path is built with
  `make virp-tool-pkcs11` and is exercised against a mock module
  (`tests/test_pkcs11_plumbing.c`), not against a real token in CI.
  Known limit: the signature binds `device_node_id`, not the device
  hostname string (SECURITY.md §4.6).
- **Durability, measured.** A hard I/O error fails the append closed. A
  silent write-drop loses head and entries together and the verifier
  reports a valid shorter chain. A torn head is detected. An approved
  command that crashes between device I/O and the OUTCOME append is
  recorded as "approved, no outcome," which is indistinguishable from
  "never contacted" (SECURITY.md §Execution Durability).

---

## Drivers

`make prod` builds `virp-onode-prod` with every driver flag set
(`Makefile`, target `prod`). The prod binary then registers these driver
names (`src/virp_onode_prod.c`, the "Register drivers" block, names from
each driver's `.name` field):

| Driver name | Transport | Build flag |
|---|---|---|
| `cisco_ios`, `cisco_iosxe` | SSH | `CISCO=1` |
| `cisco_asa` | SSH | `ASA=1` |
| `fortigate` | SSH | `FORTIGATE=1` |
| `panos` | SSH | `PANOS=1` |
| `juniper` | SSH | `JUNIPER=1` |
| `linux`, `proxmox` | SSH (FRR vtysh, host reads, Proxmox) | `LINUX=1` |
| `wazuh` | REST | `WAZUH=1` |
| `librenms` | REST | `LIBRENMS=1` |
| `pbs` (Proxmox Backup Server) | REST, certificate pinned | `PBS=1` |
| `zammad` | REST | `ZAMMAD=1` |
| `mock` | none (demo target) | always |

Every one of them sets `.route_command`, so every command on every
registered driver is classified (`grep -n '\.route_command'
src/drivers/*.c src/driver_panos.c`). The default posture is
fail-closed: a command no table row matches is refused, and a driver
with no classifier would classify everything UNCLASSIFIED and therefore
execute nothing. Driver gate suites run in `make all-tests`
(`test-drivers`).

Scope limits that apply to all drivers, from SECURITY.md §Command Gate:
one command per request, no display filters, no multi-line or config-mode
payloads through the single-command path. PAN-OS has no driver-level
BLACK backstop behind the gate (open).

---

## Scope

VIRP is a protocol with a reference implementation, Apache 2.0. Each
component exists for one of two reasons.

| Component | Serves | Status |
|---|---|---|
| `draft-howard-virp-06`, `docs/VIRP-WIRE-FORMAT.md`, `docs/VIRP-SPEC-RFC-v2.md` | the protocol | specification; -06 covers v1/v2 only |
| C library and O-Node (`src/`, `include/`) | the protocol | implemented, reference |
| Go O-Node and message layer (`implementations/go`) | the protocol | implemented; C/Go parity via `make test-interop` (skipped here, no Go toolchain) |
| Test vectors (`docs/VIRP-WIRE-FORMAT.md` §11) | the protocol | partial: inputs given, expected tag left for the reader to compute |
| ProVerif model (`proofs/`) | the protocol | v2 path only |
| Federation: Ed25519 node keys, `fed_request` / `fed_observation` / `fed_outcome` chain types with ingestion gates | the protocol | implemented record types; cross-domain trust specified only |
| Approval flow and approver registry | the protocol | implemented |
| v3 Ed25519 observations | the protocol | library only; not emitted, not enforced |
| Vendor drivers (table above) | this deployment | implemented |
| Appliance HTTP API (`api/server.py`) | this deployment | implemented |
| Report layer (`report/`) | this deployment | implemented; PASS/UNVERIFIABLE roll-up gap noted above |
| Autopilot, config backup, evidence timers (`autopilot/`, `deploy/`) | this deployment | implemented, lab specific |
| Broker (`broker/`) | this deployment | implemented, loopback only |
| Prometheus exporter (`integrations/prometheus`) | this deployment | implemented |
| NetBox sync (`integrations/netbox`) | this deployment | planned; README only, no code |
| Observation Gate | consumer | experimental, lives in IronClaw, not here |
| Role separation, external anchoring, EXECUTION_INTENT | the protocol | specified only |

Network containment around the daemon (no route from the agent host to
devices, device ACLs that accept SSH only from the O-Node address) is a
deployment control. The tree ships an nftables ruleset for one such
setup (`deploy/nftables-virp-netclaw-egress.nft`) but does not enforce
it.

---

## Build, run, test

Executed on this tree on 2026-08-22 (Linux Mint 22.3 on an Ubuntu 24.04
base, gcc 13.3, Python 3.12) unless marked otherwise.

```bash
# Dependencies (Debian/Ubuntu)
sudo apt install -y build-essential git \
  libssl-dev libsodium-dev libsqlite3-dev \
  libssh2-1-dev libcurl4-openssl-dev libjson-c-dev

git clone https://github.com/nhowardtli/virp.git && cd virp
make            # library, dev daemon, virp-tool, core test binaries
make prod       # virp-onode-prod with all drivers

make test       # core: 59/59 here
make test-onode # daemon: 132/132 here
make test-chain # chain: 33/33 here
./demo/run.sh   # 9/9 here
```

`make all-tests` is the full battery. It ends with a dependency gate
that fails closed if `fastapi`, `httpx` or `reportlab` are not
importable, because suites that skip must not roll up as success. On a
fresh clone without those modules it runs every C suite and then exits
non-zero at that gate. To get a green run, put a venv with them on
`PATH`:

```bash
python3 -m venv ~/virp-test-venv
~/virp-test-venv/bin/pip install fastapi httpx pytest reportlab
PATH=~/virp-test-venv/bin:$PATH make all-tests   # exit 0 here
```

Two suites skip with a loud message on a build host and did so here:
`test-interop` without a Go toolchain, and the live-chain federation
audit without `/var/lib/virp/chain.db`. `check-unit-drift` passes when
no `virp-*` units are installed. Not run here: `make proofs` (needs
ProVerif), `make asan-test`, `make fuzz-obs-ed25519` (needs clang).

Test files, counted with `ls tests/*.c | wc -l` and `ls tests/*.py |
wc -l` on this tree: 47 C files under `tests/` (three of them fuzz
harnesses and one a mock PKCS#11 module), 14 Python files under
`tests/`, 5 under `api/`, 1 under `broker/`, plus the adversarial
program under `tests/adversarial/`.

Start a daemon:

```bash
./build/virp-tool keygen okey /etc/virp/keys/onode.key
head -c 32 /dev/urandom > /etc/virp/keys/chain.key
./build/virp-onode-prod \
  -k /etc/virp/keys/onode.key \
  -s /run/virp/onode.sock \
  -d /etc/virp/devices.json \
  -c /var/lib/virp/chain.db \
  -C /etc/virp/keys/chain.key
```

`-c` requires `-C`, and approval mode refuses to start without a chain.
The systemd unit in [`deploy/`](deploy/virp-onode.service) shows the
intended service user, sandboxing and credential rendering. Not run
here: no daemon was installed on this host.

---

## Documentation

| Topic | Location |
|---|---|
| Threat model, trust boundaries, evidence tags per claim | [`SECURITY.md`](SECURITY.md) |
| Wire format and test vectors | [`docs/VIRP-WIRE-FORMAT.md`](docs/VIRP-WIRE-FORMAT.md) |
| Protocol specification (repo copy) | [`docs/VIRP-SPEC-RFC-v2.md`](docs/VIRP-SPEC-RFC-v2.md) |
| Changes pending for draft-07 | [`docs/DRAFT07-NOTES.md`](docs/DRAFT07-NOTES.md) |
| Approval flow | [`docs/APPROVAL-FLOW.md`](docs/APPROVAL-FLOW.md) |
| Claim verification layer | [`docs/VIRP-CLAIMS.md`](docs/VIRP-CLAIMS.md) |
| Observation flow end-to-end | [`docs/VIRP-OBSERVATION-FLOW.md`](docs/VIRP-OBSERVATION-FLOW.md) |
| Ed25519 observation review | [`docs/REVIEW-ED25519-2026-08-07.md`](docs/REVIEW-ED25519-2026-08-07.md) |
| Adversarial test program | [`tests/adversarial/README.md`](tests/adversarial/README.md) |
| Live transcript, Cisco IOS approval flow | [`docs/LIVE-PROOF-2026-07-23.md`](docs/LIVE-PROOF-2026-07-23.md) |
| Deployment record | [`DEPLOYED.md`](DEPLOYED.md) |
| Contributing | [`CONTRIBUTING.md`](CONTRIBUTING.md) |

Wanted: engineers running it against fleets other than the lab's,
reviewers attacking the protocol, and driver authors. Security issues go
to the address in [`SECURITY.md`](SECURITY.md), not the public tracker.

---

## Contact

Nathan M. Howard, Third Level IT LLC, `nhoward@thirdlevelit.com`
