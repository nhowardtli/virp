# Security Policy

## Reporting Vulnerabilities

VIRP is a security-critical protocol. If you discover a vulnerability in the cryptographic verification path, chain integrity, HMAC signing, or trust tier enforcement:

**Do NOT open a public issue.**

Email: nhoward@thirdlevelit.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if you have one)

We will acknowledge receipt within 48 hours and provide a timeline for remediation.

## Scope

The following are in scope for security reports. Each is tagged with the
evidence backing the corresponding defence:
**[tested]** covered by a checked-in test or machine proof;
**[untested]** implemented, no automated coverage;
**[fixed in branch, undeployed]** fixed and tested on a branch, but not
merged to `main` and not running in production — the defect still
applies to the deployed daemon (as of 2026-08-01 **no in-scope item
carries this tag**; every fix listed below is merged and deployed);
**[open]** confirmed present in the deployed code, not yet fixed;
**[aspirational]** intended, not yet built.

- HMAC-SHA256 signing bypass or forgery *[tested — `tests/test_virp.c`, `tests/test_obs_v2.c`, ProVerif `proofs/virp_obs_v2.pv`. Scope caveat: the signature attests the bytes the O-Node read; that those bytes answer the signed command is enforced separately by the read path — see §Observation-Body Integrity]*
- Observation lost to an O-Key rotation between minting and chain registration *[tested — `tests/test_onode.c` `test_rotation_grace_window_saves_in_flight_observation`, `..._expires`, `..._does_not_accept_a_third_key`, `test_previous_okey_loader_refuses_bad_configurations`. Identified 2026-08-08 while writing the chain_append signature gate; closed the same day by a verify-only previous-key grace window. Registration is a SEPARATE socket round-trip from collection, so an observation minted under the old key and submitted after a rotation was refused by GATE 3 and LOST — no client retries a registration. The daemon now optionally holds the PREVIOUS O-Key (`-K <path>`, window `-W <seconds>`, default 900): when the live key fails a v1 body and the window is still open, the previous key is tried as well. Bounded by construction — the key must be explicitly loaded, the window expires on a deadline, an identical or zero-window configuration is refused at startup, and it is read at exactly one site so it can never sign. The deadline is anchored to KEY-LOAD time and is memory-only, so an unrelated restart while `-K` is still present RE-OPENS a full window; removing `-K` after the drain is what actually closes it, not expiry — see the rotation runbook. Every grace-path acceptance is logged with a running count and the remaining window. THE WINDOW IS WRONG FOR COMPROMISE-DRIVEN ROTATION: if the old key leaked, this keeps honouring it for the whole window — rotate without `-K` and accept the loss of in-flight observations, which is the correct trade when the key is burned. Still not exercised against a real daemon restart; the tests rotate the live key underneath a running in-process daemon instead.]*
- Observation-body integrity — signed body not corresponding to the command in the signed header *[tested — five mechanisms: three from the `hardening-2026-07-29` review, two more from the five-driver read-path audit; all closed on `hardening/review-fixes-2026-07-29`, merged to `main`, and running in production since the 2026-08-01 deploy. Covered by `tests/test_ssh_io.c` and `tests/test_driver_fortigate_scrub.c`. The 2026-07-29 pa-850 occurrence was never root-caused. See §Observation-Body Integrity]*
- Trust tier escalation (e.g., RED command executing as GREEN) *[tested — five driver suites incl. table-driven reachability and adversarial separator injection; see `docs/VIRP-CLAIMS.md` C22–C25]*
- Chain database tampering without detection *[tested (logic) — `tests/test_chain.c` tamper detection. Production chain verified per-session 2026-07-28: 162/169 sessions hash-linked; the 7 failures are writer-convention mismatches, not tamper evidence. Narrowed 2026-07-29: "hash-linked" as measured then establishes internal link consistency, not completeness. Fixed, merged to `main`, and deployed 2026-08-01 (running commit `b6e9602c`): range completeness + signed per-session head record close the truncated-tail/zero-row acceptance — see §Verifier Limitations. Still open: the operator-facing `chain_verify` bridge API (consumer-side repo) never checks the keyed `chain_hmac` and reports a false negative on any multi-session database]*
- O-Node socket authentication bypass *[tested — `tests/test_onode.c` `test_peer_uid_allowed`, `test_peer_uid_rejected`]*
- Device credential exposure through the API layer *[untested — no suite covers the API layer's credential handling]*
- Session handshake state machine violations *[tested — `tests/test_session_negative.c`, `tests/test_session_key.c`]*

Two further defences are worth stating explicitly:

- Single-command enforcement / multi-command injection *[tested — suite only, no live device; see the scope limits below]*
- Fail-closed classification on unrecognized commands *[tested — suite only; all five drivers, both no-match paths]*

## Out of Scope

- Denial of service against the O-Node (known limitation — single-process architecture)
- Issues requiring physical access to the host machine
- Social engineering

## Current State — Status Index (introduced 2026-08-27)

Every tracked security item carries exactly one of four statuses. The
narrative sections below (audits, reviews, corrections) are the record
of how each item was found and argued; THIS index is the current state,
and is expected to resolve against the tree and the running deployment
on the date it carries. The evidence tags in §Scope ([tested],
[untested], …) are orthogonal: they say what backs a defence, not
whether an item is resolved.

- **FIXED** — in `main` AND in the running production binary, with
  commit ref.
- **FIXED, NOT DEPLOYED** — in `main`, not yet in the running
  production binary. The fix deploys with the next rebuild/restart; the
  defect still applies to the deployed daemon. (Supersedes the older
  "[fixed in branch, undeployed]" tag in §Scope for current-state
  tracking.)
- **OPEN** — confirmed present, not yet fixed, stated in its honest
  current shape.
- **OBSOLETE, RETAINED FOR HISTORY** — the item text elsewhere in this
  file (or in the repo's dated records) describes a state that no
  longer exists; the entry here points at the commit that closed it.
  History is reclassified and referenced, never deleted.

**Deployment boundary as of 2026-08-27:** the running production
binaries report build `482d8a52` (daemon restarted 2026-08-27 16:54
UTC). Everything merged to `main` after `482d8a52` is FIXED, NOT
DEPLOYED until the next rebuild.

### FIXED

- Audit §4.1 — sign_intent/sign_outcome signing oracle. Deployed
  2026-08-01 (`b6e9602c`).
- Audit §4.3 — FortiGate `execute backup` YELLOW → RED. Deployed
  2026-08-01.
- Audit §4.4 — non-constant-time digest/MAC compares. Deployed
  2026-08-01.
- Audit §4.5 — chain range completeness + signed per-session head.
  Deployed 2026-08-01.
- Audit §4.8 — proxmox driver had no classifier (everything
  UNCLASSIFIED). Closed by `8bdfe3f9` (proxmox wired to the shared
  linux/FRR classifier, `src/drivers/driver_linux.c`); in the running
  binary.
- node_id == 0 device-binding degeneracy (the sub-claim inside audit
  §4.6): the daemon now REFUSES node_id 0 at load (`5bbbacfe`) and
  every fleet device carries a unique node_id (`b733153d`); deployed
  2026-08-16 (`a3752e18` restart). The REST of §4.6 stays OPEN below.
- linux/proxmox driver-level BLACK backstop independent of gate mode
  (`3ef712fc`); driver refusal contract — refusals declare non-dispatch
  and are never recorded as executions (`f48360c1`); both in the
  running binary.

### FIXED, NOT DEPLOYED

- ASA device with no enable credential refused at config load; refused
  entries reported in fleet listings (PR #15: `b53fbf05`, `f1737806`,
  merged `4dbfb67b`).
- Collector-side allowlist body filtering is IN the running binary
  (`482d8a52` is the running build); listed here as the boundary
  marker: every merge after it awaits the next rebuild.
- Audit §4.7 — **BLACK is unconditional in the gate** (branch
  `fix/black-unconditional`, this repository's HEAD once merged).
  The gate previously refused BLACK only under
  `mode == GATE_MODE_ENFORCE`; under SHADOW a BLACK verdict was logged
  and the command proceeded to the driver. The gate now refuses BLACK
  BEFORE any mode check: SHADOW still observes what enforcement would
  have done for GREEN/YELLOW/RED/UNCLASSIFIED (that is its purpose),
  but it can never turn inexpressible into executable. The refusal is
  persisted as the same gate_rejection/1 chain entry an ENFORCE
  refusal writes, now with a `gate_mode` field naming the mode that
  refused. Invariant test:
  `test_shadow_black_refused_recorded_driver_never_invoked`
  (`tests/test_onode.c`).
- PAN-OS BLACK deny table + driver-level backstop, and the broad
  YELLOW verbs (`debug`, `test`, `less`, `tail`) replaced by
  enumerated known-safe forms (same branch). PAN-OS destructive
  operations (commit / load / scp+tftp import / delete /
  request restart|shutdown system / private-data-reset / raid) now
  classify BLACK — unapprovable, refused in both gate modes — and
  `pa_execute` refuses them again driver-side under the refusal
  contract. **PAN-OS remains the least-mature driver: this change
  narrows exposure but does not make it enforcement-equal to Cisco or
  FortiGate.**

### OPEN

- Audit §4.2 — an ABBREVIATED BLACK command falls through to RED
  (approvable) because BLACK matching is a literal full-token prefix
  compare with no abbreviation expansion, at the gate and in every
  driver backstop alike. Whether a given device accepts a given
  abbreviation is not provable from this tree.
- Audit §4.6 (core) — the approval signature does not cover the
  `device` hostname string; verification compares the UNSIGNED string.
  The signed binding is `device_node_id` — no longer degenerate (see
  FIXED above), so the practical exposure is narrowed, but the
  signature still does not say what the comments in
  `src/virp_approval.c` claim. Fixing it means widening the signed
  canonical — approval-identity binding is pending that format window.
- Typed-operation hashing does not bind the driver/registry VERSION.
  `virp_typed_op_hash()` binds the profile id and the exact validated
  octets (`src/virp_crypto.c` `command_hash_hex`, used by
  `src/virp_approval.c` for the proposal and for verify/consume alike).
  What it does NOT bind is the semantic table that gives an op id its
  meaning, so an approval issued under one table verifies unchanged
  against a later table in which the same op id means something else.
  Confirmed as a roadmap item by an outside review (2026-09-04), and
  the reviewer's framing is the one to keep: **an approval means "this
  operation under this exact semantic table", and today only the first
  half is signed.** Tracked in code as the TODO at
  `src/virp_onode.c:128-131` (the "out of scope" list, 2026-08-01);
  no code change was made when this was logged on 2026-09-04.
  The table is compiled in, so changing it means a rebuild and a
  restart — the exposure is an approval minted before that restart and
  consumed after it. That window is bounded by the approval TTL
  (`ttl_seconds`, default 300 s) and by nothing in the derivation
  itself, which is the point: the binding is a property of the deploy
  cadence rather than of the signature. Closing it widens the signed
  canonical, so it lands in the same format window as the
  approval-identity binding above rather than on its own.
- Execution intent (gate_execution/2, three-valued `executed`):
  an undeclared `!success` driver result still resolves to
  `executed:true` and is signed as DEVICE_OUTPUT. Tracked by the two
  deliberately-PENDING tests in `tests/test_onode.c`
  (`test_refusal_with_body_is_not_an_execution`,
  `test_refusal_with_body_is_not_recorded_executed`). No shipping
  driver emits that shape today (all declare non-dispatch since
  `f48360c1`); the O-Node itself is what remains to be held to
  account.
- Audit §4.5 residual — a mid-walk SQLite error is reported as "chain
  truncated" rather than as a database error (fail-closed; diagnostic
  defect, non-security).
- TCP-path mutual authentication (mTLS or request-side signing) —
  see §Trust Boundaries.
- Command-gate scope limits by design (single command per request, no
  display filters, no multi-line config transactions) — see §Command
  Gate for the honest shape and intended future forms.

### OBSOLETE, RETAINED FOR HISTORY

- "The proxmox driver has no classifier" (audit §4.8 text below) —
  true when written; closed by `8bdfe3f9`. Retained unedited in the
  audit section as the record of the finding.
- "5 of 7 devices load node_id == 0" (inside audit §4.6 text below) —
  true when written; closed by `5bbbacfe` (load-time refusal) and
  `b733153d` (unique fleet node_ids), deployed `a3752e18`.
- "SHADOW mode does not honour BLACK" as a LATENT defect note (audit
  §4.7 text below) — the code fact was re-confirmed on 2026-08-27
  HEAD before fixing; fixed on `fix/black-unconditional` (see FIXED,
  NOT DEPLOYED). The audit text stands as the record.
- The old systemd unit trust-chain notes (units executing paths out of
  the working tree; install procedure existing only as memory) — those
  notes live in the repo's deploy records, not in this file; closed by
  `32dd710f` (install procedure as code: install-prod / install-units
  / rollback-prod, every Exec* path an installed artifact) and
  `3a5d741a` + `make check-deploy-unit` / `check-unit-drift`
  (installed units compared against tracked ones, structurally).
- The per-caller policy TODO in §Trust Boundaries ("NOT implemented",
  all-or-nothing submit) — superseded 2026-08-09/11 by per-uid tier
  ceilings (`5841ec71`, `socket_uid_tier_ceilings`) and per-uid action
  allowlists (`socket_uid_action_allow`), both enforced at SO_PEERCRED
  and live in the production config; see the dated correction at that
  TODO. Sep 1 review (Task 2): the action map is now MANDATORY for
  every uid on an explicitly configured `socket_allowed_uids` — an
  allowed-but-unmapped uid was unrestricted (shutdown included), and
  the tracked template shipped four service identities that way while
  the lab host carried a hand-edited entry for netclaw only.
  `onode_start()` refuses to run, naming the uid, when the map does
  not cover the allowlist; both tracked templates now spell out every
  principal's verbs, and `tests/test_template_uid_policy.py` renders
  them in CI to assert coverage and that no service identity can
  invoke shutdown.

## Socket Peer Authentication

The O-Node Unix domain socket is gated by `SO_PEERCRED` (Linux). VIRP
currently supports Linux only; the BSD `getpeereid` equivalent is not
implemented. Every `accept()` reads the connecting process's UID and
compares it against a startup-loaded allowlist:

- `VIRP_ALLOWED_UIDS` — comma-separated UID list (e.g. `VIRP_ALLOWED_UIDS=0,1001`)
- Prod builds also honor `socket_allowed_uids` in the JSON config
- If neither is set, the allowlist defaults to the daemon's own
  effective UID — closed to every other local user

Rejected connections are closed immediately without reading any bytes
and produce a single `REJECTED connection: peer uid=...` log line.

The socket itself is created mode 0660 atomically via `umask(0117)` set
around `bind()` (with a belt-and-suspenders `chmod(0660)` after), so
there is no window in which a world-accessible node exists on disk.

## chain_append Authorization — Declared Types, Never Inferred (v0.2.1, 2026-09-02)

Two independent policies govern the O-Node control socket. Confusing them
is what broke v0.2.0.

1. **`socket_uid_action_allow`** — which *verbs* a uid may issue
   (`execute`, `chain_append`, `list_devices`, `sign_intent`, ...). Since
   the Task 2 boot invariant, every allowlisted uid must have an entry;
   an allowlisted uid with no action map is a boot failure, not a silent
   grant.

2. **`socket_uid_chain_append_types`** — which *artifact types* a uid may
   append. Enforcement is an **exact string match** against the uid's
   list. No substring matching, no prefix matching, no wildcards.

### The rule

**A uid's chain_append reach is declared, never inferred.** A uid whose
action set includes `chain_append` and which has no type list is a FATAL
boot failure that names the uid, refused *before* the socket is bound.

### What v0.2.0 did instead, and why it failed

v0.2.0 inferred the reach. Any uid merely *present* in
`socket_uid_action_allow` was treated as a "restricted federated
principal" and narrowed to the `fed_request` / `fed_observation` /
`fed_outcome` triple. That inference was written when the only mapped
uid was the netclaw bridge, and it was true of that uid by accident of
configuration rather than by declaration.

Task 2 then made an action map **mandatory** for every allowlisted uid.
The daemon's own service accounts — the autopilot, the config-backup
writer, the evidence writer — were mapped for the first time, and the
inference immediately reclassified them as restricted federated
principals. Their real appends (`observation`, `comparator_verd`,
`chainwalk_summa`, `no_drift`, `evidence_item`) were refused with:

```
[O-Node] POLICY REFUSAL: uid <N> chain_append artifact_type '<type>' — a
restricted principal may append only fed_request/fed_observation/fed_outcome
```

Two correct changes, each defensible alone, combined into a refusal of
the node's own evidence. **There was no template-only fix**: the
inference lived in the daemon, so no configuration could exempt the
service accounts. That is the property being removed — a policy you
cannot see in the config and cannot override from it.

The bridge's `fed_*` reach still exists. It is now exactly one row of
the type policy, with no special status in the code.

### Type spellings match the wire, not the source

The `artifact_type` field is 16 bytes. Longer names arrive truncated, so
the policy lists the **truncated** spellings — `comparator_verd` (from
`comparator_verdict`) and `chainwalk_summa` (from `chainwalk_summary`).
A policy written with the untruncated names would silently refuse the
traffic it was meant to admit. The list matches what is on the wire.

### What this does not do

The type policy authorizes *which* types a uid may append. It does not
weaken any gate that validates the *content* of an append: an
`observation` must still be a signed observation wire message, and the
indirect-commitment types must still carry a body. Being on the list is
permission to submit, never a waiver of verification.

## Trust Boundaries and Transport Paths

**The trusted request boundary for 1.0 is the local Unix domain socket,
and only that.** (Corrected/clarified 2026-08-07.) The controls that
decide *who may submit a request* — filesystem permissions on the
socket, `SO_PEERCRED` peer-UID allowlisting, and the uid allowlist — are
properties of the local Unix socket. They do NOT extend over a network.
Any TCP exposure of the O-Node MUST sit behind an authenticated gateway
(mTLS, or request-side signing at the VIRP message layer). **Unauthenticated
TCP is not a supported trust boundary for 1.0** — a plain socat/TCP
forwarder in front of the socket is a convenience for a trusted lab
segment, not a security boundary, and nothing below should be read as
saying otherwise.

Why the boundary is the socket and not "the handshake": the v1 EXECUTE
path does **not** require a VIRP session handshake (see the correction
in the Unix-socket bullets below). There is therefore no per-connection
cryptographic proof of caller identity on a submit — whoever can deliver
bytes to the listener can submit a request. On the Unix socket, "who can
deliver bytes" is exactly what `SO_PEERCRED` + the uid allowlist
constrain. Over unauthenticated TCP, "who can deliver bytes" is "anyone
who can reach the port," which is why that path needs an authenticating
gateway to become a boundary at all.

VIRP defines two distinct paths that reach the O-Node. Their protections
are not the same, and a protection that applies to one does not
automatically apply to the other.

**Local Unix domain socket** — `/run/virp/onode.sock` for both prod and dev.
(The client default previously drifted to `/tmp/virp-onode.sock`; /tmp is
world-writable and shared, so a pre-created socket or symlink there is a
local attack vector that SO_PEERCRED does not defend against.) Protected by:

- `SO_PEERCRED` peer-UID allowlist (see previous section) — the kernel
  reports the caller's real UID, which is checked against the
  startup-loaded allowlist before any bytes are read.
- Filesystem mode `0660` with ownership restricted to the daemon's
  service user/group.
- HMAC-SHA256 signing of every observation returned to the caller,
  using an O-Key the caller does not possess.

> **Correction (2026-08-07): the session handshake is NOT required to
> submit a v1 request.** An earlier version of this list stated a VIRP
> session handshake (`SESSION_HELLO` / `SESSION_HELLO_ACK` + HKDF
> derivation) happens "on every fresh connection." That is false for the
> v1 EXECUTE path, which is the deployed submit path: an active session
> is required only for v2 *observation* requests (`obs_version == 2`,
> enforced at `src/virp_onode.c`), not for submitting a v1 command. A
> caller can connect and submit without any handshake. The consequence,
> stated plainly: **network access to the listener == the ability to
> submit a request.** There is no cryptographic caller-identity check on
> submit — which is precisely why the trusted boundary is the Unix
> socket (where `SO_PEERCRED` + the uid allowlist decide who can deliver
> bytes), and why unauthenticated TCP is not a supported boundary.

**TCP path (CT 210 dashboard ↔ CT 211 O-Node, ports 9998/9999)** — the
dashboard's `virp-bridge.py` listens on TCP 9998 locally on CT 210 and
opens a TCP connection to CT 211:9999, where a socat forwarder proxies
to the Unix socket. On this path:

- `SO_PEERCRED` sees the local socat process's UID, **not** the remote
  dashboard's identity. It cannot distinguish authorized dashboard
  traffic from any other process on CT 211 that can reach the socat
  forwarder.
- HMAC signing of observations still applies — observations returned
  across the TCP bridge are signed at collection time with the O-Key and
  are as verifiable as on the local path. An attacker who intercepts or
  injects on the TCP path cannot forge *observations* without the O-Key.
  (What "signed at collection time" does and does not guarantee about
  the observation *body* is narrowed in §Observation-Body Integrity —
  the caveat applies equally on both paths.) **This protects returned
  observations, not the submit direction:** it does nothing to
  authenticate *who submitted the request*. Because v1 EXECUTE needs no
  handshake, anyone who can reach the TCP forwarder can submit — the
  observation-signing property does not make the TCP path a trust
  boundary for requests.
- The TCP path itself is **not** currently TLS-protected, and the
  session handshake authenticates session establishment via nonce
  exchange but does not cryptographically bind to a TCP endpoint
  identity. Confidentiality, integrity of requests in flight, and
  mutual authentication of the two containers currently rely on:
  - W1 egress isolation (CT 210 can reach only allowlisted ports on
    CT 211),
  - network segmentation between the two containers,
  - the O-Key's secrecy on CT 211 (observations remain unforgeable
    even if the request channel is compromised).

**Open work.** TCP-path mutual authentication — either mTLS between
the dashboard bridge and the socat endpoint, or request-side signing
at the VIRP message layer — is not yet implemented and is tracked as
follow-up hardening.

> **TODO — per-caller request policy (future control, NOT implemented).**
> The honest boundary today is all-or-nothing: any caller who can submit
> can submit at any tier the gate allows, because the daemon has no
> notion of *which* caller a request came from beyond the transport-level
> `SO_PEERCRED` uid. A real per-caller policy — e.g. capping
> remotely-sourced operations at GREEN, or attaching a requester role —
> depends on requester-identity plumbing that does not exist yet (the
> 2026-08-04 all-or-nothing finding). It is a later architectural phase.
> This section documents the current boundary honestly; it deliberately
> does not describe a per-caller control as if it existed. Until that
> plumbing lands, the enforced control is the Unix-socket uid allowlist,
> full stop. *(No CI assertion ties this doc claim to code yet: the
> invariant "v1 EXECUTE requires no session" is an absence, which is
> awkward to grep-assert without pinning internals; a positive test that
> a submit succeeds with no prior handshake is the right future hook.)*

> **Corrected 2026-08-27 — the per-caller control now EXISTS.** The
> TODO above was written before 2026-08-09 and stood after the
> plumbing landed. `5841ec71` added per-uid tier ceilings
> (`socket_uid_tier_ceilings`: the SO_PEERCRED uid's effective gate
> ceiling is TIGHTENED, never raised — the netclaw remote identity is
> pinned to GREEN in the production config), and Item 8 (2026-08-11)
> added per-uid action allowlists (`socket_uid_action_allow`,
> fail-closed on malformed entries). "Capping remotely-sourced
> operations at GREEN" — the exact example above — is what production
> runs today. The TODO text is retained unedited as the record;
> corrected here in the house style rather than silently rewritten.

## Ed25519 Observation Signing (added 2026-08-07)

**The scheme.** Observations can now additionally be emitted as wire
version 3 (`virp_build_observation_ed25519`): the v2 header layout and
session-HMAC trailer, PLUS an Ed25519 detached signature by the O-Node's
observation-signing key over `header || payload || hmac` — every byte
of the message except the signature itself, so the message is one
atomic signed unit and the HMAC trailer cannot be rewritten in transit.
(That span is normative and changed on 2026-08-08; the first cut signed
`header || payload` only, leaving the 32 HMAC bytes bound by nothing.
Changed while v3 had zero dependents — see `docs/DRAFT07-NOTES.md` §1
"Compatibility".) Wire format and rationale:
`docs/DRAFT07-NOTES.md` §1 and the `VIRP_VERSION_3` block in
`include/virp.h`. Verification needs only the public key
(`virp_verify_observation_ed25519`, `virp-tool obs-verify`) — the
verifier holds no secret of any kind.

**Exactly what this adds, and what it does not.**

- **Added — consumer/auditor non-forgeability.** Under the symmetric
  HMAC schemes, any party given the verify key can also mint a
  valid-verifying observation: verify key == forge key. That ceiling is
  reproduced as a unit test (a clean-VALID fake BGP route, the original
  BGP-test finding) in `tests/test_obs_ed25519_forge.c`, alongside the
  proof that the same forgery attempted with only the Ed25519 PUBLIC
  key fails for every signature a public-key holder can compute. A
  report consumer, dashboard, or external auditor can now verify
  without being trusted not to forge.
- **NOT added — daemon-compromise resistance.** The daemon holds the
  signing private key because the O-Node is the attester; a compromised
  O-Node forges v3 observations exactly as it forges HMAC ones. The
  win is independent verifiability, nothing more.
- **Verified when presented, not required — three facts, not one**
  (corrected 2026-08-18; the earlier "chain append does not check
  Ed25519" was wrong):
  1. **v3 IS verified at registration.** When a v3 observation is
     chain-appended, the daemon verifies its Ed25519 signature against the
     loaded observation-signing public key and refuses the append on
     failure (`chain_append_verify_observation`, the `VIRP_VERSION_3` arm →
     `virp_verify_observation_ed25519`). A v3 body with a bad signature
     never enters the chain.
  2. **v1/v2 remain permitted.** Chain append verifies whatever wire
     version the body declares — v1 (O-Key HMAC) and v2 (session HMAC) are
     still accepted and verified under their own keys. v3 is additive, not
     a replacement; nothing that produces or verifies HMAC observations
     changed behavior and no client default changed.
  3. **v3 is NOT universally required, and downgrade resistance is NOT
     enforced.** Nothing compels a producer to use v3: a v3-capable signer
     may present the same observation as v1/v2 and it is accepted. The
     daemon does not reject a lower version in favour of an expected v3, so
     an adversary who can produce a valid v1/v2 observation is never forced
     onto the public-key path. Requiring v3 and refusing downgrades is the
     observation re-cut phase. Until then, v3 observations are only as
     load-bearing as the verifier a consumer actually runs.
- The public-key verifier checks authenticity and integrity of the
  signed bytes only. Replay, staleness and session acceptance remain
  the accepting endpoint's checks (v2 verify semantics).
- **NOT formally modeled.** The ProVerif proofs
  (`proofs/virp_obs_v2.pv`, re-runnable via `make proofs`) cover the
  v2 HMAC observation path only — README's formal-verification claim
  is scoped the same way. A passing `make proofs` says NOTHING about
  the v3 Ed25519 path: no machine-checked model of v3 signing,
  verification, or cross-version downgrade exists yet. Its properties
  rest on the test evidence above (forge contrast, negative battery,
  fuzzing) until a v3 ProVerif model is written — future work, slated
  alongside the observation re-cut.

### Observation-Signing Key — Custody

An O-Node Ed25519 observation-signing keypair exists (`virp-tool keygen
obskey`, loader `virp_obskey_load`), distinct from both the symmetric
O-Key and the approval keypair. Its custody is deliberately the MIRROR
of the approval keypair's, and that is correct, not a contradiction:

- **Approval keypair:** the secret lives OFF-box with a human approver;
  the daemon holds only the public key. The property purchased is that
  the daemon can never approve its own proposals — approval answers
  "did a human other than the daemon authorize this?".
- **Observation-signing keypair:** the secret lives ON the daemon host.
  The O-Node is the attester — an observation is precisely the daemon's
  own signed statement of what a device returned, so only the daemon
  may hold the key that makes that statement. What the asymmetry buys
  is on the CONSUMER side: the public key verifies observations but
  cannot mint them, unlike the symmetric O-Key where the verify key
  and the forge key are the same bytes.

This key does NOT change the daemon-compromise boundary: a compromised
O-Node still forges observations, because the O-Node is the attester.

Custody enforcement (tested in `tests/test_obskey.c`): the private key
file must be a regular file, mode 0400/0600, owned by the daemon's
effective UID (or root); symlinks, group/world-accessible modes and
wrong-size (non-64-byte) files are refused at load with distinct
errors. The secret is `sodium_mlock`'d while loaded, zeroized on
destroy, and appears in no log or export path; only the public key is
exportable (raw or SPKI DER, `key_id = SHA-256(pub)[:16]`, the same
convention the approver registry uses).

## Detached Ed25519 Chain Signing (D-1, added 2026-08-23)

**The scheme.** A node may additionally sign every chain entry and every
per-session head with a dedicated Ed25519 keypair, so a third party can
verify chain entries **without the symmetric chain key**. This opens
independent (asymmetric) verification for every session created after the
cut-over. It is opt-in (`virp-onode-prod -S <secret>`); absent, the daemon
runs exactly as before — signing off, zero behaviour change — and rollback
is removing the flag. It follows the D-0 sealing ceremony (`tools/seal/`),
which covers everything written before the cut-over.

**The invariant it preserves.** The canonical bytes DO NOT CHANGE. The
twelve-field `build_canonical_json` construction, the SHA-256
`chain_entry_hash`, the `chain_hmac` under K_chain, the `head_canonical`
(`VIRP-CHAIN-HEAD-v1`) and its HMAC, the milestone canonical and the
genesis rule are byte-identical to the pre-D-1 tree. The Ed25519 signature
is a PURE ADDITION: it signs the **same** canonical bytes already hashed
and HMAC'd, and is stored in NEW columns (`chain_entries.chain_sig`,
`chain_sig_key_id`; `chain_heads.head_sig`, `head_sig_key_id`) that no
pre-D-1 reader touches. Strip those columns and the chain is exactly the
old chain, not a broken one. The invariant is locked in every build by
`tests/test_chain_invariant.c` / `.py` against the D-0 Appendix A fixtures
(`tools/seal/fixtures-appendix-a.json`) and a second, non-self-referential
set of goldens from `report/verify.py`.

**Domain separation.** One key signs two object kinds, so the signature
input is `TAG || NUL || canonical`, with
`VIRP-CHAIN-ENTRY-SIG-v1` for entries and `VIRP-CHAIN-HEAD-SIG-v1` for
heads (the NUL is signed, the `VIRP-TYPED-OP` convention). The tags differ,
so no byte string is a valid entry signature and a valid head signature at
once — an entry signature can never validate as a head signature or vice
versa. The tag is never stored and never enters the canonical.

**Three verification tiers, each independent** (`virp_chain_open_verifier_ex`,
`virp chain verify --db P [--key K] [--pubkey PUB] [--keyless]`, and
`report/verify.py`):

| tier | needs | authenticates |
| --- | --- | --- |
| keyless | nothing | hash + prev-link + completeness. The head's length claim is reported UNAUTHENTICATED. |
| symmetric | K_chain | adds the per-entry and head HMAC — the pre-D-1 behaviour, byte-for-byte. |
| asymmetric | the PUBLIC key only | adds Ed25519 on every entry and the head. No secret material is loaded in the process. |

**Session-granularity key rotation.** In a head-signed session every
entry's `chain_sig_key_id` MUST equal the head's key_id (which must equal
the verifier's key). A missing signature (stripped), a key_id that differs
from the head's, or a signature that does not verify is a **hard FAIL** at
the same severity as tampering — the sig columns sit outside the canonical,
so the signature is their only integrity protection, and a soft "unsigned"
reading would let an attacker strip a signature undetected. "Not verifiable
under this key" is a **soft, whole-session** outcome, reserved for when the
verifier simply lacks that session's public key; the other tiers still
apply. An unsigned (pre-D-1) session read with a public key counts its
entries unsigned and never fails.

**What it does NOT change.** Like the observation-signing key, this does
not move the daemon-compromise boundary: a compromised daemon holds the
secret and can still sign a forged chain, because the daemon is the
attester. What the PUBLIC key buys is on the consumer side — verify without
forge capability, and without the chain key. A K_chain holder could always
rewrite history; the Ed25519 signature adds an adversary class the HMAC
never addressed (a verifier who must hold no secret at all), it does not
remove one.

**Milestones stay unsigned in D-1** (they remain HMAC-only). Signing the
milestone canonical is noted as a draft-07 consideration in
`DEPLOY-NOTES.md`; nothing depends on a milestone signature today.

### Chain-Signing Key — Custody

A per-node Ed25519 chain-signing keypair (`virp-tool keygen chainsign`,
loader `virp_chainsign_load`) is the **sixth** key role in the tree,
distinct from every other:

- **O-Key / R-Key** — symmetric HMAC, observation / intent channels.
- **K_chain** — symmetric HMAC over the chain canonical (unchanged; still
  written on every entry).
- **Approval keypair** — Ed25519/P-256, secret OFF-box with a human
  approver; the daemon holds only the public key.
- **Observation-signing key (obskey)** — Ed25519, signs v3 observation
  *bodies*.
- **Chain-signing key (D-1)** — Ed25519, signs chain *entries and heads*.

Custody mirrors the obskey's, and for the same reason: the daemon is the
attester of its own chain, so the secret lives ON the daemon host and only
the public half is distributed. Enforcement (tested in
`tests/test_chainsign.c`): the secret file must be a regular file, mode
0400/0600, owned by the daemon's effective UID (or root); symlinks,
group/world-accessible modes and wrong-size (non-64-byte) files are refused
at load with distinct errors; the loader re-derives the public half from
the seed and refuses a file whose halves disagree. The secret is
`sodium_mlock`'d while loaded, zeroized on destroy, and appears in no log
or export path. Only the public key is exportable (raw or SPKI DER,
`key_id = SHA-256(pub)[:16]`), and it is published on the node's `/api/key`
surface (`chain_signing` block, from `VIRP_CHAIN_SIGN_PUB`) so a verifier
can obtain it from the node or out of band. Signing is fail-closed: once
`-S` is given, a signing error fails the append and a key that will not
load fails startup — the node never runs silently-unsigned when asked to
sign.

## Chain Registration — Observation Signature Gate (added 2026-08-08)

`CHAIN_APPEND` is the socket path by which a client asks the daemon to
record an entry. Every entry it writes gets a `K_chain` HMAC, so an
entry a caller induced is, at the chain layer, indistinguishable from
one the daemon minted itself. Three gates now stand in front of it, all
fail-closed, all on the EXTERNAL path only:

1. **Type namespace.** Daemon-reserved semantic types are refused
   outright; unknown types are refused rather than recorded as if they
   meant something.
2. **Body binding.** When a body is submitted the daemon recomputes
   SHA-256 over the exact received bytes and refuses a declared
   `artifact_hash` that does not match, constant-time.
3. **Signature binding (new).** When `artifact_type` is `observation`
   and a body is present, the body must actually BE a signed
   observation. Until this gate existed, gates 1 and 2 together still
   permitted arbitrary bytes — a plausible-looking device output a
   client invented — to be recorded as an `observation`, hash-bound to
   a commitment the client also chose, and stamped with the chain HMAC.
   Binding bytes to a commitment says nothing about who produced them.

Gate 3 dispatches on byte 0 of the decoded body, explicitly; an unknown
version is refused, never guessed at. It verifies the SAME bytes gate 2
hashed, via the same decoder, so what is verified is what is recorded.

| wire version | verified with | if the key is unavailable |
|---|---|---|
| v1 | O-Key HMAC (daemon always holds it) | n/a |
| v2 | derived session-key HMAC; the body's `session_id` must match the daemon's ACTIVE session | refused |
| v3 | Ed25519, public half of the observation-signing key | refused |

The v2 check is signature-only. Replay rejection, freshness and
device/command binding are an *accepting endpoint's* rules; a registrar
re-applying replay rejection would refuse the very observation it is
being asked to record. Establishing that these bytes came from a holder
of the key is the whole question here.

**Commitment-only appends — an explicit decision, not a gap left open.**
An entry with a hash and no body cannot be signature-checked, because
there are no bytes to check. Such appends REMAIN LEGAL and GATE 3 does
not run for them: the whole GATE 2 + GATE 3 block is conditioned on a
body being present (`src/virp_onode.c`, `req.artifact_content[0] !=
'\0'`). This is deliberate. It is the path `virp_autopilot.py` takes for
observations past the 8192-byte artifact field — roughly half of
LibreNMS on a five-minute cycle, 1,935 of 51,120 observation entries in
the live chain — and requiring a body would fail every one of them
closed at the first restart after deploy.

Why that is not a signature bypass — stated at the level it is
actually true. The PER-ENTRY FIELD is honest: a body-less observation
grades `obs_hmac = UNVERIFIABLE`, never PASS, so an attacker who
registers a hash gets an unverifiable row rather than a forged
observation, the same grade a legitimate oversized LibreNMS entry gets.

**The report roll-up does NOT currently carry that through, and this
rationale must not be read as claiming it does.**
`EntryVerification.ok` is `FAIL not in (...)`, and UNVERIFIABLE is not
FAIL, so a commitment-only entry reports `ok = True`, is omitted from
`summarize()`'s `failed_entries`, and is rendered as the literal string
**PASS** by `report/virp_report.py` — for an observation whose
signature was never checked. Verified on 2026-08-09 against a real
production entry (`obs:librenms-lab:1786029902471700439`), not only a
synthetic one.

That is the PASS/UNCHECKED tri-state item from the 2026-08-07 review.
It is deliberately NOT fixed here: changing `ok()` re-grades
operator-facing verdicts on tens of thousands of existing entries and
does not belong in a deploy payload assembled for something else. Until
it is fixed, "the reader grades it UNVERIFIABLE" is true of the field
and false of the PDF, and an operator reading a report cannot
distinguish a verified observation from a commitment-only one.

*[tested — `tests/test_onode.c`
`test_chain_append_commitment_only_observation_accepted` and
`..._empty_body_accepted` drive both no-body shapes through the real
handler. `tests/test_commitment_only_grading.py` pins the FIELD at
UNVERIFIABLE for a legitimate and an invented commitment alike, and
pins the ROLL-UP GAP as an `expectedFailure`
(`test_KNOWN_GAP_bodyless_entry_still_rolls_up_as_ok`) so that fixing
`ok()` turns it into an unexpected success and fails the suite —
forcing this wording to be revisited rather than left stale]*

The residue is real and stated: a caller can still write an arbitrary
hash under `artifact_type: observation`. Closing that needs a
body-retention change or an authenticated-submitter mechanism, and
neither is in this change.

### Rotating the O-Key without losing in-flight observations

Gate 3 verifies at REGISTRATION time and collection is a separate
round-trip, so a naive rotation drops every observation minted before
the swap and submitted after it. They are lost, not delayed — no client
retries a registration.

**What the `-W` deadline is anchored to.** CLOCK_REALTIME at the moment
the previous key is LOADED — process start for the daemon, since main()
loads it right after init. It is not anchored to the rotation event and
it is held in memory only; nothing persists it. **An unrelated restart
mid-rotation therefore re-opens a FULL window** — restart 10 minutes
into a 15-minute window and you get a fresh 15 minutes, not the
remaining 5. While `-K` stays on the command line every restart renews
it, indefinitely. The window bounds a single process run, not the
rotation. This is why step 4 below is not optional.

**The shipped `deploy/virp-onode.service` passes neither `-K` nor
`-W`.** Rotation with a grace window is a deliberate, temporary
override — a drop-in or a hand-run invocation — and the canonical unit
stays clean so no install carries a standing grace window it never
asked for.

Routine rotation, key NOT compromised:

1. Keep the outgoing key. Put the new key at the live path and the old
   one somewhere readable only by the daemon user, e.g.
   `/etc/virp/keys/onode.key.prev` (0600, same owner — it is subject to
   the same custody gate as the live key and will be refused otherwise).
2. Start the daemon with both, via a systemd drop-in or by hand:
   `virp-onode-prod -k /etc/virp/keys/onode.key -K /etc/virp/keys/onode.key.prev -W 900 ...`
   The daemon REFUSES TO START if the previous key will not load, has
   the same fingerprint as the live key, or `-W` is 0. That is
   deliberate: an operator who passed `-K` believes in-flight
   observations are protected, and silently ignoring the flag would
   lose exactly the entries they were trying to save.
3. Watch the drain. Every grace-path acceptance logs
   `verified under the PREVIOUS O-Key` with a running count and the
   remaining window. The drain is one collection cycle wide, so the
   count should stop climbing within minutes — well before the window
   closes.
4. **Remove `-K` once the count stops climbing**, and restart. Do not
   rely on expiry to close the window: see the anchoring note above —
   any restart while `-K` is still present renews it in full.
5. Delete the old key file once `-K` is gone.

**Compromised key — do NOT use `-K`.** The window's entire function is
to keep honouring the old key, so it keeps honouring the attacker too,
for its full duration, and every restart renews it. Rotate without it
and accept the loss of in-flight observations; that is the correct
trade when the key is burned. Raising `-W` past one collection cycle
buys nothing and widens that exposure.

**When the Ed25519 (v3) observation path reaches production it will
need the same verify-side grace window at its own key rotation** — the
obskey has exactly the mint-then-register-later shape that made this
necessary for the O-Key, so design it in rather than rediscovering it.

### Known benign artifact_bind mismatch — `obs:pbs-lab:1785538992`

One entry in the production chain reports an artifact-binding mismatch
for a reason that is NOT tampering, and anyone comparing verifier output
before and after a deploy should know about it before chasing it.

Measured read-only on 2026-08-09. Exactly one `artifact_id` appears on
two chain entries — `obs:pbs-lab:1785538992`, session
`virp-cli:pbs-lab`, sequences 0 and 1, minted 185 ms apart:

| entry | commits to |
|---|---|
| seq 0 | `5f109f05…` |
| seq 1 | `1b5550cb…` |
| the single stored body hashes to | `1b5550cb…` — **seq 1 only** |

The artifact store is keyed by `artifact_id`, so both entries resolve to
one body, and that body satisfies seq 1's commitment. **Seq 0 therefore
looks up a body that is not the one it committed to** and grades as a
hash mismatch. The cause is the second-resolution artifact id — see the
comment above `virp_chain.c`'s id construction — which two observations
inside the same second collided on. It is a naming collision, not
evidence of alteration: seq 0's own bytes were displaced, not modified.

This also accounts for the only residue in the entry/body arithmetic:
55,245 entries = 2,078 with no stored body + 53,167 with one, while the
`artifacts` table holds 53,166 rows. The extra one is this shared body.
There are no orphaned artifact rows and no duplicate artifact rows.

Not fixed here. Re-registering seq 0's body is not possible (the bytes
are gone) and rewriting chain history to drop the entry is worse than
the mismatch. Recorded so it is recognised rather than re-investigated.

### Grace-verified entries are not marked in the chain — decided

An entry whose observation verified under the PREVIOUS key is
byte-identical, in the chain, to one that verified under the live key.
Only the daemon log distinguishes them. **This is accepted; no chain
change is being made.** The reasoning, so it can be re-examined rather
than re-litigated:

- **The evidence is retained, not lost.** The grace path lives inside
  the v1 arm of gate 3, which only runs when a body was submitted, and
  the append commits that body in the same transaction or fails the
  whole request. So every grace-verified entry HAS its signed bytes
  stored. An auditor holding the old and new keys can partition entries
  by which key verifies, independently and after the fact. What is
  missing is an index, not the underlying proof.
- **The alternative is a chain-format change.** Recording which key
  verified would mean a new field inside the HMAC'd canonical object,
  which changes the canonical form for every entry and breaks
  comparability with every entry already written — **55,245 chain
  entries as of 2026-08-09, of which 51,948 are observations** (an
  earlier revision of this section cited 51,120 as the entry count; that
  was the OBSERVATION count at the time, not the total, and the chain
  grows every five-minute cycle, so treat both numbers as a dated
  measurement rather than a constant). That belongs with the
  `commitment_mode` and provenance work in a deliberate chain-format
  window, not bolted on during a rotation fix.
- **The exposure it would document is already bounded** by the window
  being verify-only, explicitly loaded, and time-bounded, with each use
  logged and counted.

If a future format change opens the canonical object, the verifying-key
identity is the natural third field alongside provenance and
`commitment_mode`.

## Observation-Body Integrity

The HMAC-SHA256 signature on an observation is sound, and the v2 header
binds command hash, device, session and sequence. What the signature by
itself does not establish is that the observation *body* is the
device's response to the command named in the header: bytes that did
not come from the signed command could enter the body before signing,
and the O-Node would then sign them faithfully.

The independent static review at tag `hardening-2026-07-29` identified
three mechanisms. A side-by-side audit of all five drivers' read paths
found two more — PAN-OS shared Cisco's defect and had a keepalive of
its own, and every driver reported a promptless read as success. All
are now addressed on branch `hardening/review-fixes-2026-07-29`.

> **Deployment status (updated 2026-08-01).** These fixes are **merged
> to `main` and deployed**. They were already present in the binary
> installed 2026-08-01 01:10 (`cc213351`) and remain in the current
> running commit `b6e9602c`. The caveats under "What was wrong" below
> describe the *pre-fix* behaviour and no longer apply to production;
> they are kept as the record of what was wrong and why.
> *[tested]*
>
> This block previously read "not merged to `main` and not deployed as
> of 2026-07-29" and stayed that way after both had happened. The
> 2026-08-01 external code audit read it, took `main` to be pre-hardening,
> and re-reported findings that were already closed. A status line that
> is not maintained is not a conservative default — it misdirects review
> effort in whichever direction it happens to be wrong. Every claim in
> this file is expected to resolve against the tree and the running
> deployment on the date it carries.

### What was wrong

**Cisco and PAN-OS read stale bytes from cached connections.** Neither
drained the channel before sending. Both terminated a read on a
heuristic — any trailing `#`/`>` (plus an `@` somewhere on the line for
PAN-OS), never compared against the connection's actual prompt — so
device output that merely resembled a prompt ended the read early and
left the true remainder buffered. These drivers hold ONE channel per
device for the life of the connection, so that remainder became the
head of the next command's read. ASA and JunOS drained first, but only
for a fixed 200 ms, and their terminators were unanchored too.

**A promptless read was reported as success.** Every SSH driver
returned the bytes it had when a read timed out without a prompt, and
`onode_execute_obs_ex` only retries when `output_len == 0` — so a
truncated-but-nonempty body was signed as ordinary GREEN device output
with nothing anywhere marking it short.

**The watchdog could interleave with an in-flight command.** The
watchdog called `drv->health_check(conn)` holding only `conn_mutex`
while execute ran holding only `exec_mutex` — different locks on the
same channel.

**FortiGate signed its own VDOM scaffolding, and never checked its
read.** The `config vdom` / `edit <vdom>` / `end` wrapper echoes were
only partially scrubbed (the old scrub dropped the first line only), and
`result->success` was set unconditionally, so a reply truncated by a
full buffer, an idle timeout or a transport error was signed as the
device's answer.

**PAN-OS's keepalive left its own reply on the channel.** A background
thread wrote a newline every 55 s and drained the reply on a
timing-based read into a 1024-byte buffer. Anything it did not consume
stayed on the shared channel for the next command.

### What changed

`src/virp_ssh_io.c` (new) replaces the four per-driver read loops in
Cisco, ASA, JunOS and PAN-OS. Three rules:

- **The prompt is learned at connect** and confirmed — two bare-newline
  probes must return the same last line — then used as an *input* to
  every subsequent read. There is no heuristic fallback: a connection
  whose prompt cannot be learned is refused outright. JunOS's ordering
  was inverted for this; it previously cleared the prompt immediately
  before each read, making the prompt a by-product of the read rather
  than a check on it. Commands that deliberately move the prompt
  (`configure` / `rollback` / `exit`, ASA enable transitions) re-learn
  it explicitly.
- **Reads terminate only on the learned prompt**, matched exactly at
  the start of the final line.
- **Drain-until-quiescent before every send**, bounded by time and
  bytes. Residue is not silently discarded: every occurrence is logged
  as `[SSH] Residue drained before send: device=<host> bytes=<n>`, so
  the rate at which this condition still arises is visible in the
  field rather than inferred.

A read that ends without the learned prompt now returns
`VIRP_ERR_NO_PROMPT`, which the drivers propagate as a hard error, so
the O-Node emits a **typed ERROR observation** carrying the command's
true tier instead of signing a truncated body as device output.
Command echoes are stripped by matching the command text rather than by
deleting the first line positionally.

The watchdog's `health_check` now runs under `exec_mutex[i]`, with the
lock order stated in the code: `exec_mutex[i]` → `conn_mutex`, never
the reverse.

PAN-OS's keepalive runs through the same primitive as a command
(drain → send → read to the learned prompt), so its window cannot leave
residue whatever the device's timing; a keepalive that does not get its
prompt back marks the session stale rather than reporting OK.

FortiGate is deliberately **not** on the shared helper — it opens a
fresh channel per command and never had cross-command carry-over — but
it now inspects its read outcome and locates the VDOM wrapper
boundaries by matching the text it sent.

`make check-shared-readpath`, part of `all-tests`, fails the build if
any of the four SSH drivers reintroduces a private read loop or drops
the shared include. Four private copies drifting apart is how this
class of defect arose; the check is structural rather than a
hand-maintained list, for the same reason `check-live-fence` is.

*[tested — `tests/test_ssh_io.c` (10 cases, four driver profiles
against a scripted mock PTY), `tests/test_driver_fortigate_scrub.c`
(4 cases against recorded FortiOS transcripts),
`test_watchdog_health_check_serialized_with_execute` in
`tests/test_onode.c`. Each case is differential: the pre-fix algorithm
is frozen into the test and asserted to get it wrong on byte-identical
input, so a case that stops being a regression test fails loudly.]*

### What is still not established

**The 2026-07-29 pa-850 occurrence has not been root-caused.** A signed
observation for `show system resources` carried `show system info`
output; a re-run returned correct output; the device had reconnected
about three minutes earlier. Several of the mechanisms above are
individually consistent with it and all are now closed, but which one
fired was never isolated under instrumentation, and no test reproduces
that specific transcript. Treat it as a recorded occurrence of the
failure class, not as a diagnosed and confirmed-fixed bug.
*[observed occurrence — one instance, not reproduced]*

**Connect-time reads remain quiescence-based.** Banner, pager-off and
the ASA enable exchange necessarily run before a prompt exists to
match. Nothing read on those paths is ever signed — it is discarded or
pattern-matched for the enable password prompt — but they are the one
remaining place where a read is bounded by silence rather than by a
known terminator. *[untested]*

**FortiGate's read-outcome check is not directly exercised.** Its
`prompt_seen` branch sits around libssh2 calls and needs a live
channel. The suite covers the failure contract it shares with the
malformed-reply path (`VIRP_ERR_NO_PROMPT` out of `fg_ssh_execute`),
not that branch itself. Closing this would mean putting FortiGate
behind the same transport vtable the other four drivers now use.
*[aspirational]*

**No live device has exercised any of this.** All evidence is suite
evidence against mock PTYs and recorded transcripts. Prompt learning is
fail-closed by design, so the first deployment is also the first test
of whether every fleet device has a prompt the learner can confirm;
a device that fails learning will fail to connect rather than fall back.
*[aspirational — no live run]*

### Consequence for the signed-at-collection claim

"Signed at the point of collection" binds command, device and session
to the bytes the O-Node read. With the branch deployed, the SSH drivers
additionally drain before sending, terminate only on a confirmed
prompt, and refuse to report an unterminated read as output — so
body-to-command correspondence is enforced by construction rather than
assumed. Until then, production retains the original caveat: a verifier
checking the signature gets a true answer to "did the O-Node sign this
body for this command/device/session?" and no answer to "is this body
the device's response to that command?"

## Command Gate — Explicit Scope Limits

The tier gate accepts **one command per request**. These are deliberate
limits of that design, not bugs; each is stated so operators do not
discover them in production.

**Separator characters are rejected fleet-wide.** Control bytes
(including newline, CR and tab), `;`, `|`, `&`, backtick, `$(` and `${`
are refused at the daemon boundary before classification, and again in
every classifier. This is what closes multi-command injection — a
classifier only ever sees the first command in such a string, while the
driver sends the whole thing to the device.

The cost is real: **display filters do not work.** `show run | include
bgp` (IOS), `show configuration | display set` (JunOS) and every other
pipe-filter idiom is refused, even though `|` on a network CLI is a
display filter and not command execution. The set is shared across all
drivers on purpose — on the linux driver `|` *is* command chaining, and a
per-driver split would let the daemon boundary and the classifiers
disagree. **Intended future shape:** a per-driver allowlist of pipe
*verbs* (`include`, `match`, `section`, `display`, `count`, `except`)
validated after the pipe, so filters are permitted and `| save`, `| tee`
or a shell pipe remain refused. Not implemented.

**Classified-equals-executed invariant (2026-08-09).** **[tested]** The
exact byte string that was classified is the exact byte string that
executes, or nothing executes. An agent test run found the classifiers
canonicalizing case for matching (`strncasecmp` / `tolower`) while the
drivers executed the caller's ORIGINAL bytes: `VTYSH -C "SHOW IP OSPF"`
classified GREEN on a lowercased copy and the gate then signed a GREEN
execution of a string it never classified. Every driver tier table now
matches **case-sensitively** (linux/vtysh, cisco, asa, juniper,
fortigate, panos — the whole class was swept, not just the reported
path); a case variant is an unlisted spelling and falls through to the
fail-closed tier with a signed refusal, exactly as abbreviations always
have. Two deliberate boundaries of the invariant: (1) whitespace runs
remain the ONE equivalence classifiers may collapse, because it is the
same equivalence `virp_canonicalize_command()` applies before the v2
command hash is signed — classifier equivalence never exceeds what the
signed hash itself collapses (pinned by
`test_case_variant_command_hash_rejected` in `tests/test_obs_v2.c`);
(2) BLACK deny lists stay case-INSENSITIVE on purpose — over-matching a
deny list is the fail-closed direction, and nothing matched BLACK ever
executes. The fix is deliberately NOT canonicalize-before-execute:
rewriting the executed bytes to match the classified copy is the same
defect in the other direction. Regression tests in every driver gate
suite (`test_no_case_folding` and per-suite case blocks).

**Multi-line and config-mode payloads are unsupported through the
single-command path.** JunOS config sequences (`configure; set ...;
commit check; commit`), IOS config blocks and any other payload needing
several statements in one session cannot be submitted as one string. The
batch action is the supported route — it classifies and gates each item
separately. A structured multi-command *proposal* format (an ordered list
of individually-tiered commands approved as a unit, executed in one
session) is the intended answer for genuinely session-bound config
transactions. Not designed yet. Until it exists, session-bound config
work is out of scope for VIRP.

**wazuh classifies its read endpoints (GREEN-only), everything else is
RED by absence.** The Wazuh driver registers `.route_command =
wazuh_gate_tier` (`driver_wazuh.c`), which `gate_classify`
(`src/virp_onode.c`) consults: the three autopilot read endpoints
(`/agents`, `/agents/summary/status`, `/manager/stats/analysisd`) are
GREEN by EXACT path match, and every other endpoint is RED. Under
ENFORCE, RED is a signed rejection plus a filed proposal. The layer-1
separator boundary still applies (it is driver-agnostic).

> **Corrected 2026-08-07.** This paragraph previously read "wazuh has no
> classifier" and stated `gate_classify` returns UNCLASSIFIED for every
> Wazuh command. That has been false since `53348603` (2026-07-29),
> which added the GREEN-only autopilot monitoring layer and wired
> `wazuh_gate_tier` into the driver's `.route_command` slot. The stale
> text claimed the fleet was *less* protected than it is — the same
> class of dangerous stale reassurance the 2026-07-31 correction below
> records, so it is corrected here in the same style rather than
> silently edited. (The paragraph further down, "REST-shaped drivers
> need their own command grammar," still correctly explains why the
> table uses exact-match paths rather than a full URL grammar.)

> **Corrected 2026-07-31.** This paragraph previously read "linux and
> wazuh have no classifier" and stated that every linux command executes
> unclassified under a SHADOW override. That has been false since
> `b5aab66` (2026-07-29), which added the linux driver's FRR/vtysh
> classifier and `route_reason` hook; the `linux=shadow` override was
> removed the same day and the deployed node has run
> `gate_default_mode=enforce` for the linux driver since. The claim was
> left standing in this document for two days. Recorded rather than
> silently edited, because a stale *reassurance* in a security document
> is worse than a stale fact — a reader who acted on it would have
> believed the fleet was less protected than it was, and the same rot in
> the other direction is the dangerous case.

**Witness script executes argv, not shell (2026-08-09).** **[tested]**
The target-side witness (`tests/adversarial/witness/virp-witness`, the
sshd ForceCommand on the sacrificial clab-frr containers) previously ran
the delivered operation with `eval` — safe only by composition with the
upstream separator gate, and exactly the sharp edge a hostile reviewer
lands on. The eval is gone: the operation is parsed into an argv over
the classifier's known-good grammar (`vtysh -c "<arg>"` becomes the
3-element argv; everything else is whitespace-split with globbing
disabled) and invoked directly, so no shell ever parses the command
bytes — a metacharacter that somehow reaches the witness is a literal
argument, never syntax. Stdout/stderr remain the raw SSH channel fds
and the exit status passes through, byte-identical to the old behaviour
for every grammar-conformant command. Pinned by
`tests/adversarial/witness/test-witness-noshell.sh`: live equivalence
against an eval reference, one canary test per injection vector
(`;`, `|`, `$( )`, backticks, `>`, `&&`, `$VAR`, glob, newline), and rc
passthrough. The upstream refusal of those vectors is separately pinned
by the driver gate suites (`virp_command_check_separators` tests).

**REST-shaped drivers need their own command grammar.** The separator set
is a CLI grammar. Wazuh's "command" is a URL path, where `&` is a
legitimate query-string separator and `?`/`/` are structural — so
applying the CLI set verbatim would refuse ordinary endpoints like
`/agents?limit=100&offset=0`. A REST driver therefore needs a per-driver
grammar (path + allowed query parameters) rather than the CLI set.
`wazuh_gate_tier` is the minimal form of that: it strips an optional
`GET ` method prefix and the query string, then EXACT-matches the path
against `WZ_ROUTE_TABLE` (GREEN for the three enumerated reads, RED for
everything else). A fuller path+query grammar is still future work; the
exact-match table is the conservative interim.

**The PBS driver answers that paragraph differently, and better.** Rather
than giving a REST driver a grammar for *paths*, `driver_pbs.c` removes
the path from the command entirely: the command is a canonical typed
operation (`pbs op=<id> [k=v ...]`), and method and URL are derived inside
the driver from a static table. There is no vendor syntax left to parse,
so the CLI separator set applies unchanged and every structural URL byte
(`/ ? # % : @`) is simply outside the value charset. This is the pattern
future REST drivers must follow — see `docs/DRIVER-TYPED-OPS.md`.

## PBS Observations — Explicit Scope Limits

The PBS driver is the first non-network domain through the gate. What its
signed observations do and do not establish:

**A signed `backup.verify.tasks` observation proves that PBS *reported*
those verification results at that time. It does not prove that any backup
is restorable, and it does not prove that PBS itself is uncompromised.**

Spelled out, because this is the claim most likely to be over-read by
someone holding a chain entry that says "verify: OK":

- **It is PBS's word, signed.** VIRP attests that the O-Node read these
  bytes from the pinned host at that moment and that they have not been
  altered since. The *truthfulness* of the content is PBS's, not VIRP's. A
  compromised or buggy PBS that reports successful verifications produces
  observations that are perfectly valid and completely wrong.
- **A verify task result is not a restore test.** PBS verification reads
  chunks and checks digests. It does not exercise the restore path, the
  target hypervisor, or whether the restored guest boots. No observation
  in this driver — none, at any tier — evidences recoverability. Only an
  actual restore does, and VIRP does not perform one.
- **`backup.datastore.usage` is capacity, not retention correctness.** It
  says how full a datastore is, not whether the right things are in it,
  nor whether retention pruning removed something that was needed.
- **`backup.snapshots.list` is an inventory of what PBS believes it holds.**
  Absence of a snapshot is evidence; presence is a claim about metadata.
- **Scope is the four enumerated reads on the allowlisted datastores.** No
  write operation exists at any tier. Nothing in this driver can start,
  stop, prune, or repair anything, so an operator reading a PBS chain must
  not infer that VIRP would have *acted* on a bad result.

**What the certificate pin does and does not cover.** The pin is an exact
SHA-256 match on the leaf certificate. It does not build a chain and does
not verify the hostname; it verifies that the peer is the recorded
certificate. For a single pinned host that is stronger than chain plus
hostname validation — a mis-issued certificate for the right name from any
trusted CA fails — but it means certificate rotation on the PBS side
breaks collection until `tls_fingerprint` is updated in `devices.json`.
That is a deliberate trade, and the failure mode is refusal, not silent
fallback: the driver has no insecure mode, enforced by
`make check-pbs-pin`.

**The gate sees shape, not values.** `route_command(const char *)` receives
no device context, so the classifier cannot consult the per-device
datastore allowlist. A well-formed request naming a non-allowlisted
datastore classifies GREEN and is then refused by the driver before any
request is issued. Fail-closed still holds, and the refusal is still
pre-network — but a reader of gate decisions alone should not conclude
that GREEN meant the datastore was permitted.

## Execution Durability — "recorded-happened-once", not "happened-was-recorded"

VIRP's crash-safety supports a precise and LIMITED claim, established by the
adversarial test program (test #2, crash around execution; see
`tests/adversarial/transcripts/02-crash-around-execution.md`):

> VIRP can prove that a **recorded** execution happened **at most once**. It
> **cannot** prove that everything that **happened** was recorded.

The gap is real and by construction. An approved apply consumes its
authorization, contacts the device, then records an OUTCOME. A crash after
the device executed but before the OUTCOME commits leaves an APPROVAL entry,
a consumed-once marker, and NO OUTCOME — the device **was** changed, yet the
chain reads "approved, never applied". That state is **indistinguishable**
from a crash where the device was never contacted. The `chain_append`
atomicity fix (entry/head/body in one transaction) does **not** close this:
the missing record is of a step **between** two chain appends, across device
I/O, not within one append. The EXECUTION_INTENT proposal
(`docs/virp-audit-design-proposals.md`) is what would let VIRP say "attempted,
disposition unknown"; until then an unresolved apply is genuinely ambiguous
and must be reconciled out-of-band against the target.

### Evidence-required execution (`evidence_required`, Sep 1 review, Task 5)

The paragraph above described the shipped state until 2026-09-01, and it
understated it: not only an approved apply but **every** gate-admitted
execution was recorded only *after* the device had acted, by
`gate_emit_execution()`, and that append was best-effort — a chain failure
was logged and ignored. Reproduced directly (`tests/test_onode.c`,
`test_evidence_append_failure_refuses_and_executes_nothing`, run against the
unfixed tree): with the chain forced read-only, the mock device executed once
and the caller received an ordinary DEVICE_OUTPUT observation while the
journal read `[GATE] execution chain append+store failed`.

The daemon now has an **evidence-required** mode, on by default
(`onode_init()`; config key `evidence_required`, a JSON boolean, shipped as
`true` in both deploy templates):

- **Before dispatch** the gate commits a `gate_intent` chain entry — device,
  driver, command, classified and effective tier, gate mode, uid, the v2
  session id when session-bound, the proposal id for an approved apply — in
  the device's `gate-enforce:<device>` session, entry + head + body in one
  SQLite transaction. The driver is not called until that commit returns.
- **If the append fails** (chain absent, read-only, full, body unbuildable)
  the operation is **refused**: a signed ERROR observation whose payload
  cites `evidence-unavailable` and the cause, `[GATE] decision=refuse
  reason=evidence-unavailable` in the journal, and `VIRP_ERR_EVIDENCE_UNAVAILABLE`
  as the typed reason. Nothing is dispatched. An approved apply that fails
  here has already spent its single-use approval; the operator re-proposes.
  Spending an approval is the cheaper failure.
- **After execution** the `gate_execution` entry (or the `outcome` entry for
  an approved apply) carries `intent_entry_hash` = the intent's
  `chain_entry_hash`, plus `intent_sequence` / `intent_artifact_id` for the
  reader. Two linked entries per dispatch.
- **A crash between the two** leaves an intent with no closer. Both verifiers
  — `virp_chain_verify_session()` (`executions_open` / `executions_closed`,
  printed by `virp chain-verify` as `OPEN_EXECUTIONS=n` and returned by the
  daemon's `chain_verify` / `chain_verify_session` actions) and
  `report/verify.py` (`summary["open_executions"]`, rendered by the report
  and printed by `virp-report`) — report it as an **open execution**: the
  chain is VALID, the world after its last word is what is uncertain.
  Reconcile against the target. Measured, not assumed: the crash test forks a
  fresh daemon, SIGKILLs it inside the driver, and verifies the recovered
  database.
- **A daemon with evidence required and no usable chain refuses to start**
  (`onode_setup_chain_and_approvals()`), naming the fix: pass `-c`/`-C`, or
  set `"evidence_required": false`. The library-level belt refuses each
  dispatch as evidence-unavailable if that state is ever reached anyway.
- **`evidence_required: false`** restores the record-after-the-fact posture
  exactly, and logs `[GATE] WARNING: evidence_required=false — dispatching …
  with NO durable pre-execution record` on every dispatch. `gate_execution`
  and `outcome` bodies then carry `intent_entry_hash: null`.

What this changes in the claim above: an execution VIRP admitted is now either
recorded before it happens or does not happen. The residual — an intent whose
outcome was never written — is no longer indistinguishable from "never
contacted the device": it is reported by name as open. The
"recorded-happened-once" guarantee is unchanged. `gate_intent` is a
daemon-reserved artifact type like `gate_execution`: a socket client cannot
mint one, so it cannot plant an open execution against a device nothing
touched.

#### Refinements (Sep 1 review, 1.1–1.5)

- **Consumption is the intent (1.1).** An approved apply's approval is
  **consumed iff a committed `gate_intent` entry names it** (the entry
  carries `approval_entry_hash` and `proposal_entry_hash`). The gate now
  VERIFIES the approval without consuming; the intent commit is the
  consumption event, and the consume record (`consumed.list`) is written
  after it as a cache. A refused intent consumes nothing — the operator
  re-applies and it executes exactly once. Before appending an intent for
  an approved apply the daemon queries the chain, type-restricted to
  `gate_intent`, for one already citing that approval entry hash and
  refuses `approval_reused` on a hit — closing the crash window between an
  intent commit and the cache write, since the chain entry survives. Two
  intents citing one approval entry hash is a verifier FAIL (double-spend),
  in both the C and Python verifiers. When `evidence_required` is **false**
  there is no `gate_intent` to be the consumption event, so `consumed.list`
  is the sole authority on single-use (the pre-Task-5 behaviour) and a
  persist failure there fails the apply closed.
- **Closer binding is type-checked (1.2).** A closer's `intent_entry_hash`
  must resolve to a `gate_intent` entry (wrong type or absent = FAIL); two
  closers for one intent = FAIL; a closer whose binding disagrees with its
  intent = FAIL (device always; command/session/uid for `gate_execution`;
  proposal_id/approval_entry_hash for `outcome`). All via the GATE 4
  pattern — type-restricted query, cJSON parse, never `strstr`. The daemon
  builds each closer from the intent it holds in memory, so a real closer
  always matches; the checks are the adversarial backstop for a crafted
  chain. Crafted-chain fixtures: `tests/test_evidence_binding.c` (C) and
  `tests/test_open_execution_grading.py` (Python).
- **Outcome append fails after execution (1.3).** The one window the
  pre-execution intent cannot close is *between* the two chain appends,
  across the device I/O: the intent commits, the device acts, the closer
  append fails. This is now **never silent** — the caller gets a signed
  ERROR citing `unchained-execution` and the open intent hash; the daemon
  latches **evidence-degraded** and refuses every further dispatch at the
  intent step until restart; the intent stays OPEN and the verifiers report
  it. The durable late-closer spool that would *recover* the outcome (retry
  + a late-append marker) is deferred to its own branch — see
  `docs/PROPOSAL-LATE-CLOSER-SPOOL.md`. The degraded-refuse behaviour is the
  fail-safe, not the recovery.
- **Strict loader (1.4).** `evidence_required` set to anything but a JSON
  boolean is a FATAL config error naming the key and the received type —
  the daemon refuses to load rather than run with a guessed posture. A
  string `"false"` (always truthy) is the trap this closes.
- **`node_config` on the chain (1.5).** The daemon records its posture at
  startup — `evidence_required`, gate mode, node-wide and per-uid tier
  ceilings, and the build id — as a daemon-reserved `node_config` chain
  entry. A reader can now bound, from the chain alone, the window in which
  unrecorded execution was permitted (`evidence_required=false`, or a build
  predating this work), and Docket answers the tier-ceiling question from
  the bundle rather than from a `devices.json` it may not have. A bundle
  with no `node_config` reports the ceiling and posture UNKNOWN rather than
  guessing.

#### Pre-merge hardening (Sep 1 review, Phase 1 second commit)

- **The replay guard is atomic with the intent append.** For an approved
  apply the daemon holds one lock (`virp_approval_consume_lock`) across the
  TTL re-check, the replay-guard chain query, the `gate_intent` commit and
  the `consumed.list` write, so the guard and the append cannot be
  interleaved by another consumer. Nothing is held across `get_connection`
  (connect precedes the locked block). In practice a single approval already
  resolves to a single device — the signed binding is the node id and the
  apply verify also matches the device NAME, and device names are unique at
  load, so the per-device `exec_mutex` already serializes every apply of one
  approval; the shared lock is the belt to that suspenders. Tested by two
  concurrent applies of one approval to one device: exactly one executes,
  one intent lands, the other refuses `approval_reused`.
- **TTL is re-checked at dispatch.** `virp_approval_verify` runs before
  connect, and connect can take seconds on a dead device, so the approval
  TTL is re-checked under the same lock immediately before the intent
  commit. An approval that lapsed during connect refuses with
  `approval_expired` and consumes nothing.
- **A cache-write failure after the intent commit does not stop
  execution.** The `gate_intent` commit is the authoritative consumption;
  if the `consumed.list` cache write then fails, the daemon logs at error
  level and executes anyway. The next apply of that approval is refused by
  the chain replay guard (which reads the chain, not the cache), so
  single-use is not lost — the cache is only an optimisation.
- **`node_config` is FATAL under `evidence_required`.** A node that cannot
  commit its startup posture record would refuse its first intent anyway
  (every dispatch needs a durable chain), so that is stated at boot, by
  name, and the daemon refuses to start. With `evidence_required` false the
  record is best-effort — logged and continued.
- **The evidence-degraded latch clears on restart only.** Once a closer
  append fails after the device acted, the daemon refuses further dispatch
  at the intent step for the life of the process; there is no automatic
  recovery on this branch (that is the deferred late-closer spool). A clean
  restart re-opens the chain, writes a fresh `node_config`, and clears the
  latch — so `node_config` is not rewritten on recovery within a run,
  because there is no in-run recovery.
- **Approved-apply outcome-fail returns `unchained-execution` too (V39
  item 1).** This was carried as a known limitation: the marker was
  returned only on the auto-execute path, so an approved apply whose
  `outcome` append failed after the device had acted could hand its caller
  an ordinary observation. It no longer can. `approval_emit_outcome()`
  returns an error, and every approved call site — the four driver-failure
  returns and the success return — replaces its response with the signed
  `unchained-execution` ERROR when that append fails. The response names
  the OPEN intent entry hash, the proposal id and the approval entry hash,
  and states in words that whether the device changed **cannot be
  determined from it**: on four of those five sites the driver also
  reported a failure, and "the outcome was not chained" must never be read
  as "nothing happened".

  What did NOT change, deliberately: the `outcome` append still happens
  where it always did, after the observation is built, so the `pre_outcome`
  fault point and the artefact set that survives a kill there are exactly
  as the adversarial crash transcript pins them. Only the caller's response
  changes. The intent stays OPEN — no synthetic outcome is written — and
  the approval stays consumed: it was spent by the committed `gate_intent`
  before dispatch, so a second apply refuses `approval_reused` (-37) and
  the daemon never retries the physical action. Evidence-degraded latches
  through the same `onode_mark_evidence_degraded()` path as the
  auto-execute case. Recovery of the lost outcome is still the deferred
  late-closer spool (`docs/PROPOSAL-LATE-CLOSER-SPOOL.md`); this is the
  fail-safe, not the recovery. Covered by
  `tests/test_approved_outcome_fi.c` (`make test-approved-outcome-fi`).
- **The fault hook is compile-gated.** The `evidence_fail_closer_once` /
  `evidence_ttl_now_override_ns` injection fields exist ONLY under
  `-DVIRP_FAULT_INJECT`, exactly like the `VIRP_FI()` crash points — the
  production daemon has neither the field nor the check. The test that uses
  them is `tests/test_evidence_fi.c`, built into `build-fi/` by
  `make test-evidence-fi`.

### Crash and storage-failure durability — measured, not assumed

Earlier this section could only say "SIGKILL, not power loss". That gap is now
closed by direct test: the process crash (SIGKILL, `fi-run.sh`) and three
storage-failure modes were exercised against a chain on a disposable
loop-backed filesystem. Each row below is a claim with a transcript behind it
(`tests/adversarial/transcripts/06-power-loss.md`, `07-torn-write.md`):

| Storage failure | What VIRP does | Evidence |
|---|---|---|
| **Hard I/O error** — the device returns an error (failing disk, full volume) | **Fails closed** — refuses the append with a typed error; never returns success for a write it cannot persist | L2 `dm-error`: ACK=0 / ERR=200 |
| **Silent write-drop** — power loss / lying disk: the write is acknowledged at the syscall but never reaches the platter | **Atomic loss** — the lost tail reverts *with* the signed head; the verifier reports VALID over an honestly-shorter chain that claims nothing it cannot show (no dangling commitment) | L3 `dm-flakey drop_writes` |
| **Torn recovery** — a cut leaves the signed head claiming more entries than survived | **Detected** — the signed-head completeness check reports BROKEN (`expected N, found M`), never VALID | main-db tear, 9/9 attempts |

Two honest limits remain — stated as limits, not defects, because the chain's
own integrity guarantee held throughout:

1. **A success reply is not proof of persistence under power loss.** VIRP's
   acknowledgement means the daemon *committed* the transaction, not that the
   commit reached durable storage; under a silent write-drop the two come apart
   (the daemon acked writes the cut then discarded). Read persistence from the
   chain's own head/entry consistency, never from the ack.
2. The "recorded-happened-once" gap above (a crash between device I/O and the
   OUTCOME append) is orthogonal to storage durability and is not closed by any
   of these results. Since 2026-09-01 the evidence-required mode above makes
   that crash *visible* — an open execution — rather than silent; it does not
   make it impossible.

## Verifier Limitations

Two verifiers ship in **this** tree — the Python claim verifier and the C
chain verifier — and both are now fixed. A third, the bridge chain
verifier, runs **consumer-side** on the CT 210 dashboard (`virp-bridge.py`,
the separate consumer repo — see §"Federation bridge" and the `chain_verify`
note under Chain database tampering); it is not in this tree and its gap is
unfixed. The gaps below are from the static review at
`hardening-2026-07-29`. (Corrected 2026-08-18: this section previously said
"three verifiers ship in this tree", which wrongly located the bridge
verifier here — this tree's bridge module is `api/virp_bridge.py`, which
exposes `verify_observation`/`parse_observation` and contains no
`chain_verify`.)

**The Python claim verifier trusted unsigned fields. Fixed.**
`api/virp_verify.py:verify_evidence` HMAC-verified `obs["raw_message"]`
but then evaluated freshness, completeness and the asserted value from
*unsigned sibling fields* of the corpus entry, and fell back to a
plaintext `obs["verified"]` boolean when `raw_message` was absent — so
a genuinely signed message paired with an arbitrary `raw_output`
returned VERIFIED, and a `{"verified": true}` entry skipped
cryptographic checking entirely.

It now decodes payload, timestamp, node_id and sequence number **from
the verified bytes** (via the C library's own parse path, bound in
`api/virp_bridge.py:parse_observation`) and evaluates the claim against
those. Unsigned `raw_output` / `obs_id` / `node_id` that disagree with
the verified bytes are rejected with a distinct mismatch error rather
than a generic failure, and the `obs["verified"]` fallback is deleted:
evidence without a verifiable `raw_message` is unverified, full stop.
One field is still read unsigned — `collection_status`, because the v1
wire format carries no collection metadata to read it from; it can
only downgrade a verdict to INCOMPLETE, never upgrade one.
*[tested — `tests/test_virp_verify.py`: forged `raw_output` over a
genuine signature, plaintext `verified:true` with no `raw_message`,
relabeled `obs_id`, mismatched `node_id`, and a stale timestamp inside
the signed bytes. Each was confirmed failing against the previous
code.]*

**The bridge chain verifier is unkeyed. NOT fixed (and lives consumer-side,
not in this tree).** The CT 210 dashboard's `virp-bridge.py:
chain_verify()` — a separate consumer repo, not `api/virp_bridge.py` here —
checks only that each row's `previous_entry_hash`
equals the prior row's stored `chain_entry_hash`. It never verifies
`chain_hmac` — the keyed value — and never recomputes
`chain_entry_hash` from row contents. A keyless attacker with DB write
access can produce a chain this verifier reports valid. (Separately, it
false-negatives on any multi-session database — see README.)
*[untested]*

**The C chain verifier accepts a truncated tail. FIXED 2026-08-01,
merged to `main` and deployed (running commit `b6e9602c`).** On first
start under the fix the daemon backfilled a signed head for every
pre-existing session — 33 sessions on virp-lab, 0 failures — under the
trust-on-upgrade rule described in mechanism 2. Two mechanisms:

1. *Range completeness.* `chain_verify_locked` now requires every
   sequence in the caller's requested range to be present and valid —
   a range whose tail is missing, a zero-row session, and an inverted
   range all return `valid:false` with a distinct `error_detail` and
   `first_broken` set to the first missing sequence. *[tested —
   `tests/test_chain.c` tail-truncation, zero-row and inverted-range
   cases, each verified to FAIL against the pre-fix behavior]*

2. *Signed head record.* Every append now updates, in the same
   transaction, a per-session `chain_heads` row (`last_sequence`,
   `last_entry_hash`) authenticated by HMAC-SHA256(K_chain) over a
   versioned canonical (`VIRP-CHAIN-HEAD-v1`). The new
   `virp_chain_verify_session()` (daemon action
   `chain_verify_session`) authenticates the head, walks
   `0..head.last_sequence` under the completeness rule, and requires
   the final verified entry to match the head's commitment. A DB
   writer WITHOUT K_chain can therefore no longer delete the chain
   tail undetected: they can neither forge a head for the shortened
   chain nor delete it (entries-without-head fails verification).
   *[tested — deleted-tail, deleted-head, keyless-forged-head and
   backfill cases in `tests/test_chain.c`; Python/C head-canonical
   byte-parity verified against a C-produced database]*

Consequently the 2026-07-28 "162/169 sessions fully hash-linked"
result still establishes only internal link consistency AS MEASURED
THEN; re-running the walk via `chain_verify_session` after deploy is
what upgrades that claim to completeness.

Scope limits, stated plainly: a holder of K_chain can still rewrite
history wholesale, head included — the head authenticates chain length
against the same adversary the per-entry HMAC targets (DB write access
without the key) and no stronger one; external anchoring remains
future work. Pre-existing sessions receive a backfilled head at first
daemon start after upgrade (TRUST-ON-UPGRADE: the backfill blesses
whatever length the database has at that moment; only appends after it
extend the authenticated length). The autopilot chainwalk now uses
`chain_verify_session`, removing the circularity where it derived the
expected range from the same database it was auditing.

## External Code Audit — 2026-08-01

An external static audit was run against `main`. Because `main` was
behind the fix branches and this file misdescribed that (see §Deployment
status above), two of its six HIGH findings were already closed and it
could not see them. The other four were real. Every finding below was
re-confirmed against this tree before being acted on — line numbers in
the audit referred to a different tree and did not all transfer.

**Fixed, merged and deployed 2026-08-01 (running commit `b6e9602c`):**

- **§4.1 — `sign_intent`/`sign_outcome` were a signing oracle.** Both
  handlers checked only that `req.command` was non-empty and then
  HMAC'd it with the O-Key. `req.command` is `char[1024]`, so any
  caller reaching the socket could obtain an O-Key-authenticated,
  GREEN-tier observation over up to 1023 bytes of its own text — text
  that looks like an observation, which is the exact distinction this
  protocol exists to make unforgeable. The documented "64 hex chars"
  contract is now enforced before signing. Separately, `api/server.py`
  never read `obs_type`, so an `INTENT_SIGNED` (0x08) observation was
  reported identically to device output with `verified: true`; the
  parser now surfaces `obs_type` and the execute path fails closed on
  anything that is not `DEVICE_OUTPUT` or a signed `ERROR`. *[tested —
  `tests/test_onode.c` drives both handlers over the socket;
  `tests/test_obs_type_not_device_output.py` forces `verified=true` to
  prove a verified 0x08 is still not device output. Both verified to
  fail against the pre-fix code]*
- **§4.3 — FortiGate `execute backup` was YELLOW.** At the shipped
  `gate_max_tier: yellow` it executed with no approval, and
  `execute backup config ftp <file> <server> <user> <pass>` makes the
  device push its whole config — admin password hashes, VPN PSKs, API
  tokens — to a caller-supplied host over a channel the O-Node never
  sees, signs or chains. Now RED, so it requires approval rather than
  being forbidden outright. *[tested —
  `tests/test_driver_fortigate_black.c`]*
- **§4.4 — chain digests and MACs were compared with `strcmp`.** Three
  sites, two of them against `K_chain`-derived values. `strcmp` returns
  at the first differing byte, which turns forging a `chain_hmac` from a
  2^256 search into a byte-at-a-time walk against a verifier that will
  re-run on demand. All three now use a constant-time comparison.
  *[tested — `tests/test_chain.c`]*
- **§4.5** is the chain-completeness work; see §Verifier Limitations.

**Confirmed and still open.** These are real in the deployed code:

- **§4.2 — an abbreviated BLACK command is downgraded to RED.** BLACK
  matching is a literal full-token prefix compare with no abbreviation
  expansion, so an abbreviated form falls through to RED, gets a
  proposal filed, and becomes *approvable*; at `gate_max_tier: red` it
  would need no approval. The driver-level backstop uses the same
  matcher, so both layers miss the same input. The code fact is
  confirmed; whether a given device accepts a given abbreviation is not
  provable from this tree. *[open]*
- **§4.6 — the approval signature does not cover the device name.** The
  Ed25519 signature is over a 72-byte canonical of magic, proposal id,
  command hash, `device_node_id`, timestamp and TTL. The `device`
  hostname string, `approver_key_id`, `operator` and `session_id` are
  outside it, and verification compares the *unsigned* `device` string.
  The only signed device binding is `device_node_id`, which is
  degenerate: on virp-lab 5 of 7 devices load `node_id == 0` and so
  share an identical binding. Comments in `src/virp_approval.c` claim
  the signature "covers the whole body"; it does not. *[open]*
- **§4.7 — SHADOW mode does not honour BLACK.** Both blocking branches
  are gated on `mode == GATE_MODE_ENFORCE`, so under SHADOW a BLACK
  verdict is logged and execution proceeds. Latent rather than live:
  the shipped config is `gate_default_mode: enforce`. *[open]*
- **§4.8 — the `proxmox` driver has no classifier.** `proxmox_driver`
  in `src/drivers/driver_linux.c` reuses every linux hook but omits
  `.route_command`, six lines below the `linux_driver` struct that sets
  it. Every command on a proxmox device therefore classifies
  UNCLASSIFIED. Under the shipped `gate_default_mode: enforce` that
  fails closed — UNCLASSIFIED is block-worthy, so such a device can run
  nothing rather than run something unreviewed — which makes this a
  functionality gap rather than an exposure *unless* it is combined with
  §4.7, where SHADOW would let the same UNCLASSIFIED command execute. No
  proxmox device is present in the deployed config. *[open]*
- **Not in the audit, found while confirming it:** `src/driver_panos.c`
  has no driver-level BLACK list at all, so PAN-OS has no second layer
  behind the gate the way Cisco and FortiGate do. The broad
  single-row YELLOW entries — FortiOS `diagnose`, PAN-OS `debug`,
  `test`, `less`, `tail` — hide sub-verbs with mutation or off-channel
  semantics, the same shape as §4.3. *[open]*
- **§4.5, residual.** The range walk still exits on any non-`ROW`
  return, so `SQLITE_BUSY`/`ERROR`/`CORRUPT`/`IOERR` mid-walk is not
  distinguished from clean exhaustion. The completeness check makes
  this fail closed — an error-truncated walk reports fewer entries than
  the range demands — so it is a diagnostic defect, not an integrity
  one: the operator is told "chain truncated" when the real cause was a
  database error. *[open, non-security]*

> **Status update 2026-08-27.** This list is the audit record and is
> left as written; current state now lives in §Current State — Status
> Index. Since the audit: §4.7 (SHADOW does not honour BLACK) was
> re-confirmed on HEAD and fixed on `fix/black-unconditional` — BLACK
> is refused before any mode check, in both modes, with the refusal
> persisted; §4.8 (proxmox no classifier) was closed by `8bdfe3f9`;
> the PAN-OS item was closed on the same branch as §4.7 (BLACK deny
> table + driver backstop; broad YELLOW verbs replaced by enumerated
> safe forms); §4.6's node_id==0 degeneracy was closed by `5bbbacfe`
> + `b733153d` while §4.6's core (unsigned `device` string) and §4.2
> (abbreviation fallthrough) remain OPEN.

## External Review — 2026-08-02

An external review (fresh reviewer, full Python suite run) reported one
regression and two C lifecycle defects. All three were reproduced
against this tree before being acted on.

**Fixed on `fix/review-2026-08-02`:**

- **Device-source selection was gated on import success, silently
  ignoring `VIRP_DEVICES`.** `api/server.py` selected between the
  `devices.yaml` registry and the operator's JSON file based on whether
  `device_registry` happened to be importable, so a `sys.path` accident
  (or a missing optional dependency) decided whether an explicit
  `VIRP_DEVICES` was honored. In the test suite this made
  `test_auth_noop_when_token_unset` order-dependent — green alone, red
  after `tests/test_validator_e2e.py` put the repo root on `sys.path`.
  Selection is now explicit with one documented precedence rule: a set
  `VIRP_DEVICES` always wins and the YAML registry is not consulted at
  all; module availability never determines configuration semantics
  (README → "Device registry configuration"). *[tested —
  `api/test_devices.py::test_virp_devices_env_bypasses_yaml_registry`
  imports the registry successfully, booby-traps every accessor, and
  proves the YAML path is never consulted; verified to fail against
  the pre-fix code]*
- **`send_framed()` ignored `send()` return values.** SOCK_STREAM
  permits partial writes even on Unix domain sockets, and a partially
  written 4-byte length prefix permanently desynchronizes framing for
  that connection. `send_all()` now exists as the symmetric counterpart
  to `recv_exact()` — complete-or-fail, EINTR retried, EAGAIN fatal by
  design — and every framed send routes through it; on failure the
  connection is treated as dead, never written mid-frame again.
  *[tested — `tests/test_onode.c` drives `send_all` over a socketpair
  with a shrunken send buffer while bombarding the sender with
  SIGUSR1 (no `SA_RESTART`), and proves a dead peer surfaces as an
  error, not SIGPIPE]*
- **Shutdown destroyed state a live worker could still hold.** The
  drain waited up to ~30s on an advisory counter, warned, and then ran
  `onode_destroy()` anyway — freeing mutexes, connections, chain state
  and key state under any worker that had not exited. (The counter was
  also incremented after `pthread_create`, so a fast worker produced a
  phantom count of 1 — the "drain timeout" noise every `test-onode` run
  printed.) The drain is now a real barrier: worker client sockets are
  `shutdown()` first so blocked workers unblock, then shutdown waits on
  a condition variable for the live count to reach zero. The 30s bound
  remains only as a last resort, and if it fires the daemon logs loudly
  and *leaks* shared state instead of freeing it under live threads.
  *[tested — `tests/test_onode.c` 71/71 and
  `tests/test_onode_concurrency.c` clean; `make asan-test` (ASan+UBSan)
  clean across core/onode/ssh-io/fg-scrub/chain]*

## Corrections to Previously Documented Behavior

Four statements in this repository asserted behavior that no code
performed. Recorded here because each was load-bearing in a security
argument at some point.

**Juniper had no BLACK batch pre-scan.** `tests/test_driver_juniper.c`
described the batch executor as pre-scanning every sub-command for BLACK
tier before running any. No such pre-scan existed in
`src/drivers/driver_juniper.c` — the claim lived only in that test file's
section comment, and the tests underneath it were exercising per-command
classification, not a batch pre-scan. The batch splitter it described has
since been deleted (`0a0d75b`).

**The 800-call concurrency suites never exercised a send site.**
`tests/test_onode_concurrency.c` calls `onode_execute` in-process; it
never opens a socket, so it could not and did not cover the daemon's
`send()` paths. The daemon-wide SIGPIPE crash (any client disconnecting
before reading its response terminated the process, taking down
verification for the whole fleet) survived every run of that suite and
was only caught once a real-socket close-before-read test was added in
`5ba6c94`.

**FortiGate BLACK enforcement was unverified.**
`tests/test_driver_fortigate_black.c` existed but **no Makefile target
referenced it**, so it was never built or run. FortiGate's BLACK-tier
blocking was untested for as long as that file has been in the tree. Wired
in with `19c0054`.

**The live-contact fence covered one target, not the class.** `a2c01ef`
fenced `TestInterop_LiveCONode` behind `VIRP_LIVE_INTEROP=1` and was read
as having fenced live-device testing generally. It had not: `test-wazuh`
opened an unguarded connection to the production Wazuh manager
(`10.0.20.10:55000`), `test-live` opened an unguarded SSH session, and
`tests/virp_sweep.c` was a fleet-wide SSH sweep with no Makefile target
at all — an orphan from the initial commit that CI had never run.

Resolved. `test-wazuh` was guarded in `0f70b61`; `test-live` now
self-skips unless `VIRP_LIVE_SSH=1` (its default host stays
`198.51.100.1`, TEST-NET-3 — the guard is the control, the reserved-range
default is defence in depth); `tests/virp_sweep.c` was deleted, since
nothing referenced it and no document described it as a supported tool
(recoverable from `fa245d8`).

The fix that matters is `make check-live-fence`, part of `all-tests`. It
is **structural, not a list**: it scans every `tests/` and `tools/`
source for outbound-contact primitives — a driver `->connect(` dispatch,
`libssh2_session_handshake(`, `curl_easy_perform(`, or a raw
`socket(AF_INET` — and fails if any file containing one lacks a
`VIRP_LIVE_*` guard. A hand-maintained list of "the live targets" would
go stale exactly the way the `a2c01ef` fence did. Verified by injecting
an unguarded live-capable test (the check failed) and reverting it (the
check passed).

## Supported Versions

| Version | Supported |
|---------|-----------|
| main branch | ✅ |
| Older commits | Best-effort |

## Recognition

Security researchers who report valid vulnerabilities will be credited in the CHANGELOG (unless they prefer anonymity).
