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

## Trust Boundaries and Transport Paths

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
- VIRP message-layer session handshake (`SESSION_HELLO` /
  `SESSION_HELLO_ACK` with nonces, followed by HKDF session-key
  derivation) on every fresh connection.
- HMAC-SHA256 signing of every observation returned to the caller,
  using an O-Key the caller does not possess.

**TCP path (CT 210 dashboard ↔ CT 211 O-Node, ports 9998/9999)** — the
dashboard's `virp-bridge.py` listens on TCP 9998 locally on CT 210 and
opens a TCP connection to CT 211:9999, where a socat forwarder proxies
to the Unix socket. On this path:

- `SO_PEERCRED` sees the local socat process's UID, **not** the remote
  dashboard's identity. It cannot distinguish authorized dashboard
  traffic from any other process on CT 211 that can reach the socat
  forwarder.
- The VIRP message-layer session handshake and HMAC signing of
  observations still apply — observations returned across the TCP
  bridge are signed at collection time with the O-Key and are as
  verifiable as on the local path. An attacker who intercepts or
  injects on the TCP path cannot forge observations without the O-Key.
  (What "signed at collection time" does and does not guarantee about
  the observation *body* is narrowed in §Observation-Body Integrity —
  the caveat applies equally on both paths.)
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

## Ed25519 Observation Signing (added 2026-08-07)

**The scheme.** Observations can now additionally be emitted as wire
version 3 (`virp_build_observation_ed25519`): the v2 header layout and
session-HMAC trailer, PLUS an Ed25519 detached signature by the O-Node's
observation-signing key over exactly the same bytes the HMAC covers
(`header || payload`). Wire format and rationale:
`docs/DRAFT06-NOTES.md` §1 and the `VIRP_VERSION_3` block in
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
- **NOT yet enforced.** v3 is additive and coexists with v1/v2; nothing
  that produces or verifies HMAC observations changed behavior, no
  client default changed, and chain append does not yet require or
  check Ed25519 signatures — that enforcement is the observation
  re-cut phase. Until then, v3 observations are only as load-bearing
  as the verifier a consumer actually runs.
- The public-key verifier checks authenticity and integrity of the
  signed bytes only. Replay, staleness and session acceptance remain
  the accepting endpoint's checks (v2 verify semantics).

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

**wazuh has no classifier.** The Wazuh driver registers no
`route_command` hook, so `gate_classify` returns UNCLASSIFIED for every
command it receives. Under ENFORCE that blocks; under a SHADOW override
it logs and proceeds. The layer-1 separator boundary still applies (it is
driver-agnostic). Nothing else about its commands is tiered.

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

**REST-shaped drivers need their own command grammar.** The separator set
is a CLI grammar. Wazuh's "command" is a URL path, where `&` is a
legitimate query-string separator and `?`/`/` are structural — so
applying the CLI set verbatim would refuse ordinary endpoints like
`/agents?limit=100&offset=0`. A REST driver therefore needs a per-driver
grammar (path + allowed query parameters) rather than the CLI set. This
is why `WZ_ROUTE_TABLE` is not wired to a `route_command` hook despite
now defaulting to RED.

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

## Verifier Limitations

Three verifiers ship in this tree. The gaps below are from the static
review at `hardening-2026-07-29`. One is fixed; two are not.

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

**The bridge chain verifier is unkeyed. NOT fixed.** `virp-bridge.py:
chain_verify()` checks only that each row's `previous_entry_hash`
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
