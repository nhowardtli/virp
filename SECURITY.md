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
**[aspirational]** intended, not yet built.

- HMAC-SHA256 signing bypass or forgery *[tested — `tests/test_virp.c`, `tests/test_obs_v2.c`, ProVerif `proofs/virp_obs_v2.pv`]*
- Trust tier escalation (e.g., RED command executing as GREEN) *[tested — five driver suites incl. table-driven reachability and adversarial separator injection; see `docs/VIRP-CLAIMS.md` C22–C25]*
- Chain database tampering without detection *[tested (logic) — `tests/test_chain.c` tamper detection. Production chain verified per-session 2026-07-28: 162/169 sessions hash-linked; the 7 failures are writer-convention mismatches, not tamper evidence. The operator-facing `chain_verify` bridge API still reports a false negative on any multi-session database — see README]*
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

**linux and wazuh have no classifier.** Neither driver registers a
`route_command` hook, so `gate_classify` returns UNCLASSIFIED for every
command they receive. Under ENFORCE that blocks; under the **SHADOW
overrides both run with in production**, SHADOW logs and proceeds — so
every linux and wazuh command executes unclassified today. The layer-1
separator boundary still applies (it is driver-agnostic), which matters
most for linux, the one driver where `|` and `;` genuinely chain
commands. Nothing else about their commands is tiered.

**REST-shaped drivers need their own command grammar.** The separator set
is a CLI grammar. Wazuh's "command" is a URL path, where `&` is a
legitimate query-string separator and `?`/`/` are structural — so
applying the CLI set verbatim would refuse ordinary endpoints like
`/agents?limit=100&offset=0`. A REST driver therefore needs a per-driver
grammar (path + allowed query parameters) rather than the CLI set. This
is why `WZ_ROUTE_TABLE` is not wired to a `route_command` hook despite
now defaulting to RED.

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
