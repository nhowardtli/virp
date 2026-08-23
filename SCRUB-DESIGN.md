# SCRUB-DESIGN.md — Scrub-at-capture (S-1)

**Status:** built and tested on VM 313 (virp-onode-home), branch
`feat/scrub-at-capture`. Not deployed — Nate deploys.
**Scope:** O-Node daemon only. No Docket, exporter, laptop-repo, or
.211 changes. Going-forward only — existing chain entries untouched.

## What it is

A generic, known-shapes secret scrubber that runs in the O-Node
observation capture path **before the body is hashed or signed**. The
redacted form IS the artifact: the observation signature (v1 O-Key
HMAC / v2 session HMAC) verifies over the redacted bytes, and the
`gate_execution` chain entry's `response_sha256` commits to the same
redacted bytes. **No unredacted original is retained anywhere** — no
"original" field, no sidecar, no reversible encoding.

It is a safety net for the ACCIDENTAL case — a device unexpectedly
echoing a credential into command output. It sits behind the
per-driver config scrubs (`cisco_scrub_config`, ASA, FortiGate),
which remain the primary defense for reads that are *known* to carry
credentials. Nothing in normal workflow asks devices to print
credentials; this catches the day something does anyway.

## Insertion point (the one place)

`src/virp_onode.c:1890` — `virp_scrub_exec_result(&result)` in
`onode_execute_obs_ex()`, immediately after the driver execute/retry
logic settles the exec result and **before**:

1. the `OUTCOME_UNKNOWN` / driver-refused ERROR observation bodies
   (built from `result.error_msg`),
2. `gate_emit_execution()` — which computes the `response_sha256`
   commitment over `result.output`,
3. both observation constructors (`virp_build_observation_tiered`,
   `virp_build_observation_v2`).

Every path that signs or commits to captured content is downstream of
this call. Reordering it below `gate_emit_execution` would make the
chain commit to unredacted bytes — the block comment at the call site
says so and must travel with the call.

Both `result.output` (the observation body) and `result.error_msg`
(driver error text, which can quote device output and feeds signed
ERROR bodies) are scrubbed. Empty fields stay empty — a marker on a
body that was never captured would fabricate content.

## What it catches (ruleset v1 — conservative, known shapes)

Redaction is a **marked substitution**, never a deletion:
`[REDACTED: <reason>]`, with enough surrounding structure kept that a
reader still sees "a password line, redacted". Because the marker is
inside the signed bytes, the redaction itself is tamper-evident.

| Shape | Behavior | Marker reason |
|---|---|---|
| `enable secret …` / `enable password …` | everything after the keyword | `enable-secret` / `enable-password` |
| `password …` / `passwd …` / `secret …` (exact token, incl. `username … password/secret …`) | everything after the keyword | `password` / `secret` |
| `snmp-server community <tok> …` | the community token only; RO/RW/ACL kept | `snmp-community` |
| `crypto … key [<enc#>] <tok> [address …]` | the key token only; peer address kept | `pre-shared-key` |
| `pre-shared-key …` / `wpa-psk …` / `psk …` (and `psk=<v>`) | value | `pre-shared-key` / `wpa-psk` / `psk` |
| line-leading `key <string>` | value — EXCEPT `key <number>` (key-chain index) and `key chain <name>` (block header) | `key` |
| `key-string …` | everything after the keyword | `key-string` |
| PEM `-----BEGIN … PRIVATE KEY-----` blocks | interior replaced by one marker line; BEGIN/END kept; an **unterminated** block redacts to end of body | `private-key-block` |
| labeled values: label token equal to or ending in `password`/`passwd`/`secret`/`token`/`api-key`/`api_key`/`apikey`/`psk` followed by `:` or `=` (e.g. `PVE_API_TOKEN=…`, `api_key: …`) | the value; label + separator kept | `token` / `api-key` / `password` / … |

Matching is exact-token and case-insensitive: `service
password-encryption` and `ip ospf authentication message-digest`
pass byte-identically. A clean body is a **byte-for-byte no-op**
(pinned by test). The scrub is idempotent: an already-redacted line
is recognized and left alone. Certificates (`BEGIN CERTIFICATE`) are
public material and are not touched.

Known accepted over-redaction: a prose line containing the bare token
`secret`/`password` redacts its remainder. Over-redaction is the
fail-closed direction; the behavior is pinned by test so changing it
is a decision, not an accident.

## What it does NOT catch — the honesty limit

**This scrubber reduces the blast radius of an accidental credential
dump for recognized formats. It does not guarantee the chain is
secret-free.** A credential that looks like ordinary text — an
unlabeled plaintext password on its own line, a bare hex or base64
token with no label — will NOT be caught, and there is a test
(`test_unlabeled_secret_is_NOT_caught`) pinning that limit so the
code and the claim cannot drift apart.

Any user-facing or reviewer-facing description must say **"secrets in
recognized formats are scrubbed at capture"** — never "no secret can
enter the chain." Overclaiming here is the one thing that would make
an otherwise honest product dishonest.

## Fail-closed behavior

If the scrubber cannot complete on a body — internal error, output
overflow, allocation failure — the **whole field** is replaced with
`[REDACTED: scrub-error]` and that marker is what gets signed and
committed. A content scanner that fails open is worse than none.
There is a test-only hook (`virp_scrub_test_force_error`) that forces
an internal failure to prove this end-to-end; it can only cause
over-redaction, and there is deliberately NO hook that disables
scrubbing.

## Going-forward only

The scrub runs at capture time on new observations. It performs no
retroactive scan, no migration, no rewrite of any existing entry —
gate G4 asserts a pre-existing entry is byte-identical across a
scrubbed append and that chain linkage stays unbroken.

## Signing/verification unchanged

No change to signing algorithms, canonicalization, entry structure,
or the D-1 detached Ed25519 chain-signing path — only the body bytes
that feed them. Gates G1–G3 verify scrubbed captures at the D-1
pubkey-only Ed25519 tier (`virp_chain_open_verifier_ex` with only the
public key) — the in-tree form of the CRYPTOGRAPHICALLY-VERIFIED
verdict.

## Behavior change to know about

Pre-S-1, the caller received the raw device output and only the chain
was secret-free (commitment-only design). Post-S-1 the redaction
happens before signing, so **the caller receives the redacted body
too**, and `response_sha256`/`response_len` commit to the redacted
bytes. `tests/test_onode.c`'s secret-safety test was updated
accordingly (its old "caller DID receive the secret" assertion is
deliberately inverted now).

## Tests

- `tests/test_virp_scrub.c` (`make test-scrub`, in `all-tests`):
  22 unit tests — ruleset shape-by-shape with CANARY property, clean
  no-op, idempotence, CRLF, overflow fail-closed, forced-error
  fail-closed, the honesty-limit pin, wrapper behavior.
- `tests/test_onode.c` gates (`make test-onode`):
  - **G1** clean capture: no-op scrub, signed observation carries the
    exact device bytes, chains, Ed25519-tier verified.
  - **G2** planted `enable secret` + PEM block + `snmp-server
    community`: markers in the signed body, no CANARY anywhere (obs,
    entry, DB file, WAL), commitment matches independently recomputed
    scrubbed bytes, Ed25519-tier verified.
  - **G3** forced scrubber failure: body is exactly
    `[REDACTED: scrub-error]`, raw content reaches nothing, still
    signs and verifies.
  - **G4** existing entry byte-identical across a scrubbed append,
    linkage unbroken.
