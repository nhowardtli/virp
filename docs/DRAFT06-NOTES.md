# Protocol-Visible Changes Pending for draft-06

Running record of implemented, protocol-visible decisions that the next
RFC revision (`draft-howard-virp-06`) must incorporate. Each entry
states the wire-level decision and where the normative comment lives in
the tree. Append new entries; do not rewrite old ones.

---

## 1. V3 observations: Ed25519-signed observation format (2026-08-07)

**Decision.** A third observation wire version, dispatched on byte 0
(`version = 3`), rather than an optional field bolted onto v1/v2:

```
[ header : 88 bytes ] [ payload : P ] [ hmac : 32 ] [ ed25519 sig : 64 ]
```

- The 88-byte header is byte-for-byte the v2 field layout (normative
  comment above `VIRP_OBS_V2_HEADER_SIZE` in `include/virp.h`), with
  `version = 3`.
- `hmac` is unchanged v2 semantics:
  `HMAC-SHA256(session_key, header || payload)`.
- `sig` is an Ed25519 detached signature by the O-Node's
  observation-signing key (the "obskey", key_id = SHA-256(pub)[:16])
  over `header || payload || hmac` — **every byte of the message except
  the signature itself**. This span is normative.

**Build and verify order (normative).** Build: serialize the header,
append the payload, compute the HMAC over `header || payload`, append
it, then sign `header || payload || hmac`. Verify: check the Ed25519
signature over `header || payload || hmac` first; a session-key holder
MAY then check the HMAC over `header || payload`. A public-key consumer
holds no session key and MUST NOT need one.

**Why a distinct version, not an optional field.** Byte 0 alone
determines the verification obligations (unambiguous dispatch — what
the observation-format unification needs). Because both trailers cover
the version byte, stripping the Ed25519 trailer and relabeling the
message v2 requires re-computing the HMAC, i.e. the session key; and a
v3 signature can never validate a v2 blob.

**Why the signature covers the HMAC (revised 2026-08-08).** The two
trailers attest the same *content* — the HMAC over `header || payload`
is unchanged v2 semantics — but they are **nested, not parallel**. The
first cut had them parallel, each covering `header || payload` and
neither covering the other, on the reasoning that each is checked by
its own audience (HMAC by the session holder, Ed25519 by public-key
consumers). That reasoning was wrong about one thing: it left the 32
HMAC bytes inside the message and outside every signature. A relay
holding neither key could rewrite them and the message still verified —
the same attested observation under an unlimited number of distinct
byte strings, hence an unlimited number of distinct SHA-256 artifact
hashes. Since the chain binds `artifact_hash` to the exact submitted
bytes, that malleability would have become a chain-identity problem the
moment v3 reached `chain_append`. A signed message is one atomic unit;
"checked by its own audience" is about who verifies, not about what is
bound.

**Compatibility.** This is a breaking change to the v3 signed span.
`sig` computed over `header || payload` no longer verifies. It was made
while **v3 has zero dependents** — nothing emits v3 in production, no
chain entry carries a v3 body, and `chain_append` does not yet check
Ed25519 signatures at all — so the change costs nothing today and would
have been permanent the moment it had one dependent. v1 and v2 are
untouched.

**Scope of the guarantee (state this in the draft).** The Ed25519
signature removes CONSUMER/AUDITOR forge capability — a holder of only
the public key can verify but cannot mint, unlike the symmetric HMAC
where verify key == forge key (demonstrated as a contrast in
`tests/test_obs_ed25519_forge.c`). It does NOT address O-Node
compromise: the daemon holds the private key because the daemon is the
attester. Enforcement (e.g. at chain append) and default-on are NOT
part of this change; v3 coexists additively with v1/v2.

Normative comment in-tree: the `VIRP_VERSION_3` block in
`include/virp.h`. Key custody: `include/virp_obskey.h` and SECURITY.md
"Ed25519 Observation Signing".

---

*(The typed-operation command hash — `virp_typed_op_hash`, see
`src/virp_crypto.c` — is an earlier protocol-visible change also
flagged "note for draft-06" in code; it predates this file and is
recorded here only by reference.)*
