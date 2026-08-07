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
  over **exactly the same bytes**: `header || payload`.

**Why a distinct version, not an optional field.** Byte 0 alone
determines the verification obligations (unambiguous dispatch — what
the observation-format unification needs). Because both trailers cover
the version byte, stripping the Ed25519 trailer and relabeling the
message v2 requires re-computing the HMAC, i.e. the session key; and a
v3 signature can never validate a v2 blob.

**Why the same covered bytes as the HMAC.** The symmetric and
asymmetric schemes attest identical content, so their guarantees are
directly comparable, and a future verifier can check either or both
without canonicalization differences. Neither trailer covers the
other: each is checked by its own audience (HMAC by the session
holder, Ed25519 by public-key consumers).

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
