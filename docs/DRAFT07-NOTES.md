# Protocol-Visible Changes Pending for draft-07

Running record of implemented, protocol-visible decisions that the next
RFC revision (`draft-howard-virp-07`) must incorporate. Each entry
states the wire-level decision and where the normative comment lives in
the tree. Append new entries; do not rewrite old ones.

**Status of -06 (filed 2026-08-01).** This file was previously named
`DRAFT06-NOTES.md`. `draft-howard-virp-06` is filed and specifies the
**v1 and v2 observation formats only**. It incorporated NEITHER entry
below:

- **v3 Ed25519 observations** — not specified in -06. §17.3 of -06 lists
  asymmetric observation signing as *future work*, and Appendix A
  records the removal of the earlier per-observation Ed25519 claim that
  the implementation did not support. v3 is -07 material.
- **Typed-profile command hashing** — not specified in -06 either; §17.7
  scopes it as future work. The in-tree markers for it (see
  `src/virp_crypto.c virp_typed_op_hash` and `DEPLOYED.md`) therefore
  carry to -07.

Everything in this file is implemented **ahead of specification**. Do
not cite the filed draft as the authority for any of it.

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

## 2. Detached Ed25519 chain signing (D-1, 2026-08-23)

**Decision.** A chain entry and a per-session head MAY additionally carry a
detached Ed25519 signature, stored ALONGSIDE the existing authenticated
content, so a party holding only the signer's public key can verify entries
without the symmetric chain key.

**The canonical bytes are unchanged — normative.** The signature signs the
EXACT bytes the entry hash and `chain_hmac` already cover
(`build_canonical_json`, the twelve-field fixed-order construction), and the
head signature signs the exact `head_canonical` bytes
(`{"last_entry_hash":…,"last_sequence":…,"session_id":…,"v":"VIRP-CHAIN-HEAD-v1"}`).
The SHA-256 entry hash, the K_chain HMAC, the head HMAC, the milestone
canonical and the genesis rule (`SHA-256("VIRP_CHAIN_GENESIS:"+session_id)`)
are byte-identical to -06/pre-D-1. Any evidence issued before the cut-over
verifies unchanged; the D-0 seal (`tools/seal/`) attests it.

**Signature construction (normative).**

```
entry_sig = Ed25519.sign(sk, "VIRP-CHAIN-ENTRY-SIG-v1" 0x00 || canonical_entry_bytes)
head_sig  = Ed25519.sign(sk, "VIRP-CHAIN-HEAD-SIG-v1"  0x00 || head_canonical_bytes)
```

- The domain-separation tag INCLUDES its terminating NUL in the signed
  input (the `VIRP-TYPED-OP` convention). The two tags differ, so no byte
  string validates as both an entry signature and a head signature.
- The tag is prepended to the signature INPUT only. It is never stored and
  is not part of any canonical object.
- `scheme = "ed25519-detached-v1"`. `key_id = SHA-256(pub)[0:16]`
  (sha256-raw-16), rendered as 32 lowercase hex.
- Signatures and key_id are stored in NEW columns
  (`chain_entries.chain_sig`, `chain_sig_key_id`; `chain_heads.head_sig`,
  `head_sig_key_id`); a BUNDLE representation distinguishes signed entries by
  their presence, tagged `signature_scheme: "ed25519-detached-v1"` +
  `signing_key_id`, with `chain_format` remaining `v1` (the canonical format
  is unchanged). The C tree emits only these storage-level facts; era
  labelling ("independently verifiable") belongs to the bundle layer, not
  this tree.

**Session-granularity key binding (normative).** Per-session chains restart
at sequence 0, so a session is signed under exactly one key. In a
head-signed session every entry's `chain_sig_key_id` MUST equal the head's
key_id. A verifier holding the matching public key MUST reject (as
tampering) a head-signed session with any entry that is unsigned or carries
a different key_id. A verifier that does not hold the session's key reports
it unverifiable-under-this-key (not a failure).

**Three verification tiers (normative).** keyless (hash + link +
completeness, head length claim unauthenticated), symmetric (adds the
K_chain HMAC — unchanged), asymmetric (adds Ed25519 under the public key,
no secret required). Each is independently sufficient for what it claims;
they compose.

**Milestones are NOT signed in D-1** (HMAC only). Signing the milestone
canonical is deferred to a later change; recorded here so -07 does not
assume a milestone signature exists.

**Compatibility.** Pure addition, opt-in per node (`-S`). Old sessions
remain format v1 and are covered by the D-0 seal; new sessions are born
dual-signed from sequence 0. There is NO migration of old data. An old
verifier that ignores the sig columns verifies everything it verified
before, over identical bytes.

Normative comment in-tree: `include/virp_chainsign.h` and the D-1 blocks in
`src/virp_chain.c`. Golden vectors: `tests/vectors/chain-signing-v1.json`.
Key custody: SECURITY.md "Detached Ed25519 Chain Signing (D-1)".

---

*(The typed-operation command hash — `virp_typed_op_hash`, see
`src/virp_crypto.c` — is an earlier protocol-visible change, now
flagged "note for draft-07" in code. It predates this file, was NOT
incorporated into -06 (§17.7 scopes typed operations as future work),
and is recorded here only by reference.)*

---

## 3. HKDF `info` purpose label for session-key derivation (deferred, 2026-08-31)

**Decision (not yet implemented — wire break, rides the next canonical-
format window).** -06 §6.1 specifies the HKDF-Expand `info` input as
exactly the 8-octet big-endian generation counter. -07 should prefix a
purpose label:

```
info = "VIRP-SESSION-OBS-v2" || 0x00 || u64be(generation)
```

Not fixing a current attack: today only the session observation key is
derived from the master/transcript pair. The label makes accidental
cross-purpose key reuse structurally impossible if anything else
(approval, federation) is ever derived from the same inputs — the same
domain-separation discipline the chain-signature tags already follow.

Changing `info` changes the derived key, so this cannot ship alone; it
must land with the observation-format version bump. Sequencing decision
recorded at the deferral comment in `src/virp_transcript.c
virp_hkdf_sha256` (crypto review 2026-08-31, finding 6, second half).
The PRK-cleanup half of that finding is already fixed in-tree.

---

## 4. Evidence-required execution — chain-visible surface (Sep 1 review, Task 5 / 1.1–1.6)

Landed in `fix/evidence-required`. These are the protocol- and chain-visible
elements a draft-07 reader must know; the mechanism and rationale are in
`SECURITY.md` "Evidence-required execution".

- **`gate_intent` chain entry (type, daemon-reserved).** Written before the
  driver runs, in session `gate-enforce:<device>`. Body (`gate_intent/1`):
  `device, driver, command, classified_tier, gate_max_tier,
  effective_max_tier, ceiling_source, gate_mode, decision
  (auto-execute|approved-apply), uid, session (v2 hex or null), proposal_id,
  approval_entry_hash, proposal_entry_hash (both null for an auto-execute),
  obs_version, intent_ns`. A socket client may not mint one.

- **Closer link.** `gate_execution` and `outcome` bodies carry
  `intent_entry_hash` (+ `intent_sequence`, `intent_artifact_id`) naming the
  intent they close. `gate_execution` also now carries `session` for the
  binding check. `intent_entry_hash: null` marks a closer written with
  `evidence_required=false`.

- **Open-execution verdict.** A `gate_intent` with no closer citing its
  `chain_entry_hash` is an OPEN execution: reported by
  `virp_chain_verify_session` (`executions_open`/`executions_closed`), by
  `virp chain-verify` (`OPEN_EXECUTIONS=n`), by the daemon's `chain_verify`
  actions, and by `report/verify.py` (`summary["open_executions"]`). It is
  **not** a chain failure — the chain is intact; the world after its last
  entry is uncertain. Reconcile against the target.

- **Closer binding rules (verifier FAIL, both C and Python).** A closer's
  `intent_entry_hash` must resolve to a `gate_intent` entry (wrong type or
  absent = FAIL). Two closers for one intent = FAIL. Two intents citing one
  `approval_entry_hash` = FAIL (double-spend). A closer whose binding
  fields disagree with its intent = FAIL, compared over the fields both
  carry: `device` always; `command`/`session`/`uid` for `gate_execution`;
  `proposal_id`/`approval_entry_hash` for `outcome`. All checks use the
  GATE 4 pattern (type-restricted query + cJSON parse, never `instr`/
  `strstr`).

- **`node_config` chain entry (type, daemon-reserved).** Written once at
  startup in session `node-config:<node_id>`. Body (`node_config/1`):
  `node_id, build_id, evidence_required, gate_default_mode, gate_max_tier,
  uid_ceilings[], emitted_ns`. Lets a reader bound the window in which
  unrecorded execution was permitted, and lets Docket read the tier ceiling
  from the bundle. Verifiers accept it present or absent with no grading
  change.

- **Evidence-required mode / degraded state.** `evidence_required` (config
  boolean, default true) gates dispatch on a durable pre-execution record;
  a non-boolean value is a FATAL config error (1.4). When a closer append
  fails *after* the device acted, the caller receives a signed ERROR citing
  `unchained-execution` and the open intent, and the daemon latches
  **evidence-degraded**, refusing further dispatch at the intent step until
  restart (1.3). The durable late-closer spool that would recover such an
  outcome is deferred — see `docs/PROPOSAL-LATE-CLOSER-SPOOL.md`.

## 5. Three body-level truth gaps still open (recorded together)

These are pre-existing honesty gaps in the daemon's own record bodies, NOT
introduced by the evidence-required work, tracked here so draft-07 accounts
for them in one place:

1. **`gate_execution.executed`** is three-valued in intent
   (EXECUTED / REFUSED / UNKNOWN) but an undeclared `!success` driver
   result still resolves to `executed:true` and is signed as
   DEVICE_OUTPUT. Pinned by the two deliberately-PENDING tests in
   `tests/test_onode.c` (`test_refusal_with_body_is_not_an_execution`,
   `test_refusal_with_body_is_not_recorded_executed`). No shipping driver
   emits that shape today; the O-Node is what remains to be held to account.
2. **`gate_rejection`** records `gate_mode` but the SHADOW-vs-ENFORCE
   distinction in the body can still be read ambiguously by a consumer that
   keys on tier alone; the field is present but under-used.
3. **`decision` value set** across `gate_intent` / `gate_execution` /
   `gate_rejection` is not a closed enum in the schema — a reader must know
   the daemon's spellings (`auto-execute`, `approved-apply`) rather than
   validate against a declared list.
