# VIRP Audit — Design Proposals: #7 and #8

Deferred design-scope items from the 2026-08-18 hostile audit. **No implementation** — problem, options, recommendation, migration path, test strategy. All source anchors are against `/opt/virp` main `0015bae2` (post Batch 1–3).

---

## #7 — Asymmetric (Ed25519) observation signing on the execute path

### Problem
Observations of executed commands are signed with **symmetric HMAC**: v1 (master O-Key) or v2 (per-session HKDF of the O-Key). `onode_execute_obs_ex` caps `obs_version` at 2 (`src/virp_onode.c:1285`, `if (obs_version != 1 && obs_version != 2) return VIRP_ERR_VERSION_MISMATCH`), and the wire parser rejects v3 before the function is even reached (`:404`, bound 2). The Ed25519 builder `virp_build_observation_ed25519` exists and the daemon loads the Ed25519 obskey — but the execute path **never emits v3**. Ed25519 is used *only to verify* externally-submitted v3 observations during `chain_append` (`:2712`, `virp_verify_observation_ed25519(state->obskey.public_key, …)`) and in the CLI `obs-verify`.

Consequence: symmetric signing means **the verifier must hold the same key that signs**, so anyone able to verify an observation can also forge one. A leaked O-Key — or a compromised verifier that holds it — can mint observations that pass verification. There is no signer/verifier separation for the evidence the whole system produces. The asymmetric primitive is built and half-wired (verify side only); the value it would buy — offline, key-holder-less verification and non-forgeability by verifiers — is not realized on the path that mints evidence.

**Scope caveat:** a cryptographic-posture gap, not a live bypass. v1/v2 HMAC is sound against parties without the key. The gap is the trust model (symmetric) versus what's already achievable (asymmetric), plus the "looks asymmetric but isn't" confusion of carrying an unused v3 mint path.

### Options
1. **Emit v3 (Ed25519) from the execute path for everything.** Sign with the private obskey, emit wire v3; verifiers use the public key. Requires raising the version cap, wiring the *private* obskey into the mint path (only the public key is referenced on the daemon today), client negotiation to request v3, and migrating consumers (report verifier, chain_append) to treat v3 as the normal PASS case.
   - *Pros:* real signer/verifier separation; a leaked verifier key can't forge.
   - *Cons:* Ed25519 sign is ~an order slower than HMAC (negligible for the ~18-obs/5-min battery; a burst path could feel it); private-key custody becomes critical (daemon-only, rotated, never on a verifier); collides with v2's whole reason for existing (session keys live only in daemon memory) — v2's fate must be decided.
2. **Hybrid: keep v1/v2 by default, add opt-in v3 "high-assurance" per device/session.** Evidence that must be non-repudiable without the signing key (compliance exports, cross-org federation) gets v3; the high-volume monitoring battery stays HMAC.
   - *Pros:* incremental; bounds perf and key-custody cost to where it's wanted; reuses the existing verify side.
   - *Cons:* two trust models to reason about; the report must render both honestly (it already distinguishes `V2-SESSION`).
3. **Do nothing / remove the dead v3 path.** Accept symmetric signing; delete the builder and verify branch to end the "we look like we do asymmetric" confusion.
   - *Pros:* least code; honest about the real model.
   - *Cons:* abandons the invested asymmetric capability and the verify-side ability to accept peer v3 observations.

### Recommendation
**Option 2 (hybrid, opt-in v3).** The execute path stays v1/v2 by default; add a per-device / gate-level flag selecting Ed25519 minting for evidence that must be verifiable without the signing key. Realizes the asymmetric value where it matters, keeps low-cost HMAC for the battery, reuses the present verify side. Decide and document v2's role (session-corroboration) alongside.

### Migration path
1. Wire the **private** obskey into `onode_execute_obs_ex` behind a config/compile flag (today only `public_key` is referenced daemon-side).
2. Raise the parser/version cap to accept `obs_version 3` as a *requested* format (bound `2→3` at `:404`; the `!= 1 && != 2` cap at `:1285`).
3. Add negotiation: client requests v3; daemon emits v3 only for flagged devices/sessions.
4. Migrate `report/verify.py` to treat v3 as first-class PASS (public-key verify), not UNVERIFIABLE/UNCHECKED.
5. Key management: document obskey rotation; startup assertion that the private key is present **only** where minting is enabled; ensure it never ships to a verifier.
6. Roll out device-by-device; v1/v2 for the rest.

### Test strategy
- **Unit:** v3-flagged `onode_execute_obs_ex` emits a wire-v3 observation that verifies under the *public* key and is REJECTED under a wrong key; a forge attempt holding only the public key fails.
- **Production path (closes the audit's "synthetic-only" gap):** exercise the real execute *socket* path emitting v3, not just the crypto helper — current v3 tests call the builder directly and bypass `onode_execute_obs_ex`.
- **Report:** a v3 observation renders PASS and exits 0; a tampered v3 body renders FAIL; v1/v2 devices unchanged.
- **Perf:** micro-benchmark Ed25519 mint vs HMAC to size the burst-path cost.
- **Negative:** daemon refuses to start with v3-minting enabled but no private obskey; refuses to emit v3 for a non-flagged device.

---

## #8 — Bind the driver / classifier / tier version into the approval

> **External corroboration (M3, 2026-08-18).** An external reviewer
> independently rediscovered this finding — labelled M3 in their report —
> which raises confidence it is real and worth doing. Their framing
> sharpens the fix: bind an **immutable effective-policy hash** into the
> signed approval, covering (a) the classifier tables, (b) the
> typed-operation registry and its version, (c) the gate policy in effect,
> and (d) the device binding; **refuse the apply on any mismatch**. That is
> a stronger version of Option 1 below (a single hash over all
> policy-relevant inputs rather than a hand-picked vendor+tier pair), and
> is the recommended target if the table-versioning cost is acceptable.

### Problem
The signed approval canonical binds `proposal_id + command_hash + device_node_id + approved_at + ttl` (`src/virp_approval.c:179-200`; `out+4` proposal_id, `+20` command_hash, `+52` node_id, `+60` approved_at, `+68` ttl). It binds **neither** the driver identity/version, the classifier/registry version, the typed-profile version, **nor** the tier in effect at approval time.

At apply, the daemon re-derives everything from **live** state: driver via `virp_driver_lookup(vendor)` (`src/virp_onode.c:1386`), tier via `gate_classify` (`:1401`), command_hash via the *current* typed profile (`:1514`). So between approve and apply (within the TTL, default 300s), if the driver table, the device's vendor, or the classifier changes, the operation's **interpretation** can change after a human approved it. `command_hash` binds the command **string**, not its meaning.

Concrete (hard-to-reach) scenario: operator approves `show foo` on `edge-1` (vendor `cisco`). Before apply, `edge-1`'s vendor is changed to `linux` — hostname unchanged ⇒ node_id unchanged; on the non-typed path the hash is `sha256(canonicalized string)`, driver-agnostic, so it still matches. At apply every check passes and the **linux** driver interprets/executes `show foo` — a different meaning than the cisco driver the human reviewed. Same class if a driver's `route_command`/typed-profile table is swapped between approve and apply. (Reclassification *toward BLACK* is caught — apply refuses BLACK at `:~1503`; the drift that slips through is same-hash / different-driver-or-table.)

**Scope caveat:** requires a config/table change within the 300s TTL (and, for the typed path, a matching profile) plus store access — narrow, latent, not a live bypass. It is a "historical authorization context" gap: the approval doesn't freeze the interpretation frame it was granted under.

### Options
1. **Bind a driver/classifier table version + vendor into the canonical.** Add fields to `virp_approval_build_canonical`: vendor and a monotonic "classifier table version" (hash/counter of the tier tables + typed profiles). Computed identically at challenge, re-derived at `verify_consume`; a post-approval change fails the signature.
   - *Pros:* cryptographically freezes the interpretation frame.
   - *Cons:* canonical format change (versioning; existing approvals); must introduce and maintain a stable monotonic table version; any legitimate driver update invalidates in-flight approvals (acceptable — re-approve).
2. **Bind the approved TIER + vendor only.** Add the granted tier and the vendor to the canonical; at apply, re-classify and require the same tier + same vendor.
   - *Pros:* much smaller; catches the concrete scenario (vendor swap, tier drift); no table-versioning infra.
   - *Cons:* doesn't catch a *same-tier* reinterpretation within one driver (a table edit that keeps the tier but changes semantics) — rarer.
3. **Shrink the TTL / apply-time equivalence check against an unsigned snapshot.** Reduce the window; assert at apply that driver+tier match a snapshot recorded in the proposal, alert on mismatch.
   - *Pros:* no canonical change; defense-in-depth.
   - *Cons:* an unsigned snapshot is editable by a store-writer (the same trust caveat as #5's hostname) — weaker than signing.

### Recommendation
**Option 2 (bind tier + vendor into the signed canonical).** Closes the concrete, plausible scenario with a bounded canonical change and no new versioning infrastructure. Keep Option 1's table-version as a later hardening if same-tier reinterpretation becomes a concern. Pair with a modest TTL review.

### Migration path
1. Add a **canonical version byte** (today's layout is fixed) so v1 and v2 canonicals are distinguishable; `verify_consume` dispatches on it.
2. Extend `virp_approval_build_canonical` to include vendor + granted tier (v2 canonical). Compute at challenge/sign; re-derive at `verify_consume` (`src/virp_approval.c:~947`) from live state; mismatch → a distinct error (e.g. `VIRP_ERR_APPROVAL_CONTEXT_DRIFT`).
3. Accept v1-canonical approvals during a grace window (or force re-approval); document the cutover.
4. Record vendor+tier in the proposal metadata JSON for operator visibility, but the SIGNED bytes are the authority.

### Test strategy
- **Unit:** v2 canonical with (vendor, tier); `verify_consume` accepts when live vendor+tier match, rejects (`APPROVAL_CONTEXT_DRIFT`) when vendor or tier changed between challenge and apply.
- **Scenario/regression:** approve on vendor `cisco`, flip device to `linux`, apply → refused; approve + unchanged → granted; BLACK reclassification still refused (existing behavior).
- **Back-compat:** a v1-canonical approval still verifies during the grace window; after cutover it's refused with a clear "re-approve under new format" message.
- **Negative:** tampering with the vendor/tier bytes fails the signature (now signed).

---

## H1 — m-of-n (quorum) approval for RED

### Problem
RED is documented (in several places, now corrected) as requiring
multi-human / m-of-n approval, but the implementation requires exactly ONE
enrolled approver's signature — the identical single-record, single-key,
single-signature mechanism as YELLOW (`src/virp_approval.c`
verify_consume loads one record, one key, one signature;
`src/virp_onode.c` apply calls one `virp_approval_verify_consume`). There
is no quorum, no distinct-approver requirement, no threshold. For a truly
critical (RED) operation, a single compromised or coerced approver key is
sufficient to admit it. m-of-n would require m distinct human approvers
before a RED apply.

### Options
1. **Proposal-scoped approval set with a signed threshold policy.** Extend
   the proposal to carry a threshold `m` and the set of eligible approver
   key-ids `n`, bound into the SIGNED proposal canonical. Each approver
   submits an independent APPROVAL record (distinct key, distinct
   operator identity) against the proposal; apply succeeds only once ≥ m
   DISTINCT eligible approvers have valid, unexpired, non-reused
   signatures. Quorum evaluation happens atomically at apply.
   - *Pros:* real dual/-n control for RED; threshold is per-proposal and
     signed, so it cannot be lowered after the fact.
   - *Cons:* multi-record approval store and a quorum-evaluation path;
     canonical/format changes; approver-set management (who is eligible).
2. **Fixed node-wide 2-of-n for RED** (simpler): any RED apply requires two
   distinct enrolled approvers; no per-proposal threshold.
   - *Pros:* much less machinery; covers the headline "no single approver
     for RED" gap.
   - *Cons:* inflexible; no per-operation risk tiering.
3. **Do nothing / keep single-approval, and only fix the docs** (done in
   H1). Accept single-approval RED as the current contract.

### Recommendation
Option 1 (proposal-scoped set + signed threshold), because RED spans a
wide risk range and a per-proposal `m` lets policy scale `m` with impact
(the context-dependent escalation the spec already imagines). If that is
too much, Option 2 is a meaningful interim.

### Design points (the reviewer's requirements)
- **Proposal-scoped approval set:** eligible approver key-ids + threshold
  `m` are chosen at propose time and bound into the signed proposal.
- **Distinct key / operator identities:** quorum counts DISTINCT approver
  key-ids (and distinct operators); the same key twice is one vote.
- **Threshold bound into the signed canonical:** `m` and the eligible set
  are covered by the proposal signature so neither can be weakened between
  propose and apply.
- **Atomic quorum evaluation:** the m-of-n check runs inside the same
  apply transaction that consumes the approvals and writes the OUTCOME —
  no check-then-act window (the same discipline as the GATE-5 in-txn fix).
- **One-time execution:** the consumed set is single-use; a replayed quorum
  cannot admit a second execution (extends the existing single-use
  OUTCOME/consume enforcement to a set).

### Migration path
1. Add a proposal canonical version carrying `{m, [approver_key_ids]}`.
2. New multi-approval store shape (a directory of APPROVAL records per
   proposal) + a distinct-approver quorum loader.
3. `verify_consume` becomes `verify_quorum_consume`: gather ≥ m distinct
   valid approvals, verify each, consume the set atomically at apply.
4. YELLOW stays single-approval; RED opts into the quorum path. Keep the
   single-approval path for a grace window / for tiers below RED.

### Test strategy
- m-1 valid approvals do NOT admit; the m-th distinct approval does.
- The same approver signing twice counts once (no self-quorum).
- Lowering `m` or editing the eligible set after propose fails the
  proposal signature.
- Atomicity: concurrent apply attempts consume the set exactly once (one
  OUTCOME); a replay after quorum is refused.
- An expired/reused/unenrolled member does not count toward `m`.

## M2 — mandatory pinned verifier for validator decisions

### Problem
`api/validator/__init__.py` `validate_turn()` returns a decision even when
the signed observation is UNVERIFIED — no verification bridge supplied, or
the bridge's HMAC check fails/raises — with `ValidationResult.verified =
False`. (M2 labelling now logs a WARNING and documents the experimental
status loudly, but the decision is still returned.) A caller that ignores
`.verified` acts on an unauthenticated decision, which a man-in-the-middle
on the socket/TCP-proxy path could forge.

### Options
1. **Mandatory pinned verifier.** `validate_turn()` REQUIRES a verifier
   (pinned O-Key / public key), verifies every observation, and RAISES on
   an absent or failed verification instead of returning an unverified
   decision. Add a key-rotation trust policy (accept current + previous
   key within a bounded window; reject outside it).
   - *Pros:* an unverified decision can never be acted on; matches the
     enforcement posture the daemon side already has.
   - *Cons:* callers must provision the verifier key; key-rotation handling.
2. **Opt-in strict mode.** A `require_verified=True` flag that raises;
   default stays advisory (today's behaviour).
   - *Pros:* incremental; no forced provisioning.
   - *Cons:* leaves the unsafe default in place.

### Recommendation
Option 1 for any enforcement use — a validator whose decision can be
forged is not a control. Ship it behind a version/flag if needed, but make
verified-or-raise the intended production contract, and keep the current
advisory client clearly marked EXPERIMENTAL (done in M2) until it lands.

### Migration path
1. Add a required verifier parameter (pinned key material) and a
   key-rotation trust policy (current+previous within a window).
2. Verify every observation; raise `ValidatorUnverified` on absent/failed
   verification rather than returning `verified=False`.
3. Migrate callers to provision the verifier; keep the advisory path under
   an explicit `advisory=True` during the transition.

### Test strategy
- A forged/tampered observation raises, never returns a decision.
- Absent verifier raises (no silent unverified return).
- A decision signed under the previous key within the window verifies;
  outside the window it raises.

## EXECUTION_INTENT — durable "attempted, disposition unknown" record (-07 material)

Origin: the adversarial test program, test #2 (crash around execution); see
`tests/adversarial/MEMO-execution-intent.md`.

### Problem — the five-realities collapse, and why it SURVIVES the atomicity fix
Test #2 crashed the daemon at each boundary of an approved apply and asked a
single question: after the crash, does the target's record of what happened
agree with VIRP's? It does not. Today the chain (and the spool) cannot
distinguish:
  - `post_consume` — authorization burned, **device never contacted**, from
  - `post_exec` — authorization burned, **device executed**.

Both leave: an APPROVAL entry, a consumed-once marker, and NO OUTCOME. To
every reader they are identical, yet in one the device changed and in the
other it did not. This is the same limit as the claims-hygiene item:
VIRP supports "a recorded execution happened at most once", not "everything
that happened was recorded".

**Crucially, this ambiguity is NOT the `chain_append`/`artifact_store`
non-atomicity — that is a separate, already-shipped fix** (entry, head and
body now commit or roll back together inside one transaction, see
`src/virp_chain.c` `chain_append_locked`). The five-realities gap lives
**between `consume_once()` and the OUTCOME append** — i.e. *between* two
chain operations, across the device I/O, not *within* one append. No
amount of per-append atomicity closes it, because the missing record is a
record of a step that happens between appends.

### Proposal
A new chain artifact type committed at the ONE instant that separates "not
attempted" from "attempted, disposition unknown":

```
EXECUTION_INTENT { proposal_id, approval_entry_hash, device, device_node_id,
                   command_hash, attempt_at_ns, daemon_build_id }
```

Chain semantics gain the middle row VIRP currently cannot say:

| chain state | meaning |
|---|---|
| approval, no intent, no outcome | authorization spent or lost; **device never contacted** |
| approval, **intent**, no outcome | **authorized execution attempted; disposition unknown** |
| approval, intent, outcome | executed, result recorded |

### NORMATIVE placement constraint
The intent record MUST be committed **after `consume_once()` and immediately
before `drv->execute()`** — the single line that separates "not attempted"
from "attempted". Two corollaries, both normative:
  1. The intent commit MUST NOT be atomic with the consume. They must be
     separable, because the gap between them is the exact distinction being
     bought; coupling them reproduces today's ambiguity and buys nothing.
  2. The intent is its own `BEGIN IMMEDIATE`→`COMMIT`, before device I/O.

### Cost
- **Storage/schema:** none — a new `artifact_type` on the existing
  `virp_chain_append()`. No migration. (Do NOT reuse the unused `intents`
  table — different, AI-intent-shaped concept; its columns would misdescribe
  this.)
- **Latency:** one extra `BEGIN IMMEDIATE`→`COMMIT` per privileged apply,
  on the critical path before device I/O — single-digit ms against SSH
  connect + exec. Applies only to approved RED/YELLOW applies, never GREEN
  reads (the autopilot's per-minute load is untouched).
- **Wire:** none — a local durable record; nothing new crosses the socket.
- **Operational (the real cost):** an intent with no outcome is a permanent
  "unknown" that someone must **reconcile**. Today those cases are invisible
  and therefore free; afterwards they are visible and demand a monitoring
  surface, a runbook, and an agreed answer to "what do we do with an
  unresolved intent". That visibility is the point, but it is not zero.

### Spec status
-07 material, and small: it adds an artifact type to the
PROPOSAL → APPROVAL → OUTCOME vocabulary (C21), so any spec text enumerating
chain artifact types changes. It does not touch the wire format, the
observation header, canonicalization, or any signature construction. If -07
is open, fold it in; not worth opening a revision for on its own.

### Test strategy
- A crash injected at the new intent boundary leaves `approval + intent, no
  outcome`; the verifier reports "attempted, disposition unknown", never
  "never contacted".
- A crash BEFORE the intent commit leaves `approval, no intent, no outcome`;
  the verifier reports "never contacted" — the two are now distinguishable.
- Reconciliation: an unresolved intent surfaces to the monitoring runbook.

## Crypto review 2026-08-31 — future hardening (findings 8 and 9)

Both from the source-level crypto review (findings 1–7 fixed in-tree on
fix/crypto-review). Neither is a present crypto bug; both are recorded
so the claims they affect are not over-stated in the meantime.

### #C8 — approval client reconstructs the canonical bytes it signs

`virp approve` displays the human-readable command but signs the opaque
144-hex canonical blob the daemon supplies (`src/virp_tool.c`). It does
not rebuild the canonical approval from the displayed fields and prove
that hashing the displayed command yields the command_hash inside the
blob. Under the normal threat model (O-Node trusted, agent adversarial)
this is acceptable — but the stronger claim "even a malicious O-Node
cannot trick the approver key into signing something other than what
the operator saw" is NOT yet supported, and must not be made until the
client does the reconstruction itself. Design: client-side
`build_canonical(VAP1, proposal_id, sha256(displayed command),
device_node_id, approved_at_ns, ttl)` + byte-compare before signing.

### #C9 — enforce low-S on the P-256 approval verifier

ECDSA accepts (r, s) and (r, n−s) alike unless low-S is required, so
one legitimate P-256 approval signature has two valid byte encodings.
Not a forgery vector, but VIRP cares about stable evidence bytes;
enforce low-S at verification (reject s > n/2) and normalize at the
PKCS#11 signing path. Ed25519 (libsodium) is already canonical-S and
unaffected.

## Out of this set (tracked separately)
- **Evidence option-1:** an approved-YELLOW collection path so AC-1/CM-2 stay *covered* (not just gap-documented). A collector + approval-flow design change; larger than the option-2 gap fix already merged.
