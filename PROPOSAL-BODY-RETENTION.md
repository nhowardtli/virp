# PROPOSAL: an explicit "body not retained" state

Status: PROPOSAL ONLY — nothing in this document is implemented. Phase 2 of the
2026-08-27 body-retention session. HARD STOP: requires nhoward's ruling before any
implementation, because the recommended option changes what goes into a commitment
(canonical bytes) and is therefore wire-format / draft-07 material.

**Does this touch canonical bytes? The recommended option (B) does — it adds one
field to the canonical entry JSON, gated on `artifact_schema_version`. The fallback
option (D) does not.** That distinction is the whole decision.

---

## 1. The state we are naming

Today, "a body existed, was not retained, and here is its commitment" is expressed
by **the absence of an `artifacts` row**. Verified facts this proposal rests on
(full evidence in SESSION-BODY-RETENTION.md):

- The canonical entry form is a fixed 12-field JSON (`report/verify.py:208-241`,
  matching `src/virp_chain.c:build_canonical_json`). `artifact_content` is not in
  it; the body binds only through `artifact_hash`.
- Neither `chain_entries` nor `artifacts` has any retention-status field
  (`src/virp_chain.c:791-800`, schema confirmed against the live snapshot).
- The verifier (`report/verify.py:817-841`) *infers* the reason a body check
  cannot run: stored length == 8191 → "truncated at the daemon limit"; missing row
  → generic "no artifact body is stored"; plus two hardcoded type sets. All
  heuristics. A body that is exactly 8191 chars for a legitimate reason, or a
  body that goes missing for a bad reason, is indistinguishable from the honest
  cases by construction.
- Both existing loss populations grade UNVERIFIABLE today, not FAIL (verifier run
  over the full 207,854-entry snapshot: rollup FAIL = 0). The problem is not that
  honest entries read as tampering — it is that the honest state is **undeclared
  and unauthenticated**: nothing the writer signed says "I did not retain this
  body on purpose," so the verifier's honest-sounding reasons are guesses that
  tampering could hide behind.

Target state: at write time, a body that will not be retained in full is recorded
as such **inside the HMAC'd entry**, with `artifact_hash` still committing to the
full original bytes, so a reader gets: chain integrity PASS + an authenticated
declaration "body not retained (reason R), commitment intact."

## 2. Options

### Option B (recommended): a `body_retention` field in the canonical entry

Add one field to the canonical JSON and to `chain_entries`:

```
body_retention TEXT NOT NULL DEFAULT 'full'
   'full'      — body submitted and stored; sha256(body) == artifact_hash enforced
                 at append (GATE 2, already live)
   'none'      — writer declares the body is deliberately not stored;
                 artifact_hash still commits to the full original bytes
   'filtered'  — reserved for the Phase 3 collector filter if a chained
                 declaration is ever wanted (currently recorded in-body instead;
                 see §6)
```

Canonical JSON gains `"body_retention":"<value>"` in alphabetical position, and
`artifact_schema_version` moves `'1'` → `'2'` for entries that carry it. Canonical
construction becomes version-gated in both writers and verifiers: version 1 →
today's 12 fields byte-for-byte; version 2 → 13 fields. Existing entries are
untouched and re-verify exactly as today (their canonical bytes never change).

- **Wire-format change: yes.** New canonical field ⇒ version bump ⇒ draft-07
  material. This is the same window the code has already reserved for the
  deferred `commitment_mode` field (`src/virp_onode.c` chain_append comment:
  "That changes the canonical form, so it belongs with the provenance field in a
  chain-format change window") — the two should land in the same window.
- **Daemon append rule:** `body_retention='none'` requires empty
  `artifact_content`; `'full'` requires a body passing GATE 2. A body present
  with `'none'`, or absent with `'full'`, is refused. This closes the current gap
  where commitment-only is simply "the client didn't send a body" — silence
  becomes an explicit, checkable claim.
- **Tamper evidence:** the declaration is under `chain_entry_hash`, `chain_hmac`,
  and (when `-S` lands) the Ed25519 entry signature. Deleting a stored body
  post-hoc can no longer masquerade as deliberate non-retention: the entry says
  `'full'` and the body is gone → FAIL, correctly.

### Option D (fallback, no canonical change): a bound retention-stub body

New artifact type (e.g. `observation_unretained`) whose *body* is a small JSON
stub `{"schema":"retention/1","body_sha256":"<full-body sha256>","body_len":N,
"reason":"oversized"}` and whose entry `artifact_hash` = sha256(stub). The stub
is tamper-evident through the existing binding; the full-body commitment lives
one indirection away, inside the stub.

- No canonical change, expressible today, not draft material.
- **Rejected as the recommendation for two reasons.** (1) The entry's
  `artifact_hash` no longer commits to the observation bytes — it commits to a
  statement *about* them. That is exactly the indirect-commitment pattern the
  verifier already has to special-case for comparator/chainwalk types
  (`INDIRECT_COMMITMENT_TYPES`, graded UNVERIFIABLE), and the chain_append
  comment block explicitly calls that pattern a defect to be retired, not
  extended. (2) An old verifier grades such an entry `artifact_bind: PASS`
  (true but misleading) with no signal that the evidence bytes were never
  checked — a new silent overclaim, which is the class of mistake this whole
  session exists to stop.

### Rejected outright

- Overloading `artifact_schema_version` or `artifact_type` string values to
  smuggle a retention flag through the existing canonical form: unversioned
  semantic change to fields readers already interpret; still draft material in
  effect, with none of the clarity.
- Any migration that touches the 2,211 existing entries: forbidden by the
  append-only rule, and correctly so.

## 3. How the verifier should render it

Add a distinct terminal verdict for the declared state — proposed label
**`NOT-RETAINED`** (rendered e.g. "NOT-RETAINED — declared at write; chain
integrity verified; commitment to the full body recorded; body content not
checkable"). Precedence: `FAIL > UNVERIFIABLE > UNCHECKED > NOT-RETAINED > PASS`.

- It is not PASS/VERIFIED: `.ok` stays false for evidence-consumption purposes;
  no rendering may imply the body was checked.
- It is not FAIL: chain integrity passed and the state was declared by the
  writer under the chain HMAC.
- **UNVERIFIABLE remains, and remains alarming**: it now means "a body check
  cannot run and the writer did *not* declare why." Post-cutover, a bodyless
  version-2 entry claiming `'full'`, or any undeclared retention gap, is at
  minimum UNVERIFIABLE. The declared state drains the honest population out of
  UNVERIFIABLE so the residue is signal, not noise.

## 4. Backward compatibility

- **Old verifier, new (version-2) entry:** an unmodified verifier recomputes the
  12-field canonical form, mismatches, and reports FAIL on every version-2
  entry. Option B therefore requires verifiers to be updated **before** any
  writer emits version 2 — the version-gated canonical build ships and deploys
  first, the writer flag turns on second. This ordering constraint is the main
  operational cost of Option B and is why it needs a coordinated format window.
  (Docket's verifier is in the same position; it gets the version gate and the
  NOT-RETAINED label as draft-07 work, out of scope this session.)
- **New verifier, the 2,211 truncated legacy entries:** they fail
  hash-binding forever, and that stays true and stays visible. They are
  version-1 entries, so they keep today's heuristic grading: UNVERIFIABLE with
  the RETENTION_TRUNCATED reason. Proposed report language, rendered wherever
  they are summarized:

  > 2,211 observation entries (librenms-lab, 2026-07-29 → 2026-08-06) were
  > truncated by the daemon's 8,192-byte artifact field on write, before the
  > 2026-08-06 hash-binding gate existed. The chain entry commits to the full
  > response; only the first 8,191 bytes were stored. The stored prefix can
  > never re-verify against the commitment. This is a recorded write-path
  > defect, not evidence of tampering; the population is closed (bounded by the
  > 2026-08-06 daemon fix) and is identified by stored length exactly 8,191.

  They must **not** be re-labeled NOT-RETAINED: that state means "declared at
  write," and nothing was declared. Papering over them with the new label would
  forge a declaration that was never made.
- **New verifier, the 17,637 bodyless legacy entries:** same principle — they
  stay UNVERIFIABLE ("no artifact body is stored"), with report text noting the
  oversized-body cause and the 2026-08-06 → cutover date range. Only entries
  written after the cutover can earn NOT-RETAINED.

## 5. Should the size cap move?

Independent of the labeling fix: **yes, raise it — it converts most of the
ongoing 864-entry/day loss into retained bodies.** Facts:

- The cap is the request-struct field `char artifact_content[8192]`
  (`src/virp_onode.c:74`); storage is unbounded TEXT; the transport frame caps a
  whole request at 64 KiB (`VIRP_MAX_MESSAGE_SIZE`, `include/virp.h:25`).
- Everything currently being lost fits comfortably under the frame: librenms
  `GET /api/v0/devices` responses are ~13.3 KB raw (~17.8 KB base64), pbs
  `backup.datastore.usage` ~28.5 KB raw (~38 KB base64) — measured from
  gate_execution `response_len` on the snapshot.
- Proposal: raise the field to 60 KiB (leaving headroom inside the 64 KiB
  frame), move `onode_request_t` off the stack (it is stack-allocated at
  `src/virp_onode.c:2961`; +52 KiB per handler frame is not acceptable), and
  keep the client-side guards keyed to the same constant, exported in one place
  instead of the three hardcoded `8192`s (`virp_onode.c`, `virp_tool.c:938`,
  `virp_autopilot.py:404`) and the verifier's separate `8191`
  (`report/verify.py:144`) — four copies of one constant is its own defect.
- DB growth: ~864 bodies/day × ~20-38 KB ≈ 20-30 MB/day worst case, against a
  342 MB chain after 30 days. Real but manageable; nhoward's call on whether
  that rate is acceptable for this lab.
- Not draft material (the cap is daemon-local, not wire format — the 64 KiB
  frame already is the wire limit), but it is a daemon change requiring a
  restart, so it lands with the same deployment as the format window or earlier
  at nhoward's discretion. Bodies past the raised cap still need the
  NOT-RETAINED state — the cap move shrinks the population, the label fixes its
  honesty.

## 6. Interaction with Phase 3 (collector-side credential filtering)

The Phase 3 filter (implemented this session) removes credential fields **before
hashing**, so the commitment is over the filtered bytes and the entry verifies
end-to-end with no format change. The filtering is recorded *inside the body
itself* (a `_virp_filtered` annotation naming the removed keys), which travels
under the existing hash — no canonical change needed, no ruling needed. If a
chained, body-external declaration of filtering is ever wanted (e.g. so a reader
can see "filtered" without parsing the body), that is the reserved
`body_retention='filtered'` value in Option B, and it should ride the same
format window. Nothing in Phase 3 blocks on this proposal.

## 7. Decision requested

1. Approve Option B (canonical `body_retention` field, version-gated canonical
   build, verifier-first deployment order) for the draft-07 / format-change
   window — or direct Option D / another shape.
2. Rule on the size-cap raise (§5): raise to 60 KiB, keep 8 KiB, or another
   value.
3. Confirm the 2,211 legacy entries keep their UNVERIFIABLE/truncated grading
   and the report language in §4, and are never re-labeled.
