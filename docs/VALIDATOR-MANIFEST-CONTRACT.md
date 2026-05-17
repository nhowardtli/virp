# Validator Manifest Contract

Author: Third Level IT
Last revised: 2026-04-23
Status: locked — changes require re-review of `src/virp_validator.c`

This document specifies the **AI-layer obligation** that makes the CT 211
response validator's trust boundary actually work. It is a policy
document. The code that enforces these rules lives in
`src/virp_validator.c` and is wired into the O-Node at
`ONODE_ACTION_VALIDATE_TURN` (= 13).

---

## 1. Why there is a manifest

The AI layer on CT 210 emits prose that cites device state. Without a
per-turn, structured sidecar, the validator on CT 211 has no way to
distinguish

  > "BGP peer 10.0.0.1 is established (we just ran `show ip bgp summary`)"

from

  > "BGP peer 10.0.0.1 is established" (fabricated, no tool call)

The manifest is that sidecar. It is the AI layer making a promise, in
structured form, about what its prose is claiming — and the validator
on CT 211 checks that promise against chain.db and the prose bytes.

The entire scheme relies on one fact: **CT 210 cannot write chain.db
and cannot forge an artifact_hash**. That is the structural trust
boundary. The manifest is how CT 210 points at chain.db entries that
back its prose; the validator on CT 211 verifies the pointers.

---

## 2. When a manifest is required

Every response turn emitted by the AI layer to a human must be
accompanied by a manifest. There is no "trivial turn" exemption. A
turn with zero device-state claims emits a manifest with
`assertions: []`; an empty list is legal and evaluates to PASS
provided the prose_hash matches.

A turn with device-state claims but no manifest, or an unparseable
manifest, **is not fail-open**. The validator will commit a BLOCK
with `turn_violation = MANIFEST_MISSING` or `MANIFEST_MALFORMED` to
chain.db and return the signed decision. There is no path where the
prose is delivered without an entry in chain.db.

---

## 3. Manifest JSON schema

```jsonc
{
  "session_id":   "<string, [A-Za-z0-9._-]{1..63}>",
  "prose_hash":   "<64 lowercase hex chars, SHA-256 of the exact prose bytes>",
  "tool_call_refs": [
    "<64 lowercase hex char SHA-256 of an artifact this turn produced>",
    // ... up to VALIDATOR_MAX_TOOL_CALL_REFS (64) entries
  ],
  "assertions": [
    {
      "device":       "<string, [A-Za-z0-9._-]{1..63}>",
      "claim_type":   "state_read" | "state_change" | "config_change",
      "evidence_ref": "<64-hex>" | null
    }
    // ... up to VALIDATOR_MAX_ASSERTIONS (32) entries
  ]
}
```

### Field-by-field

- **`session_id`** — the turn's session identifier, matching what the
  O-Node uses for chain.db entries this turn. Must satisfy the token
  regex; non-ASCII or punctuation beyond `._-` is rejected.

- **`prose_hash`** — SHA-256 of the exact byte sequence the AI layer
  intends to emit to the user, *as UTF-8*. If the prose changes by
  even a trailing newline after the manifest is sent, validation
  fails with `PROSE_HASH_MISMATCH`. The hash is lowercase hex, no
  prefix.

- **`tool_call_refs`** — the set of artifact_hash values for tools this
  turn produced (executions, lookups, etc. — every call whose result
  the O-Node committed to chain.db). Up to 64. A hash an assertion
  cites via `evidence_ref` must appear here AND in chain.db for
  `session_id`. The `tool_call_refs` is the AI layer's declaration of
  what it used; the chain check is the independent verification.

- **`assertions[].device`** — target device the claim is about. Must
  satisfy the token regex. VIRP device identifiers already do; if
  your naming scheme uses `:` or `/`, the parser will reject the
  assertion. Don't work around this by renaming — flag it so the
  validator's token policy is revised.

- **`assertions[].claim_type`** — one of three literal strings.
  Anything else parses successfully to `UNKNOWN` and is evaluated as
  BLOCK. The three legal values and their evidence semantics:

  | claim_type      | no evidence | evidence present |
  |-----------------|-------------|-------------------|
  | `state_read`    | WARN        | chain + turn check |
  | `state_change`  | **BLOCK**   | chain + turn check |
  | `config_change` | **BLOCK**   | chain + turn check |

  `state_read` is the lenient default for "I am reporting current
  device state." `state_change` is any claim about a runtime event
  (adjacency flap, interface toggle, route withdrawal). `config_change`
  is any claim about configuration having been modified.

- **`assertions[].evidence_ref`** — either a 64-lowercase-hex
  SHA-256, or JSON `null`. A missing key is accepted as equivalent to
  `null` for forward-compatibility, but **the AI layer MUST emit
  `null` explicitly** — this prevents a bug in the AI layer's
  serialization from silently dropping the field and landing in WARN
  instead of being visibly missing.

---

## 4. The four rules the AI layer must obey

These are policy on the CT 210 side. The validator enforces them on
the CT 211 side; violations land in chain.db and on the response
banner.

1. **Every device-state claim in prose has an assertion.** If the
   prose says "BGP peer up on r1" the manifest has one assertion with
   `device: "r1"`, `claim_type: "state_read"`. If the prose makes
   three claims, the manifest has three assertions.

2. **Every assertion has an explicit `evidence_ref`.** Either a
   64-hex pointing to an artifact_hash produced by this turn, or
   `null`. Omitting the field is not the same as `null`: although the
   parser tolerates it for forward compatibility, the AI layer should
   never rely on that tolerance.

3. **`prose_hash` is computed over the exact bytes that will be
   delivered.** No trailing whitespace normalization, no Unicode
   folding, no late mutation. Compute it on the final buffer, right
   before handing the tuple (prose, manifest) to the validator
   client.

4. **A missing manifest is never OK.** If the AI layer decides mid-
   turn that it has no claims to make, it still emits a manifest
   with `assertions: []`. The only way to skip the validator is to
   skip emitting the turn.

---

## 5. Fail-closed enumeration

The validator's decision precedence is BLOCK > WARN > PASS. The
turn rolls up to the strongest decision seen across assertions and
any turn-wide violation. Below is the complete list of situations
that fail-close to BLOCK:

| Condition | `turn_violation` / per-assertion violation |
|-----------|---------------------------------------------|
| Manifest missing (no `manifest` key, or empty) | `MANIFEST_MISSING` |
| Manifest unparseable JSON | `MANIFEST_MALFORMED` |
| Manifest exceeds 32 assertions or 64 tool_call_refs | `MANIFEST_TOO_LARGE` |
| Manifest structurally invalid (non-hex hash, non-string device, etc.) | `MANIFEST_MALFORMED` |
| `SHA-256(prose) != prose_hash` | `PROSE_HASH_MISMATCH` |
| claim_type not in the three legal strings | `UNKNOWN_CLAIM_TYPE` |
| `state_change` or `config_change` with `evidence_ref: null` | `NO_EVIDENCE_STATE_CHANGE` |
| `evidence_ref` not present in `tool_call_refs` | `EVIDENCE_NOT_IN_TURN` |
| `evidence_ref` in `tool_call_refs` but not in chain.db for this session | `EVIDENCE_NOT_IN_CHAIN` |

WARN is reserved for exactly one case:

| Condition | violation |
|-----------|-----------|
| `state_read` with `evidence_ref: null` | `NO_EVIDENCE_STATE_READ` |

This is the only soft outcome. Everything else is either PASS or BLOCK.

---

## 6. Response format (what the client receives)

The O-Node returns a signed VIRP OBSERVATION (`obs_type =
VIRP_OBS_VALIDATION_DECISION = 0x10`) whose payload is UTF-8 JSON:

```json
{
  "decision": "pass" | "warn" | "block",
  "turn_violation": 0,
  "turn_error_class":      "none|format|schema|provenance|content",
  "turn_remediation_hint": "none|regenerate_manifest|report_schema_gap|rerun_with_tools|fabrication_detected",
  "chain_sequence": 42,
  "chain_entry_hash": "<64-hex>",
  "artifact_hash":    "<64-hex>",
  "assertions": [
    {"decision": "pass", "violation": 0,
     "error_class": "none", "remediation_hint": "none"},
    {"decision": "warn", "violation": 1,
     "error_class": "provenance", "remediation_hint": "rerun_with_tools"}
  ]
}
```

- The outer observation is signed by the O-Key. CT 210 can verify
  using the same bridge used for any other O-Node response; without
  a bridge, CT 210 still has chain.db as the durable tamper-evident
  record.

- On BLOCK, `attach_banner` returns banner-only. Prose is suppressed by
  the library. Callers that need to surface blocked prose for audit or
  debugging must explicitly opt in with `allow_blocked_prose=True`.
  Fail-closed is the default.

- `chain_sequence` and `chain_entry_hash` point at the row the
  validator just wrote under `artifact_type = "validation"`. An
  auditor can replay the chain and reproduce the decision from
  `artifact_hash`, which is SHA-256 of the canonical decision JSON.

- `turn_violation == 0` means the rollup was not triggered by a
  turn-wide issue (prose hash, manifest missing/malformed). If the
  rollup is BLOCK but `turn_violation == 0`, the cause is the
  first per-assertion BLOCK — the banner helper in
  `api/validator/__init__.py` does this fallback.

### 6.1 Error class and remediation hint (Phase 2)

Every non-PASS verdict carries two structured tokens that route the
model's response: `error_class` is the category, `remediation_hint`
is what the model should do. The mapping is a pure function of the
violation code:

| Violation                       | error_class    | remediation_hint        |
|---------------------------------|----------------|--------------------------|
| `NONE`                          | `none`         | `none`                   |
| `NO_EVIDENCE_STATE_READ`        | `provenance`   | `rerun_with_tools`       |
| `NO_EVIDENCE_STATE_CHANGE`      | `provenance`   | `rerun_with_tools`       |
| `EVIDENCE_NOT_IN_TURN`          | `provenance`   | `rerun_with_tools`       |
| `EVIDENCE_NOT_IN_CHAIN`         | `content`      | `fabrication_detected`   |
| `UNKNOWN_CLAIM_TYPE`            | `schema`       | `report_schema_gap`      |
| `PROSE_HASH_MISMATCH`           | `content`      | `fabrication_detected`   |
| `MANIFEST_MALFORMED`            | `format`       | `regenerate_manifest`    |
| `MANIFEST_TOO_LARGE`            | `format`       | `regenerate_manifest`    |
| `MANIFEST_MISSING`              | `provenance`   | `rerun_with_tools`       |

**How a well-aligned model should route each class:**

- `format` → the validator could not parse the manifest. Regenerate
  the manifest. **Do not** apologize for fabricating prose; this is
  a structural input failure, not a content failure.
- `schema` → the validator does not recognize a claim_type the model
  emitted. This is a known protocol gap. Report it; **do not**
  self-correct prose.
- `provenance` → evidence is missing or not from this turn. The
  remediation is to rerun the tool that should have produced the
  evidence and reattach the resulting artifact_hash. **Do not**
  apologize for fabrication; the prose may be substantively correct
  but is unverifiable as emitted.
- `content` → the prose either contradicts chain.db (the cited
  evidence does not exist for this session) or the declared
  prose_hash does not match the bytes actually emitted. This is the
  only class that warrants self-correction. Investigate whether the
  prose was fabricated, then either correct or withdraw it.

The false-confession failure mode the typed surface guards against:
a model that reads a `format` or `schema` BLOCK as a `content` BLOCK
and self-attributes fabrication that did not occur. The
`remediation_hint` token is the canonical signal — if the hint is
not `fabrication_detected`, the model should not apologize for
fabricating.

### 6.2 Persistence (Phase 2)

Every validation commit now writes both a `chain_entries` row
(`artifact_type = "validation"`, as before) **and** an `artifacts`
row holding the canonical decision JSON as `artifact_content`. The
two rows share `artifact_id = "val-<first-16-hex-of-hash>"`.

This enables post-hoc forensic comparison: a future auditor with
chain.db can read what the validator *actually said*, not just its
hash. Prior to Phase 2, the `artifacts` table contained 0 validation
rows; the validator's verdict bodies were unrecoverable. The Phase 2
behavior is additive — the chain header is still the canonical
record, and the artifact write is best-effort (a failure to persist
the body logs a warning on the daemon's stderr but does not fail
the validate_turn call).

### 6.3 Backward compatibility

The wire format change is additive. A pre-Phase-2 CT 210 client
that reads only the original fields (`decision`, `turn_violation`,
`chain_sequence`, `chain_entry_hash`, `artifact_hash`, and the
per-assertion `decision` + `violation`) continues to work — the new
fields are silently dropped. A Phase-2-aware client receives the
typed surface.

The Python client in `api/validator/__init__.py` provides
`violation_class()` and `violation_hint()` helpers that derive
class/hint from violation code, so a client talking to an older
onode (where the wire doesn't carry the new fields) can still
populate `ValidationResult.turn_error_class` and
`turn_remediation_hint` from the violation. Forward-compat: the
client uses `.get()` accessors on the new fields and falls back to
the derivation helpers when absent.

---

## 7. Non-goals (explicit)

- **The validator does not parse prose beyond re-hashing it.** No
  regex matching, no NER, no semantic analysis. The AI layer's
  structured assertion list is the only input the validator uses to
  reason about content.

- **The validator is not a replacement for the CT 210 Observation
  Gate.** Pass 1 (device reference check) and Pass 2 (content
  fidelity) on CT 210 continue to run. The validator is an
  out-of-band second check with a different — and stronger — trust
  boundary.

- **The validator does not store prose.** Only `prose_hash` lands in
  chain.db. The prose bytes themselves are logged on CT 210 only; the
  hash is the pointer across the boundary.

- **The validator does not introduce a second chain key.** Decisions
  are committed using the existing `K_chain`, as
  `artifact_type = "validation"`. No new table.

---

## 8. References

- Library implementation: `src/virp_validator.c`, `include/virp_validator.h`
- Unit tests: `tests/test_validator.c` — real chain.db, no mocks
- O-Node dispatcher: `ONODE_ACTION_VALIDATE_TURN` case in `src/virp_onode.c`
- Client: `api/validator/__init__.py`
- Chain schema: `src/virp_chain.c` (`chain_entries` CREATE TABLE)
