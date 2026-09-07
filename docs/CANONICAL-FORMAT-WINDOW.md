# The canonical-format window

The object that is SHA-256'd and HMAC'd per chain entry
(`build_canonical_json` in `src/virp_chain.c`, mirrored in
`report/verify.py:canonical_json` and in the Go verifier) is FROZEN.
Adding, removing, renaming or reordering a field in it changes the
canonical bytes of every entry ever written and breaks re-verification of
the whole corpus: 55,245 entries as of 2026-08-09 on .211, and it grows
every five-minute cycle.

Several things genuinely need such a change. They are collected here so
they land TOGETHER, once, in a deliberate window with a
chain-format-version bump and a migration that reads the old width, and
so that nothing gets bolted on during an unrelated fix.

Nothing on this list may be implemented outside the window. Anything that
can be done without touching the canonical form is not on this list.

## 1. Provenance / `peer_uid` on external appends

An externally submitted entry does not record WHICH socket principal
submitted it. The daemon knows the peer uid at append time and cannot
commit to it. Tracked in `SECURITY.md`.

## 2. `commitment_mode`

A commitment-only append (no `artifact_content`) and a body-bearing
append are indistinguishable inside the canonical object, so GATE 2 and
GATE 3 are skipped as a side effect of an empty field rather than by
decision, and a client can cite any 64-hex string as an unsigned
observation. The indirect types (`comparator_verdict`,
`chainwalk_summary`) commit to a signed observation the chain does not
retain, which the verifier can only special-case by name. An explicit
`commitment_mode` inside the canonical object states the intent.
Tracked in `docs/HASH-BOUNDARY.md` §2.

## 3. Registry digest in the signed approval payload

A typed-op approval does not bind the driver/registry VERSION, so an
approval can survive a table change that alters what an op id means.
Tracked at `src/virp_onode.c` (`onode_typed_profile` TODO).

## 4. Asymmetric-signing migration / verifying-key identity

Which key verified an entry is recoverable only by partitioning entries
by trial verification. Recording it means a new field inside the HMAC'd
object. Tracked in `SECURITY.md`, "the alternative is a chain-format
change".

## 5. `artifact_type[16]` (HAM review, 2026-09-06, item 11)

**The problem.** `artifact_type` is `char[16]` — fifteen usable
characters — in `include/virp_chain.h`, `src/virp_onode.c` and the
canonical object. That width is now shaping the vocabulary instead of
carrying it:

- `comparator_verdict` (18) and `chainwalk_summary` (17) reach the daemon
  TRUNCATED, as `comparator_verd` and `chainwalk_summa`. Both spellings
  are listed in `virp_chain_type_is_indirect()` so the predicate is
  correct wherever it is called from, and `report/verify.py` carries the
  same pair. The truncated forms are what production actually stores.
- The federation types were deliberately kept at or under 15 characters
  (`fed_observation`, `federated_request`… note the second one does NOT
  fit and rides as `evidence_item` instead) so they would "survive
  `artifact_type[16]` intact". A width limit is choosing type names.
- The -07 text names `authorization_decision` (22) and
  `device_accounting` (17). Neither can be a first-class artifact type
  today.
- TACACS+ evidence therefore hides under `evidence_item` with the real
  type in a `schema` field inside the body. That works, and it means the
  chain's own type column does not say what the entry is; only the body
  does, and the body is not in the canonical object.

**Do not add more abbreviations.** Every one of them is a place where the
chain's type column and the thing's actual name disagree, and each is a
special case some future verifier has to know by heart.

**Proposed shape.** Two options, to be decided in the window:

- *(a) Variable-length type with a registry.* `artifact_type` becomes a
  length-prefixed string in the canonical object, bounded (64 bytes is
  ample), with a registry of known types in one place that the daemon,
  both verifiers and Docket read. Truncation stops existing; an
  over-length type is REJECTED (see item 10 of the same review), which is
  the rule the rest of the ingress already follows.
- *(b) Type + schema promoted to first class.* Keep a bounded `type` for
  the coarse class the daemon enforces policy on (`observation`,
  `evidence_item`, …) and add `schema` to the canonical object as a
  second, wider field, so `evidence_item` + `tacacs_accounting/2` is one
  addressable thing rather than a type plus a body convention.

(b) is the smaller change to the daemon's policy code, which keys on the
coarse type today, and it makes the existing `schema`-in-body convention
honest. (a) is cleaner to explain. Either way the `_verd` / `_summa`
aliases become historical spellings that the migration must keep
verifying, never rewrite.

**Compatibility approach.** Chain-format-version bump. The verifier reads
the OLD fixed-width form for every entry written under the old version
and the new form after it, selecting on the version, exactly as the
signed/unsigned era distinction is now selected per session (see
`docs/VERIFIER-SEMANTICS.md`). No entry is ever rewritten. The truncated
aliases stay in the indirect-type list forever, because the entries that
carry them are permanent.

**-08 reconciliation.** The draft has to say which of (a) or (b) is
normative, name the registry or the second field, and state that the
pre-window fixed-width form remains verifiable. Until then, `-07`'s
`authorization_decision` and `device_accounting` are names the
implementation cannot spell, and that gap should be stated in the draft
rather than papered over with another abbreviation.
