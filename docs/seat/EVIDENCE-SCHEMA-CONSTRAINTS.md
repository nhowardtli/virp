# Constraints on a seat-appended `evidence_item` body

Status: **draft for redline.** Written 2026-09-07 so a seat operator's schema
proposal has something concrete to argue with. Nothing here is enforced by the
daemon yet; where a rule is already enforced somewhere else that is said
explicitly. Numbers are proposals with reasons, not decisions.

Audience: anyone appending `evidence_item` through a seat — today uid 987 —
and whoever reviews their schema.

## 0. What a seat is, so the constraints read as consequences

A seat is an identity with no device reach. It may verify the chain and append
one artifact type. It cannot execute, cannot list the fleet, and cannot read a
device. Everything it appends is therefore a claim it makes about **its own
work**, never an observation the node made.

That distinction drives every rule below. A record the node minted is signed
over something the node saw. A record a seat appends is signed over something
the seat said. Both sit in the same chain, so the seat's bodies must be shaped
so nobody can later read one as the former.

## 1. The body is JSON, and it is an object

A single JSON object, UTF-8, no BOM, no trailing newline significance.

Not a bare array, not a scalar, not JSON-in-a-string. A reader must be able to
find a field by name without first guessing a shape, and every rule below is
expressed as a constraint on named fields.

## 2. Two required fields name the schema

    {
      "schema": "seat.evidence.<name>/<major>",
      "produced_at": "2026-09-07T16:04:57Z",
      ...
    }

* **`schema`** — a versioned name, `<namespace>.<name>/<major>`. Required in
  every body, including the first. A body without one is unreadable in two
  years and unreviewable today, because "what fields does this have" has no
  answer that survives the next change.
* **`produced_at`** — RFC 3339, UTC, `Z` suffix, second precision or finer.
  This is when the seat produced the claim, which is not when the chain
  accepted it. Both are useful and they are not the same instant.

`<major>` moves when a field changes meaning or is removed. Adding an optional
field does not move it. This is the ordinary compatibility contract and it is
stated so a reviewer can hold a proposal to it.

## 3. Hashes and manifests, not payloads

**The body carries references to evidence, not the evidence.**

Allowed shapes:

    "artifacts": [
      {"path": "run/2026-09-07/output.bin",
       "sha256": "e3b0c442...",
       "bytes": 1048576}
    ]
    "inputs":  [{"sha256": "..."}, ...]
    "counts":  {"processed": 311, "failed": 0}
    "verdict": "PASS"            (from a closed set the schema names)

Not allowed: file contents, log excerpts, command output, stack traces,
base64 blobs, screenshots, or any field whose value is "what happened, in
prose". If the evidence is a file, the body names its hash and where it lives.

Three reasons, in order of how much they cost when ignored:

1. **A hash is checkable and prose is not.** The point of the chain is that a
   reader can re-derive a claim. `sha256` of a named artifact can be
   recomputed years later; "the run completed successfully" cannot.
2. **Prose is where secrets leak.** Every credential incident in this estate
   came through a free-text field carrying something nobody intended — a
   config dump, an error message with a token in it. A schema with no
   free-text field has no such surface.
3. **Bodies are permanent.** The chain is append-only by design. A body that
   should not have been written cannot be withdrawn, only annotated.

## 4. No free-text fields

No `notes`, `description`, `message`, `comment`, `reason`, `detail`, `error`.

Where a human-meaningful outcome is genuinely needed, it is an enum the schema
declares — `"verdict": "PASS" | "FAIL" | "INCONCLUSIVE"` — and the detail
behind it is an artifact hash. An enum is checkable, greppable, and cannot
carry a token.

**The one carve-out**, and it should be argued for rather than assumed: a
`correlation_id` matching `^[A-Za-z0-9_.:-]{1,64}$`. Bounded, no whitespace,
no free-form punctuation. It exists so a seat can tie a record to its own
run without inventing a session namespace, and its character class is narrow
enough that it cannot become a prose field by degrees.

## 5. Size cap: **8 KiB** for the stored body

Proposed, with the reasoning, because this one is a real trade and a reviewer
should be able to push back on it.

* **8 KiB is where the daemon already changes behaviour.** Bodies at or above
  roughly that size are handled commitment-only elsewhere in this system — the
  hash is chained and the body is not stored. Setting the seat's cap at the
  same line means a seat never silently crosses into a different storage mode
  and gets a record that grades differently from the one it thinks it wrote.
* **A conforming body cannot approach it.** A schema name, a timestamp, a
  correlation id and a few dozen `{path, sha256, bytes}` entries is a few
  hundred bytes to low single-digit KiB. A body pressing on 8 KiB is evidence
  that something is being inlined that rule 3 says should be a hash — so the
  cap doubles as a smell test for the rule above it.
* **The chain is shared and permanent.** `.211`'s chain is already ~350k
  entries; per-entry cost is paid by every future verify, and a full-chain
  verify on that node does not currently complete in a useful window. A seat
  is not entitled to spend that budget on inlined data.

If a seat genuinely needs to record more, it records a **manifest**: one body
listing hashes, with the bulk stored outside the chain and fetched by hash.

Over the cap the append is rejected. It is not truncated — a truncated body
whose `sha256` no longer matches its content is worse than no body.

## 6. The scrubber runs regardless

Every body passes the same scrubbing path as any other artifact, and **that is
not negotiable by schema design.** A seat cannot opt out by declaring its
fields safe, and a body that scrubs clean today still scrubs tomorrow.

Read this the right way round: the scrubber is a backstop, not a licence. It
is the reason a mistake is survivable, not a reason to relax rules 3 and 4.
A schema that relies on the scrubber to stay clean has the dependency
backwards.

## 7. Identity and correlation

* The **appending identity is the uid**, established by `SO_PEERCRED` at the
  socket. A body must not restate who wrote it; a self-declared `author` field
  is unverifiable and invites disagreement with the uid that actually appended.
* `session_id` is **not** part of the body. It is a wire field, and for a seat
  it is namespace-constrained (see the seat README).
* `correlation_id` inside the body is how a seat groups its own records. It is
  the seat's own string and carries no authority.

## 8. What a reviewer should check, in order

1. Is there a `schema` field, and does it carry a major version?
2. Does any field hold content rather than a reference to content?
3. Is there any field that could hold a sentence?
4. What is this body's size at p99, not at its example?
5. If every field were public, what would be lost? (They are effectively
   public: the chain is shared and permanent.)
6. Does anything in the body assert identity, authority or a verdict the seat
   is not in a position to know?

## 9. Open, deliberately

* Whether `verdict` belongs in a seat body at all, or whether a seat should
  only ever record *what it did* and leave grading to a reader.
* Whether `artifacts[].path` should be constrained to a namespace the way
  `session_id` now is — a path is a weak free-text field wearing a name.
* Whether the 8 KiB cap should be enforced at the daemon for seat uids
  specifically, rather than left to schema review.
