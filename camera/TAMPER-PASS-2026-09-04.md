# Two-point tamper pass — axis-20260904-v5, 2026-09-04

What a byte flip in a *referenced* artifact costs an examiner, measured
rather than reasoned about. Two tamper points, two tools, on copies:
`virp-verify --pin --producer-key` over the bundle, and
`virp_camera.py audit --pubkey` over the chain DB.

This note records the state **as found**, before any fix. Findings 1–3
are what the three commits after it address; finding 4 is left for a
`/6` session because it grows a signed object.

Nothing in the lab was written. The original bundle, the outbox and the
spool on 313 were verified unchanged by digest afterwards.

## Method

Three copies, each a bundle + the camera outbox + the chain DB, in a
scratch directory:

| copy | flip | where |
|---|---|---|
| A | 1 byte in the seq-24 segment mp4, offset 74291, `0x85`→`0x84` | outbox |
| B | 1 byte in the seq-26 `validation_results.txt`, `invalid GOPs: 0`→`1` | outbox |
| C | *(control)* 1 byte in the **carried body** for seq-24, `"gops_valid":5`→`6` | bundle + DB |

Both tamper points sit on `camera_segment/5` records, on two different
records, so a hit on one could not be a hit on the other. C exists so a
negative result on A and B cannot be a broken harness: it flips
something both tools genuinely cover.

## What the `/5` record body commits to by hash

Taking seq 24 (`artifacts/d489b652…`) as the exemplar, each digest
verified against the real file before anything was touched:

| field | digest over | artifact | checked |
|---|---|---|---|
| `segment_sha256` | segment mp4 bytes | `…000024.….mp4` | matches |
| `prev_segment_sha256` | previous segment's mp4 bytes | seq 23's mp4 | continuity |
| `byte_len` | *(length, not a digest)* | same mp4 — 148582 | matches |
| `sensor_signature.validator_output_sha256` | raw bytes of `validation_results.txt` | `…000024.….validation.txt` | matches |
| `sensor_signature.sensor_key_sha256` | PEM text of the key **extracted from the stream**, not `sensor_pubkey.pem` on disk | the sensor leaf public key | — |
| `sensor_signature.device_chain.anchor_sha256` | pinned CA file bytes | `trust/axis-edge-vault-attestation-ca.pem` | matches |

The body is then covered by `producer_sig`, its bytes by the entry's
`artifact_hash`, and that by `chain_entry_hash` → `chain_hmac` → the
Ed25519 entry and head signatures.

**The bundle carries none of those artifacts.** `axis-20260904-v5`'s
`artifacts/` holds nine files of 1.3–1.6 KB: the record bodies, and
nothing else. Every mp4 and every `validation_results.txt` lives only in
the capture host's outbox. A bundle is a chain of records about video,
not video.

## Results

| copy | tamper point | tool | property | verdict |
|---|---|---|---|---|
| — | none (baseline) | virp-verify | `artifact_binding` VERIFIED, `producer_signature` VERIFIED | CRYPTOGRAPHICALLY-VERIFIED (exit 0) |
| — | none (baseline) | audit | INTEGRITY | OK (exit 0) |
| **A** | seq-24 mp4 | virp-verify | **none — no property changed** | CRYPTOGRAPHICALLY-VERIFIED (exit 0), **not caught** |
| **A** | seq-24 mp4 | audit | **none — no property changed** | INTEGRITY OK (exit 0), **not caught** |
| **B** | seq-26 validation output | virp-verify | **none — no property changed** | CRYPTOGRAPHICALLY-VERIFIED (exit 0), **not caught** |
| **B** | seq-26 validation output | audit | **none — no property changed** | INTEGRITY OK (exit 0), **not caught** |
| C | carried body | virp-verify | `artifact_binding` FAILED, `producer_signature` FAILED, `producer_trust` MISMATCH | FAILED (exit 1) |
| C | carried body | audit | body hash ≠ `artifact_hash`, prev-chain break (3 failures) | INTEGRITY FAILED (exit 1) |

For A and B the output is byte-identical to the untampered run. Not
"the same verdict" — the same bytes. Nothing was examined.

The requirement the pass was run against was that the two points fail
DIFFERENT properties. They failed none. "Neither tool reports a stronger
verdict than the untampered run" holds only vacuously.

## Finding 1 — the mp4 is referenced, carried nowhere, recomputed by neither tool

`segment_sha256` binds it. `virp-verify` says so itself, in its own
epilogue: *"segment_sha256 is a reference this tool does not
recompute."* `audit` has the DB and never opens a file.

One command does read an mp4, and it caught the flip cleanly:
`verify-segment` returned `NO MATCH` / exit 1 on the tampered file and
`MATCH` / exit 0 on an untampered neighbour. It is not one of the two
tools in the pass, and it takes one file at a time.

## Finding 2 — the validator output is recomputed by nothing at all

Worse than finding 1, and it is worth being exact about why.

`validator_output_sha256` is written at build time
(`virp_camera.py:1066,1075`) and read back nowhere. On the Rust side it
appears only as a field *name* in the shape check
(`docket-bundle/src/camera.rs:77`), never as a digest to verify.

`verify-segment` gives no coverage either: it compares the file against
`segment_sha256` only. A `validation_results.txt` therefore reads
`NO MATCH` whether it was tampered with or not — confirmed by running
the untampered file through it and getting the same verdict. The answer
carries zero signal, which is worse than no answer, because it has the
shape of one.

The binding field already exists in the record. What is missing is
carriage and a checker — not a schema change.

## Finding 3 — `_body_policy` omits `SCHEMA_V5`

Surfaced by the baseline, unrelated to either tamper point.

`_body_policy` (`virp_camera.py:1831`) tests
`schema not in (SCHEMA_V2, SCHEMA_V3, SCHEMA_V4)`. `SCHEMA_V5` is not in
the tuple, so every `/5` record is graded as carrying no capture policy,
and audit reports:

```
COVERAGE: UNDECLARED
  axis-m3085v-b8a44fdd572c UNDECLARED  4 of 9 records declare no capture policy (camera_segment/1)
```

All four carry a valid `capture_policy`. The message also misattributes
them to `camera_segment/1`, which is the only schema that legitimately
has none.

`virp-verify` grades the same nine records `INTERRUPTED / ACCOUNTED`.
The two tools disagree about coverage on `/5`, and the one that reads
the producer's own records is the one that is wrong. The same
hand-typed tuple appears a second time at line 1707, where a `/5` body
with a *broken* policy would go unflagged for the same reason.

A version bump has to be adding a row to one table, not remembering
every tuple that needs a new member.

## Finding 4 — the device leaf certificate is bound by nothing

`device_chain` carries `anchor`, `anchor_sha256`,
`chain_to_anchor_verified`, `leaf_serial_matches_device`,
`leaf_not_after`: four assertions and one digest, and the digest is of
the **anchor**, not the leaf. The leaf's public key is bound indirectly
through `sensor_key_sha256`. The certificate itself — serial, notAfter,
issuer — is bound by no digest at all, so the three booleans about it
cannot be re-derived by a later reader from anything the record carries.

The field that would close it is `device_chain.leaf_sha256`. Adding it
grows `sensor_signature`, and growing that object is a version bump by
the rule `/4` and `/5` were each created under. Left for a `/6`
session; recorded here so it is not rediscovered.

> **Closed at `camera_segment/6`.** `device_chain.leaf_sha256`, over the
> leaf's DER. The bump turned out to be invisible at the level the field-set
> rule was written for: `/5` and `/6` carry the same sixteen
> `sensor_signature` keys, so `device_chain` had to be field-checked at its
> own version — on both sides — or a `/5` object would have validated as a
> `/6` and a `/6` as a `/5`. Nothing had ever checked that object's shape.
> Findings 1–3 were closed in the three commits after this note; this
> paragraph is the only edit it has taken, and the findings above stand as
> written.

## What this pass proves, and what it does not

It proves that a byte flip in the video a `/5` record was written about
survives both tools with a clean verdict, today. It does not prove the
records are wrong: every signature, hash and link in the bundle is
sound, and the control shows both tools detect body tampering the
moment it happens.

The gap is one of *reach*, not of soundness. The chain says what the
producer signed. It has never said the file on disk is still the file
that was signed about — and until finding 1 and finding 2 are closed,
no tool an examiner is likely to run says it either.

## Addendum 2 — finding 2 recurred twice, and the test that could not see it

Written 2026-09-04 evening, after taking `/6` through the real path for
the first time. The `/5` bundle above was assembled from a capture-host
outbox. Nothing had ever pointed `--artifact-dir` at an O-node.

The first live `/6` session put six records on the real chain and then
`audit --artifact-dir` on 313 read **SEGMENT PAYLOAD: ABSENT** for every
one of them. Not a grading bug. The files were not there.

| artifact | cited by | written | shipped | checkable at the O-node |
|---|---|---|---|---|
| segment mp4 | `segment_sha256` | yes | yes | yes |
| validator output | `validator_output_sha256` | yes, capture host only | **no** | **no** |
| leaf certificate | `device_chain.leaf_sha256` | **no** | **no** | **no** |

Both are finding 2 again: *a digest inside a signed record whose preimage
does not travel*. The validator output was written beside the segment and
`ship()` sent only the segment and the body. The leaf was never written
at all — `/6` added the digest and dropped the bytes it was taken over,
which means the commit that introduced `leaf_sha256` reproduced, on the
same day, the defect this note was written about.

A hash whose preimage is unobtainable is an assertion, not a commitment.
It has the *shape* of something checkable, which is the property that
makes it worse than saying nothing — the same reason `verify-segment`'s
old `NO MATCH` on a validation output was worse than no answer.

### The test gap

Every SEGMENT PAYLOAD test built a capture-host **outbox** — a directory
the driver had just written every file into, complete by construction.
The suite asked "does the axis grade a complete directory correctly?"
and never "what does it do when a file did not arrive?"

The **spool** is the directory an examiner actually points
`--artifact-dir` at, and it was never constructed in a test. So the axis
was only ever exercised where it could not fail, and the two artifacts
that never shipped were invisible to 251 passing tests.

The existing test `test_the_raw_validator_output_is_kept_beside_the_segment`
passed throughout and always would have. It asserted the file was
*written*. The claim that was wrong is that it *ships*, and nothing
asserted that, because on a laptop the two are indistinguishable.

Closed by three tests that build a spool layout with a file removed: a
complete spool VERIFIES, a spool missing the validator output grades
ABSENT on that field alone with nothing FAILED, and a spool missing the
segment grades ABSENT on that one. Plus one asserting the validator
output is handed to `ship()`, not merely written.

### What the leaf turned out to be

Not per-record. One certificate signs every segment the device emits, so
the bundle carries it **once** and eleven `/6` records cite the same
digest. Flipping one byte in the carried leaf DER fails all eleven, not
one — every record that commits to that digest is a record whose
commitment no longer holds. Correct, and worth knowing before designing a
per-record expectation around it.
