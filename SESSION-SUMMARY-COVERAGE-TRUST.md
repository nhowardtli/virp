# Camera driver — trust-root fail-closed, capture coverage, content reuse

Branch `feat/coverage-and-trust`, off `feat/camera-driver` @ `4ee5950`.
Not merged, not pushed. Work done on 313 (virp-onode-home, 10.0.0.13).

Scope discipline held: the driver holds no VIRP key and is not compiled
into the daemon; nothing here touched the D-1 signing binary or 313's
burn-in. No `submit-spool` run, no chain append, chain DB opened
read-only only (`file:…?mode=ro`), `/var/spool/virp-capture` untouched
(7642 paths, mtime+size manifest unchanged). No producer secret was
read, printed or copied.

Files: `camera/virp_camera.py` (+672/−45),
`tests/test_camera_trust_and_coverage.py` (new, 61 tests),
`tests/fixtures/camera_aug24_tapo_a2d2dc.json`,
`tests/fixtures/camera_aug24_duplicate_pairs.json`.
All four camera suites green: 17 + 10 + 23 + 61 = 111 tests.

---

## Item 1 — trust-root fail-closed

### What the tip actually did (this contradicts the prompt — read this)

The prompt states that `audit --pubkey <path>` "reports SUCCESS when the
path does not exist … printed zero failures and gave a clean verdict."
**At `4ee5950` it does not.** Measured against the live 2553-record
corpus, on both the committed tip and the byte-identical deployed copy
preserved at `/tmp/virp_camera.py`:

| prerequisite failure | before (4ee5950) | after |
|---|---|---|
| missing pubkey file | exit **1**, unhandled `FileNotFoundError` traceback | exit **2**, `TRUST ROOT NOT ESTABLISHED: cannot read trust root …` |
| unreadable (mode 000) | exit **1**, unhandled `PermissionError` | exit **2**, named |
| directory instead of file | exit **1**, unhandled `IsADirectoryError` | exit **2**, named |
| empty file (0 bytes) | exit 1, **2553 misdiagnosed** `producer_key_id … is not among the pinned keys` | exit **2**, `… is empty (0 bytes) — an empty file pins no key` |
| malformed (PEM text) | exit 1, 2553 misdiagnosed FAILs | exit **2**, `… is 69 bytes, not a 32-byte raw Ed25519 public key` |
| wrong length (16 B) | exit 1, 2553 misdiagnosed FAILs | exit **2**, named |
| 32 bytes of junk | exit 1, 2553 misdiagnosed FAILs | exit 1, **one** line: `none of the 1 pinned key(s) … matches the producer_key_id of any of the 2553 records — the pinned set does not describe this corpus` |
| **`--session-prefix` matching nothing** | **exit 0**, `all stored bodies hash to their recorded artifact_hash; prev-hash chain intact` — and with `--pubkey` present, `; producer signatures valid` | exit **2**, `SCOPE NOT ESTABLISHED: no camera evidence matched …` |

So the class of bug the reviews predicted is real and does appear more
than once, but the *confirmed* fail-open is the last row, not the first.
An audit whose scope matched nothing printed a clean verdict and exited
0 — and the "producer signatures valid" clause was emitted whenever
`--pubkey` was passed at all, including when exactly zero signatures had
been checked. That is the same invariant violation, reached by a
different door. The `--pubkey` rows were already nonzero-exit, but by
crashing or by misdiagnosing one prerequisite failure as 2553 evidence
failures, which is not "fail loudly before any evidence is evaluated".

Full transcript: `item1-before-after.txt` in the session scratchpad;
reproduce with `tests/test_camera_trust_and_coverage.py`.

### What changed

- `TrustRootError` and `load_trust_root(path)`: one loader, one failure
  type. Checks, in order — non-empty path string; not a directory;
  readable; non-empty; exactly 32 bytes; accepted by Ed25519; and the
  `cryptography` package importable at all (a trust root that was
  requested but cannot be *used* is not established either).
- `_load_pubkeys` routes through it and additionally refuses an empty
  pinned set.
- **Key loading moved to the top of `audit_chain`, before the DB query.**
  Nothing is read from the chain until every requested trust root is in
  hand. `verify_segment` likewise loads the key before it opens the file.
- `main()` catches `TrustRootError` for `audit` and `verify-segment`,
  prints `TRUST ROOT NOT ESTABLISHED: …` plus `no evidence was
  evaluated; this is NOT a clean audit.` to stderr, and returns **2**.
  Exit 2 is now "prerequisite failure", distinct from exit 1 "evidence
  failed" — automation can tell them apart.
- Empty scope returns 2 with `SCOPE NOT ESTABLISHED`.
- The clean-verdict line now reports what was actually done:
  `INTEGRITY: OK — all N stored bodies hash … ; 2544/2553 producer
  signature(s) verified against 2 pinned key(s)`, or explicitly
  `NO producer signature was checked (no --pubkey)`.
- A pinned set that loads but matches no record's `producer_key_id` is
  one loud failure, not one per record. This matters because **32
  arbitrary bytes are a syntactically valid Ed25519 public key** — a
  junk file of the right length cannot be rejected at load time by any
  means, so it has to be caught by "it describes nothing here".

### Other places the driver takes a trust root

The reviews were right that it appears more than once.

- `verify-segment --pubkey` — same loader, same abort, now *before* the
  file is hashed. Previously an unhandled `FileNotFoundError`.
- **The producing side has a trust root too**, and it was unchecked:
  `replay` and `live` read `<data-dir>/producer.pub` with a bare
  `open()` and derived `key_id` from whatever came back. A truncated,
  empty or stale `producer.pub` would have stamped every record with a
  `producer_key_id` that verifies against nothing — evidence that looks
  signed and can never be checked. New `_producer_identity()` validates
  the pub as a trust root **and** asserts it is the public half of the
  secret this run will sign with; a mismatch aborts with exit 2 before
  any segment is touched.
- **No genesis argument exists anywhere in this driver** (`grep genesis
  camera/virp_camera.py` → nothing). Nothing to harden there.
- Reviewed and deliberately left alone: `submit-spool --db` degrades to
  sidecar-only dedup when the chain DB is unreadable. That is an
  idempotency backstop, not a trust root, and it cannot make a verdict
  look stronger — the worst case is a duplicate append, which is visible
  on the chain. Named here so it is a decision, not an oversight.

---

## Item 2 — capture coverage semantics (`camera_segment/2`)

### The record change

`camera_segment/1` is untouched and stays readable forever; **no
existing record was re-signed, rewritten or re-hashed.** `build_body()`
takes an optional `policy`: absent → `/1`, byte-for-byte what the
producer has always built (the existing suites pin this); present →
`/2`, the same fields plus `capture_policy`. `submit-spool` relays both.

```json
"capture_policy": {"nominal_segment_s": 6.0, "jitter_s": 2.0,
                   "max_unexplained_gap_s": 0.0}
```

### Where the policy lives, and why

**Authoritative copy: inside every signed body.** That is the only copy
a verifier may trust. A verifier constant cannot describe two streams
that legitimately differ — the Tapo cuts at ~6 s (median duration 5.997 s
over 363 records), the Reolink sub at ~10 s (median 9.980 s over 9) — and
a file on the capture host can be edited after the fact. Because the
policy is inside the signed bytes, an operator cannot retroactively
loosen `max_unexplained_gap_s` to make a bad window look clean: doing so
invalidates `producer_sig`, which is pinned by test.

**Defaults copy: `<data-dir>/capture-policy.json`,** written by
`capture_policy_resolve()` on first use and reused thereafter. Per-run
CLI flags (`--nominal-segment-s`, `--jitter-s`,
`--max-unexplained-gap-s`) override it and are written back. So: the
data_dir gives cadence stability across restarts of one camera, the CLI
lets a new stream declare its own, and neither can change a record that
already exists.

Defaults: `nominal_segment_s` = `--segment-time` for `live` (else 6.0);
`jitter_s` = 2.0, matching `CAPTURE_GAP_TOLERANCE_NS`, the threshold the
producer itself already uses to emit a gap record — the two are the same
number on purpose, so any hole the grader counts is one the producer was
supposed to have signed; `max_unexplained_gap_s` = 0.0, i.e. strict.
`capture_policy_new()` refuses `jitter_s >= nominal_segment_s`, which
would tolerate a wholly missing segment as continuous coverage.

### No heartbeat interval — the conclusion, with reasoning

Considered and rejected. A heartbeat is a liveness promise, and a
producer that has stopped cannot emit the signed bytes that would keep
it — so declaring one would put a promise in the signed record that the
very failure mode it covers guarantees will be broken. Worse, grading
trailing silence against a heartbeat makes the verdict a function of
wall-clock time at audit: the same fixed corpus would grade differently
on two runs, which an evidence audit must never do. "Has this camera
stopped?" is a monitoring question about a live process, not a property
of the evidence. Left out of the signed bytes rather than signed and
unmet.

### Grading

Per camera, in `segment_seq` order, hole = `next.capture_start −
prev.capture_end`, graded against **the later record's own policy**
(that record is the one making the continuity claim):

| condition | result |
|---|---|
| any record on the camera declares no policy | `UNDECLARED` for the whole camera |
| hole ≤ `jitter_s` (all overlaps included) | covered |
| hole > `jitter_s`, record carries a signed gap | `ACCOUNTED` outage |
| hole > `jitter_s`, no gap, ≤ `max_unexplained_gap_s` | `TOLERATED` outage → still ACCOUNTED |
| otherwise | `UNEXPLAINED` outage |

Camera verdict = worst outage. `UNEXPLAINED` > `ACCOUNTED` >
`CONTINUOUS`; `coverage_axis()` takes the worst camera.

**A signed gap record never yields `CONTINUOUS`.** It moves the verdict
from `INTERRUPTED / UNEXPLAINED` to `INTERRUPTED / ACCOUNTED` and no
further, and the seconds not covered are printed either way
(`1 outage(s), 300.0 s not covered`). That distinction is pinned by
`test_gap_with_signed_record_is_accounted_not_complete`.

One correction to the naive rule, forced by the real corpus: a *negative*
hole is an overlap, and overlapping windows leave no time unrecorded, so
an overlap is never an interruption. The 2026-08-24 replay records
overlap by 4–6 s (file-mtime windows against moov-derived durations) and
would otherwise have graded as outages. Overlaps deeper than the declared
jitter are reported on their own line as a timing observation that does
not move the verdict.

Chain completeness and coverage completeness stay separate: the exit code
is still driven by integrity alone, so an intact chain across an
uncovered window exits 0 while printing `COVERAGE: INTERRUPTED /
UNEXPLAINED`. `--fail-on-coverage` (opt-in, exit 3) is there for
operators who want to gate on it.

---

## Item 3 — content reuse as an observation

Not implemented as a failure. `duplicate hash ⇒ FAILED` would fire on
every one of the 18 real pairs and on any static scene. Reuse is a fourth
axis printed alongside coverage, and it never changes the audit's exit
code (pinned by `test_duplicate_hash_never_fails_the_audit`).

**The rule implemented, and why each arm:**

- `EXPECTED` — same camera, Δseq == 1, windows abut within the declared
  jitter. A static 640×360 scene re-encoding to identical bytes
  back-to-back is ordinary and there is nothing to explain: both records
  cover their own distinct window.
- `DUPLICATE / EXPLAINED` — same camera, Δseq > 1, and the producer's own
  **signed** bytes carry a gap record somewhere in `(lo_seq, hi_seq]`.
  The producer stated a discontinuity across exactly the interval in
  which the bytes reappear. A re-ship after a restart is that. The
  explanation is attested, not asserted by the auditor.
- `DUPLICATE / UNEXPLAINED` — everything else, and **always** when the
  same bytes appear under two different `camera_id`s: two cameras cannot
  legitimately produce identical files, so no static-scene argument
  applies.

`EXPLAINED` is a policy judgement about the producer, not a
cryptographic fact. It says a signed statement exists that accounts for
the reuse. It does not say the reuse was harmless — the 18 pairs are a
real defect that lost real footage; they are explained, not fine.

**Result on the live corpus:** 2535 distinct `segment_sha256` over 2553
records; 18 duplicated, 36 records involved, all in
`camera:tapo-c100:2026-08-24`, all same-camera. Two re-shipped blocks:
seqs 7–12 reappear as 14–19 (Δseq 7) across the signed driver-restart gap
at seq 14; seqs 52–63 reappear as 65–76 (Δseq 13) across the signed
driver-restart gap at seq 65. Every one grades `DUPLICATE / EXPLAINED`,
with `Δseq`, `Δcapture_start`, camera and byte_len printed. Axis for the
corpus: `CONTENT REUSE: DUPLICATE / EXPLAINED`. No `EXPECTED` case occurs
in this corpus.

---

## Item 4 — fixtures frozen from real history

`tests/fixtures/camera_aug24_tapo_a2d2dc.json` — the 7 bodies of
`camera:tapo-c100:2026-08-24` signed by
`a2d2dc0fac250b722c6a77c87be9e341`, verbatim as stored, plus that
public key. Tests pin key-id derivation, `sha256(stored) ==
artifact_hash`, signature validity, canonical round-trip byte-for-byte,
`/1 ⇒ UNDECLARED`, and that a wrong pinned key never passes them.

`tests/fixtures/camera_aug24_duplicate_pairs.json` — facts for all 18
pairs, plus **both re-shipped blocks whole and verbatim** (segment_seq
7–19 and 52–76, 38 records). Whole blocks rather than the bare pairs
because a subset is not prev-chain self-consistent; as frozen, the set
audits standalone as `INTEGRITY: OK` / `COVERAGE: UNDECLARED` /
`CONTENT REUSE: DUPLICATE / EXPLAINED`, all 18 pairs `EXPLAINED`,
including the named seq 52/65 (Δseq 13, Δcapture_start 1410.2 s,
byte_len 1486427, one camera).

### Key custody — this contradicts the prompt

**The `a2d2dc…` copy exists** at `~/camera-provenance-aug25/producer.pub`
on 313: 32 bytes, `sha256(pub)[:16]` =
`a2d2dc0fac250b722c6a77c87be9e341`. Verified before anything else was
done, as asked.

But the premise that it "survived only in a Claude Code scratchpad" is
wrong, and the risk is lower than the prompt assumes:

- `/var/lib/virp/camera/producer.pub` is the same key
  (`a2d2dc0fac250b722c6a77c87be9e341`), owned by `virp`, in a 0700 dir on
  `/var/lib` — it survives the pending reboot.
- `/var/lib/virp/camera/producer.key`, mode 0600 `virp`, is present. The
  **secret is not gone**; that identity can still sign. I did not read,
  print or copy it — its existence and mode come from `ls`.
- The scratchpad copies under `/tmp/claude-1000/…/707e5d2c…/scratchpad/`
  *will* be lost on reboot, but they are the third copy, not the only one.

The only pubkey genuinely at risk is a different one — see below.

### A third producer key the prompt does not mention

The corpus carries **three** producer keys, as stated, but they are not
the two whose pubs are on 313:

| key_id | records | pub on 313? |
|---|---|---|
| `a2d2dc0fac250b722c6a77c87be9e341` | 7 (tapo-c100 replay) | yes (two copies + secret) |
| `008353cf219c224e970f03455aa50e82` | 2537 (tapo-c100 live, tapo-c100-accept, synthetic-restart-accept) | yes |
| `4727a5b94680ba53812ec49a42fe77ad` | 9 (`camera:reolink-rlc810a-sub:2026-08-29`) | **no — nowhere on 313** |

A filesystem-wide search as root found no `.pub` for `4727a5b9…`.
Ed25519 has no public-key recovery, so those 9 records **cannot be
signature-verified on this host** until the pubkey is fetched from the
Reolink capture host (presumably the laptop, which also holds
`008353cf…`). This is the custody gap actually worth acting on, and it
directly limits acceptance criterion 2 below.

Also, incidentally: the corpus has 5 sessions and **four distinct
`camera_id`s** — `tapo-c100`, `tapo-c100-accept`,
`synthetic-restart-accept`, `reolink-rlc810a-sub` — not two. Two are
physical cameras and two are acceptance identities, but the coverage
grader keys on `camera_id`, so it grades four streams.

---

## Item 5 — fail-closed tests

`tests/test_camera_trust_and_coverage.py`, 61 tests under one invariant:
**no prerequisite failure may increase the apparent strength of the
verdict.** Classes: `TrustRootLoadTests` (every load failure mode),
`AuditFailsClosedTests`, `VerifySegmentFailsClosedTests`,
`ProducerIdentityFailsClosedTests`, `CapturePolicyTests`,
`CoverageGradingTests`, `ContentReuseTests`, the two fixture classes,
and `NoPrerequisiteFailureStrengthensTheVerdictTests`, which runs the
full-strength audit first and then asserts every degraded variant exits
nonzero and prints neither `INTEGRITY: OK`, nor `VERDICT: MATCH`, nor
`signature(s) verified`.

---

## Acceptance

**1. Item 1 first and independently** — done, table above; before/after
per failure mode, every one nonzero after, with the failure named before
any evidence is read.

**2. Full corpus regression** — 2553 camera entries, unchanged in count.
Read-only against the live `/var/lib/virp/chain.db`:

- integrity alone (`audit --db /var/lib/virp/chain.db`): **exit 0,
  0 failures, all 2553 stored bodies hash to their recorded
  artifact_hash, prev-hash chain intact.**
- with both available pubkeys: **2544/2553 producer signatures verify**;
  the 9 `reolink-rlc810a-sub` records fail only as
  `producer_key_id 4727a5b9… is not among the pinned keys`, because that
  pubkey is not on this host. Per-prefix: tapo-c100 363/363 OK,
  tapo-c100-accept 2114/2114 OK, synthetic-restart-accept 67/67 OK.
- **Criterion 2 is therefore met for 2544 of 2553 and cannot be met for
  the remaining 9 on 313** until `4727a5b9…`'s pubkey is copied from the
  Reolink capture host. This is a missing input, not a regression: the
  same 9 records fail identically on `4ee5950`.
- `/var/spool/virp-capture`: 7642 paths, mtime+size manifest identical
  before and after. Nothing written. `chain.db` opened only via
  `file:…?mode=ro`; the working copy used for corpus analysis was made
  with sqlite3's backup API.

**3. `/2` coverage grading, end to end through the real CLI** against a
stub O-node socket, then audited:

| case | verdict |
|---|---|
| 6 segments, 6 s cadence, declared policy | `COVERAGE: CONTINUOUS` |
| 300 s outage, producer-signed gap record | `COVERAGE: INTERRUPTED / ACCOUNTED` — `ACCOUNTED seq 3→4 hole 300.0s gap=driver-restart` |
| same 300 s outage, no gap record | `COVERAGE: INTERRUPTED / UNEXPLAINED` — `UNEXPLAINED seq 3→4 hole 300.0s gap=none` |

Integrity `OK` and signatures 100 % verified in all three — coverage and
integrity are visibly independent. The third case had to be built by
signing a gap-less body with the scratch producer key, because the
current producer (Fix D) *always* emits a gap record beyond 2 s; that
body is exactly what a pre-Fix-D producer emitted, and the 69.1 s
`gap: null` hole at seq 77 of `camera:tapo-c100:2026-08-24` is the real
instance of it.

**4. `/1` records report UNDECLARED** — all four cameras in the live
corpus: `COVERAGE: UNDECLARED`, "N of N records declare no capture policy
(camera_segment/1)". Never `CONTINUOUS`. Pinned by
`test_v1_records_report_undeclared_never_continuous` and
`test_one_v1_record_undeclares_the_whole_camera` (one `/1` record
undeclares the whole camera — conservative on purpose).

**5. The real duplicate pair** — seq 52/65 reports `DUPLICATE /
EXPLAINED` with Δseq 13, Δcapture_start 1410.2 s, one camera, one
byte_len, and the basis `a signed gap record (driver-restart) sits at
seq 65, inside the interval in which the bytes reappear`. Audit exit 0.

---

## Things found that contradict the prompt

1. `audit --pubkey <nonexistent>` did **not** report SUCCESS at
   `4ee5950`; it exited 1 on an unhandled traceback. The confirmed
   fail-open of that class is `--session-prefix` matching nothing:
   exit 0, clean verdict, and `producer signatures valid` printed with
   zero signatures checked. Both fixed.
2. The `a2d2dc…` pubkey did **not** survive only in a scratchpad. It is
   also at `/var/lib/virp/camera/producer.pub`, and its **secret half is
   still present** at `/var/lib/virp/camera/producer.key` (0600 `virp`).
   The identity is not lost.
3. A third producer key, `4727a5b94680ba53812ec49a42fe77ad` (9 records,
   `camera:reolink-rlc810a-sub:2026-08-29`), has **no public key anywhere
   on 313**. That is the real custody gap, and it caps acceptance
   criterion 2 at 2544/2553.
4. The corpus has four distinct `camera_id`s, not two.
5. A naive gap rule would have mis-graded the 2026-08-24 replay records,
   whose windows *overlap* by 4–6 s. Overlaps are reported but never
   counted as interruptions.

## Not done, deliberately

- Nothing re-signed, rewritten or re-hashed. The 18 duplicate pairs, the
  `gap: null` hole at seq 77, and the overlapping replay windows are all
  reported where they are, and left on the chain as they are.
- No refactoring or cleanup outside these five items.
- `submit-spool --db` unreadable → sidecar-only dedup: reviewed, left,
  reasoning above.

## Suggested next steps

1. Copy `4727a5b9…`'s `producer.pub` from the Reolink capture host to
   313 (`~/camera-provenance-aug25/` alongside the other two) and re-run
   the full-corpus audit for a 2553/2553 signature pass.
2. Take a `/2` capture on a real camera so a live stream grades
   `CONTINUOUS` rather than `UNDECLARED`. Every record on the chain today
   is `/1`; the axis only becomes useful once the producer has been
   redeployed.
3. Decide whether the submitter should gate on `--fail-on-coverage`.
