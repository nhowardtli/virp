# Test #3 — Fixes from the crash/evidence findings, and what fixing them taught us

**Date:** 2026-08-03/04 · **Host:** virp-lab · **Branch:** `test/adversarial-2026-08-03`
**Baseline:** `a2b3b70e` (transcript 02 + EXECUTION_INTENT memo). Nothing pushed, nothing
installed; the installed daemon is byte-identical to session start
(sha256 `db8f3fab…d5154`, mtime 2026-08-01, still the running `/proc/<pid>/exe`).
All daemon exercise under `/run/virp-fi/` (fresh subdirectory `atomicity/`; the
transcript-02 evidence in `/run/virp-fi` itself was never reopened for writing).

This transcript is a fix log, not a hunt — but two of the fixes changed what we
believe about earlier findings, so it also carries corrections. Corrections are
marked **CORRECTION** and stated against the specific earlier claim.

---

## 1. The three fixes of 2026-08-03

### 1a. `8d2d49ae` — chain entry and artifact body are one transaction

`virp_chain_append()` committed the entry in its own `BEGIN IMMEDIATE`
transaction; `virp_chain_artifact_store()` wrote the body afterwards in
autocommit. Transcript 02 (`mid_outcome`) killed between them and produced a
chain entry committing to a body that does not exist; the same window let a
plain copy of the live DB capture the state without any crash.

Fix: `virp_chain_append_with_artifact()` — entry INSERT, signed-head upsert,
and body INSERT in one transaction. A body-store failure fails the whole
append, typed (`VIRP_ERR_CHAIN_DB`); it is not a partial-success condition
because there is no partial state left to describe. The task named four call
sites; the tree had **five** append+store pairs (outcome emitter,
gate-rejection persister, `CHAIN_APPEND` socket handler, proposal filing,
approval submit) and all five were converted — the cited line numbers were
stale. The stop-trigger surfaces (consume point, −36-before−37 order,
`consume_once`, outcome boundary) were not touched; none turned out to be
necessary.

The `mid_outcome` fault-injection point moved with the boundary it names, to
between the two INSERTs *inside* the transaction. Re-run on the isolated
stack: armed kill leaves **0 entries, 0 bodies, 0 heads** (the half-written
record is rolled back, not stranded); the same kill on the pre-fix build left
1 entry, 0 bodies, chain VALID. Unarmed control: both present.

### 1b. `ba6d6d14` — batch execution enforces the device-output subtype gate

The single-command path refused to render a non-{DEVICE_OUTPUT, ERROR}
observation as device output (§4.1); the batch path did not, and `/api/sweep`
presented batch payloads as `output`. Demonstrated pre-fix: a genuinely
HMAC-valid forged 0x08 came back from `/api/sweep` as
`{"verified": true, "output": "BGP totally healthy, trust me"}`. Fixed
per-item (a forged item becomes an error result and must not discard its
siblings); regression tests exercise `_batch_execute_chunk()` and
`POST /api/sweep`, not the single path, and assert on accept/reject behavior
only — nothing pins the known-loose parser. The companion survey
(`tests/adversarial/CHECKLIST-single-vs-batch-invariants.md`) checked every
single-path invariant three ways; its three open flags: the Go port signs
`sign_intent`/`sign_outcome` without the §4.1 digest validation, the Go port
emits its errors as DEVICE_OUTPUT (0x07), and the C batch parser silently
drops items beyond 16.

### 1c. `6732d9eb` — `virp chain verify` exists

`virp_chain_verify_session()` was library-only; transcript 02 had to carry its
own verifier. Wired, two forms: `--session S [--socket]` asks the running
daemon (sole writer, sole key-holder); `--db PATH --key PATH [--session S]`
verifies directly for the auditor-with-a-copy case, with a stated caveat that
`virp_chain_init()` opens the DB read-write (schema ensure, WAL, head
backfill) — copies only. Exit 0 only when something was verified and all of
it passed. See §3 for what this command does **not** check.

## 2. The production audit trail, closed out

The corrected verifier (§3) over a fresh consistent backup
(`sqlite3 ".backup"`, read lock, live DB untouched) of
`/var/lib/virp/chain.db`:

```
sessions verified=48 broken=0  entries-with-missing-body=21
```

All 21 orphaned commitments are now root-caused. Two classes:

**Class 1 — 20 gate-rejection orphans, 2026-07-29 19:20:04 → 2026-07-30
01:49:48 UTC** (range confirmed by query against the backup). The pre-fix
gate-rejection path appended the entry and stored no body (later best-effort
store, DEPLOYED.md "gate-reason retention"). The *class* is closed by
`8d2d49ae`: entry and body now land together or not at all. The 20 existing
entries stay orphaned forever — their reasons were never stored, and nothing
can conjure the bytes back.

**Class 2 — one collision-displaced observation, 2026-07-31 23:03:12 UTC.**
Two distinct observations in the same second both minted the
second-resolution id `obs:pbs-lab:1785538992` (session `virp-cli:pbs-lab`):

```
seq 0  commits to 5f109f05…  23:03:12.043856417   body ABSENT
seq 1  commits to 1b5550cb…  23:03:12.228956298   body present (255 bytes)
```

185 ms apart. `artifacts` was `UNIQUE(artifact_id)` and the store was
`INSERT OR REPLACE`, so seq 1's body displaced seq 0's. **Not** the class 1
bug: the chain is honest — both entries, both hashes correct — the *store*
lost evidence, silently. The id scheme moved to nanosecond resolution
mid-session (seq 3 onward), which narrows the window but neither detects nor
prevents the class.

**Stated plainly:** the first observation's evidence bytes are permanently
lost. The chain proves the evidence existed, when, and what its SHA-256 was;
it cannot produce the bytes. The audit path surfaced the loss on 2026-08-03 —
four days after it happened. Nothing alerted at the time.

### The fix — `f93324a6`, keyed by what the entry commits to

Task A answer, stated before changing anything: `8d2d49ae`'s
`virp_chain_append_with_artifact()` did **transactional evidence loss** on
this collision — `OR REPLACE` ran inside the transaction, both appends
succeeded, the first body was destroyed at the second commit. Reproduced: the
new regression test fails 2/23 on `8d2d49ae`. The atomicity fix made the loss
atomic, not impossible.

`f93324a6`: storage keyed `UNIQUE(artifact_id, artifact_hash)` with
`ON CONFLICT DO NOTHING`. Distinct evidence under a colliding id stores both
rows — nothing displaces stored bytes, no append is lost to a collision;
identical (id, hash) re-store is idempotent. Readers must join entry→body on
**both** columns. Legacy DBs are rebuilt in one transaction by
`virp_chain_init()` (detected via `sqlite_master`; fails closed; all rows
preserved) — **the production DB was not migrated tonight**; it migrates on
the first daemon start after this deploys, like the head-backfill precedent.
Regression tests replay the exact collision (both bodies retrievable, both
entries verify), the idempotent case, and the legacy migration. The
`mid_outcome` FI result from 1a was re-proven on the rebuilt binary after
this change: armed kill 0/0/0, control persists both.

## 3. CORRECTIONS

**The transcript-02 "near-miss" was mis-explained.** Transcript 02 reported
the 21st body-less entry in a production *copy* as a snapshot race — "the
copy caught the daemon between chain_append and artifact_store; the live
database has the body." What the live read actually found was **the second
observation's body sitting under the first observation's id**. The checker
joined artifacts by `artifact_id` alone, so id-presence masked the hash
mismatch. The snapshot-race mechanism is real (transcript 02 demonstrated it
independently), but it was the wrong explanation for *this* entry: seq 0's
body was not late, it was already destroyed. The verifier's join is corrected
to `(artifact_id, artifact_hash)` — under which the same live DB shows 21
missing bodies, not 20.

**`virp chain verify` reports VALID on a database known to carry 21 orphaned
commitments.** `virp_chain_verify_session()` checks per-entry HMACs,
prev-hash linkage, and completeness against the signed head. It does **not**
check entry-to-body correspondence — that is a deliberate scope statement,
now verified against production reality: run tonight against the backup with
21 confirmed orphans, every affected session reports VALID (demonstrated on
`virp-cli:pbs-lab` directly). "VALID" from the shipped verifier means the
*ledger* is intact, not that the *evidence room* is stocked. The body-
correspondence check exists only in the adversarial verifier
(`tests/adversarial/verifier/virp-chain-verify.c`); folding it into the
shipped command is future work, deliberately not smuggled into tonight's
scope.

**Version-string lag.** During task-3 verification, the binary carrying
`6732d9eb`'s code reported `virp-tool ba6d6d14`. Mechanism, not mystery:
`VIRP_GIT_HASH` stamps `git rev-parse HEAD` at **link time**, and in this
program builds routinely precede the commit of the code they contain — the
same lag reproduced tonight with a binary containing `f93324a6`'s code
reporting `6732d9eb`. Consequence for evidence handling: `virp-tool <hash>`
identifies the HEAD the binary was linked under, not the source state it was
built from. Any transcript citing a version string should note whether
uncommitted work was present.

## 4. Task D — audit of artifact-id minting (list only, nothing changed)

Every writer that mints artifact ids, and the id's collision resistance:

| writer | id shape | resolution / basis |
|---|---|---|
| `src/virp_tool.c:853` (CLI chain-register — the writer that minted the Jul 31 collision) | `obs:<device>:<ns>` | `clock_gettime(CLOCK_REALTIME)`, true ns — **fixed mid-session Jul 31; this was the second-resolution minter** |
| `autopilot/virp_autopilot.py:372` | `obs:<device>:<ns>` | `time.time_ns()`, true ns |
| `autopilot/virp_autopilot.py:849` | `chainwalk:<ns>` | `time.time_ns()`, true ns |
| `autopilot/virp_autopilot.py:1043` | `comparator:<ns>` | `time.time_ns()`, true ns |
| `autopilot/virp_config_backup.py:555` | `baseline:<device>:<ns>` | `time.time_ns()`, true ns |
| `autopilot/virp_config_backup.py:352` | `obs:<device>:<ns>` | `int(time.time() * 1e9)` — ns-**shaped**, float-derived (~µs true precision) |
| `autopilot/virp_config_backup.py:393` | `nodrift:<device>:<ns>` | same float-derived pattern |
| `autopilot/virp_config_backup.py:461` | `drift:<device>:<ns>` | same float-derived pattern |
| `autopilot/virp_evidence.py:477` | `obs:<device>:<ns>` | same float-derived pattern |
| `autopilot/virp_evidence.py:491` | `evidence:<device>:<name>:<ns>` | same float-derived pattern |
| daemon: proposal/approval/outcome | `proposal:<id>` etc. | 128-bit random hex — no timestamp, collision-free by construction |
| daemon: gate rejections | `gatereject-<hash16>` | content-hash-derived — identical rejections share an id *and* a hash, which the new (id, hash) key treats as idempotent, correctly |
| Go port | — | mints no artifact ids (no chain writer; chain-shaped requests fall to the refuse-by-default arm) |

**Second-resolution minters remaining: none.** The two `int(time.time())`
call sites in `virp_autopilot.py` (:739, :931) are payload timestamps, not
artifact ids; `report/verify.py` is a reader. Flagged but deliberately not
"fixed": the five float-derived sites in `virp_config_backup.py` /
`virp_evidence.py` are nanosecond-shaped with roughly microsecond real
precision. Post-`f93324a6` this is a cosmetic nonuniformity, not a loss
window — id collisions can no longer displace or drop anything; generation-
time uniqueness is now a nicety, not a load-bearing guarantee. That inversion
is the point of the fix.

## 5. State at close

- Branch `test/adversarial-2026-08-03` at `f93324a6` (plus this transcript);
  synced to `/opt/virp` by fetch + ff-merge. Nothing pushed to any remote.
- Nothing installed; production daemon binary and socket untouched; the
  production chain was touched only by `sqlite3 ".backup"` (read lock) and
  its key only as a scratch copy (0600, deleted after use).
- Suites at close: chain 23/23, core 51/51, onode 69/69, approval/registry/
  pkcs11 32/32, e2e + drivers green, chain-concurrency 800-write PASS,
  Python API suites green.
- Lab artifacts: `/run/virp-fi/atomicity/` (FI atomicity runs, both rounds),
  scratchpad production backup used for §2/§3 (session-scoped, disposable).
