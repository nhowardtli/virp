# SESSION-BODY-RETENTION.md

Body retention integrity + collector credential filtering session, 2026-08-27.
Branch `fix/body-retention-integrity`, clone at `f48360c1` (matches `/opt/virp`
HEAD; see §0). All chain numbers were measured against the adjudication snapshot
`~/claims-adj/chain-snap.db` (2026-08-27 01:05 UTC, 207,854 entries) — the live
DB was never opened. Every claim below carries its source; anything inferred is
marked inferred.

---

## 0. Tree state

- Clone HEAD == `/opt/virp` HEAD == `f48360c1` (`git rev-parse HEAD` both
  sides). `/opt/virp` working tree clean (`git -C /opt/virp status --porcelain`
  → empty).
- **The running daemon is older than HEAD** (inferred from file timestamps —
  no version string is embedded in the binary):
  `/usr/local/lib/virp/virp-onode-prod` is dated 2026-08-18 18:26, while HEAD's
  last commits are 2026-08-25/26 (PRs #10–12 and the two Defect B commits).
  Those commits are in the tree I audited but not in the process that is
  writing the chain. None of them touch the body-retention paths examined here
  (verified by reading the commits' subjects and the paths in §1, which predate
  them), so the findings apply to both.
- Baseline: `make all` clean; full `make all-tests` baseline recorded in §4.

## 1. The truncation mechanism (fact, not theory)

The write path for an autopilot observation body, with every point where the
body is measured, hashed, copied, or bounded:

| # | Step | Location |
|---|---|---|
| 1 | Client hashes the FULL signed observation: `h = sha256(raw_obs)` | `autopilot/virp_autopilot.py:395` |
| 2 | Client builds `content = "base64:" + b64(raw_obs)` | `autopilot/virp_autopilot.py:404` |
| 3 | Client-side size guard (added 2026-08-06, commit `8a2a6342`): body included only `if len(content) < 8192`, else commitment-only | `autopilot/virp_autopilot.py:405` |
| 4 | CLI path has the equivalent refuse-guard (`body_len >= 8192` → refuse) | `src/virp_tool.c:938` |
| 5 | Transport frame caps any request at 64 KiB | `include/virp.h:25` (`VIRP_MAX_MESSAGE_SIZE`) |
| 6 | **Daemon request field is fixed at 8,192 bytes**: `char artifact_content[8192]` | `src/virp_onode.c:75` |
| 7 | **The truncation itself**: JSON extraction copies with `snprintf(out, out_len, "%s", ...)`, which silently keeps the first 8,191 bytes + NUL and returns success | `src/virp_onode.c:110` (`json_extract_string_cjson`, used via `EXTRACT_STR("artifact_content", ...)` at `:419`) |
| 8 | GATE 2 (added 2026-08-06, commit `9452dc0d`): daemon recomputes sha256 over the submitted body and refuses a mismatch with the declared `artifact_hash` | `src/virp_onode.c:3213-3231` |
| 9 | Storage is unbounded `TEXT`, insert is idempotent `ON CONFLICT DO NOTHING` — no bound, no overwrite, no pruning path anywhere (`grep DELETE FROM artifacts` → only a one-time 2026-08-03 key migration) | `src/virp_chain.c:791-800, 927-933` |

**Ordering, established from the code:** the commitment is computed by the
*client* over the full raw bytes (step 1) and recorded verbatim in the chain
entry; the daemon truncated the body at JSON extraction (step 7) *before* any
daemon-side check existed, and stored the 8,191-byte prefix against the
full-body hash. The commitment was never recomputed over the truncated form.
Since 2026-08-06, step 8 runs after step 7, so a truncated submission now fails
hash-binding and is refused outright — the truncating write path is closed, not
removed.

**Size distribution, measured:** all 2,211 truncated bodies are stored at
**exactly 8,191 bytes** — no other length ≥ 8,100 exists
(`SELECT length(artifact_content), COUNT(*) ... GROUP BY 1` on the snapshot:
single row `8191|2211`). That matches the snprintf cap (8,192-byte buffer − NUL)
exactly. All 2,211 are `librenms-lab`, dated 2026-07-29 → 2026-08-06 — the
population closes on the day the fixes landed.

## 2. Do the two populations share a code path?

**Same client path and same root constraint; different mechanism by epoch.**

Both populations are autopilot `chain_append` submissions whose
`base64:` content reached 8,192 bytes — the constraint is the daemon field in
§1 step 6 in both cases.

- **Truncated-but-present (2,211):** submissions from *before* 2026-08-06.
  No client guard existed and no daemon hash-binding existed; the daemon
  truncated at extraction (§1 step 7) and stored the prefix.
- **No-body-retained (17,637):** submissions from 2026-08-06 onward. The
  client guard (§1 step 3) omits `artifact_content`, so the daemon stores
  nothing; the entry carries only the commitment. It is not a retention policy
  and not pruning — nothing deletes bodies (§1 step 9); the body is simply
  never submitted.

Population 2 breakdown (snapshot, joined on `(artifact_id, artifact_hash)` —
the pair the entry commits to, which is how the verifier joins):

| Source | Entries | Command families (from gate_execution records for the same devices) |
|---|---:|---|
| `pbs-lab` | 11,752 | `pbs op=backup.datastore.usage` (responses 28.3–28.5 KB), `backup.snapshots.list` (20.7–24.9 KB) |
| `librenms-lab` | 5,876 | `GET /api/v0/devices` (13.3 KB) |
| federation bridge (`ncfed-obs-*`), netclaw verify, one test probe | 8 | commitment-only by design of those clients |
| `obs:pbs-lab:1785538992` | 1 | a 2026-07-31 seconds-resolution artifact_id collision: the id exists in `artifacts` with a *different* hash, so this entry's committed body is absent (the known collision class, separately tracked) |

All are `artifact_type` observation except 7 `fed_observation` (plus 20 legacy
`gate_rejection` bodyless entries that predate reason retention, 2026-07-30 —
expected, graded by type). Measured ongoing rate: **839/day** average over
2026-08-06 → 2026-08-27 (the prompt's "roughly 864/day" is consistent as a
steady-state figure).

### Do they verify today?

I ran the repo's own verifier (`report/verify.py:verify_chain`) over the entire
207,854-entry snapshot (driver script preserved in the session scratchpad;
keys unavailable → HMAC checks UNCHECKED, which does not affect artifact
binding):

| Population | rollup | artifact_bind detail |
|---|---|---|
| 2,211 truncated | **UNVERIFIABLE — all 2,211** | `RETENTION_TRUNCATED` via the length heuristic (`report/verify.py:815-832`: stored length ≥ `ARTIFACT_CONTENT_MAX` = 8191, `verify.py:144`) |
| 17,637 bodyless | **UNVERIFIABLE — all 17,637** | "no artifact body is stored for this entry" (`verify.py:818-821`) |
| Whole chain | **rollup FAIL: 0** | first_broken_link: None |

So: **refuted in the strict sense that they "verify correctly."** They are not
graded as tampering (0 FAILs), but they do not PASS either — both populations
roll up UNVERIFIABLE, and the verifier's `.ok` is false for them
(`verify.py:736-743`). That is the honest grade. The important weakness: the
*reason* attached to each UNVERIFIABLE is a **heuristic**, not a recorded fact
— the truncated population is recognized only by the stored length being
exactly 8,191 bytes, and the bodyless population's reason is a bare "no body
stored" with nothing distinguishing deliberate commitment-only from a body
that went missing.

### The question that decides the fix

**Does the current schema have any way to state "a body existed, it was not
retained, here is its commitment" as distinct from "there is no body"? No.**
Neither `chain_entries` nor `artifacts` has any retention field (schema:
`src/virp_chain.c:791-800`, confirmed against the snapshot's
`PRAGMA table_info`). The canonical entry form is a fixed 12-field JSON
(`report/verify.py:208-241`) and contains nothing about retention. Absence of
an `artifacts` row is the only signal, and it is unauthenticated and
reason-free. The design for fixing this is in `PROPOSAL-BODY-RETENTION.md`
(Phase 2 — awaiting ruling; not implemented).

## 3. What was implemented (Phase 3): collector-side credential filtering

The exposure (adjudication Q8, re-verified by population counts above): librenms
`GET /api/v0/devices` responses carry non-empty SNMPv3 `authpass` /
`cryptopass` / `authname` / `authalgo` / `cryptoalgo`, SNMP `community`, and
`sysContact` email PII, and 2,211 such bodies are already chained permanently.

**Point of collection found:** the librenms driver's `execute()` writes the raw
API response into `result->output` (`src/drivers/driver_librenms.c:331-334`);
the daemon then hashes it into the `gate_execution` record
(`src/virp_onode.c:924`) and signs it into the observation
(`src/virp_onode.c:2039` onward). The daemon already has a designated
**SCRUB-BARRIER** (`src/virp_onode.c:1874-1885`) — the single point before
anything commits to or signs captured bytes, enforced by
`scripts/check-obs-build-ordering.sh`. The filter is hooked exactly there.

New code:

- `src/virp_body_filter.c` + `include/virp_body_filter.h` — config-driven,
  **allowlist-only** response filter. One call added at the barrier:
  `virp_body_filter_apply(drv->name, command, &result)`
  (`src/virp_onode.c:1886`). The ordering guard still passes.
- Rules: per `(driver, endpoint path)` — method word and query string are
  stripped for matching. Loaded from `$VIRP_BODY_FILTERS`, else
  `/etc/virp/body-filters.json`, else **compiled-in defaults**. A config that
  is missing or unparseable falls back to the built-ins, never to "no
  filtering" (fail closed). `deploy/body-filters.json` ships the same rules as
  the built-ins.
- The librenms rule (`librenms-devices-v1`): envelope allowlist
  `status, count, message`; per-device-record allowlist of 20
  availability/asset keys (`device_id, hostname, sysName, ip, os, type,
  hardware, version, serial, status, status_reason, ignore, disabled, uptime,
  last_polled, last_discovered, last_ping, last_ping_timetaken, location_id,
  dependency_parent_id`). Credential and contact fields are removed by not
  being named — as is whatever field LibreNMS adds next. (The battery's own
  consumer reads only `status`/`count`: `autopilot/virp_autopilot.py:527-532`.)
- **Recorded, not silent:** a filtered body gains a `_virp_filtered`
  annotation naming the removed keys — names only, never values — inside the
  body, *before* hashing, so the record travels under the existing
  `artifact_hash` with **no canonical-bytes change**. A body from which
  nothing was removed stays byte-identical and carries no annotation.
- **Fail closed:** if a matched endpoint's payload does not parse as JSON (the
  dangerous case: a capture-truncated credential dump), the payload is
  *withheld* — replaced by a stub recording mode, reason, original length and
  original sha256. Raw unfiltered bytes of a matched endpoint can no longer
  reach the chain at all.
- Vacated buffer bytes are cleansed (`OPENSSL_cleanse`) so removed values do
  not linger in memory that later code might copy.

What this changes about future entries: every future `GET /api/v0/devices`
observation (and its `gate_execution.response_sha256`) commits to the filtered
bytes. The chain entry verifies end-to-end exactly like any other body-bearing
entry — confirmed by test. One expected one-time effect at deploy: anything
comparing response bytes/hashes across the cutover sees a change (the
`response_sha256` recorded per execution changes; the autopilot's baseline
evaluators are count-based and unaffected).

Tests (`tests/test_body_filter.c`, wired into `make all-tests` as
`test-body-filter`; all credential-shaped values synthesized and marked):

1. sensitive fields removed and recorded by key — and the values absent from
   the *entire* buffer, cleansed tail included;
2. a clean body is byte-identical with no annotation;
3. non-matching driver/path untouched;
4. unparseable matched payload withheld, stub commits to original sha256;
5. filtered body hashes and chains cleanly (daemon-side
   `virp_chain_artifact_digest` == client-declared sha256; full
   `virp_chain_append_with_artifact` + `virp_chain_verify` round-trip);
6. rules load from a config file, and a config replaces (not overlays) the
   built-ins.

### Sweep of the other collectors (report only — nothing fixed)

| Collector | GREEN surface | Exposure class | Assessment |
|---|---|---|---|
| **zammad** (`src/drivers/driver_zammad.c:73-88`) | `/api/v1/tickets`, `/tickets/<id>`, `/ticket_articles/by_ticket/<id>`, `/ticket_states`, `/groups` | **PII — the significant one.** Ticket records and especially ticket *articles* carry customer names, email addresses, and full message bodies into chained observations. | Needs its own allowlist rule (a config line in `body-filters.json` once field needs are decided). Not done this session. |
| **wazuh** (`src/drivers/driver_wazuh.c:76-78`) | `/agents`, `/agents/summary/status`, `/manager/stats/analysisd` | `/agents` returns per-agent records (IPs, OS versions, node names) — topology detail, no credential fields (agent keys live under `/agents/<id>/key`, which is RED by absence). | Low. Candidate for a rule on `/agents` if agent inventory detail is considered sensitive. |
| **pbs** (`src/drivers/driver_pbs.c`) | `backup.datastore.usage`, `backup.snapshots.list`, `backup.version.read`, `backup.verify.tasks` | Usage numbers, snapshot names, verification digests (the Q8 "hex digests" class). No credentials. | Low. |
| **librenms `/health`, `/alerts`** | per-device health metrics, alert list | No credential fields observed in the response classes; alerts name devices/rules. | Low; left unfiltered. |
| **SSH config drivers** (cisco/asa/fortigate/linux) | `show running-config` family | Already have **scrub-at-capture** implementations with their own test suites (`test-cisco-scrub`, `test-asa-scrub`, `test-fg-scrub`, `test-linux-scrub`). The latent FRR exposure from Q8/A17 (no credential directives in FRR configs today) stands. | Covered by existing mechanism; not touched. |

## 4. Verification against baseline

Baseline `make all-tests` was run before the change and the full suite again
after; both logs are preserved in the session scratchpad
(`baseline-tests.log`, `postchange-tests.log`).

- **Both runs exit 2, at the same target, for the same pre-existing reason:**
  `test-fed-outcome-observation`, a read-only audit of the **live** chain
  (`/var/lib/virp/chain.db`), fails 2 of 4 on historical chain rows dated
  2026-08-11 → 2026-08-14. Verified pre-existing: a pristine clone of
  `f48360c1` with none of this session's changes fails identically
  (`make -C <pristine> test-fed-outcome-observation` → `FAILED (failures=2)`).
  Because make aborts there, `test-api` is unreached in **both** runs; run
  directly on the post-change tree it passes (87 passed).
- **`[FAIL]`-marked tests: 2 in baseline, 2 post-change — the same two**, both
  in `test-onode` and both explicitly annotated `[PENDING] known-failing by
  design; NOT a pass` (the Defect B `gate_execution/2` three-valued-executed
  acceptance criteria). No new failure appeared; no pending failure
  disappeared.
- **The only summary-line difference between the two logs** (ignoring
  timings) is the addition of `test-body-filter: 6 passed, 0 failed`.
- **No canonical-byte change:** `test-chain-invariant` (the D-0 Appendix A
  canonical-bytes lock) passes with every fixture identical;
  `test_golden_vectors_reproduce` and `test-chainsign-vectors` pass; the
  C↔Go `test-interop` vectors pass byte-identically in both runs. No fixture
  was updated.
- One process note for honesty: the *first* baseline invocation overlapped
  later build activity in this working tree, and a first post-change run
  overlapped a `test-onode` invocation in the pristine clone (shared `/tmp`
  fixture paths) and showed 2 spurious extra failures. Both runs were redone
  cleanly with nothing else executing; the numbers above are from the clean
  runs.

Diff shape (before commit): `Makefile` +17/−1 (object + test-target wiring),
`src/virp_onode.c` +2 (the `#include` and the one barrier call), and four new
files (`src/virp_body_filter.c`, `include/virp_body_filter.h`,
`tests/test_body_filter.c`, `deploy/body-filters.json`), plus this report and
`PROPOSAL-BODY-RETENTION.md`. No existing test, fixture, or vector was
modified.

## 5. What I did NOT do, and why

- **Phase 2 (not-retained state): designed only, not implemented** —
  `PROPOSAL-BODY-RETENTION.md`. The recommended shape adds a canonical field,
  which is a wire-format change (rule 3 / hard stop). My recommendation is in
  the proposal (§7): canonical `body_retention` field in a version-gated
  format window, verifiers updated first; raise the daemon body cap to 60 KiB;
  the 2,211 keep their truncated-legacy grading forever.
- **No change to the 2,211 or any existing entry.** Append-only; the stored
  prefixes and their failing bindings are the historical record of the defect.
- **No verifier changes.** The RETENTION_TRUNCATED heuristic's weakness (a
  legitimately-8,191-byte tampered body would be mislabeled UNVERIFIABLE
  rather than FAIL) is real but is Phase 2 material — fixing it properly is
  the declared retention state.
- **No size-cap change** — proposed in the proposal (§5), awaiting ruling,
  since it changes daemon memory layout and DB growth rate.
- **No zammad/wazuh filter rules** — sweep-and-report only, per the phase
  instructions; the zammad PII finding needs a decision on which ticket fields
  the evidence use-case actually requires.
- **No credential rotation, no `-S` signing, no heartbeat/manifest work, no
  Docket changes** — all explicitly out of scope.
- **Not deployed, not restarted, not pushed, not merged.** The running daemon
  does not contain this filter until nhoward deploys it.

## 6. Claims in the session prompt that the source contradicted

1. **"…rather than verifying as FAILED and looking like tampering"
   (Phase 2 framing).** Contradicted by the current verifier: the 2,211
   truncated entries grade **UNVERIFIABLE** (reason RETENTION_TRUNCATED), not
   FAIL — the whole snapshot has **zero** rollup FAILs (verifier run, §2).
   The length heuristic at `report/verify.py:815-816` already catches them.
   The honest restatement: they verify *unverifiable* on an undeclared,
   heuristic basis — the fix is making the state declared, not preventing a
   false tampering alarm that currently does not fire.
2. **"17,636 observations have no retained body."** The count by the join the
   verifier actually uses (`(artifact_id, artifact_hash)`) is **17,637**;
   17,636 is the id-only join. The extra entry is the 2026-07-31 id-collision
   entry (§2). Also, 8 of the population are not oversize-related at all
   (federation bridge / netclaw / probe commitment-only entries).
3. **"ongoing at roughly 864/day."** Measured average over the full
   2026-08-06 → 2026-08-27 window: **839/day**. Same order, slightly lower;
   not a contradiction of substance.
4. **"the 2,211… no longer hash to their own commitment" — confirmed** (no
   contradiction; verified via the verifier's artifact_bind mismatch +
   truncation length match).
5. The Phase 1 hypothesis space "same path at a larger size, a different path
   entirely, a retention policy, or a pruning job" resolves to: same
   submission path, same size constraint, **no** retention policy, **no**
   pruning job — the split is temporal (before/after the 2026-08-06 guard +
   GATE 2), not architectural (§2).

## 7. What remains owed on this bug after this session

1. **nhoward's ruling on `PROPOSAL-BODY-RETENTION.md`** — the declared
   not-retained state (canonical field vs. stub), and the size-cap raise.
   Until the cap moves, ~839 bodies/day continue to be commitment-only; until
   the state is declared, their honesty rests on a length heuristic and a
   type list.
2. **Deploy of the Phase 3 filter** (build + install + daemon restart —
   explicitly not this session). Until then, every `GET /api/v0/devices`
   response continues to enter the chain unfiltered — currently
   commitment-only (>8 KiB), but the credentials still transit the daemon and
   land in any retained form the moment the size cap moves. **The filter must
   be deployed before or with any cap raise.**
3. **Credential rotation** for the SNMPv3 material already chained (nhoward's
   action, out of scope here). The 2,211 bodies retain those values forever.
4. **Zammad allowlist rule** — the sweep's significant finding: ticket/article
   PII is being chained. Needs a field-needs decision, then one config stanza.
5. **Wazuh `/agents` rule** — optional, lower value.
6. **Docket verifier rendering** of the NOT-RETAINED state and of the 2,211
   legacy entries (draft-07 material per the proposal; Docket repo out of
   scope this session).
7. The **id-collision bodyless entry** (`obs:pbs-lab:1785538992`) belongs to
   the separately-tracked artifact_id collision work — noted here so it is not
   double-counted as an oversize loss.
8. The verifier's truncation heuristic edge (`ARTIFACT_CONTENT_MAX` vs. a
   genuine 8,191-byte body) is subsumed by Phase 2; if the proposal is
   rejected, it needs its own treatment.
