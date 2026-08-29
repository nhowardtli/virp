# Merge reconciliation — 313's `main` ↔ `origin/main`

**Date:** 2026-08-29
**Branch:** `merge/reconcile-313-origin`
**Merge commit:** `873ca75` (parents `f770256` = 313's main, `ba93598` = origin/main)
**Merge base:** `6e7021e` — *seal: OTS attestation confirmed in Bitcoin (block 963675)*

Not pushed. Not merged to `main`. Nothing installed, no service restarted,
`/var/lib/virp/chain.db` and `/etc/virp` untouched (the body-filter config
under `/etc/virp` was never read — the probe below ran against the compiled-in
defaults). Nothing was reformatted, cleaned up, or refactored while resolving.

## 1. What each side carried

**313's main** — 20 commits ahead of the base:

* camera segment-attestation driver, Phase 2 live capture, restart-integrity
  fixes A–F, trust-root fail-closed, coverage/content reuse (16 commits, all
  in `camera/`, `tests/test_camera_*`, no conflict)
* `33fcb84` **onode: scrub-at-capture (S-1)** — `src/virp_scrub.c`,
  `include/virp_scrub.h`, one call in `onode_execute_obs_ex()`
* `520e605` SCRUB-DESIGN.md
* `b16037f` / `81bb802` cisco driver config-mode support + mode-aware health probe

**origin/main** — 15 commits ahead of the base:

* `ba93598` **gate: BLACK is unconditional** — refused before any mode check,
  in SHADOW too; plus a PAN-OS BLACK deny table
* `482d8a5` **collector: allowlist body filtering at the scrub barrier**
* `6e9a3bf` / `f48360c` **Defect B** — route a proved-non-dispatch refusal to
  ERROR; drivers declare non-dispatch on refusal. `6e9a3bf` also introduced the
  `SCRUB-BARRIER` marker and `scripts/check-obs-build-ordering.sh`
* four merged PRs from an outside contributor (`#5`, `#10`, `#11`, `#12`,
  `#14`, `#15`): ASA enable-credential refusal, `ssh_legacy` dev-loader parity,
  `linux_gate_set_protected_vmids` extern, chainsign vectors without PyNaCl
* CI changes

Conflicting files: `Makefile`, `src/virp_onode.c`, `tests/test_onode.c` —
**six hunks**. Everything else auto-merged, including `src/drivers/driver_cisco.c`,
which both sides changed (§2.7).

## 2. Conflict-by-conflict record

Every hunk resolved as a **union**. Nothing from either side was dropped,
weakened, or silenced.

### 2.1 `Makefile` — `LIB_OBJS` (was line 45)

| side | wanted |
|---|---|
| 313 | `$(BUILD_DIR)/virp_scrub.o` |
| origin | `$(BUILD_DIR)/virp_body_filter.o` |

**Kept:** both, in that order. Two independent translation units; the conflict
was purely textual adjacency in the object list. Both intents preserved — the
library now links both mechanisms, which §3.2 shows is required.

### 2.2 `Makefile` — `all-tests` prerequisite list (was line 1867)

Both sides appended one suite to the same long line.

| side | wanted |
|---|---|
| 313 | `test-scrub` inserted after `test-onode` |
| origin | `test-body-filter` inserted after `test-fg-scrub` |

**Kept:** both, each at its own side's position:

```
... test test-onode test-scrub test-ssh-io test-fg-scrub test-body-filter test-cisco-scrub ...
```

Computed as a set union rather than hand-typed, then verified by diffing the
resolved list against each side's list: exactly one addition each way, no
removals. `test-scrub` and `test-body-filter` targets both exist and both run
(§4). **This is the hunk where a wrong resolution silently drops test targets;
the union is the only resolution that drops none.**

### 2.3 `src/virp_onode.c` — the scrub barrier (was line 1949) — **the decision hunk**

Both sides inserted a redaction mechanism at the same point in
`onode_execute_obs_ex()`, immediately after `pthread_mutex_unlock(&state->exec_mutex[dev_idx])`.

| side | wanted |
|---|---|
| 313 | its S-1 comment block + `virp_scrub_exec_result(&result);` |
| origin | the `SCRUB-BARRIER` marker comment + `virp_body_filter_apply(drv->name, command, &result);` |

Origin's marker comment, written by `6e9a3bf` *before* either mechanism existed,
says outright: *"feat/camera-driver inserts `virp_scrub_exec_result(&result)`
exactly HERE (S-1, scrub-at-capture); the marker is placed before that merge so
the rebase cannot land the scrub in the wrong place unnoticed."* Origin then put
`virp_body_filter_apply` at that same "HERE". **Neither side ever decided the
order between the two.** That decision is mine and is documented in §3.2.

**Kept:** all three pieces — origin's marker comment verbatim (the ordering
guard greps for the literal string `SCRUB-BARRIER`, and deleting it fails the
guard by design), then `virp_body_filter_apply()`, then 313's S-1 comment
verbatim and `virp_scrub_exec_result()`. A merge note between them records why
both are kept and why in that order.

**Result preserves both intents.** Neither supersedes the other — §3.2 shows,
by measurement, that each covers a body the other does not touch at all.

Merged source: marker at `src/virp_onode.c:1949`, filter at `:2000`, scrub at `:2018`.

### 2.4 `tests/test_onode.c` — new test blocks (was lines 3841–4344)

Both sides opened a new `/* ==== */` banner block at the same offset, each
running ~250 lines to a shared closing `}`.

| side | wanted |
|---|---|
| 313 | "Scrub-at-capture (S-1) gates — G1..G4" + `gxs_*` helpers, 4 tests |
| origin | "BLACK is unconditional (2026-08-27)", 3 tests |

**Kept:** both blocks, concatenated. 313's block closes its final function with
the shared `}`, then origin's banner is re-emitted and its block follows with
the original `}`. No semantic conflict — pure adjacency. Helper namespaces are
disjoint (`gxs_*` vs the pre-existing shared `gx_*`), which the `-Werror` build
confirms.

### 2.5 `tests/test_onode.c` — `RUN_TEST` registrations (was line 7073)

| side | wanted |
|---|---|
| 313 | `printf("-- Scrub-at-capture (S-1) gates G1-G4 --")` + 4 `RUN_TEST` |
| origin | `printf("[BLACK unconditional ...]")` + 3 `RUN_TEST` |

**Kept:** both, 313's group then origin's. All seven run and pass (§4.3).
If this hunk had been resolved either-way instead of union, four or three tests
would have compiled into the binary and never been called — the test count would
have looked plausible and the gate would have been unwatched.

### 2.6 Summary table

| # | file | what 313 wanted | what origin wanted | resolution |
|---|---|---|---|---|
| 1 | Makefile:45 | `virp_scrub.o` | `virp_body_filter.o` | both |
| 2 | Makefile:1867 | `+test-scrub` | `+test-body-filter` | both |
| 3 | src/virp_onode.c:1949 | S-1 scrub call | barrier marker + body filter call | all three, filter → scrub |
| 4 | tests/test_onode.c:3841 | S-1 G1–G4 block | BLACK block | both blocks |
| 5 | tests/test_onode.c:7073 | 4 `RUN_TEST` | 3 `RUN_TEST` | all seven |

(Hunk 6 in raw marker terms is the `=======` half of #4/#5; the conflict
regions are five, spanning six marker triples as git reported them.)

### 2.7 The near-miss: `src/drivers/driver_cisco.c`

Not a conflict, but both sides changed this file and git auto-merged it, so it
was read rather than trusted. 313 added config-mode support (`cisco_is_mode_changing`,
prompt-transition recovery); origin's `f48360c` added `no_dispatch` /
`NOT_SENT` to the BLACK refusal in `cisco_execute()`. The merged function keeps
origin's BLACK check *first*, then the `!conn->connected` check, then 313's
config-mode logic — the correct order. `test_driver_cisco` goes 16/16 (origin) →
52/52 (merged), i.e. 313's config-mode tests all present and passing alongside.

## 3. What was verified, and how

### 3.1 BLACK is refused before any mode check, in SHADOW too

Read from the merged source, not inferred from tests.

```
src/virp_onode.c:1704   onode_gate_mode_t mode = gate_effective_mode(state, drv->name);
src/virp_onode.c:1712   bool block = gate_tier_blocks(gate_tier, eff_max);
src/virp_onode.c:1724   fprintf(stderr, "[GATE] mode=%s ...")      <- mode read, not branched on
src/virp_onode.c:1754   if (gate_tier == VIRP_TIER_BLACK) {        <- FIRST branch
                            pthread_mutex_unlock(...);
                            return gate_refuse_obs(..., mode, ...);
                        }
src/virp_onode.c:1762   if (mode == GATE_MODE_ENFORCE && block && proposal_id ...)   <- first mode branch
src/virp_onode.c:1832   } else if (mode == GATE_MODE_ENFORCE && block) {
```

Between the mode being computed (1704) and the BLACK refusal (1754), `mode`
appears **only inside the log `fprintf`'s ternaries** — an expression, not
control flow. The first branch on `mode` is at 1762, eight lines *after* the
BLACK return. The BLACK branch also does not consult `block`, so a
misconfigured ceiling that makes `gate_tier_blocks(BLACK, eff_max)` false
cannot admit it either. It runs before the approval-apply path, so an `apply`
reference on a BLACK command is never examined and never consumed.

Behavioural confirmation: `test_shadow_black_refused_recorded_driver_never_invoked`
PASS, `test_black_enforce_refused_at_gate` PASS,
`test_shadow_yellow_red_still_proceed_and_are_recorded` PASS (SHADOW for
non-BLACK tiers is unchanged). The mock driver deliberately has no BLACK
backstop, so these probe the gate alone.

`scripts/check-obs-build-ordering.sh` passes, and its `--selftest` passes in all
four directions (compliant file accepted, violation caught, NULL-result commit
not flagged, deleted marker caught).

### 3.2 The scrub path — do the two mechanisms coexist, duplicate, or conflict?

**They coexist. They do not duplicate, and nothing is scrubbed twice.** This was
*measured*, not reasoned about, with a throwaway probe (scratchpad only, not
committed) linking the merged `libvirp.a` and running both mechanisms over
realistic bodies.

| | `virp_body_filter_apply()` (origin) | `virp_scrub_exec_result()` (313) |
|---|---|---|
| kind | structural allowlist | textual known-shapes redaction |
| scope | `result.output`, only for a `(driver, endpoint)` a rule matches | `result.output` **and** `result.error_msg`, every driver |
| config | `$VIRP_BODY_FILTERS` → `/etc/virp/body-filters.json` → built-ins | none; compiled ruleset |
| records | `_virp_filtered` naming removed keys, in-body, under `artifact_hash` | `[REDACTED: <reason>]` markers in place |
| fail-closed | matched payload that will not parse → withheld stub (sha256 + length) | any scrub failure → whole field becomes `[REDACTED: scrub-error]` |

**Measured result 1 — the S-1 scrubber does nothing to a JSON REST body.**
Given a librenms `GET /api/v0/devices` payload carrying
`"community":"CANARY-COMMUNITY"`, `"authpass":…`, `"cryptopass":…`,
`"sysContact":…`, the scrubber run *alone* returns the body **byte-identical,
zero redactions**. Its generic labeled-secret rule wants a label token followed
by `:` or `=`; in JSON the label is `"authpass"` — the closing quote sits
between the label and the colon, so it does not match. It does not even redact
an `"api_token":"CANARY-TOKEN"` key. On this class of body, **origin's allowlist
is the only defense**, and 313's scrubber cannot be said to subsume it.

**Measured result 2 — the body filter does nothing to CLI output.** Given
cisco `show running-config` text with `username admin password 7 …` and
`snmp-server community … RO`, `virp_body_filter_apply("cisco", …)` returns
`VIRP_BF_UNTOUCHED` (no rule matches a non-REST driver), and the scrubber then
produces `username admin password [REDACTED: password]` /
`snmp-server community [REDACTED: snmp-community] RO`. On this class of body,
**313's scrubber is the only defense**.

**Neither is redundant. Neither is a duplicate. No body is redacted twice** —
a field both could reach is removed structurally by the allowlist first and is
simply not present when the scrubber runs. In the merged order the librenms
body is byte-identical before and after the scrub call (248 bytes → 248 bytes),
i.e. the scrub is a verified no-op there rather than a second pass.

Note this leaves a third layer untouched and still primary: the **per-driver
config scrubs** (`cisco_scrub_config` and siblings, `test-cisco-scrub`,
`test-asa-scrub`, `test-fg-scrub`, `test-linux-scrub`) that both sides already
had. Three layers, all kept: driver-level config scrub → collector allowlist →
generic S-1 net.

**Order: filter first, scrub second.** My decision; neither side made it.

1. The scrub must be the **last** transform before any consumer, so S-1's
   contract — *"the redacted form IS the artifact; the hash commits to it, the
   signature verifies over it"* — is literally true with nothing rewriting the
   bytes afterwards. Under the reverse order the body filter would be the last
   word and S-1's comment would become false.
2. The filter must parse its payload as JSON. A scrub marker substituted into a
   value position would break that parse and downgrade an ordinary body to a
   fail-closed *withhold*. **Honest limit: I could not make this happen with
   today's rulesets** — per measured result 1 the scrubber never matches JSON
   key syntax, so the reversed order also produced a correct result in the
   probe. Argument 2 is therefore forward-looking, not a demonstrated bug.
   Argument 1 stands on its own.

The one behavioural difference between the two orders: in a *withhold*, the
stub's `original_sha256` is over pre-scrub bytes under the chosen order and over
post-scrub bytes under the reverse. A digest is not a disclosure, and provenance
over the bytes as captured is the more useful of the two.

The ordering guard is satisfied: no result-carrying `gate_emit_execution()` or
observation constructor appears above the marker. The two `gate_emit_execution()`
calls that *are* above it (`:1880`, `:1927`) pass `result == NULL` and are
legitimately exempt — checked, not assumed.

### 3.3 Defect B — non-dispatch refusal still routes to ERROR and is still declared

Merged source, `src/virp_onode.c:2087`:

```c
if (!result.success && result.error_msg[0] &&
    (result.no_dispatch ||
     result.disposition == VIRP_DISPOSITION_NOT_SENT ||
     result.output_len == 0)) {
```

— origin's widened predicate intact, including the additive `output_len == 0`
clause, and it still returns `VIRP_OBS_ERROR` via
`virp_build_observation_tiered(..., VIRP_OBS_ERROR, VIRP_SCOPE_LOCAL, ...)` at
`:2140`. The OUTCOME_UNKNOWN branch above it (`:2039`) is unchanged and still
sits first, so the unprovable case still returns UNKNOWN rather than falling
into the refusal branch.

Step 2's driver declarations survive the auto-merge — `no_dispatch = true`
and/or `VIRP_DISPOSITION_NOT_SENT` present in `driver_cisco.c:1170`,
`driver_asa.c:1007/1038`, `driver_juniper.c:673/696/1014`,
`driver_fortigate.c:814/830`, `driver_panos.c:909/920/937/955`.

`make test-refusal-contract` — all five drivers PASS
(`test_asa_black_refusal_obeys_contract`, `test_cisco_…`, `test_juniper_refusals…`,
`test_fortigate_refusals…`, `test_panos_black_refusal…`).

## 4. Build and test results

### 4.1 Build

`make all` and `make prod` both clean under `-Wall -Wextra -Werror -pedantic
-std=c11`. No new warnings.

### 4.2 Two environment failures, both pre-existing, both host-state

`make all-tests` **fails on this box, and failed identically before the merge**,
at its first prerequisite:

1. **`check-deploy-unit` → `check-unit-drift`** — compares repo `deploy/*.service`
   against `/etc/systemd/system` on *this host*. The installed
   `virp-onode.service` is the burn-in unit ("VIRP O-Node (home, governs pve-lab)")
   and diverges from the tracked one. The Makefile itself says this target is
   *"Expected to FAIL on virp-lab today"*. Both `deploy/virp-onode.service`
   (`c3aaf28`) and `scripts/check-unit-drift.sh` (`fd6876a`) are **byte-identical
   on 313's main, origin/main and the merge** — the merge changed nothing here.
2. **`check-test-deps`** — `fastapi`, `httpx`, `reportlab` not importable, so
   `test-api` and `test-virp-report` SKIP and the trailing gate fails the
   aggregate by design. Also host state, also identical on both parents.

Because `check-deploy-unit` aborts the run at target #1, **no suite ran at all**
under a plain `make all-tests`. All runs below therefore use the same
`all-tests` prerequisite list **minus `check-deploy-unit`**, extracted
programmatically from each tree's own Makefile so each side is measured against
its own list.

### 4.3 Merge branch — every suite passes

`make <all-tests minus check-deploy-unit> check-obs-build-ordering test-refusal-contract`
→ **RC=0**. Re-run after the merge commit; identical.

| suite | result |
|---|---|
| test_virp | 59/59 |
| **test_onode** | **141/143 (2 PENDING)** |
| **test_virp_scrub** (313) | **22 tests, 0 failures** |
| test_ssh_io | 13/13 |
| test_driver_fortigate_scrub | 4/4 |
| **test_body_filter** (origin) | **6 passed, 0 failed** |
| test_driver_cisco_scrub | 17, 0 failures |
| test_driver_asa_scrub | 15, 0 failures |
| test_driver_linux_scrub | 14, 0 failures |
| test_driver_linux_connect | 2, 0 failures |
| test_driver_cisco | 52/52 |
| test_driver_cisco_gate | 194/194 |
| test_driver_linux_gate | 199/199 |
| test_driver_juniper | 162/162 |
| test_driver_asa | 180/180 |
| test_driver_panos | 163/163 |
| test_driver_fortigate_black | 149/149 |
| test_driver_wazuh | 3/3 |
| test_driver_librenms | 22/22 |
| test_driver_pbs | 107/107 |
| test_driver_pbs_gate | 74/74 |
| test_driver_zammad_gate | 246/246 |
| test_typed_op_hash | 19/19 |
| test_ingress_nul | 17/17 |
| test_pbs_truncation | 26/26 |
| test_autopilot | Ran 44, OK |
| test_config_backup | Ran 39, OK |
| test_render_devices | 20/20 |
| test_evidence | Ran 50, OK (skipped=12, reportlab) |
| test_chain | 33 |
| test_chain_invariant (C) | 11 |
| test_chain_invariant (py) | 49 |
| test_federation | 10 |
| test_session_negative | 8/8 |
| test_session_key | 6/6 |
| test_obs_v2 | 15/15 |
| test_obskey | 5/5 |
| test_obs_ed25519 | 7/7 |
| test_obs_ed25519_forge | 3/3 |
| test_obs_ed25519_neg | 4/4 |
| test_chainsign | 5/5 |
| test_chain_signing | 14 |
| test_chainsign_vectors | 17 |
| test_validator | 11 |
| test_approval | 24 |
| test_approvers | 9 |
| test_pkcs11_plumbing | 1 |
| test_commitment_grading | Ran 3, OK |
| test_fed_outcome_observation | Ran 4, OK |
| check-obs-build-ordering | PASS (+ 4-way selftest) |
| test-refusal-contract | 5/5 drivers PASS |
| test-api | SKIPPED (fastapi/httpx absent) |
| test-virp-report | SKIPPED (reportlab absent) |

The seven tests that came out of the two conflicted test blocks all ran and all
passed: `test_scrub_G1_clean_capture_verifies`,
`test_scrub_G2_planted_secrets_redacted_and_verifies`,
`test_scrub_G3_fail_closed_full_redaction`,
`test_scrub_G4_existing_entries_untouched`,
`test_black_enforce_refused_at_gate`,
`test_shadow_black_refused_recorded_driver_never_invoked`,
`test_shadow_yellow_red_still_proceed_and_are_recorded`.

### 4.4 Counts against what each side had before

Both parents were checked out into detached worktrees and run with the same
method. Per-suite result lines were extracted and diffed mechanically.

**Baseline — 313's main (`f770256`): RC=2.** It **fails on its own**, before
any merge, at `test-chainsign-vectors`:
`ModuleNotFoundError: No module named 'nacl'`. That is exactly the failure
origin's `69bf43b` ("chainsign vectors must not hard-require PyNaCl") fixes, so
the merge *repairs* a pre-existing red on 313. The run aborts there, so 313
never reaches its last five suites.

**Baseline — origin/main (`ba93598`): RC=0**, all suites pass.

**Merge vs origin/main — two differences, both increases, no decreases:**

| suite | origin/main | merge | delta |
|---|---|---|---|
| test_onode | 137/139 (2 PENDING) | 141/143 (2 PENDING) | +4 = S-1 gates G1–G4 |
| test_driver_cisco | 16/16 | 52/52 | +36 = 313 cisco config-mode |
| *(new)* test_virp_scrub | — | 22, 0 failures | 313's scrub unit suite |

**Merge vs 313's main — all increases, no decreases:**

| suite | 313 main | merge | delta |
|---|---|---|---|
| test_onode | 136/136 | 141/143 (2 PENDING) | +7 = BLACK ×3, PENDING ×2, Defect B ×2 |
| test_driver_panos | 140/140 | 163/163 | +23 = PAN-OS BLACK deny table |
| *(new)* test_body_filter | — | 6 passed | origin's allowlist suite |
| test_chainsign_vectors | **run aborted (no PyNaCl)** | 17 passed | fixed by origin's `69bf43b` |
| test_validator / test_approval / test_approvers / test_pkcs11 | never reached | 11 / 24 / 9 / 1 | 313's run died first |

Every other suite is identical across all three runs.

`test_onode` totals reconcile exactly. The merge base `6e7021e` was checked out
and built to confirm the starting number rather than infer it: **132/132**.
132 + 313's 4 (S-1 gates G1–G4) + origin's 7 (3 BLACK, 2 PENDING, 2 Defect B)
= **143**, which is the merged total. Nothing was lost in either test-block
union, and nothing was double-counted.

**The 2 PENDING are not merge damage.** They are origin's
`PENDING_TEST(test_refusal_with_body_is_not_an_execution)` and
`PENDING_TEST(test_refusal_with_body_is_not_recorded_executed)` — declared
known-failing by design in `f48360c`, pending the three-valued
`gate_execution/2` `executed` field. They fail identically on origin/main.

## 5. Open items — flagged, not fixed

Nothing was left unresolved in the conflicts themselves. These are observations
about the merged tree, deliberately not acted on (no cleanup, no scope creep):

1. **The ordering decision in §3.2 is mine.** Neither side wrote down the
   relative order of the allowlist filter and the S-1 scrub. It is defensible
   (argument 1 is structural and load-bearing) and it is now documented at the
   call site in `src/virp_onode.c`, but a reviewer who disagrees should say so
   before this reaches `main`. Swapping the two lines is the whole change.
2. **`check-obs-build-ordering` is not wired into `all-tests` or CI.** Origin
   added the guard, the Makefile target, and a four-way selftest — but nothing
   invokes it in a normal run. The invariant it protects is precisely the one
   this merge had to get right. I ran it manually (PASS); I did not add it to
   `all-tests`, because that is a change neither side made.
3. **`test-refusal-contract` is likewise unwired.** Five refusal-contract suites
   exist, all pass, none run under `all-tests` or CI. Same reasoning.
4. **The S-1 scrubber does not see JSON.** §3.2, measured result 1. This is
   consistent with SCRUB-DESIGN.md's stated honesty limit, but it is sharper
   than the doc implies: for a REST endpoint with **no matching filter rule**,
   a credential in the JSON body is protected by *neither* barrier mechanism —
   only by whatever the driver itself scrubs. The librenms device inventory is
   the one endpoint with a rule today. This is a pre-existing gap that the
   merge neither creates nor closes, but it is now the sharpest edge in the
   scrub story and should be an item, not a footnote.
5. **`make all-tests` cannot pass on this host** for the two environment
   reasons in §4.2. Both predate the merge and both are host state, not code.
   Anyone re-running this should use the minus-`check-deploy-unit` form and
   install `fastapi httpx pytest reportlab` (and `pynacl`, though origin's
   `69bf43b` makes it optional) to close the two skips.

## 6. Reproducing the verification

```bash
git checkout merge/reconcile-313-origin
make all && make prod                       # clean under -Werror
scripts/check-obs-build-ordering.sh --selftest && scripts/check-obs-build-ordering.sh
T=$(grep '^all-tests:' Makefile | sed 's/^all-tests://' \
      | tr ' ' '\n' | grep -v '^$' | grep -v '^check-deploy-unit$' | tr '\n' ' ')
make $T check-obs-build-ordering test-refusal-contract
```

Read, in this order: `src/virp_onode.c:1754` (BLACK before any mode branch),
`:1949`–`:2018` (the barrier, both mechanisms, the order and why),
`:2087` (Defect B refusal routing), `:2140` (its `VIRP_OBS_ERROR` return).
