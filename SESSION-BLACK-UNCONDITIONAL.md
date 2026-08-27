# SESSION — BLACK is unconditional (gate invariant, PAN-OS, SECURITY.md)

| | |
|---|---|
| Date | 2026-08-27 |
| Host | virp-lab / 10.0.10.211 |
| Branch | `fix/black-unconditional` (from `main` @ `0019813e`, clean) |
| Status | **NOT DEPLOYED.** Nothing in this session touches the running daemon. The running binaries report build `482d8a52` (restarted 2026-08-27 16:54 UTC). This branch's changes reach production only with the next rebuild/install/restart, which the operator controls. Until then the deployed daemon still carries the SHADOW/BLACK gap. |

**The invariant enforced:** BLACK means inexpressible, and inexpressible
is not mode-dependent. SHADOW observes what enforcement would have done
for GREEN, YELLOW, RED and UNCLASSIFIED — that is its purpose — but it
must never turn inexpressible into executable.

---

## Phase 0 — the finding, verified on HEAD

The review examined an older snapshot. Every claim was re-established
against `main` @ `0019813e` before acting. File:line refs below are
pre-fix positions on that commit.

1. **CONFIRMED — SHADOW passed BLACK to the driver.**
   `gate_tier_blocks()` (`src/virp_onode.c:652-657`) returns true for
   BLACK (and UNCLASSIFIED) unconditionally, but both rejection branches
   in `onode_execute_obs_ex()` required `mode == GATE_MODE_ENFORCE &&
   block` (`:1494`, `:1565`). Under SHADOW, a BLACK verdict fell through
   to `get_connection()` (`:1771`) and `drv->execute()` (`:1792`).

2. **Driver BLACK backstops on HEAD** (the review said Cisco, ASA,
   Juniper, FortiGate; PAN-OS none):
   - cisco: `src/drivers/driver_cisco.c:1074` (`cisco_is_black_tier`)
   - asa: `src/drivers/driver_asa.c:1023`
   - juniper: `src/drivers/driver_juniper.c:681`
   - fortigate: `src/drivers/driver_fortigate.c:798` (`fg_is_black_tier`)
   - **linux/proxmox: `src/drivers/driver_linux.c:352` — the review
     under-counted; this backstop exists (since `3ef712fc`) and is the
     strictest placement (before the connected check).**
   - **PAN-OS: none — confirmed.** Worse than the review stated: pre-fix
     `pa_route_command()` could not even RETURN BLACK (no BLACK entries;
     destructive commands like `commit`, `request restart system`,
     `delete` fell through to RED — blocked under ENFORCE but
     *approvable*, and under SHADOW they executed).
   - PR #15 (`b53fbf05`/`f1737806`, ASA refuse-at-load) changed config
     loading only; it did not alter any driver backstop. Confirmed.

3. **UNCLASSIFIED in SHADOW on HEAD: proceeds (executes).** Pinned by
   the pre-existing tests `test_shadow_executes_unclassified_with_honest_tier`
   (`tests/test_onode.c:2490`) and the SHADOW-permissive preconditions in
   the separator tests (`:580-583`).

4. **SHADOW configuration and shipped default.** Compiled-in default is
   ENFORCE with `gate_max_tier=YELLOW` (`src/virp_onode.c:4496-4498`);
   the PROD loader (`load_gate_config`, `src/virp_onode_prod.c:461`)
   reads `gate_default_mode` / per-driver `gate_modes` / `gate_max_tier`
   from devices.json; the dev binary parses no gate keys. **Production
   config on this host today: `gate_default_mode=enforce`,
   `gate_max_tier=yellow`, NO `gate_modes` overrides** — so the gap was
   latent here, exactly as audit §4.7 said.

5. **Baselines** (clean build, main @ 0019813e):
   - `make test` 59/59 · `make test-onode` 134/136 (2 PENDING,
     known-failing by design: gate_execution/2 three-valued executed) ·
     chain/invariant/federation 33+11+49+10, all pass.
   - `make test-drivers`: 16, 194, 199, 162, 180, **140 (panos)**, 149,
     19, 3, 22, 107, 74, 246, 19, 17, 26 — all pass.
   - Python: autopilot OK, config-backup OK, evidence OK,
     commitment-grading OK, **fed-outcome-observation FAILS on baseline
     (2 failures — it audits the LIVE chain and flags 2026-08-11 rows;
     pre-existing, unrelated)**, virp-report / chainsign-vectors /
     validator-e2e / api: see final table below.

### Review/tree claims that current main contradicted

- **"Only Cisco, ASA, Juniper, FortiGate have driver backstops"** —
  linux/proxmox has one too (`driver_linux.c:352`).
- **Code comment (pre-fix `virp_onode.c:1335-1337`): "linux and wazuh
  run with SHADOW overrides in production"** — the production
  devices.template.json on this host has NO `gate_modes` key; the node
  runs enforce for every driver. Stale comment (left in place — it sits
  inside the Layer-1 refusal rationale, which is mode-independent and
  still correct).
- **Code comment (pre-fix `virp_onode.c:1508-1515`): "the linux/FRR
  table is pinned to top out at RED by `test_never_returns_black()` in
  `tests/test_driver_linux_gate.c`"** — doubly wrong on HEAD: that test
  lives in `tests/test_driver_zammad_gate.c:749` (pinning the *zammad*
  table), and the linux classifier DOES return BLACK
  (`linux_gate_classify` never-tier, `driver_linux.c:2480-2491`).
  The comment was rewritten as part of the gate restructure.
- **"Old systemd trust-chain notes" in SECURITY.md** — no such notes
  exist in SECURITY.md on HEAD (searched current text and the file's
  git history). The underlying concern (units executing repo paths,
  install-by-memory) was real and was closed by `32dd710f` +
  `3a5d741a` (`check-deploy-unit` / `check-unit-drift`); the new
  OBSOLETE section records that closure and where the notes actually
  lived (deploy records).

---

## Phase 1 — BLACK unconditional in the gate (`src/virp_onode.c`)

- The two-site rejection blob was extracted into one helper,
  `gate_refuse_obs()` (proposal filing — never for BLACK; chain
  persistence; log; signed ERROR observation).
- A dedicated branch now sits BEFORE any mode logic, and before the
  approval-apply path — the reader sees **"BLACK: refuse, always"** as
  its own branch:

  ```
  if (gate_tier == VIRP_TIER_BLACK) { unlock; return gate_refuse_obs(...); }
  ```

- **Recording:** the SHADOW refusal writes the SAME `gate_rejection/1`
  entry an ENFORCE refusal writes. The body gains an additive
  `gate_mode` field ("ENFORCE"/"SHADOW") — the same field
  `gate_execution/1` has carried from the start, so the chain shows a
  BLACK was attempted and refused under SHADOW instead of leaving that
  to be inferred from an absence. Schema id kept at `/1` (additive
  field; precedent: `effective_max_tier`/`ceiling_source` were added
  additively; consumers checked — `capture_chain.py`,
  `test_virp_report.py`, the report tooling — none enumerate fields
  strictly).
- The `[GATE]` journal line logs `decision=block` for BLACK in BOTH
  modes (nothing hypothetical to report).
- **Behavior delta on the apply path:** a BLACK command carrying a
  `proposal_id` is now refused by the unconditional branch BEFORE any
  approval verification — the approval reference is not examined and
  nothing is consumed. Previously it produced "apply rejected
  (TIER_VIOLATION)"; now it produces the standard "tier gate blocked"
  refusal. Both refuse; the in-path TIER_VIOLATION check is retained as
  an explicitly-marked belt.
- SHADOW for GREEN/YELLOW/RED/UNCLASSIFIED: byte-for-byte the same
  admit-and-record path as before (pinned by new test, below).

### The UNCLASSIFIED-in-SHADOW decision

**UNCLASSIFIED in SHADOW proceeds (observed). Implemented as-is — i.e.
unchanged.** I judge this forced by existing policy, so it is NOT
queued for a ruling; the reasoning, for review:

1. It is already pinned by tests on main
   (`test_shadow_executes_unclassified_with_honest_tier`, plus the
   SHADOW separator tests' preconditions).
2. The design comment at `onode_init` states that classifier-less
   drivers yield UNCLASSIFIED for everything and "deployments that need
   them must opt them into shadow explicitly" — refusing UNCLASSIFIED
   under SHADOW would make that opt-in meaningless and SHADOW useless
   for exactly its primary use case.
3. BLACK and UNCLASSIFIED are different in kind: BLACK is a
   classifier's affirmative verdict of inexpressibility; UNCLASSIFIED
   is the absence of knowledge, which is precisely what SHADOW exists
   to observe (and it is recorded honestly — tier UNCLASSIFIED on the
   observation, `gate_execution` entry with `gate_mode=SHADOW`).

If that reasoning is rejected, the change is one condition in the same
branch structure.

### Phase 1 tests (tests/test_onode.c, mock driver)

The mock classifier gained a BLACK verb (`selfdestruct`) and its
execute() deliberately has NO BLACK backstop — so these tests probe the
gate alone; a leak executes and is caught directly.

- `test_black_enforce_refused_at_gate` — **new**. No end-to-end
  gate-level BLACK-under-ENFORCE test existed on main (the session
  prompt assumed one did; the closest things were driver-classifier
  assertions and `gate_tier_blocks` mirrors). Refused even at
  `max_tier=RED`, ERROR observation, wire tier clamped to RED, driver
  never invoked (exec-attempt counter = 0).
- `test_shadow_black_refused_recorded_driver_never_invoked` — **the
  invariant test** (greppable by "shadow"+"black"). Proves the state is
  SHADOW-permissive first (UNCLASSIFIED executes), then: BLACK refused,
  driver never invoked, chain holds a `gate_rejection/1` entry with
  `classified_tier=BLACK`, `gate_mode=SHADOW`, `executed:false`, no
  proposal, body hash bound to the entry's commitment.
- `test_shadow_yellow_red_still_proceed_and_are_recorded` — pins
  SHADOW's purpose: YELLOW (would-allow) and RED (would-block) both
  proceed and leave `gate_execution` records naming SHADOW.
- BLACK-via-driver-with-no-backstop in SHADOW: covered twice — at the
  mock (no backstop, above) and at PAN-OS (real driver, Phase 2 below).

## Phase 2 — PAN-OS grammar and BLACK table (`src/driver_panos.c`)

- **BLACK deny table** `PA_BLACK_COMMANDS` + `pa_is_black_tier()` —
  prefix-matched, case-insensitive, structurally identical to
  `CISCO_BLACK_COMMANDS`/`FG_BLACK_COMMANDS`. Entries (derived from the
  PAN-OS CLI reference / Palo Alto KB, cited in the table comment):
  `commit`, `load `, `scp import`, `tftp import`, `delete`,
  `request restart system`, `request shutdown system`,
  `request system private-data-reset`, `request system raid`.
  (There is no bare `import` verb in PAN-OS — imports arrive as
  `scp import ...`/`tftp import ...`; `delete` covers saved-config,
  certificate and key deletion in both op and config mode, matching
  ASA's bare-`delete` precedent.)
- **`pa_route_command()` returns BLACK** for deny-table matches —
  like ASA/JunOS, unlike Cisco/FortiGate whose classifiers top out at
  RED. This is what lets the Phase 1 gate branch protect PAN-OS in
  SHADOW *at the gate*, before any connection.
- **`pa_execute()` backstop** — before the connected check (linux
  precedent: policy is independent of reachability), refusal-contract
  shape (`no_dispatch` + `NOT_SENT`, empty output, reason in
  `error_msg`, `VIRP_OK`).
- **YELLOW narrowed:** `debug`, `test`, `less`, `tail` are OUT.
  `debug` reaches process restarts; `less`/`tail` read arbitrary on-box
  log files; none had an enumerated safe subset — so their commands
  fall to RED by absence ("approvable is the correct home for 'we have
  not enumerated what's safe'"). Kept as YELLOW: exact known-safe
  forms only — `test security-policy-match`, `test nat-policy-match`,
  `test pbf-policy-match`, `test decryption-policy-match`,
  `test routing fib-lookup` (verified against the PAN-OS CLI docs),
  plus the existing `ping`/`traceroute`. No prefix-match widening
  anywhere.
- **Stated plainly (and in SECURITY.md): PAN-OS remains the
  least-mature driver. This change narrows exposure but does not make
  it enforcement-equal to Cisco or FortiGate.**

### Phase 2 tests

- `tests/test_driver_panos.c` (140 → 163 passing): every BLACK entry
  classifies BLACK (incl. case-insensitivity); formerly-YELLOW verb
  arguments now RED (`debug dataplane pool statistics`,
  `debug software restart process`, `less mp-log`, `tail follow`,
  unlisted `test scp-server-connection`); allowlisted exact YELLOW
  forms still YELLOW; and a gate-level pair driving the REAL driver
  through a real O-Node state: `request restart system` refused at the
  gate in ENFORCE **and** SHADOW, before any connection attempt.
  The old `test_no_match_fails_closed` entries for `commit`/`delete
  .../request restart system` (previously RED-by-absence) moved to the
  BLACK section — strictly tighter; the fail-closed default is still
  pinned by other unlisted commands.
- `tests/test_driver_panos_refusal.c` (**new**, wired into
  `test-refusal-contract`): `pa_execute` refuses `request restart
  system` and `commit force` under the full refusal contract, on a
  DISCONNECTED conn (policy beats reachability). All five refusal
  suites pass.

## Phase 3 — SECURITY.md current-state taxonomy

New section **"Current State — Status Index (introduced 2026-08-27)"**
with the four statuses; every tracked item carries exactly one:

- **FIXED** — audit §4.1/§4.3/§4.4/§4.5 (deployed 2026-08-01); §4.8
  proxmox classifier (`8bdfe3f9`); node_id==0 closed (`5bbbacfe` +
  `b733153d`, deployed `a3752e18`); linux/proxmox mode-independent
  backstop (`3ef712fc`); refusal contract (`f48360c1`).
- **FIXED, NOT DEPLOYED** — deployment boundary stated as running
  build `482d8a52`; PR #15 (ASA refuse-at-load); audit §4.7 BLACK
  unconditional (this branch); PAN-OS BLACK table + narrowed YELLOW
  (this branch, with the least-mature sentence).
- **OPEN** — §4.2 abbreviation fallthrough (honest shape restated);
  §4.6 core: approval signature does not cover the `device` string,
  pending the format window (its node_id==0 sub-claim moved to FIXED);
  execution intent (gate_execution/2 three-valued `executed`, tracked
  by the two PENDING tests); §4.5 residual diagnostics; TCP-path
  mutual auth; command-gate scope limits.
- **OBSOLETE, RETAINED FOR HISTORY** — proxmox-no-classifier text,
  node_id==0 text, the SHADOW/BLACK latent note, the systemd
  unit-trust-chain concern (closed `32dd710f`/`3a5d741a`), and the
  per-caller-policy TODO (superseded by `5841ec71` per-uid ceilings +
  Item-8 action allowlists) — each pointing at its closing commit.

No history deleted or edited: the audit list, review sections and old
TODOs stand as written; dated blockquote status notes (house style,
matching the existing 2026-07-31/2026-08-07 corrections) are appended
at the audit open-items list and at the per-caller TODO, pointing into
the new index.

## Also observed, deliberately untouched

- `make test-refusal-contract` in a plain driver-less build fails to
  LINK (`libvirp.a` lacks `virp_ssh_hostkey.o` unless a driver flag is
  set — Makefile:161). Pre-existing on main since the target's
  introduction (`f48360c1`); the suites link and pass under a
  driver-enabled build (`BUILD_DIR=build-drivers CISCO=1 ... ASA=1
  JUNIPER=1 FORTIGATE=1 PANOS=1`), which is how they were run here.
- `make test-fed-outcome-observation` fails on the live chain
  (2 failures, rows from 2026-08-11) — fails identically on the
  baseline; a live-data audit finding, not a regression.

## Final suite results vs baseline

| Suite | Baseline (main @ 0019813e) | After (this branch) |
|---|---|---|
| make test | 59/59 | 59/59 |
| make test-onode | 134/136 (2 PENDING) | 137/139 (same 2 PENDING; +3 new tests) |
| chain / chain-invariant / federation | 33 · 11+49 · 10 | identical |
| test-drivers (16 suites) | all pass; panos 140/140 | all pass; panos 163/163, rest identical |
| test-refusal-contract (driver build) | 4 suites pass | 5 suites pass (panos added) |
| Python: autopilot, config-backup, evidence, commitment-grading | OK | OK |
| Python: fed-outcome-observation | FAIL (live-data, pre-existing) | FAIL (identical) |
| Python: virp-report | 47 tests OK, 1 skipped (runs ~77 min — verifies the 207k-entry live chain in Python) | same run¹ |
| Python: chainsign-vectors | 17/17 (needs `build/test_chain_signing` present — `make test-chain-signing` first; 13/17 + "binary missing" is the clean-build trap, not a failure) | 17/17 |
| Python: validator-e2e | OK (3 tests) | OK |
| Python: api | SKIP — fastapi/httpx not importable on this host (pre-existing environment condition) | SKIP (same) |

¹ The Python suites are pure Python and do not link the C tree; the
suites that DO invoke built C binaries (chainsign-vectors,
chain-invariant) were re-run against the final tree and pass. The
77-minute virp-report run was executed once, spanning the session; its
live-chain subject is independent of the working tree.

## Not deployed — restated

**Nothing from this session runs in production.** No install, no
restart, no push. The running daemon (build `482d8a52`) still executes
a BLACK-classified command under a SHADOW override and still has no
PAN-OS BLACK table. The fix ships with the next rebuild, operator-
controlled. SECURITY.md's FIXED-NOT-DEPLOYED entries say the same.
