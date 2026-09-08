# OVERNIGHT-REPORT-2 — V39 review items

Unattended run, laptop only. Fresh clone `~/virp-overnight-2`, branched off
`origin/main` at `2cb9130`. Nothing was pushed, merged or tagged; no host was
contacted; no database, unit file or installed binary was touched; no other
`~/virp*` clone was opened for writing.

Written 2026-09-02 (UTC).

## Table

| # | Item | Branch | Head | Tests before → after | Status | One line |
|---|------|--------|------|----------------------|--------|----------|
| 0 | Baseline (read-only) | — (measured on `main`) | `2cb9130` | see §0 | **DONE** | Baseline captured. Two pre-existing harness defects found (F1, F3) — F3 turned out to explain the long-standing `test_onode` "flakiness" entirely; under an isolated `/tmp` the suite is 157/159 exit 0, deterministically. Before-image for item 1 recorded from a real fault-injected run. |
| 1 | Approved apply, outcome append fails | `fix/approved-outcome-fail` | `88c1a03` | 30 new checks 0 → 30; regression suites unchanged | **DONE** | `approval_emit_outcome()` returns an error; the approved path now returns the signed `unchained-execution` error instead of an ordinary success. |
| 2 | Signing activation, fail closed | `fix/signing-activation` | `aba582c` | `test-signing-activation` 3 passed / 2 PENDING (new); chain suites unchanged | **PARTIAL** | Not ruled → option C. Runbook + tests written; the two option-A acceptance criteria are pinned as PENDING known-failing. No daemon code change. |
| 3 | Bind sessions to the peer UID | `fix/session-owner-uid` | `ff0f809` | `test-session-owner` 10/10 (new); `test-onode` 157/159 unchanged | **PARTIAL** | Ownership recorded at HELLO from SO_PEERCRED and enforced on HELLO/BIND/EXECUTE(v2)/CLOSE; the evidence-recording half was stopped at the canonical-bytes fence and is written up instead. |
| 4 | Evidence-degraded concurrency | `docs/degraded-concurrency` | `eabb33c` | n/a (memo) | **DONE** | `docs/DEGRADED-CONCURRENCY.md`: today's behaviour, options (a) and (b) with costs, no recommendation. |

---

## Provisional decisions taken (every point where a human would have been asked)

**P0 — Another Claude Code session was open in a `~/virp*` clone.** The
launch precondition says not to start while one is working there. PID 717514
had cwd `~/virp-remediation-2026-08-31` with uncommitted changes, but no file
in that tree had been modified for over an hour, so it was idle rather than
working. My work is in a separate fresh clone and never touched that one.
**Provisional answer: proceed.**

**That judgement was half wrong, and the report has to say so.** That session
woke up mid-run: at 00:09 local it was executing `rm -rf /tmp/virp-*` and its
own `./build/test_onode` from that clone. It never touched
`~/virp-overnight-2` and I never wrote into its tree — the isolation of the
*work* held. What did not hold was the isolation of the *measurements*: we
share `/tmp`, and every suite in this project hardcodes `/tmp/virp-*` paths
(F3). Every shared-`/tmp` number I took before spotting that is unreliable,
and **none of them are used in this report**; everything below was re-measured
under a private tmpfs namespace. The launch precondition was there for exactly
this reason, and "idle for an hour" was not a safe reading of "not working".

**P1 — `fix/v0.2.1` does not exist on `origin`.** The order assumes it was
merged or parked. There is no such branch and no such merge on `main`.
**Provisional answer: branched off `origin/main` @ `2cb9130` as instructed.**

**P2 — Item 2 has no box ticked.** Treated as **option C**, exactly as the
order specifies: tests-and-runbook only, against option A as the provisional
choice, and **no daemon code change**.

(Further per-item decisions are recorded in their sections.)

---

## §0 — Baseline

### How to reproduce a clean baseline

This turned out to be the substance of item 0. `make all-tests` is **not**
reproducible on a laptop unless two things are done first, and neither is
obvious from the target:

    make clean                        # F1: a FAILED asan-test poisons build/
    unshare -Umr sh -c \
      'mount -t tmpfs tmpfs /tmp; cd <repo> && make -k all-tests'   # F3

The `unshare` gives the run a private tmpfs `/tmp`, which is the only thing
that makes the hardcoded `/tmp/virp-*` test paths safe against another clone
running the same suites. It costs two known artifacts, because it also maps
the caller to uid 0 in the namespace:

- † `test_key_load_ownership_integration` (in `test`) takes a `geteuid()==0`
  branch and calls `chown(path, 65534, 65534)`; uid 65534 is not mapped
  inside the namespace, so the `chown` fails. 61/61 outside.
- ‡ `1.1(item3) cache write fails after intent` (in `test-approval`) makes a
  write fail with `chmod(DIR, 0500)`; root ignores directory permissions, so
  the write succeeds and the test's own precondition collapses. 31/31
  outside.

Both are the isolation, never the code, and both are re-checked un-isolated
for every item below.

### Numbers — `main` @ `2cb9130`, clean build, ISOLATED `/tmp`

`make -k all-tests` → **MAKE_EXIT=2**, from exactly **one** real pre-existing
cause plus two artifacts of the isolation itself:

1. **`test-refusal-contract`: 5 binaries fail to LINK** — real, pre-existing,
   already on record. `test_driver_{asa,cisco,juniper,fortigate,panos}_refusal`
   need `virp_ssh_hostkey.o`, which is only compiled when an SSH driver flag
   is set. The Makefile prints the explanation and the fix (`make prod`, or
   `make ASA=1 build/test_driver_asa_refusal`). This is the only genuine
   `all-tests` failure on `main`.
2. `test` and `test-approval` fail **only inside the isolation namespace**,
   for the two root-DAC reasons at † and ‡ above. Outside it they are 61/61
   and 31/31.

**`test-onode` passes: 157/159, exit 0**, the only two non-passes being the
by-design PENDING pair (`gate_execution/2` three-valued `executed`). That is
the headline correction to my own first three baseline attempts, which
reported 152–155/159 with a *varying* set of socket-test failures. Those were
never flakiness in the tests — they were `/tmp` collisions (F3), including
with another Claude session running the same suites from a different clone
(F4). Under an isolated `/tmp` the suite is deterministic on every branch.

Reproducing this requires two things that are not obvious from the target,
and the first of them is finding F1:

    make clean                          # F1 — a FAILED asan-test poisons build/
    unshare -Umr sh -c 'mount -t tmpfs tmpfs /tmp; cd <repo> && make -k all-tests'

Everything else in `all-tests` passed. Rather than reprint a suite table
whose rows I cannot attribute with confidence (the recursive-`$(MAKE)`
targets interleave their output), here are the suites I actually **gated the
night's work on**, each run individually with an isolated `/tmp`, on `main`:

| Target | Result |
|---|---|
| `test` (test_virp) | 61/61 (62 tests / 1 failure inside the namespace — the root-only branch, see †) |
| `test-onode` | **157/159, exit 0** — the only two non-passes are the by-design PENDING pair |
| `test-chain` | 33/33 |
| `test-evidence-binding` | 7/7 |
| `test-chain-invariant` | 49/49 (D-0 Appendix A locks) |
| `test-chainsign-vectors` | 17/17 (D-1 golden vectors) |
| `test-chain-signing` | 14/14 |
| `test-federation` | 11/11 |
| `test-validator` | 11/11 |
| `test-approval` | 31/31 |
| `test-approvers` | 9/9 |
| `test-evidence` | 50 tests OK |
| `test-commitment-grading` | 3 tests OK |
| `test-open-execution-grading` | 14 tests OK |
| `test-evidence-fi` | all FI checks passed |
| `test-chain-atomicity-fi` | passed (`mid_outcome` SIGKILL) |
| `test-api` | 87 passed |
| `asan-drivers` | **246/246, exit 0** |
| `asan-test` | same flaky cluster as `test-onode` (F2/F3); **no ASan or UBSan report of any kind** |

### Silent skips (per the Aug 9 finding)

Five, all announced but none of them failing the build:

- `check-deploy-unit` — `SKIP: no virp-* units installed under
  /etc/systemd/system`. Correct on a laptop; means the unit-drift gate is
  **not** exercised here.
- `test-interop` — `SKIPPING test-interop: no Go toolchain on PATH`. The Go
  reference implementation is not cross-checked in this run.
- `tests/test_fed_outcome_observation.py` — `SKIPPING: no chain database at
  /var/lib/virp/chain.db`. Federated observation pointers are not covered.
- 8 × `[SKIP]` in the Wazuh driver suite — require `VIRP_LIVE_WAZUH=1`.
- `test-virp-report` degrades without `reportlab` (documented in the Makefile).

### Fault-injection harness

- `make onode-fi` **builds** (`build-fi/virp-onode-prod`, LAB ONLY).
- `make test-evidence-fi` **passes** (all FI checks).
- `make test-chain-atomicity-fi` **passes** (`mid_outcome` SIGKILL).
- `tests/adversarial/fi-run.sh` **cannot run on the laptop** and was not run.
  It requires `/opt/virp/build-fi/virp-onode-prod`, `/opt/virp/build/virp`,
  `/run/virp-fi`, `sudo`, the witness installer under `/opt/virp/tests/`, and
  a live `clab-frr-ospf-frr1` container. `/opt/virp` and `/run/virp-fi` do not
  exist here and the container is not running. Reaching it would mean touching
  an O-Node host, which the fence forbids. **Recorded as fenced, not as
  passing.**

### Before-image for item 1 — measured, not assumed

Written as `tests/test_approved_outcome_fi.c` in probe mode and run against
**unmodified** `main`. An approved RED apply, device acted, `outcome` append
forced to fail (`evidence_fail_closer_once`):

    [probe] rc=0 obs_type=7 ran=1
    [probe] payload="R-AOFI#reload
    % Invalid input detected at '^' marker.
    "

- The caller received **`obs_type=7` = `VIRP_OBS_DEVICE_OUTPUT`** — a signed
  ordinary-success observation carrying the device's own bytes. Nothing in it
  says the outcome was not chained.
- Chain: exactly **one** `gate_intent` citing the approval, **zero** `outcome`
  entries; the `approval:R-AOFI` session still ends at the `approval` entry.
- Verifier: `valid=1 first_broken=-1 executions_open=1 executions_closed=0`.
- The daemon **had** latched `evidence_degraded` — silently, from the
  caller's point of view.
- A second apply of the same approval was refused `approval_reused` (-37)
  and dispatched nothing.

That is the defect in one screen: *the ledger and the caller disagreed, and
only the ledger was right.*

### Findings from item 0 (harness defects, none fixed — out of scope)

**F1 — a failed `asan-test` poisons every later plain build.** `asan-test`
builds into the shared `build/` tree and cleans it *as its last step*. Its
test run failed for the F3 reason, so it exited non-zero before the cleanup
and left ASan-instrumented objects behind; the next ordinary `make
all-tests` then fails to LINK **thirty-five** targets with `undefined
reference to __asan_*`. The Makefile comment predicts this exactly ("If
asan-test is INTERRUPTED before this line, run `make clean` once") — the gap
is that a *failing* asan-test counts as interrupted, and nothing says so at
the point of failure. Cheap fix, not taken tonight: make the cleanup a
trap/`.ONESHELL` step, or run the tests with `-` so the clean always runs and
the failure is re-raised after it.

**F2 — `test_onode`'s socket tests are NOT flaky; they were being
trampled.** `test_sign_intent_*`, `test_sign_outcome_*` and
`test_peer_uid_allowed` fail with `n == -1` (no connection) or `-8`, in a set
that varies run to run. I recorded that as flakiness across three attempts,
and it isn't: it is F3. Give the run a private `/tmp` and `test_onode` scores
**157/159, exit 0, every time, on every branch tonight** — the only two
non-passes being the by-design PENDING pair. The mechanism is a stale
`/tmp/virp-onode-*.sock`: `bind()` fails, the in-test daemon never listens,
and every test that talks to that socket returns -1. It varied with build
flags only because it varied with timing and with what the previous run left
behind. **Correction to my own §0 first draft, which called it flakiness.**

**F3 — test suites across clones collide in `/tmp`.** Paths like
`/tmp/virp-onode-test.sock`, `/tmp/virp-onode-test-cappend.db` and
`/tmp/virp-test-approvals` are hardcoded and are not cleaned up on exit. Two
clones (this one and `~/virp-remediation-2026-08-31`) running tests at the
same time write the same files. This is also how my first three baseline
attempts disagreed with each other. Fix would be a per-run temp directory
(`mkdtemp`, or `$TMPDIR` honoured), not more `rm -rf` in the Makefile.

---

## §1 — Approved apply, outcome append fails (`fix/approved-outcome-fail`)

**Status: DONE.** Head `88c1a03`, two commits off `main` (the fix, then a
one-line Makefile commit putting the new FI target into `all-tests`).

### What was required and what landed

| Required | Landed |
|---|---|
| `approval_emit_outcome()` returns an error | yes — `virp_error_t`; `VIRP_OK` when the chain is disabled (nothing to fail), the append's own error otherwise |
| Signed error of a new kind, `unchained-execution`, never ordinary success | yes — at **all five** approved call sites, not just the success one |
| The error names the intent entry hash and the approval | yes — `intent %.16s is OPEN`, plus `approval <proposal_id> (approval entry %.16s)` |
| Intent stays visibly OPEN; no synthetic outcome | yes — nothing is written on the failure path |
| Approval consumed permanently; no daemon retry | yes — already true structurally (the committed `gate_intent` IS the consumption); pinned by test |
| Evidence-degraded latches, same latch | yes — unchanged `onode_mark_evidence_degraded()` |
| Physical action failed AND append failed → still `unchained-execution`, and the response says the caller cannot tell | yes — the four driver-failure sites carry the same error, and the message contains "whether the device changed cannot be determined from this response" |

### The shape of the change

One helper, `gate_unchained_execution_obs()`, now serves both halves. With
`proposal_id == NULL` it emits the **auto-execute** wording character for
character as it was, so `tests/test_evidence_fi.c` sees an identical payload;
with a proposal id it adds the approval reference and the
cannot-be-determined sentence.

The five approved sites are the four driver-failure returns
(`src/virp_onode.c` — driver execute failed, the no-dispatch retry, the
typed `OUTCOME_UNKNOWN`, and the driver-refused branch) and the success
return after the observation is built.

### What was deliberately NOT changed

The `outcome` append stays **after** the observation build. SECURITY.md said
closing this gap meant moving it, and that moving it was entangled with the
`pre_outcome` fault point. That premise was wrong in a useful way: the caller's
response can be replaced *after* a failed append without moving the append at
all. So `VIRP_FI("pre_outcome")` sits exactly where the adversarial crash
transcript pins it, and the artefact set that survives a kill there is
unchanged.

That is **proved, not asserted**: `tests/test_approved_outcome_fi.c` phase C
forks a child which builds its own daemon on the same on-disk paths, arms
`VIRP_FI_POINT=pre_outcome`, and applies. The parent asserts the child died
by SIGKILL, that the `gate_intent` committed before the kill (so the approval
is consumed), and that **no** `outcome` entry survived — the same three facts
`tests/adversarial/transcripts/02-crash-around-execution.md` records for that
row.

### Tests

`make test-approved-outcome-fi` — new, LAB-ONLY, `build-fi/` only, private
`/tmp` chain and spool. **30 checks, three phases:**

- **Phase A (negative).** Clean approved apply with no fault: ordinary
  `VIRP_OBS_DEVICE_OUTPUT`, the payload is the device's own bytes verbatim,
  no `unchained-execution` marker, the `outcome` entry lands, the daemon is
  not degraded. This is the "byte-identical to today's" requirement. See the
  caveat below on what "byte-identical" can mean.
- **Phase B (the fix).** Outcome append forced to fail after the device
  acted: signed ERROR (not DEVICE_OUTPUT), payload cites
  `unchained-execution`, names the proposal id, says `OPEN`, says the device's
  state cannot be determined, says `evidence-degraded`, carries no device
  output; exactly one `gate_intent` cites the approval and **zero** `outcome`
  entries exist; the `approval:<device>` session still ends at the APPROVAL
  entry; the latch is set; a second apply dispatches nothing and is refused
  `approval_reused` (-37); the C verifier reports `valid=1 first_broken=-1
  executions_open=1 executions_closed=1` (the open one is this apply, the
  closed one is phase A).
- **Phase C (non-regression).** The `pre_outcome` SIGKILL described above.

Python parity: `test_unchained_approved_apply_is_open_not_broken` in
`tests/test_open_execution_grading.py` builds the resulting shape — an
`approved-apply` `gate_intent` with no closer — and asserts `report/verify.py`
grades it CLEAN with one open execution and no failure, matching the C
verifier. `make test-open-execution-grading`: 15 tests, was 14.

### Regression evidence (isolated `/tmp`, see §0 F3)

| Suite | Result | exit |
|---|---|---|
| `test` (test_virp) | 61/62 (1 namespace artifact†) | 2 |
| `test-onode` | 157/159 (2 PENDING by design) | 0 |
| `test-approval` | 30/31 isolated (1 namespace artifact‡); **31/31 un-isolated** | 2 / 0 |
| `test-chain` | 33/33 | 0 |
| `test-evidence-binding` | 7/7 | 0 |
| `test-chain-invariant` | 49/49 | 0 |
| `test-commitment-grading` | 3 tests OK | 0 |
| `test-open-execution-grading` | **15** tests OK (was 14) | 0 |
| `test-chainsign` / `test-chain-signing` / `test-chainsign-vectors` | pass / 14 / 17 | 0 |
| `test-evidence` | 50 tests OK | 0 |
| `test-session` | pass | 0 |
| `test-evidence-fi` | all FI checks passed (**unchanged**) | 0 |
| `test-chain-atomicity-fi` | pass | 0 |
| `test-approved-outcome-fi` | **30/30, new** | 0 |

† `test_key_load_ownership_integration` calls `chown(path, 65534, 65534)`
under a `geteuid()==0` branch. Inside the isolation namespace uid 65534 is
not mapped, so the `chown` returns -1. Passes outside the namespace.

‡ `1.1(item3) cache write fails after intent` makes the consume-cache write
fail with `chmod(DIR, 0500)`. Root ignores directory permissions, so inside
the namespace the write succeeds and the test's own precondition fails.
**31/31 outside.** Both artifacts are the isolation, not the change.

### Provisional decisions and caveats

**D1.1 — "byte-identical to today's" cannot be taken literally, and is not
claimed.** A signed observation carries a sequence number and is signed over
it, so two runs of the same successful apply never produce identical bytes.
What is claimed, and what phase A pins, is that the success return path is
*unreached* by this change: the new code is a `return` inside
`if (oerr != VIRP_OK)`, after the existing append call, so when the append
succeeds the function returns through exactly the same statement as before.
The diff shows it.

**D1.2 — the error buffer grew from 512 to 768 bytes.** The auto-execute
message text is unchanged, but the buffer that holds it is larger because the
approved wording is longer and both share the helper. For a command long
enough to overflow 512 bytes, the old code truncated the message and the new
code truncates later. That is strictly more information in the one case it
differs, and no test depends on the truncation point. Recorded because it is
the only behavioural difference on the auto-execute path.

**D1.3 — a v2 approved apply burns one session sequence number on the
failure path.** At the success site the observation has already been built
(and, for `obs_version == 2`, `session.last_seq` already incremented) before
the outcome append is attempted; the replacement error is a v1 tiered
observation. So a v2 caller that hits this sees a gap in its session sequence.
The verifier's replay store checks monotonicity, not density, so a gap is not
a failure — but it is a real difference and it is the direct consequence of
NOT moving the append. The alternative (move the append earlier) was rejected
because it moves `pre_outcome`. **Flagged for Nate; no action taken.**

**D1.4 — no Docket fixture was emitted, and there is nothing to emit it
for.** The order says "if Docket's Rust verifier has a fixture format for
this". It does not. `grep -r gate_intent ~/docket` returns nothing at all:
Docket's `virp-verify` crate has no notion of `gate_intent`, closers, or
open-execution grading, and its fixtures (`crates/virp-verify/tests/fixtures/
comp-*-20260829`) are whole exported bundle *directories* produced by a real
camera producer against a live O-Node — deliberately never hand-written ("a
fixture that no producer emitted is how a verifier ends up agreeing with a
format nothing actually produces", per that directory's own README). Emitting
one would mean either hand-writing a bundle, which that README forbids, or
running the export tooling — which is not in this repo. **Recorded as a gap:
Docket does not grade open executions at all.** That is a finding worth more
than the fixture would have been.

---

## §3 — Bind sessions to the peer UID (`fix/session-owner-uid`)

**Status: PARTIAL** — the enforcement half is DONE; the evidence-recording
half was stopped at the canonical-bytes fence, as the order requires, and is
written up instead. Head `ff0f809`, one commit off `main`.

### What was required and what landed

| Required | Landed |
|---|---|
| Store `session_owner_uid` at HELLO from the kernel-authenticated peer uid | yes — `state->session_owner_uid` / `session_owner_valid`, guarded by `session_mutex` |
| HELLO, BIND, v2 EXECUTE, CLOSE must come from that uid; mismatch refused | yes — all four |
| Refusal names the session and nothing else; does not leak the owner uid | yes — see D3.1 on the word "signed" |
| Record both the kernel uid and the asserted client identity in the evidence | **STOPPED at the fence** — see below |
| Tests: cross-uid HELLO/BIND/EXECUTE/CLOSE refused; same-uid unchanged; the netclaw bridge sequence still passes as one uid | yes — `tests/test_session_owner.c`, 10 checks |

### The check itself

`onode_session_owner_refused_locked()` is the single decision, called from
four places — the HELLO, BIND and CLOSE handlers and the v2 EXECUTE
pre-flight. It is permissive when no owner is recorded, permits the owner,
refuses a different uid, and does not gate the internal `(uid_t)-1` caller.
It also **expires** a stale record: a DISCONNECTED or CLOSED session is owned
by nobody. That is what keeps the ordinary serial workflow — uid A opens,
uses and closes a session, uid B then opens its own — working exactly as
before. Ownership guards concurrent misuse; it is not a lease.

The HELLO check and `virp_handle_hello()` run under **one** acquisition of
`session_mutex`. A check that released the lock before the handshake would be
the race it exists to close.

On the EXECUTE path the check sits in the existing `obs_version == 2`
pre-flight, **before** the gate and before any connection — the same L1
discipline as an over-tier refusal, so a refused request costs nothing on the
wire.

### Provisional decisions

**D3.1 — the refusal is a typed framed error, not a signed observation.**
The order says "signed error naming the session". The three session actions
answer with either a JSON frame (HELLO_ACK, `{"status":"bound"}`,
`{"status":"closed"}`) or a framed 4-byte typed error code; the v2 EXECUTE
pre-flight likewise already returns bare codes (`VIRP_ERR_SESSION_INVALID`,
`VIRP_ERR_INVALID_LENGTH`). Emitting a signed observation from those four
points would change the response *shape* that every existing client parses —
a wire-contract change well beyond this item, and one the order's own
"conservative path" instruction argues against. **Provisional answer:** use a
new typed error, `VIRP_ERR_SESSION_FORBIDDEN` (-54), through each action's
existing error channel, and name the session in the daemon's own stderr log,
which is not the other caller's channel. The 4-byte code inherently cannot
name the session — but the caller supplied the session id in its own request,
so the refusal tells it nothing it did not already know, which is exactly the
property "names the session and nothing else" was asking for. **If Nate wants
a literal signed error here, that is a follow-up and a wire-contract
decision.**

**D3.2 — the evidence-recording half was stopped, not attempted.** The order:
"Record both the kernel uid and the asserted client identity in the evidence
the session produces. If this changes canonical bytes of any existing entry
type, STOP this item: write the design in the report instead."

It does. `gate_intent/1` and `gate_execution/1` already carry the kernel uid
as `uid` and the session as `session`; what is missing is the identity the
client *asserted* — the `client_id` string from SESSION_HELLO
("netclaw-bridge", and so on). Adding it means adding a field to both bodies,
which changes the JSON those types hash and sign. That is the fence.

I read "STOP this item" as stopping *this requirement*, not the whole item:
the enforcement half touches no canonical bytes at all, is the actual
security fix, and discarding it would have been a strictly worse outcome for
the same fence. **Provisional answer: implement the enforcement, stop the
recording, write the design.** Flagging it because the other reading exists.

### The design that was not implemented (D3.2)

The goal: a chain reader should be able to say *which local uid acted* AND
*which application that uid claimed to be*, without trusting either claim
more than it deserves. Today it can only say the first.

Two identities, of very different quality:

- **kernel uid** — `SO_PEERCRED`, established by the kernel at accept time,
  unforgeable by the peer. Already recorded as `uid`.
- **asserted `client_id`** — a free string the client puts in SESSION_HELLO.
  It is *not* authenticated and must never be recorded as though it were. Its
  value is correlation (which bridge, which tool), not authority.

Shape, when a format window opens:

    gate_intent/2, gate_execution/2   (the /2 bump already queued in
                                       docs/DRAFT07-NOTES.md §5)
      "uid":              <int|null>     unchanged — kernel, authenticated
      "client_id":        <string|null>  NEW — asserted, UNAUTHENTICATED
      "client_id_source": "session_hello"

`client_id_source` is not decoration: it is the field that stops a later
reader from mistaking an asserted string for an authenticated one. A verifier
must never compare `client_id` across entries to establish identity, and the
grading rules must not gain any check keyed on it.

Two cheaper alternatives, if the /2 bump is far off:

1. **A new entry type, no existing canonical touched.** A daemon-reserved
   `session_open/1` written once per successful HELLO, carrying
   `{session, uid, client_id, client_id_source, opened_ns}`, in a
   `session:<hex>` chain session. Every `gate_intent` already records
   `session`, so a reader joins on it. This is implementable **today**
   without touching a single existing body — the same manoeuvre item 4's
   option (b) uses for `degraded_latch/1`. It is the recommended path if
   the recording is wanted before the format window.
2. **`node_config`-style: record nothing new, and say so.** Leave the chain
   as it is and document that asserted identity is deliberately absent.
   Honest, and cheapest, but it leaves the attribution brief without its
   input.

### Tests

`make test-session-owner` — new, 10 checks:

- **Decision (5).** No owner is permissive; the owner is admitted and a
  different uid refused, with the record left intact by a refusal; the
  internal `(uid_t)-1` caller is not gated; ownership lapses on CLOSED and
  on DISCONNECTED and the stale record is cleared; NEGOTIATED, BOUND and
  ACTIVE all stay owned — the mid-handshake steal window, where uid A has
  HELLO'd but not yet BOUND, which is the case that would survive a check
  keyed only on "session is ACTIVE".
- **v2 EXECUTE (4).** A foreign uid gets `VIRP_ERR_SESSION_FORBIDDEN` and the
  mock driver records **zero** execute attempts; the result is asserted to be
  distinct from -30. The owner is not refused. An unowned session behaves as
  it did before the branch. A v1 EXECUTE from any uid still executes, because
  a v1 observation carries no session and there is nothing to misattribute.
- **Bridge sequence (1), over a real socket, one uid.** `session_hello` →
  the daemon records `getuid()` as the owner → `session_bind` returns
  `{"status":"bound"}` → v2 `execute` returns an observation and is not
  refused → `chain_append` is answered and is not gated by ownership →
  `session_close` by the owner succeeds and releases ownership. This is the
  netclaw bridge's exact action list from the Sep 1 template.

**Red proof, actually run.** Replacing the pre-flight call with `false` makes
`test_v2_execute_cross_uid_refused` fail — the foreign uid executes. Restored
immediately; the branch carries the real check.

### Regression evidence (isolated `/tmp`)

| Suite | Result | exit |
|---|---|---|
| `test` | 61/62 (namespace artifact, see §1 †) | 2 |
| `test-onode` | 157/159 (2 PENDING by design) | 0 |
| `test-session` | pass | 0 |
| `test-session-owner` | **10/10, new** | 0 |
| `test-session-key` | pass | 0 |
| `test-obs-v2` | pass | 0 |
| `test-chain` | 33/33 | 0 |
| `test-approval` | 30/31 isolated (artifact ‡), 31/31 un-isolated | 2 |
| `test-evidence-binding` | 7/7 | 0 |
| `test-federation` | 11/11 | 0 |
| `test-validator` | 11/11 | 0 |

### Deployment risk — read this before merging item 3

This is a **behaviour change visible to any host where two different local
uids touch the session at once.** Before, the second uid silently took the
session; now it is refused `-54`. That is the point of the fix, and it is
also the way it could break something that currently "works".

On 313 the principals that reach the socket are not one uid — the bridge, the
console/agent, the autopilot and the CLI have distinct uids and distinct
`socket_uid_action_allow` sets. What matters is whether more than one of them
performs `session_hello` / `session_bind`, and whether they overlap in time.

Two facts that bound the risk, both from this tree rather than from the live
host, because the fence forbids looking:

- **`chain_append` is not gated**, so a federation principal that only
  appends is unaffected regardless of uid.
- **v1 EXECUTE is not gated**, and project memory records `obs_version`
  pinned to **v1** on both bridge paths since 2026-08-11 — so the v2 execute
  half of this change should be inert in production as it stands.

The exposure that remains is `session_hello` / `session_bind` / `session_close`
from a *second* uid while a first uid's session is live. **I could not check
whether that happens on 313, and did not try.** The pre-merge question for
Nate is exactly that: does more than one uid open a session on that box? If
yes, the ownership rule is still right, but the losing caller needs to learn
to handle -54 before this lands. `journalctl -u virp-onode | grep SESSION_HELLO`
against the uid in each line answers it in one command, on the host, when you
are ready to look.

### Findings not fixed

**F3.1 — `ACTION_HEALTH` drops the peer uid.** The health action calls
`onode_execute_obs()`, which forwards `(uid_t)-1` as the client uid, and it
forwards the caller's `obs_version` — so a health request with
`obs_version: 2` reaches the v2 path as an internal caller and is not subject
to session ownership. It is not subject to the per-uid tier ceiling either,
which is the older and larger half of the same gap. The fix is one line
(`onode_execute_obs_ex(..., client_uid, ...)`), but it newly subjects health
probes to per-uid ceilings, which is a deployment-visible change on 313 and
outside tonight's scope. **Recorded, not fixed.**

**F3.2 — there is no session reaper.** Ownership lapses when the session
reaches DISCONNECTED or CLOSED, and `virp_session_check_timeouts()` is what
drives an idle ACTIVE session there. Nothing in the daemon calls it on a
timer. An abandoned ACTIVE session therefore holds ownership until the next
HELLO from its owner or a restart. Pre-existing (the timeouts were already
only advisory); the ownership work makes the consequence sharper, because now
a stuck session also blocks other uids. **Recorded, not fixed.**

**F3.3 — the bridge test asserts a negative on `chain_append`.** Step 4 of
the bridge sequence asserts only that `chain_append` is *not* refused with
-54; it does not assert the append succeeded, because a `fed_request` append
from a non-federation principal has its own policy answer that is not this
item's business. Stated so the test is not read as broader than it is.

---

## §2 — Signing activation, fail closed (`fix/signing-activation`)

**Status: PARTIAL, by instruction.** No box was ticked before launch, so this
ran as **option C**: tests and runbook only, against option A as the
provisional choice, and **no daemon code change**. Head `aba582c`, one commit
off `main`.

**`-S` was not added anywhere. No host was contacted, no database was opened
off this laptop, no unit was touched.**

### The 313 shape, reproduced from an empty database

`tests/test_signing_activation.c` builds it in three steps — two unsigned
appends, activation, two signed appends — and gets the verdict verbatim:

    first_broken=0
    Missing Ed25519 signature at sequence 0 in a signed session
    (stripped signature)

That is what Docket returned eighteen times. The mechanism, stated plainly:
a chain session is signed or unsigned **as a whole**, and the daemon's
sessions are keyed by device rather than by process lifetime, so they outlive
restarts and simply continue at the next sequence. "Add `-S` to the unit and
restart" therefore cannot be a safe cutover and never was.

### What the suite pins

Passing (today's shipped behaviour):

1. **Fresh database born signed** — every entry and the head carry a
   signature, exactly one `chain_sig_key_id` across the session, the head's
   key_id equals the entries', and the session verifies. This is the
   "session key binding holds" requirement.
2. **Restart with the same key** — re-enabling is idempotent, the session
   continues, still exactly one key_id, still verifies.
3. **The straddle** — reproduced and asserted to FAIL, with `first_broken`
   named. It must keep failing: it is the evidence for the rule.

PENDING, known-failing by design, each naming its acceptance criterion:

4. **`-S` on a nonempty database must be refused, and the file must be
   byte-identical afterwards** (sha256 of the whole file before and after).
   It is not refused today. The byte-identity half is not free: the four
   `ALTER TABLE ADD COLUMN` statements run before anything could refuse, so
   under option A **the refusal has to come first**, ahead of the schema
   migration — otherwise a refused activation still leaves a migrated
   database behind. That is the one non-obvious implementation constraint
   this exercise turned up.
5. **Reopening a signed database with a different signing key must be refused
   at startup, naming both key_ids.** Today the daemon signs new entries
   under the new key_id and the disagreement surfaces later, at read time, as
   `Signature key_id mismatch at sequence N` — on somebody else's screen.

The PENDING discipline is `tests/test_onode.c`'s: counted in their own
bucket, never as passes, the suite refuses to print a clean line while they
exist, and an **unexpected PASS is a hard failure** so the marker cannot
silently become a lie. The suite still exits 0, so `make all-tests` is not
broken by it — the same contract `test-onode` already has.

D-0 Appendix A fixtures and the D-1 golden vectors are untouched and are not
duplicated here; `make test-chain-invariant` (49/49) and `make
test-chainsign-vectors` (17/17) still pass.

### `docs/SIGNING-CUTOVER.md`

The procedure, written but **not executed**: pre-flight (`systemctl cat`,
confirm the current `-c`/`-C`, stop if `-S` is already there); an **online**
`sqlite3.Connection.backup()` snapshot as the daemon user via the Python
standard library, because there is no `sqlite3` CLI on 313 and a live
WAL-mode database must never be `cp`'d; hash it; seal it via the D-0 ceremony
(`tools/seal/`) after verifying the existing seal still checks out; move the
old database aside — **never delete it**, it is what the seal attests; mint
the key and lock it down; add `-S` and start on a fresh database; verify the
first session with the **public key only** (that is the point of D-1); then
verify through the Docket bundle path, expected verdict PASS /
CRYPTOGRAPHICALLY-VERIFIED with zero FAILED sessions.

It says explicitly, as the order requires, that **chain-sign is already a
separate key from `K_chain`** — `-C` is the symmetric key, `-S` is a
dedicated Ed25519 secret — so the reviewer's "dedicated key" point is
satisfied and a third key must not be invented to satisfy it again.

It also records something the exercise made obvious and that is worth
Nate's attention: **rollback is not free.** Removing `-S` and continuing to
append into sessions that already carry signatures recreates exactly the
straddle. So a rollback must ALSO move the signed database aside and start a
third one, or accept FAILED verdicts on every session spanning the rollback.
That asymmetry is the strongest argument for cutting over onto a fresh
database rather than for any of the three options in the abstract.

### Provisional decisions

**D2.1 — option C, as instructed.** No box ticked → C. No daemon code
change. If Nate ticks A, the two PENDING tests become the specification and
their markers come out in the same commit that satisfies them.

**D2.2 — the straddled sessions on 313 stay FAILED under every option, and
should.** They record a real inconsistency. Rewriting them to make a verifier
happy would be strictly worse than reporting them, and the runbook says so.

**D2.3 — option B was not tested.** Under C the order asks for option A only.
Worth noting for the ruling, though: B ("refuse to append into a session
whose entries have a different signing state") needs a per-session
signed/unsigned probe on every append — a read on the hot path that A does
not need, since A settles the question once at startup. That is a real cost
difference between the two options and it is not visible from the rule
statements alone.

---

## §4 — Evidence-degraded concurrency (`docs/degraded-concurrency`)

**Status: DONE.** Head `eabb33c`, one commit off `main`.
`docs/DEGRADED-CONCURRENCY.md`, memo only, no code, no recommendation
section.

The findings worth surfacing here rather than leaving in the document:

- **The latch is read in exactly one place** — `gate_emit_intent()`. It stops
  the *next* dispatch from starting and says nothing about dispatches already
  past that point. Nothing polls it between the intent commit and the closer.
- **An in-flight action whose closer SUCCEEDS after the latch is invisible.**
  It leaves an ordinary closed pair, indistinguishable in the chain from one
  that ran before the latch. Only actions whose closer *failed* leave an OPEN
  intent. So the chain under-reports the set an operator must reconcile —
  not by hiding an unrecorded action (none escape), but by not marking which
  recorded actions ran after the node knew it was degraded.
- **The latch is not on the chain at all.** Process state and a stderr line.
  A bundle exported afterwards shows the open intents, which is the evidence
  that matters, but never the moment the node stopped dispatching.

Option (a)'s cost, quantified from the current structure rather than asserted:
`exec_mutex` is **per-device** (`ONODE_MAX_DEVICES` = 64) and "different
devices are independent" is an explicit invariant in its comment; workers cap
at `ONODE_MAX_WORKERS` = 32. Serializing intent→execute→outcome under one
lock held across device I/O takes the node from 32-wide to one execution at a
time fleet-wide — roughly 0.3–3 commands/second for the whole node — and turns
a 43-device sweep from "the time of the slowest device" into "the sum of all
43". It also couples every device to every other's stalls, which the
per-device design exists to avoid, and inverts the documented lock-ordering
rule in `include/virp_onode.h`.

Option (b) is throughput-free and introduces a **new** entry type
(`degraded_latch/1`), so no existing canonical bytes change and the D-0/D-1
fixtures are untouched. Its two real costs are named in the memo: every exit
from the intent→closer span must decrement the counter or it is monotonically
wrong (five exits today), and the latch entry is a chain append attempted at
the exact moment the chain has just proven it cannot take a write — so it
will usually fail, must be best-effort by construction, and the design must
not claim the count is durable.

---

## Whole-suite comparison, `main` vs. every branch

Each branch was checked out on its own, `make clean`'d, and given a full
`make -k all-tests` under an isolated `/tmp`. The point of the exercise is
the **failure set**, not the exit code: `all-tests` exits 2 on `main` too, so
"exit 2" alone says nothing.

| Branch | Head | Failing targets | exit |
|---|---|---|---|
| `main` | `2cb9130` | `test`†, `test-approval`‡, and the 5 `test_driver_*_refusal` LINK failures | 2 |
| `fix/approved-outcome-fail` | `80453df` | **identical set** | 2 |
| `fix/approved-outcome-fail` +`all-tests` entry | `88c1a03` | **identical set** | 2 |
| `fix/session-owner-uid` | `ff0f809` | **identical set** | 2 |
| `fix/signing-activation` | `aba582c` | **identical set** | 2 |
| `docs/degraded-concurrency` | `eabb33c` | **identical set** | 2 |

† and ‡ are the two isolation artifacts described in §0; they fail on `main`
too, and outside the namespace they pass everywhere. **No branch adds a
failing target, and none removes one.** `test-onode` is 157/159 exit 0 on
every branch, including `main`.

All three new targets are in `all-tests` and ran there: `test-session-owner`
(10/10) on item 3, `test-signing-activation` (3 passed / 2 PENDING, exit 0)
on item 2, and `test-approved-outcome-fi` (30/30) on item 1 — added in
`88c1a03`, because a test nothing runs is not a guard. It sits next to
`test-evidence-fi`, the target it mirrors, which already pulls the
`-DVIRP_FAULT_INJECT` tree into `all-tests`, so it costs no extra build.
`test-chain-atomicity-fi` deliberately stays out, unchanged.

## Compliance with "Never, tonight"

| Rule | Status |
|---|---|
| push, merge, tag | **none.** Five local branches (four work + this report); `git rev-parse --abbrev-ref <branch>@{upstream}` says "no upstream configured" for every one of them, and `git branch -r` still lists exactly the six remote branches the clone came with. `main` = `origin/main` = `2cb9130`, untouched, and every branch is one commit ahead of it (item 1 is two: the fix, then the `all-tests` entry). No tag was created — the 89 tags present all arrived with the clone; the newest, `v0.2.0` (2026-09-01), predates this session. |
| ssh to any box, deploy, migrate a database, edit a unit | **none.** No network command was run against 313, 10.0.10.211 or the Spark. `/opt/virp` does not exist on this laptop and was not created. |
| change canonical bytes of any existing entry type | **none.** Item 1 changes a function's return type and a caller's response; item 3 adds daemon state and a typed error code; items 2 and 4 add a test, a doc and a memo. `make test-chain-invariant` (D-0 Appendix A) and `make test-chainsign-vectors` (D-1 goldens) pass on every branch. The one requirement that WOULD have crossed this line (item 3's evidence recording) was stopped and written up. |
| add `-S` anywhere | **none.** Item 2 is a test and a runbook. The runbook was written, not executed. |
| touch any other `~/virp*` clone | **none for writing.** `~/virp-remediation-2026-08-31` was read twice — `git log`/`git status` and a `find -newermt` — solely to answer the launch precondition. See P0 and F4. |
| amend earlier session summaries | **none.** Every correction is in this file. |

## Findings not fixed, collected

| # | Finding | Where |
|---|---|---|
| F1 | A **failed** `asan-test` leaves ASan objects in the shared `build/` tree and 35 later targets fail to link with `undefined reference to __asan_*`. The Makefile predicts an *interrupted* run; a *failing* one is the same hazard and says nothing. | §0 |
| F2 | `test_onode`'s socket-test failures are a SYMPTOM of F3, not flakiness. Under an isolated `/tmp`: 157/159, exit 0, every run, every branch. Listed separately because the symptom is what anyone else will hit first. | §0 |
| F3 | Test suites hardcode `/tmp/virp-*` paths and do not clean up. Two clones running tests at once fight over the same sockets and databases — which is what happened tonight (F4). A per-run `mkdtemp` is the fix. | §0 |
| F4 | The other Claude session in `~/virp-remediation-2026-08-31` woke mid-run and executed `rm -rf /tmp/virp-*` and its own `test_onode`. Every shared-`/tmp` measurement taken before I isolated is unreliable, and is not used in this report. | P0 |
| F5 | **Docket does not grade open executions at all.** `grep -r gate_intent ~/docket` returns nothing: the Rust `virp-verify` crate has no notion of `gate_intent`, closers, or open/closed grading. The C and Python verifiers do; the third implementation does not. | §1 D1.4 |
| F6 | A v2 approved apply that hits `unchained-execution` burns one session sequence number (the success observation was already built and numbered before the append was attempted). Monotonic, so not a verifier failure — but a real gap in a v2 caller's sequence, and the direct price of not moving the `outcome` append. | §1 D1.3 |
| F7 | `ACTION_HEALTH` forwards `(uid_t)-1` instead of the peer uid, so a health request bypasses session ownership *and* the per-uid tier ceiling. One-line fix, deployment-visible on 313, out of scope tonight. | §3 F3.1 |
| F8 | No session reaper: `virp_session_check_timeouts()` is never called on a timer, so an abandoned ACTIVE session holds ownership until its owner returns or the daemon restarts. Pre-existing; ownership makes the consequence sharper. | §3 F3.2 |
| F9 | Option A's refusal must precede the four `ALTER TABLE ADD COLUMN` statements, or a refused activation still migrates the database. Not visible from the rule statement. | §2 |

## For the morning

Review order per the work order: **1, 3, 2.** Item 4 is a memo and item 0
changed nothing.

- **Item 1** (`fix/approved-outcome-fail`, `88c1a03`) is the one that closes
  a stated known limitation and is self-contained. Three things to check:
  that the auto-execute wording really is unchanged (it shares a helper now),
  D1.3 (the v2 sequence gap), and whether phase C's forked-daemon test is a
  pattern you want repeated.
- **Item 3** (`fix/session-owner-uid`, `ff0f809`) needs two rulings, not one:
  D3.1 (typed error code vs. a literal signed error, which is a
  wire-contract decision) and D3.2 (whether to take the cheap
  `session_open/1` route for asserted identity now, or wait for the `/2`
  format window).
- **Item 2** (`fix/signing-activation`, `aba582c`) is inert until you tick a
  box. The runbook stands on its own either way. Read D2.3 before ruling:
  option B costs a per-append read that option A does not.
- **Item 4** (`docs/degraded-concurrency`, `eabb33c`) is a memo; the decision
  is yours and the document deliberately does not make it.

Nothing here has been deployed, and nothing needs to be for any of it to be
reviewed.
