# Producer gap strictness, scrub coverage, unwired tests, spool naming

Branch `fix/producer-hardening`, four commits off `main` (`fe47c38`, the
reconciliation merge). Not merged, not pushed.

| | commit | |
|---|---|---|
| Item 1 | `05c47d9` | `camera:` a gap must be a gap — the verifier's rule, enforced by the producer |
| Item 2 | `0d45c4d` | `scrub:` S-1 reads JSON key syntax — the barrier gap §3.2 measured |
| Item 3 | `c5d5070` | `build:` run the two guards that were wired to nothing |
| Item 4 | `0c5f876` | `camera:` name spool jobs `<camera>.<seq>.<sha>`, not `<seq>.<sha>` |

Host constraints observed: nothing installed, no service restarted,
`/var/lib/virp/chain.db` opened read-only (`file:…?mode=ro`) and copied
only through sqlite3's backup API into the session scratchpad, `/etc/virp`
read-only, no `producer.key` read, printed or copied. The transient
`virp-camera-submitter.service` (pid 781116, running the DEPLOYED
`/var/lib/virp/camera/virp_camera.py`) was left alone; none of this
reaches it until someone deploys it.

---

## Item 1 — producer gap strictness

### The divergence

`audit`'s continuity walk excused a break on `body.get("gap") is not
None`. A truthy scalar, an empty object, an `after_seq` pointing anywhere
at all would do. Docket grades a record FAILED unless a present gap is an
object carrying an integer `after_seq` citing a real predecessor plus a
bounded nonempty reason. The producer could therefore sign — and this
auditor could pass — a record the verifier rejects.

### The rule, and where it is enforced

`gap_defect(gap, segment_seq, prev_seq)` returns `None` or a one-line
statement of what is wrong. It is applied at **four** points, not one:

| point | what it does |
|---|---|
| `build_body()` | refuses to build a body it would fail — and since the signature is applied to what `build_body` returns, refusing to build is refusing to sign |
| `audit` continuity walk | a defect is a FAILURE, and the gap excuses no sequence or prev-hash break |
| `grade_coverage()` | an invalid gap does not make an outage ACCOUNTED |
| `grade_content_reuse()` | an invalid gap does not make a reappearance of bytes EXPLAINED |

Leaving the last two lax would have let a record that fails integrity
still launder its coverage and reuse verdicts.

### The six cases, and the case Docket added after the fact

**Docket's own matrix is not on this host.** `~/docket-work/docket` is an
ELF dated 2026-08-23; its strings carry chain-viewer and bundle-export
material and no camera gap grading at all, and there is no Docket source
anywhere on 313 (`~/laptop-home/docket/` is an empty directory). Per the
prompt's own instruction — *"Docket's implementation is the reference for
semantics, not for code: re-derive it from the format"* — these are the
six outcomes the record format admits, enumerated from the prose:

| # | case | verdict |
|---|---|---|
| 1 | no gap (absent / `null`) | valid — continuity is claimed |
| 2 | not an object (`true`, `"driver-restart"`, `4`, a list) | FAILED |
| 3 | `after_seq` missing, or not an integer (string, float, bool) | FAILED |
| 4 | `after_seq` cites nowhere real (too early, the future, itself) | FAILED |
| 5 | `reason` missing, empty, not a string, or over the 128-char bound | FAILED |
| 6 | object citing the previous record for this camera, bounded nonempty reason | valid |

and the late addition: **the external-predecessor form** — `after_seq ==
segment_seq - 1` on a record whose predecessor this corpus does not
carry — is valid; **any gap on segment 0 is invalid**, it has no
predecessor at all, external or otherwise.

All of it is pinned in `tests/test_camera_trust_and_coverage.py` as a
24-row table (`GapValidityMatrixTests`) plus the emission guard and the
three graders (`GapEmissionGuardTests`, `InvalidGapExcusesNothingTests`).

### Where I widened the prompt's rule, and why

The prompt scopes the external-predecessor form to *"a camera's FIRST
carried record in a session"*. Implemented exactly that way, it **fails a
real frozen fixture of real chain bodies**:

```
FAIL: camera:tapo-c100:2026-08-24 camseg:tapo-c100:52:1787612839664195197:
      gap after_seq 51 does not cite the previous record for this camera (19)
```

`tests/fixtures/` holds the Aug-24 duplicate-pair evidence as **two**
verbatim blocks, seq 7–19 and seq 52–76. The record at seq 52 carries a
real `driver-restart` gap citing 51, which is correct — I confirmed
against the chain that session `camera:tapo-c100:2026-08-24` holds 356
records, seq 0–355, **contiguous**, with 20–51 present. The fixture is a
deliberate slice; the record is not at fault.

Docket scopes the form to the first record because Docket grades whole
chains, where a mid-corpus hole cannot arise from filtering. This auditor
is handed filtered corpora on purpose (`--session-prefix`, and this
fixture). So the form is accepted **wherever a block opens**:

- On a **complete** corpus the two citations are the same number
  (`prev_carried_seq == segment_seq - 1` when the stream is contiguous),
  so a complete chain grades identically here and in Docket — the
  acceptance requirement, met exactly.
- They differ only where the **corpus** is incomplete, and there the
  looser branch is the correct one: refusing it would invent a defect
  against a valid signed record because the operator filtered the query.
- Nothing the rule exists to catch is lost. An `after_seq` that is
  neither the carried predecessor nor the immediate one still grades
  FAILED, as does a non-object, an empty reason, or a gap on segment 0.

### Chain scan — the answer is zero

Read-only snapshot of `/var/lib/virp/chain.db` via sqlite3's backup API,
then every `camera_segment` body replayed through the new rule:

```
camera_segment bodies on chain: 2571
  reolink-rlc810a-sub          27 records  seq 0..26     seq-holes=0  gaps=1
  synthetic-restart-accept     67 records  seq 0..66     seq-holes=0  gaps=4
  tapo-c100                   363 records  seq 0..362    seq-holes=0  gaps=5
  tapo-c100-accept           2114 records  seq 0..2113   seq-holes=0  gaps=10

gap value shapes:  absent/null 2551 · object keys=after_seq,reason 20
gap reasons:       driver-restart 17 · capture-discontinuity 3 · longest 21 chars
records that would grade differently under the new rule: 0
```

Every stream is contiguous; every one of the 20 gaps is a well-formed
object with exactly `{after_seq, reason}`. `audit` over the full snapshot
produces **byte-identical output before and after the change**. Nothing
was modified, re-signed, or written.

> Contradicting the prompt, harmlessly: the prompt says 2553 live
> chain-bound records. The chain now holds **2571** camera_segment
> bodies — burn-in capture has continued since that number was taken.
> Nothing in the finding depends on which number is used.

---

## Item 2 — the scrub barrier and JSON

### Blast radius of option (b), measured first

Every gate-admitted REST endpoint in the tree, from each driver's own
route table, against `VBF_BUILTIN_RULES` / `deploy/body-filters.json`:

| driver | endpoint | filter rule? |
|---|---|---|
| librenms | `/api/v0/devices` | **yes** (`librenms-devices-v1`) |
| librenms | `/api/v0/alerts` | no |
| librenms | `/api/v0/devices/<id>/health` | no |
| wazuh | `/agents` | no |
| wazuh | `/agents/summary/status` | no |
| wazuh | `/manager/stats/analysisd` | no |
| zammad | `/api/v1/tickets` | no |
| zammad | `/api/v1/ticket_states` | no |
| zammad | `/api/v1/groups` | no |
| zammad | `/api/v1/tickets/<id>` | no |
| zammad | `/api/v1/ticket_articles/by_ticket/<id>` | no |
| zammad | `POST /api/v1/ticket_articles` (YELLOW write) | no |
| pbs | `/api2/json/version` | no |
| pbs | `/api2/json/status/datastore-usage` | no |
| pbs | `/api2/json/admin/datastore/{store}/snapshots` | no |
| pbs | `/api2/json/nodes/localhost/tasks?typefilter=verify` | no |

**One of sixteen rows, one of fourteen distinct endpoints.** Option (b)
would WITHHELD the other thirteen. And of the four endpoints the live
autopilot battery polls every cycle
(`autopilot/virp_autopilot.py:182-185`), **three have no rule**:

```
GET /agents/summary/status     wazuh      no rule  -> would be withheld
GET /manager/stats/analysisd   wazuh      no rule  -> would be withheld
GET /api/v0/alerts?state=1     librenms   no rule  -> would be withheld
GET /api/v0/devices            librenms   RULE     -> survives
```

Option (b) would take out three quarters of the monitoring battery.

There is a second problem with (b) as stated: the filter has no reliable
"is this a REST body" discriminator. `command_path()` is the closest
thing, and it accepts *any* command whose second whitespace token starts
with `/` — `cat /etc/hosts` on the linux driver reads as a REST path.
Failing closed on that predicate would withhold ordinary CLI output too.

### The choice: (a), and both are needed

**Implemented (a).** It refuses nothing that passes today, it closes the
gap on *every* endpoint rather than the ones someone has written a rule
for, and it also covers JSON that arrives through a CLI driver.

**(b) is still needed and is the better end state** — it is the only
mechanism that catches a credential under a key name nobody anticipated,
which is precisely S-1's honesty limit. But its precondition is an
allowlist rule for each of the thirteen unruled endpoints, and writing
those rules *is* the work, not a side effect of it. Fail-closing before
they exist would break the monitoring product to close a leak. It belongs
in its own item, after the rules, together with a real REST discriminator.

### What was implemented

`rule_json_labeled_secret()` in `src/virp_scrub.c`: a quoted key followed
by `:` whose name matches the label vocabulary, with the whole **value
span** — string, number, literal, balanced object or array — replaced by
a **quoted** marker, so a redacted body still parses as JSON. Unlike the
line rules it does not stop at the first hit; one compact body is one
"line" and carries many keys.

Vocabulary: everything `label_reason()` already knows, plus the SNMP
credential family (`community`, `authpass`, `privpass`, `cryptopass`).
That widening is scoped to the JSON rule rather than to `label_reason()`
so **the CLI path is byte-identical** — those are not CLI label shapes;
the CLI form is `snmp-server community <tok>`, which `rule_snmp_community`
has always had.

Neither barrier weakened: `virp_body_filter.c` is untouched, the three
first-token CLI rules still run first, and a line with no `"key":` pair
falls through to the token sweep exactly as before.

### Verification — the §3.2 method

A throwaway probe (scratchpad, not committed) linking the real
`libvirp.a` and measuring what each mechanism does to a real body:

| body | before | after |
|---|---|---|
| **A** librenms `/api/v0/devices` (ruled) | filter FILTERED, 5 fields out; scrub alone: 0 redactions | filter unchanged; **merged 277 → 270 → 270**, scrub still a verified no-op there — no body redacted twice |
| **B** librenms `/api/v0/alerts` (unruled, polled every cycle) | UNTOUCHED; **all 5 canaries survive both barriers** | all four *credential* canaries redacted (`snmp-community`, `snmp-authpass`, `snmp-privpass`, `token`) |
| **C** wazuh `/agents/summary/status` (unruled, polled every cycle) | UNTOUCHED; both canaries survive both barriers | both redacted |
| **D** cisco `show running-config` (CLI) | filter UNTOUCHED, scrub 169 → 180 | **byte-identical to before** — §3.2 measured result 2 intact |

Both of §3.2's measured findings still hold as findings: the body filter
still does nothing to CLI output (D), and the two mechanisms still
coexist without duplicating (A: 270 → 270 across the scrub call). What
changed is §3.2's measured result 1 — the scrubber alone is no longer a
no-op on a JSON body, which is the entire point.

### Residuals, stated not fixed

- **`sysContact` still passes.** It is PII, not a credential shape. S-1
  is a credential scanner; the allowlist is what removes PII, and only on
  a ruled endpoint. Widening S-1 into PII is a different policy axis.
- **A JSON string *value* containing `token: ` still over-redacts.** The
  pre-existing whitespace token sweep sees `token:` and redacts to end of
  line, closing braces included, so that body stops being JSON.
  **Measured byte-identical before and after** this change, and pinned by
  `test_json_string_value_carrying_a_bare_label_over_redacts`. Left alone
  deliberately: fixing it means teaching the sweep to redact *less*,
  which is a weakening and needs its own review.
- The honesty limit holds one level down: JSON *syntax* is now read, but
  the vocabulary is still known key names. Pinned by
  `test_json_unlabeled_value_is_still_NOT_caught`.

`include/virp_scrub.h` and `SCRUB-DESIGN.md` updated to match.

---

## Item 3 — the two unwired guards

Both were open items 2 and 3 of the reconciliation merge
(`MERGE-RECONCILIATION-20260829.md` §5), left unwired there on purpose
because wiring them was a change neither parent made.

- `check-obs-build-ordering` → the `check-*` guards at the head of
  `all-tests`, **and** the CI "Static checks and lints" step, where a
  source guard fails fast and legibly.
- `test-refusal-contract` → the suite list next to `test-drivers`,
  **and** its own named CI step, so a failure there reads as a
  refusal-contract failure rather than a line in the battery.

`all-tests` minus `check-deploy-unit` now carries **43** targets,
including both.

---

## Item 4 — spool naming

`<seq>.<sha>` → `<camera>.<seq>.<sha>`.

### Consumers, enumerated before changing anything

| consumer | verdict |
|---|---|
| `process_live_segment` | builds the name — now via `spool_job_name()` |
| `sftp_ship`'s `ship()` | puts `<name>.mp4`/`.body` then `<name>.done` LAST; opaque string, no parsing |
| `_staged_pair(outbox, sha)` | globs `*.<sha>.body` — a **suffix** match, so a camera prefix is transparent to restart reconciliation |
| `_reconcile_workdir` | takes the job name from the staged body's own basename; a pair staged under either scheme re-ships under its own name |
| `_submit_spool_locked` | lists `*.done`, strips the suffix, pairs `<name>.mp4`/`.body`. Scheme-agnostic; the name decides only `sorted()` drain ORDER |
| `submit_one` | **never parses the name.** `camera_id`, `segment_seq`, `capture_end_utc_ns`, `session_id`, `artifact_id`, `artifact_hash` and the sidecar key all come from the signed body. The name appears only in log lines and `sidecar["source_file"]` |
| handoff / checkpoint records | carry `shipped_as` as a string; nothing ever reads it back |
| `done/` | **write-only.** `os.replace()` into it; nothing in the tree lists or parses it |
| `deploy/camera-spool-access.sh` | references the directories only, never a filename pattern |
| `/etc/ssh/sshd_config.d/60-virp-capture.conf` | chroot + `internal-sftp -d /incoming`; directories only |
| the running submitter (pid 781116) | the DEPLOYED copy; untouched, not restarted |

Nothing on the chain moves, therefore. The name is an operator-facing
handle and a uniqueness key within one directory, and that is all it has
ever been.

> **`relay_detections.sh` does not exist.** Not in the repo, not
> anywhere on 313 (searched `/etc`, `/usr/local`, `/opt`, `$HOME`). The
> only occurrences on this host are inside this session's own prompt
> text and transcript. Nothing was changed for it and nothing needs to
> be; if it exists, it is on another host and its author should be told
> that a spool name has gained a `<camera>.` prefix and that the name
> was never a source of truth.

### Mixed-convention behaviour, plainly

The ~7600 files in `/var/spool/virp-capture/done` are **not renamed**,
and nothing needs them to be: `done/` is written and never read.

During a rollover `incoming/` holds both forms at once and **drains both
in one pass**, because pairing is by suffix off the `.done` marker and
`submit_one` takes nothing from the name. The single visible difference
is order: `sorted()` puts every digit-leading old name ahead of every
letter-leading new one (ASCII `'0'` 0x30 < `'a'` 0x61), so a pre-existing
backlog drains before new work — which is the order you want. Per-camera
capture order is preserved either way, since `audit` walks `segment_seq`
per camera and explicitly not chain-append order. Both behaviours are
pinned by test.

### One thing the change adds

The camera token now reaches a **filesystem path** — an sftp `put` inside
a chroot — which the old name never did. `spool_camera_token()` bounds
it: 1–64 ASCII letters/digits/underscore/hyphen, first character
alphanumeric. Checked at live-cfg build (before the capture child spawns,
so an operator sees it before footage exists) and again where the name is
built. It **refuses rather than sanitizes**: silently mapping an unsafe
id onto a safe token would put two cameras back on one name, which is the
collision this change removes. All four live `camera_id`s pass unchanged.

---

## Things that contradict the prompt

1. **Docket's matrix is not on this host.** No Docket source anywhere;
   the binary predates the hardening and grades no camera gaps. The six
   cases above are derived from the prompt's prose, as the prompt itself
   instructs.
2. **The external-predecessor rule as scoped fails a real fixture.** It
   had to be accepted wherever a block opens, not only on a camera's
   first carried record — see Item 1. On a complete corpus the two are
   the same rule.
3. **`relay_detections.sh` does not exist** anywhere on 313.
4. **2553 → 2571.** The chain has grown since the prompt's number.
5. **Option 2(b) needs more than a fail-closed switch**: 13 of 14
   endpoints have no rule, 3 of the 4 the live battery polls, and the
   filter has no reliable REST discriminator today.
6. **The camera suites are wired more thinly than "the full camera
   suite" implies** — flagged, not fixed, since Item 3 named exactly two
   targets:
   - `make test-camera` runs only `tests/test_camera_driver.py`;
   - `test_camera_phase2.py`, `test_camera_restart_integrity.py` and
     `test_camera_trust_and_coverage.py` have **no make target at all**;
   - `test-camera` is **not** in `all-tests`.
   They do run in CI, but only incidentally: the "Complete Python suite
   (pytest)" job has no `testpaths` config, so a bare `python3 -m pytest
   -q` collects them. That job installs `pytest httpx pyyaml reportlab`
   and not `cryptography`, which every camera suite needs for Ed25519 —
   worth checking before anyone relies on that path.

## Not done, deliberately

- Nothing that changes the canonical bytes of an existing record.
  Reported, not done — and the scan says there is nothing to report.
- No `sqlite3` CLI (absent); no writes to the chain DB.
- No renaming of the ~7600 existing spool files.
- Option 2(b), and the allowlist rules it needs.
- The token-sweep over-redaction inside JSON string values.
- Wiring the three unwired camera suites.

---

## Results

### Build

`make all` and `make prod` both clean under `-Wall -Wextra -Werror
-pedantic -std=c11`. No new warnings. (`make all rc=0`, `make prod
rc=0`.)

### Full battery, against the pre-change baseline

`make all-tests` still cannot pass on this host, for the reason
`MERGE-RECONCILIATION-20260829.md` §4.2 gives: `check-deploy-unit`
compares repo units against `/etc/systemd` and the installed
`virp-onode.service` is the burn-in unit, which diverges by design — the
Makefile itself says to expect this. Both runs therefore use the
**minus-`check-deploy-unit`** form, extracted programmatically from the
Makefile, which now carries **43** targets including the two newly wired
ones:

```
T=$(grep '^all-tests:' Makefile | sed 's/^all-tests://' \
     | tr ' ' '\n' | grep -v '^$' | grep -v '^check-deploy-unit$' | tr '\n' ' ')
make $T
```

**Baseline** (`main`, `fe47c38`, plus `check-obs-build-ordering
test-refusal-contract` named explicitly since they were not yet in the
list) → **RC=0**.
**This branch** → **RC=0**, with both guards now arriving through
`all-tests` itself.

Every suite result is identical to baseline except the one that grew:

| suite | baseline | this branch |
|---|---|---|
| test_virp | 59/59 | 59/59 |
| test_onode | 141/143 (2 PENDING) | 141/143 (2 PENDING) |
| **test_virp_scrub** | **22 tests, 0 failures** | **32 tests, 0 failures** |
| test_body_filter | 6 passed, 0 failed | 6 passed, 0 failed |
| test_ssh_io | 13/13 | 13/13 |
| test_driver_cisco_scrub | 17, 0 failures | 17, 0 failures |
| test_driver_asa_scrub | 15, 0 failures | 15, 0 failures |
| test_driver_linux_scrub | 14, 0 failures | 14, 0 failures |
| test_driver_fortigate_scrub | 4/4 | 4/4 |
| test_driver_cisco | 52/52 | 52/52 |
| test_driver_cisco_gate | 194/194 | 194/194 |
| test_driver_linux_gate | 199/199 | 199/199 |
| test_driver_juniper | 162/162 | 162/162 |
| check-obs-build-ordering | PASS (named by hand) | PASS (via all-tests + CI) |
| test-refusal-contract | 5/5 (named by hand) | 5/5 (via all-tests + CI) |

The 2 PENDING in `test_onode` are the pre-existing known-failing-by-design
tests, unchanged.

### Camera suites (Python, run by hand — see contradiction 6)

| suite | baseline | this branch |
|---|---|---|
| test_camera_driver | 17 OK | 17 OK |
| test_camera_phase2 | 10 OK | **18 OK** |
| test_camera_restart_integrity | 23 OK | 23 OK |
| test_camera_trust_and_coverage | 61 OK | **74 OK** |
| **total** | **111** | **132** |

### Reproducing

```bash
git checkout fix/producer-hardening
make all && make prod
T=$(grep '^all-tests:' Makefile | sed 's/^all-tests://' \
      | tr ' ' '\n' | grep -v '^$' | grep -v '^check-deploy-unit$' | tr '\n' ' ')
make $T
for t in driver phase2 restart_integrity trust_and_coverage; do
    python3 tests/test_camera_$t.py
done
```

Read, in this order: `camera/virp_camera.py` `gap_defect()` (the rule and
why the external-predecessor form is not scoped to the first record),
`src/virp_scrub.c` `rule_json_labeled_secret()` (the blind spot and what
the widening is scoped to), `camera/virp_camera.py` `spool_job_name()`
(the naming and the path-safety bound it needs).
