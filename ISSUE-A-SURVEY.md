# ISSUE-A Survey — synthesized text in signed observation bodies

Phase 1 (read-only) of `fix/observed-prompt-truth`. Surveyed at main = 81bb802.
Snow's finding verified: the reported class is real, and it is much larger than
the two sites he named.

---

## 1a. Classifier contamination — ANSWER FIRST

**The IOS classifier does NOT consume any prompt — templated or learned. Nothing
in the code that decides exec mode consumes the templated prompt. Snow's
classifier verdicts are not being biased as they are computed.**

Evidence, on `origin/feat/ios-classifier` (3d46a0c):

- The classifier's only input is the command string. `virp_onode.c:711-712`
  dispatches `drv->route_command(command)`; canonicalization at
  `virp_onode.c:1442-1443` calls `drv->canon_command(command, ...)`. No prompt,
  recorded or learned, is in scope at either call. `cisco_canon.c` is a pure
  string function over the command.
- Every live exec-mode decision uses the **learned** prompt, never the recorded
  header: `conn->in_enable` is set from `conn->prompt` at connect
  (`driver_cisco.c:481`) and re-derived after mode transitions from a fresh
  re-learn (`driver_cisco.c:1218-1221`, via `cisco_parse_mode` on the re-learned
  prompt). ASA equivalent at `driver_asa.c:427`. Nothing parses
  `result->output` to decide mode.
- No in-repo analysis tooling decides mode from the recorded header either:
  `report/verify.py` splits the first line on `"$ "` (linux-driver format) only
  to separate command from output — structural, not a mode decision. Nothing in
  `report/`, `autopilot/`, or `api/` reads the `#`/`>` out of an observation
  body.

**The caveat Snow does need, immediately:** the *recorded evidence itself* is
contaminated as a record, even though the verdict computation is not. Every
signed observation from the cisco driver carries `hostname#command` as its first
line regardless of the session's true mode, and that fabricated line is the
**only** mode indicator inside the observation. So:

- If his device-verdicts come from live device responses and he knows (out of
  band) what mode each session held, his verdict *conclusions* are clean.
- If any step of his analysis — including a human or an AI reading the archive
  later — derives session mode from the recorded observations, it will read
  privileged exec everywhere. A `>` session that answered `% Invalid input`
  is recorded as `R25#sh run` + error, which reads as a privileged-mode
  rejection. That is exactly the bias toward privileged-mode interpretation on
  the prefixes under test.
- Either way, the corpus he is signing does not record the session's true mode.
  If mode is part of what the evidence is supposed to prove, the corpus needs
  mode carried out-of-band, or a re-run after this fix.

**Recommendation: he does not need to stop for classifier bias. He should stop
(or add out-of-band mode records) if his corpus is meant to be durable evidence
of behavior-at-privilege-level, because the observations self-assert `#`
unconditionally.**

---

## 1b. The full class — 16 production sites (+2 mock), not 2

Every driver formats a synthesized first line into `result->output`, and
`result->output` is signed verbatim as the observation body
(`virp_onode.c:1988` — `obs_data = (const uint8_t *)result.output`). Snow's two
sites are instances of a repo-wide convention — `driver_wazuh.c:526` literally
comments *"Format output like other drivers: hostname>endpoint\nresponse"*.
This is a habit, not a bug.

### SSH/CLI drivers — a true (learned) prompt exists and is discarded

| # | Site | Synthesized | Signed body? | True value available? |
|---|------|-------------|--------------|----------------------|
| 1 | `driver_asa.c:975` (`asa_store_output`) | `hostname` + `#` + command | Yes — normal exec path | Yes — `conn->prompt` (learned, re-verified before every command by `asa_verify_enable`); needs plumbing into `asa_store_output`, which currently receives only `hostname` |
| 2 | `driver_asa.c:1031` | `hostname# command` + refusal text, entire body synthesized | Yes — BLACK refusal sets `output_len>0`, flows through the DEVICE_OUTPUT path in onode | Prompt: yes (runs after connected check). Body: nothing was observed — this is constructed text signed as device output |
| 3 | `driver_cisco.c:1124` (store helper) | `hostname` + `#` + command | Yes — normal exec path | Yes — `conn->prompt`; caveat: mode-changing commands re-learn mid-execute (`driver_cisco.c:1214-1225`), so the header must capture the **pre-dispatch** prompt, the one the command was actually typed at |
| 4 | `driver_cisco.c:1163` | BLACK refusal, entire body | Yes — same flow as #2 | Prompt possibly stale (BLACK check runs before the connected check); body: nothing observed |
| 5 | `driver_juniper.c:875` | `hostname` + `>` + command | Yes — normal exec path | Yes — `conn->prompt`. Real JunOS prompt is `user@host>` (config mode `#`): the template fabricates the format AND the mode |
| 6 | `driver_juniper.c:689` | BLACK refusal, entire body | Yes | Same as #2 |
| 7 | `driver_juniper.c:740` | `hostname>command` + "commit rejected…" text | Yes | Prompt: yes (just re-learned two lines above). Text: constructed driver narration, not device bytes |
| 8 | `driver_juniper.c:1001` | `hostname> multi-command string refused: …` | Yes | Constructed refusal; prompt available |
| 9 | `driver_panos.c:929` | `hostname` + `>` + command | Yes — normal exec path | **Yes, doubly**: `conn->prompt` is learned, and the true prompt `username@hostname>` is physically present in `raw_output` — the code strips the real prompt and then re-fabricates a fake one (see the format comment at `driver_panos.c:905-913`). PAN-OS `>` vs `#` is a real mode distinction |
| 10 | `driver_fortigate.c:806` | `hostname $ command` + refusal | Yes — BLACK refusal | Prompt learned? FortiGate normal path does NOT use the shared prompt module the same way; note the ` $ ` here is also an invented mode char (real FortiGate prompts end `#` or `$` by profile) |
| 11 | `driver_linux.c:422` | `hostname$ command` | Yes — the header is written into `result->output` before the first device byte | **No** — linux driver uses an SSH exec channel; no interactive prompt ever exists. `$` is pure invention, and on a root session the real convention would be `#` — an inverted privilege claim. Fallback form applies |

### REST drivers — no prompt exists at all; `>` is invented CLI cosplay

| # | Site | Synthesized | Signed body? | True value available? |
|---|------|-------------|--------------|----------------------|
| 12 | `driver_wazuh.c:527` | `hostname>endpoint [HTTP n]` | Yes | No prompt exists; hostname/endpoint/HTTP code are true values but the `>` framing imitates a CLI prompt |
| 13 | `driver_librenms.c:331` | same shape | Yes | same |
| 14 | `driver_pbs.c:905` (`pbs_format_observation`) | `hostname>command [GET path] [HTTP n]` | Yes | same |
| 15 | `driver_zammad.c:1253` | `hostname>POST path [HTTP n]` + derived JSON | Yes | same (the recorded derived JSON is documented, deliberate derivation evidence) |
| 16 | `driver_zammad.c:1352` | `hostname>path [HTTP n]` | Yes | same |

### Test-only

| # | Site | Note |
|---|------|------|
| 17 | `driver_mock.c:310` | `hostname#command\n<canned>` — mirrors the habit |
| 18 | `driver_mock.c:318` | fabricates an entire IOS error (`% Invalid input detected…`) under a `#` header — a synthesized device-error message, signed in tests |

**Count: 16 production sites across 10 drivers, plus 2 in the mock. This is a
habit — one inherited formatting convention — and the protocol note must treat
it as such, not as two stray lines.**

### Adjacent findings (same theme, noted for completeness)

- **The hostname is synthesized too, at every site.** It is the registry's
  configured name, not anything the device sent. This is not hypothetical: R24
  in the lab presents an `R25#` prompt (known since the 2026-07-29 cross-learn
  incident, referenced at `driver_panos.c:404`). Every signed R24 observation
  header asserts a hostname the device never printed.
- **BLACK/commit/multi-command refusals (sites 2, 4, 6, 7, 8, 10) sign 100%
  driver-constructed text through the DEVICE_OUTPUT path** because
  `output_len > 0` skips both ERROR branches in `handle_execute`
  (`virp_onode.c:1894, 1940`). The onode already has the sanctioned channel for
  constructed text — typed `VIRP_OBS_ERROR` observations. Moving refusals there
  is arguably the right fix for those sites; flagged for the Phase 2 decision.
- **FortiGate's normal exec path is the existing in-tree precedent for honesty**:
  it stores scrubbed device bytes with no synthesized header at all
  (`driver_fortigate.c:466`).

---

## 1c. The learned prompt

**Where learned:** `virp_ssh_learn_prompt` (`virp_ssh_io.c:232`), the July 29
read-path rewrite. Two bare-newline probes; each takes the last non-blank line
of a quiescent read; both probes must match byte-for-byte or learning fails.
Used by cisco, ASA, juniper (at connect; re-learned on mode transitions) and
PAN-OS (deferred to warm-up/keepalive after connect).

**Available at observation-construction time?** Yes, in all four SSH drivers —
`conn->prompt` sits in each driver's conn struct (`driver_cisco.c:58`,
`driver_asa.c:231`, `driver_juniper.c:215`, `driver_panos.c:246`). But the
store/format helpers (`asa_store_output`, cisco's store helper,
`pbs_format_observation`) receive `hostname` as a parameter, not the conn — so
the fix is parameter plumbing, not architecture. Two timing details matter:

- cisco re-learns mid-execute on mode-changing commands; the honest header
  value is the prompt **as of dispatch**, captured before `virp_ssh_exec`.
- ASA re-learns via `asa_verify_enable` before every command, so its
  `conn->prompt` is fresh at dispatch.

**Can learning fail or be skipped?** It can fail; it cannot be silently
skipped. There is no heuristic fallback by design ("no fallback prompt" —
`virp_ssh_io.h`). Cisco/ASA/juniper refuse the connection on learn failure.
PAN-OS defers learning, but `virp_ssh_exec` independently refuses to run
against an unlearned prompt (`driver_panos.c:412`), so no command output can
exist without a learned prompt. **State when unlearned: no execution possible on
SSH drivers.** The unlearned case therefore only genuinely arises for the linux
exec-channel driver and the REST drivers, where no prompt ever exists — which is
what the Phase 2 fallback form is for.

**Stored byte-exact?** Nearly. `read_quiescent_last_line`
(`virp_ssh_io.c:207-217`) trims trailing padding (space, tab, CR —
`is_trailing_pad`) and newlines from the end, then takes the final line. So the
learned value is the prompt line's bytes with trailing whitespace/CR removed —
no case folding, no truncation (a line ≥128 bytes fails the learn rather than
truncating). One consequence for Phase 2: a device whose prompt ends in a
significant trailing space (FortiGate prints `hostname # `) would have that
space trimmed; the recorded header will carry the learned bytes, and the era
note should say the learned value is trailing-whitespace-trimmed device bytes.

---

## Phase 5 target (located, not fixed)

`api/server.py:803` — the legacy `devices.json` fallback in `load_devices()`:

```python
"driver": "cisco" if d.get("vendor", "").startswith("cisco") else d.get("driver", "unknown"),
```

Any vendor starting with `cisco` — including `cisco_asa` — collapses to driver
`cisco`. The registry path directly above it already maps correctly
(`_VENDOR_TO_DRIVER` at `api/server.py:756` has `"cisco_asa": "cisco_asa"`), so
the fix is to use the same map in the fallback. `/api/devices` then reports the
truth on both source paths.

---

## Contradictions with the prompt (the valuable part)

1. **Snow's cisco line number is stale.** On current main the cisco site is
   `driver_cisco.c:1124`, not 1044. ASA 975 matches exactly. He is likely
   reading a deployed/older checkout; nothing else about his description
   diverges.
2. **The count is 16, not 2** — and the wazuh comment shows it propagated as a
   deliberate convention ("Format output like other drivers"). The protocol
   note needs habit language, per the prompt's own criterion.
3. **The fabrication is wider than the `#`.** The hostname in the header is the
   registry name, not device bytes (R24/R25 is a live counterexample in the
   current fleet). The prompt framed this as a privilege-character issue; the
   whole first line is synthesized.
4. **PAN-OS is worse than "never consulted":** the true prompt is present in
   the captured buffer and is actively stripped, then replaced with a
   fabrication (`driver_panos.c:916-929`). Not just an omission — a discard.
5. **One piece of good news the prompt didn't predict:** FortiGate's normal
   exec path already signs raw device bytes with no synthesized header — an
   in-tree precedent for the fix's target shape.
6. **Refusal bodies (BLACK, commit-rejected, multi-command) are a sub-class the
   prompt didn't name:** fully synthesized bodies signed through the
   DEVICE_OUTPUT path, while a typed ERROR-observation channel for constructed
   text already exists in the onode. Phase 2 needs a decision on whether these
   move to the ERROR channel or get the tagged-constructed-header form.

---

# Phase 2 addendum — corrections to this survey, found while implementing

The ticket asks for contradictions. Four of these correct **this document**.

1. **My claim 4 was overstated, and it was the one the ticket acted on.**
   I reported PAN-OS as "the only site where true bytes are destroyed rather
   than merely ignored," and the ticket reasonably ordered the work around it.
   That is not accurate. `virp_ssh_read_until_prompt` strips the trailing
   prompt in **all four** SSH drivers — it is the read terminator — and in all
   four the bytes are retained in `conn->prompt`, because a read only
   terminates on an exact match of the learned value. Nothing was destroyed
   anywhere; all four ignored a value they still held. PAN-OS remains
   distinctive for a weaker reason: its comment *documented* the true prompt
   format (`username@hostname>`) and templated `hostname>` anyway, so the
   discard was explicit and it discarded strictly more identity than the
   others. Fixing it first cost nothing, but the stated rationale was wrong.

2. **Snow's ASA line number is exact; his cisco line number was stale** (1124
   on main, not 1044) — as reported in Phase 1, now confirmed by the edit.

3. **"Omit the header entirely" is wrong for two of the five prompt-less
   drivers.** PBS derives its request path from the approved op through a
   lookup table, and Zammad derives the exact JSON a write op posts. Neither
   is recoverable from the command alone, and both are deliberately recorded
   as derivation evidence. Deleting them would destroy real evidence to fix a
   different problem. They keep their line under an explicit
   `VIRP_OBS_DERIVED_TAG` marker instead — the ticket's own option (b).
   Wazuh and LibreNMS *were* safe to omit outright: for those two the
   endpoint IS the command string, so the header carried nothing the frame
   did not already hash. Linux was safe to omit outright as well.

4. **The mock driver is deliberately excluded**, against the ticket's "every
   site." `driver_mock.c` IS the device; everything it emits is simulated
   device output by construction, so its `#` is the simulated device's
   presented prompt rather than a claim about a real session. Several
   onode/approval tests pin its exact shape as a fixture. A comment records
   the exclusion at the site. Production site count is therefore 16 fixed,
   2 mock sites intentionally unchanged.

5. **The JunOS commit-reject refusal performs real device I/O**, which the
   Phase 1 survey flagged as a question and Phase 3 resolved. The commit is
   never sent, but `rollback 0` **is** written to the device — and the body
   being deleted was the only place that recorded it. That fact moved into
   `error_msg`. `no_dispatch = true` is still correct, because that flag
   licenses retry of *the command*, and the commit genuinely was not
   dispatched.

6. **Branch 3 corrects a live miscount, not just a cosmetic label.**
   `narration_check.py` already documents "a refusal is an error frame" and
   computes `executed = otype != "error"`. Because driver-level refusals were
   emitted as `device_output`, every one of them counted as an execution in
   that layer's census. The drivers now match what the checker always
   assumed.

7. **Deleting a refusal body is not sufficient and would have been a worse
   bug.** The daemon tests outcome-UNKNOWN first
   (`disposition == UNSET && !success && output_len == 0 && !no_dispatch`).
   A refusal that clears its body without setting `no_dispatch` matches that
   condition exactly, and would have recorded "the command may have executed;
   not retried" for a command never transmitted — trading a false privilege
   claim for a false execution claim. Every site sets `no_dispatch`;
   `tests/test_refusal_observation_type.c` pins it.

8. **The PBS test targets are not broken.** They fail to link under a bare
   `make` because the PBS driver is opt-in; `make PBS=1 test-pbs-trunc`
   builds and passes (27/27). Worth stating because a bare `make test-pbs`
   looks like a pre-existing failure and is not one.

9. **No FastAPI venv existed on this laptop.** `~/virp-api-venv` (in the
   memory notes) lives on 313, not here. Created locally to run the Phase 5
   API tests; 45/45 pass.
