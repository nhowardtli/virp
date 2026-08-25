# ISSUE-A Phase 2 design — consumer audit, device identity, and the placement decision

Written before implementation, per ticket. Companion to ISSUE-A-SURVEY.md.

---

## 1. Consumer audit — what reads observation bodies today

Audited: Docket (report engine + query UI, `~/docket`), the narration checker
(`~/narration_check.py` + `~/virp_harness.py` + `~/virp_console.py`), `report/`,
`autopilot/`, `api/`, `broker/`, and the IronClaw MCP server
(`~/netclaw-main-extracted/.../mcp-servers/ironclaw/`).

**Headline: no automated consumer parses the fabricated `hostname#` header.
The only reader the fabricated line ever informed is the human or AI reading
the evidence — which is exactly who it lies to.** Detail:

| Consumer | How it uses bodies | Branch 1 impact | Branch 2 impact | Branch 3 impact |
|---|---|---|---|---|
| Docket view/query (`crates/docket/src/query.rs`) | `body_display` renders bytes verbatim; `derive_device` uses JSON `device` field / `obs:<dev>:<ts>` artifact_id — never the text header | none | none | none |
| Docket bundle verify | hashes only (cannot see this defect — the detectability boundary) | none | none | none |
| narration_check.py | typed fields only (`otype`, `tier`, `command` from the tool call); `payload` is ground-truth text for content claims, not parsed structurally. Doc line: *"A refusal is an error frame"*; `executed = otype != "error"` | none | none | **fixes a live miscount**: a driver-level refusal today arrives as `device_output` ⇒ counted `executed=True`. Branch 3 makes drivers match the checker's documented assumption |
| virp_console.py / virp_harness.py | structural frame decode; body verbatim to the model | none (model now reads true prompt) | none | refusals render as error obs — matches the console's existing error rendering |
| report/verify.py `parse_observation_payload` (+v2) | splits first line on `"$ "` (linux) or first `">"` (REST-ish) to extract `command`/`output` for display. `#` headers were **never** parsed | none — junos/panos `prompt>command` still splits at the first `>` | **silent meaning change**: split stops matching ⇒ `command` = "" and `output` = full text. Content stays correct (nothing to strip); the *display* `command` in `virp_report.py:938` degrades to "-" and `virp_evidence_report.py:213` returns the whole body (which is now the right content anyway). Parser updated in Branch 2 to treat headerless bodies as output-only, with command sourced from the chain's gate_execution body | none |
| autopilot/virp_evidence.py `strip_echo` | hard-codes the linux `hostname$ command\n` header and strips it | n/a | prefix miss ⇒ returns payload unchanged — which is **correct** for headerless bodies; old frames still strip. Comment updated in Branch 2 | none |
| autopilot/virp_evidence.py `classify_output` | matches `%` device diagnostics on the first line post-strip | none | improves — first line is now real output | none |
| IronClaw MCP | passes full payload to Genie parsers (header line is unmatched noise either way); renders payload to the AI verbatim | none, AI benefit | n/a (no genie for REST/linux) | refusal text arrives via error obs — `_format_error` path already exists |
| api/server.py, virp_bridge.py, broker | command comes from the request; bridge/broker decode structurally only | none | none | none |
| api/virp_verify.py | line-oriented assertion checks over full output | an assertion written against a header line would change meaning — none exist in-tree; flagged for operators with out-of-tree assertion files | same | none |

**Things that would break or silently change meaning — the report asked for:**
1. Branch 2 changes what `report/verify.py`'s extracted `command` means for new
   frames (extraction goes empty). Fixed in the same branch; old frames parse
   as before. Anyone re-running evidence reports across the era boundary sees
   consistent content, different `command` sourcing.
2. Branch 3 changes the observation TYPE for driver-level refusals
   (DEVICE_OUTPUT → ERROR). Anything counting "device_output frames" as
   "commands that produced output" changes census across the boundary — that
   census was previously **wrong** (it counted refusals as executions), which
   is the narration_check finding above. This is a semantics correction, not
   a regression, but it is a boundary and goes in the era note.
3. Old evidence: nothing here reinterprets it. Entries signed with the
   fabricated prompt stay untouched; the era note (Phase 4) records that their
   first line is not a privilege-level claim.

## 2. Device identity at observation time

What the daemon actually holds when it builds an observation:

- **Registry name** (`conn->device.hostname`) — an operator config claim.
  This is what every header templates today, and it is also the addressing
  identity in `artifact_id` (`obs:<device>:<ts>`) and the chain. It is not
  device bytes.
- **Endpoint** (`host:port`) — config.
- **SSH host key** — verified against known_hosts at connect
  (`virp_ssh_hostkey.c`). This is the *cryptographic* device identity, and it
  is checked but not recorded in observations.
- **Learned prompt bytes** (SSH CLI drivers) — the device's *presented*
  identity, containing its self-reported name. Available at observation time
  in `conn->prompt`.
- REST drivers: only registry name + endpoint (+ TLS peer, not captured).

**Answer: the true device-presented identity IS available at observation time
for the four SSH drivers — it is inside the learned prompt — and only the
registry name exists for REST/linux.** Branch 1 therefore fixes the hostname
fabrication and the `#` fabrication with the same bytes: the header carries the
learned prompt verbatim, so an R24-registered device that presents `R25#` now
signs `R25#`, and the registry-vs-presented disagreement becomes *visible
evidence* instead of being silently papered over. The registry name remains,
correctly, in the addressing fields (artifact_id, chain entries), which are
daemon claims and labeled as such. Recording the host key fingerprint in
observations is the stronger end-state; that is typed-field territory (below).

## 3. The placement decision: body vs typed field

Decision: **the learned prompt goes in the body now, as the first line,
byte-exact (`<learned-prompt><command>\n<device output>`); the typed field is
adopted as the v3+ end-state and queued as a protocol note.** Reasoning, both
ways:

**For the typed field (the ticket's lean, and the correct end-state):** the
prompt is session context, not command output; mixing categories inside one
signed blob is the underlying defect; a typed field makes "body = device bytes
only" structurally enforceable, so the Phase 3 guard becomes a wire-format
invariant instead of a test convention.

**Why not now:** the v1 observation payload is `{obs_type, obs_scope,
obs_length, data}` with *strict* length accounting — the console
(`decode_observation`), the bridge (C `virp_parse_observation` + explicit
bounds enforcement), verify.py, and the evidence layer all reject any frame
whose data length doesn't account for every byte ("v1 defines no trailer").
There is no TLV extension point; adding a field means a new obs version.
obs_version is pinned v1 in both production paths; v3 wiring
(`feat/v3-observation-wiring`) and disposition-enum are both unmerged and
already sequenced against each other. Riding this fix on that stack would gate
an evidence-truth fix behind two unmerged wire-format changes — and
bundle-format change is explicitly out of scope for this ticket.

**Why the body placement is honest and not a compromise on the defect:** the
first line is no longer synthesized in the failure-mode sense. Its command
half is the string the gate classified and hashed into the frame; its prompt
half is bytes the device actually sent on this session (learned by two
confirmed probes, re-confirmed by every completed read — reads terminate only
by matching those exact bytes). The line is a *reconstruction from
session-attested components*, replacing a *fabrication from config*. What
remains imperfect is category mixing — true bytes of two different categories
sharing the body — and that is a schema problem for v3, not an evidence-truth
problem. The defect Snow found (a privilege claim the device never made)
cannot recur: the `#`/`>` is now whatever the device sent.

Queued for v3 (recorded in the Phase 4 draft): body = transport bytes only;
prompt, presented-hostname, host-key fingerprint, HTTP status move to typed
daemon-attested fields.

## 4. Branch plan

Stacked, landing in order; each buildable and tested alone:

1. **`fix/observed-prompt-truth-1-learned-prompt`** — cisco, asa, juniper,
   panos (+ mock alignment). PAN-OS first: it is the only site that *destroys*
   true bytes (strips the real `user@host>` prompt from the capture, then
   fabricates `hostname>`). Store helpers take the header prompt as a
   parameter; execute snapshots `conn->prompt` **before dispatch** (cisco and
   juniper re-learn mid-execute on mode transitions; the header must carry the
   prompt the command was typed at). Tests drive the real execute path with
   the scripted mock PTY from test_ssh_io.c via test-only conn factories.
2. **`fix/observed-prompt-truth-2-headerless`** — linux, wazuh, librenms, pbs,
   zammad: header line omitted entirely; body = device/response bytes
   (FortiGate's normal path is the precedent). True metadata that lived in
   those headers is not silently destroyed: HTTP status → `result->exit_code`
   (already the convention on error paths) plus the gate_execution chain body;
   the zammad derived-JSON derivation record moves under an explicit
   constructed marker (see deviation note in that branch) rather than
   cosplaying as CLI output. report/verify.py + virp_evidence.py updated
   era-aware in the same branch.
3. **`fix/observed-prompt-truth-3-refusal-error`** — the six refusal sites
   emit `output_len = 0`, `success=false`, `no_dispatch=true` (where proven)
   and their text moves to `error_msg`, so the O-Node's existing
   driver-refusal branch signs a typed VIRP_OBS_ERROR observation with the
   command's true tier. Lands last; changes observation-type semantics.
   Special case flagged now: juniper's commit-reject site performed real
   device I/O (config mode entered, rollback applied), so `no_dispatch=true`
   would be false there — its treatment is decided inside branch 3 with the
   actual code in front of us, and reported.

Phase 5 (`api/server.py:803`) lands on the umbrella branch — independent.
