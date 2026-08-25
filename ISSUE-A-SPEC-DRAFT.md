# ISSUE-A Phase 4 — DRAFT text, for review

**Not committed to any spec file.** Three drafts below: a normative
security-considerations line, an era note, and a detectability note.
Nothing here has been merged into `docs/VIRP-SPEC-RFC-v2.md`,
`docs/DRAFT07-NOTES.md`, or `SECURITY.md`. Landing location is proposed
per section; the wording is what needs review first.

---

## 1. Normative line — draft security considerations

Proposed for the Security Considerations section of `draft-howard-virp-07`,
sitting next to the queued note that approvals prove authorization rather
than execution. Both say the same kind of thing: an artifact proves
exactly one property, and readers must not read a second one into it.

> ### N.N. Observed Fields Carry Device Bytes Or Are Absent
>
> An Observation body is a record of what a device transmitted. An
> implementation MUST NOT place synthesized content in an
> observed-body position.
>
> Specifically:
>
> 1. Any byte an implementation writes into an Observation body that
>    did not arrive from the observed device MUST be either (a) omitted
>    entirely, or (b) marked with an unambiguous in-band marker
>    identifying it as originating from the O-Node rather than from the
>    device. An implementation MUST NOT emit a synthesized value whose
>    form is indistinguishable from a value the device could have sent.
>
> 2. Where an implementation records the session context in which a
>    command was issued — a shell prompt, a mode indicator, an
>    administrative identity — that value MUST be bytes the device
>    transmitted during the same session, recorded octet-for-octet. It
>    MUST NOT be reconstructed from configuration, and it MUST NOT be
>    defaulted. An implementation that has not observed such a value
>    MUST omit it or mark it absent under (1).
>
> 3. Where session context was observed at one instant and the recorded
>    command was issued at another, the value recorded MUST be the one
>    in effect at the instant of issue. An implementation MUST NOT
>    restamp an observation with context acquired after the command was
>    dispatched.
>
> 4. A device identifier recorded in an Observation body MUST be the
>    identity the device presented. An identifier drawn from local
>    configuration is an O-Node claim, not an observation, and belongs
>    in an O-Node-attested field.
>
> 5. An implementation's refusal to execute a command is an O-Node
>    event, not a device response. It MUST be recorded as an ERROR
>    Observation and MUST NOT be recorded as device output.
>
> These requirements are not satisfied by integrity protection. A
> Verifier confirms that Observation bytes were not altered after
> signing; it cannot determine whether they were true when written.
> Truthfulness at composition time is solely the O-Node's obligation.

**Note on (1):** "omit entirely" and "mark unambiguously" are both
permitted because they fail differently and both fail visibly. What is
prohibited is the third option — a plausible default — because it fails
invisibly. A reviewer notices a hole; a reviewer does not notice a
well-formed lie.

---

## 2. Era note — body semantics

Proposed for the era-boundary record kept alongside the other
body-semantics boundaries, including the camera driver's `duration_s`
change of 2026-08-25.

> ### Era boundary — Observation body composition (2026-08-25)
>
> **Applies to:** every Observation emitted by a VIRP O-Node before
> 2026-08-25, from all SSH and REST drivers.
>
> **What changed.** Observation bodies were composed with a synthesized
> first line. The four SSH drivers built it by templating the
> configured hostname, a literal prompt character, and the command. The
> learned session prompt was never consulted. The prompt-less drivers
> (linux exec channel, and the REST drivers) emitted the same shape
> although no prompt exists on those transports at all.
>
> **What this means for evidence written before the boundary:**
>
> - The prompt character in the first line of an Observation body
>   **does not indicate the privilege level of the session**. On IOS and
>   ASA it was always `#`, which denotes privileged exec; a command
>   collected at a user-exec prompt (`>`) was recorded as `#`. The
>   character records nothing about the session and MUST NOT be read as
>   evidence of the mode a command was issued from.
> - The hostname in the first line is the **configured registry name**,
>   not an identity the device presented. Where the two disagreed — a
>   device presenting a different name than its registry entry, which
>   has been observed in the lab fleet — the record shows the registry
>   name and the disagreement is not visible.
> - On the linux driver the `$` character likewise indicated nothing;
>   an SSH exec channel presents no prompt. On a root session the shell
>   convention would be `#`, so the recorded character was typically
>   the inverse of the session's actual privilege.
> - On the REST drivers the `>` framing imitated a CLI prompt for a
>   transport that has none.
> - **Driver-level refusals were recorded as device output.** A BLACK-tier
>   refusal, a JunOS commit rejection, and a multi-command refusal each
>   produced a body composed by the O-Node and signed through the
>   device-output path. Consumers that counted device-output
>   observations as executions therefore counted these refusals as
>   commands that ran. After the boundary they are typed ERROR
>   observations.
>
> **After the boundary:** the first line carries the learned prompt
> octet-for-octet, captured at dispatch; where no prompt was learned the
> line is tagged rather than defaulted; prompt-less drivers emit no
> header, and where an O-Node-derived value is still recorded (a request
> path resolved through a lookup table, the JSON a write operation
> derived) the line is prefixed with an explicit daemon-attested marker.
>
> **No existing chain entry was altered, rewritten, or back-filled.**
> Entries signed before this boundary remain exactly as signed. They are
> evidence of what the software did. This note changes only how they must
> be read.

---

## 3. Detectability note

Proposed for the same era record and for the verifier documentation.

> **A bundle verifier cannot detect this class of defect.** Verification
> establishes that Observation bytes are unaltered since signing and that
> the chain linking them is intact. This defect produced bytes that were
> untrue at the moment they were signed. The signature over them is
> valid, the chain over them is intact, and the verifier is correct to
> say so. Integrity and truthfulness are different properties, and only
> the first is cryptographically checkable after the fact.
>
> **This boundary has now appeared three times**, in three unrelated
> subsystems:
>
> 1. **Item 5 (2026-08-11)** — a clamped body signed with
>    `success=true` and `truncated=no`. The bytes were unaltered; the
>    length accounting around them was false.
> 2. **Camera driver (2026-08-25)** — re-emitted segments carried
>    re-stamped capture windows. The segment bytes were unaltered; the
>    time window attributed to them was false.
> 3. **ISSUE-A (2026-08-25)** — synthesized prompt and identity in the
>    observation header. The bytes were unaltered; the privilege level
>    and device identity they asserted were false.
>
> Three independent occurrences is a pattern, not a coincidence, and the
> pattern has a shape: **the defect is always in the relationship between
> a body and the metadata asserted about it, never in the body's
> integrity.** Every one was found by a human comparing a record against
> the world, and none could have been found by verifying a bundle.
>
> The structural response is to stop mixing categories inside one signed
> blob. Where device bytes and O-Node claims share a body, no verifier
> can tell a reader which is which. Moving session context, presented
> identity, transport status, and derived request parameters into typed,
> separately-attested fields would make the category boundary
> machine-checkable rather than a matter of driver discipline. That is a
> wire-format change and is proposed as v3+ work; the in-band marker
> introduced by ISSUE-A is the interim measure, not the destination.

---

## Landing plan (proposed, not executed)

| Draft | Proposed destination | Blocked on |
|---|---|---|
| §1 normative line | `draft-howard-virp-07` Security Considerations; mirror into `SECURITY.md` | review of wording |
| §2 era note | era-boundary record beside the camera `duration_s` note | confirmation of where that record canonically lives |
| §3 detectability | same era record + verifier docs (`report/verify.py` module docstring) | review |
| typed-field proposal | `docs/DRAFT07-NOTES.md` as a new numbered entry | depends on v3 observation wiring landing first (`feat/v3-observation-wiring`, unmerged) |
