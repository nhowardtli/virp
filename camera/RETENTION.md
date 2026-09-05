# Retention as a signed record — camera_retention/1

Status: IMPLEMENTED both sides 2026-09-05. Driver side in
`camera/virp_camera.py`; Docket side in the public verifier repo
(`virp-verify` / `docket-bundle` / `tools/export`), shipped in
virp-verify v0.1.3. §5 below is now a description of what exists,
not a handoff.

## 1. What this is

Old evidence files are deleted on a schedule (30 days on the capture
host's outbox, 14 days in the O-node spool's `done/`). Deletion is the
one thing this system does that looks exactly like the attack it exists
to catch, so no byte is ever deleted silently: every batch is declared
first in a producer-signed, chain-appended `camera_retention/1` record
naming the policy, the camera, the tier, and the exact digests removed.
A verifier can then tell "absent by declared policy" from "absent
unexplained" — once Docket learns to read the record (§5); until then
both still grade ABSENT, which is honest, just undifferentiated.

## 2. The record

Frozen exact field set (the field set IS the schema, the same rule as
`sensor_signature`); growing it is a version bump to `/2`:

```
schema              "camera_retention/1"
camera_id           whose artifacts were removed
tier                "capture-host" | "spool"
policy_days         the policy in force, sealed into the record (30 / 14)
deleted_at_utc_ns   when the batch was journalled (one scan, one instant)
removed             [ { sha256, kind, byte_len } … ]  — exact triple each
removed_count       claim; must equal len(removed)
removed_bytes       claim; must equal the sum of byte_len
producer_key_id     the deleting host's key
producer_sig        Ed25519 over the canonical body minus this field
```

`kind` vocabulary (closed): `segment`, `record_body`, `validator_output`,
`leaf_der`, `handoff`, `marker`, `other`. `other` exists so a file this
code deletes but cannot classify still gets its digest declared —
unknown is never skipped.

Sessions: `camera-retention:<camera_id>:<UTC date of deleted_at>`.
Camera sessions (`camera:<id>:<date>`) stay pure camera_segment streams;
the coverage grader never sees a retention record as a segment.

Artifact ids: `camret:<camera_id>:<tier>:<deleted_at_utc_ns>:<chunk>`.
One scan may write several records for one camera because the daemon's
8192-byte artifact field caps a record (~60 items each); chunking is
deterministic, and every chunk is its own complete, valid record.

## 3. Order is the whole design

journal (atomic write) → deliver the signed record → delete the files
→ advance the journal. A crash before delivery deletes nothing. A crash
after delivery resumes from the journal; bodies rebuild byte-identical
(deleted_at comes from the journal, not the clock), so redelivery
deduplicates on body sha — the spool submitter's sidecar + chain-keyed
idempotency, the same mechanism segments use. At no point do bytes
disappear that no signed record declares. A failed delivery raises and
deletes nothing; the journal survives for the next run.

## 4. Tiers and transport

- **capture-host** (Spark, 30 days, per camera): `virp_camera.py
  retention --tier capture-host --dir <data-dir>/outbox --days 30
  --spool virp-capture@10.0.0.13 …`. The record ships as a RECORD-ONLY
  spool job (`<camera>.retention.<ns>.<chunk>.body` + `.done`, no
  `.mp4`) through the same pinned sftp channel as the segments it
  covers. The submit-spool gate accepts a record-only job **only** when
  the body's own schema declaration is `camera_retention/1` and the body
  validates against §2 — a segment job whose `.mp4` is racing the marker
  still waits, and a malformed retention body is left for a human.
- **spool** (313, 14 days, `done/`): `virp_camera.py retention --tier
  spool --dir /var/spool/virp-capture/done --days 14 …` runs on the
  O-node host as user `virp`, signs with 313's own producer key
  (`/var/lib/virp/camera/producer.key`), and appends directly through
  the daemon socket. camera_id per batch is read from each job's own
  `.body` (the body's claim, not a filename guess); grouping is by the
  job-name camera token.

## 5. The Docket handoff (IMPLEMENTED 2026-09-05)

For `referenced_artifact_binding` to grade the distinction, two surfaces
changed:

1. **Exporter** (`tools/export/export_bundle.py`, now in the public
   verifier repo): when a cited digest has no carried bytes, and a
   `camera_retention/*` record inside the exported session set lists that
   digest in `removed[]`, the citation is listed not carried with reason
   `absent_by_declared_policy` and a POINTER to that record. The existing
   `NotCarried` reason vocabulary (`not_found`, `eacces`, other) was the
   extension point. The exporter verifies nothing: it holds no producer
   key and judges nothing. It records where the claim is.

2. **Verifier** (`docket-bundle`):
   `NotCarried::AbsentByDeclaredPolicy { retention_session,
   retention_sequence }` grades the citation "absent by declared policy,
   never a pass" — a distinct detail under the ABSENT-family status, NOT a
   new pass state, and only after re-verifying that the cited retention
   record is carried, hashes to its `artifact_hash`, is producer-signed
   under a key the examiner supplied out of band, and actually lists the
   digest. A retention record the bundle does not carry, or one that fails
   any of those, must NOT soften the absence: that stays plain ABSENT, and
   the failed claim is REPORTED rather than dropped — a broken declaration
   is worse than none, because someone wrote it down.

### The pointer is a required PAIR

`retention_session` and `retention_sequence` are **both required**. Chain
sequences are per session and every session starts at 0, so a bare
`retention_sequence: N` is ambiguous with the citing session's own entry at
N — and the retention record always lives in a different session
(`camera-retention:<camera>:<date>`) from the `camera:` session that cites
the digest. A lone sequence names two records and identifies neither.

A citation carrying one field without the other is **malformed, not merely
unresolved**. It grades ABSENT — a definite absence, never UNVERIFIABLE —
and the report names the field that is missing. UNVERIFIABLE would say the
evidence could not be looked at; this is a defect in the manifest, not a
question about the evidence. It is equally not folded into plain
`not_found`, which would hide that a claim was written here at all.

### Unknown schemas are ABSENT, and say so

A carried body whose `schema` this verifier does not examine grades
`producer_signature` ABSENT with the reason *"schema not examined by this
verifier"*, naming the schema. Never a pass. Silence about an unexamined
body reads as "checked and fine" to anyone scanning a grade, which is the
collapse this whole vocabulary exists to prevent. `camera_segment/*` and
`camera_retention/*` are the examined set; both carry the same
`producer_key_id`/`producer_sig` pair over the same canonical
body-minus-sig, so both are graded by one code path and one vocabulary.

The trust statement to preserve: a retention record proves the operator
*declared* the deletion under a producer key at a chained time. It does
not prove the bytes matched their digests at deletion time (nothing
re-verified them on the way out), and it never upgrades an absence into
a pass.

## 6. What this does not do

- No standalone "the file was deleted" grading in `audit` yet (same §5
  ruling applies if wanted there).
- `/var/lib/virp/camera/artifacts/` on 313 (the O-node's
  content-addressed store submit_one writes) is NOT under any retention
  policy — deliberately out of scope 2026-09-05, flagged to nhoward.
- Nothing rewrites or re-signs history: retention deletes files and
  appends records; chain entries are untouched.
