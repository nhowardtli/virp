#!/usr/bin/env python3
"""
virp_camera.py — VIRP camera driver: live-segment attestation producer.

The base tier of the camera product: NO AI, no detection — observe and
attest only. Turns a directory of closed video segments (Phase 1:
--replay; Phase 2 adds --live with an ffmpeg child) into a continuous
chain of hash-bound camera_segment/1 records on the O-node trust chain,
so Docket can answer "what did this camera record, when, and is it
unaltered since ingest" from signed entries.

How a segment becomes evidence:
  1. sha256 over the segment file bytes; the file is stored
     content-addressed as <data-dir>/artifacts/<sha256>.mp4 (the same
     convention as bundle artifacts/).
  2. A camera_segment/1 body is built as single-line canonical JSON
     (sorted keys, no whitespace), serialized ONCE; artifact_hash is
     sha256 over exactly those stored bytes. The daemon's GATE 2
     re-derives the same hash over the received bytes and refuses a
     mismatch, and `audit` re-checks the stored rows after the fact —
     the chainwalk_summary pretty-print defect cannot recur silently.
  3. The body is submitted as artifact_type=evidence_item via
     chain_append. evidence_item is the established externally
     submittable, hash-bound record type (autopilot/virp_evidence.py);
     "camera_segment/1" is the schema INSIDE the body, per that
     convention. The daemon stores the body and D-1 Ed25519-signs the
     chain entry with its own chain-signing key.

Continuity is committed INSIDE the bodies: each record carries
prev_segment_sha256, so segment N commits to segment N-1 and a dropped,
reordered or replaced segment is detectable from the signed bodies
alone, independent of chain sequencing. The prev chain runs across
daily sessions and across restarts; what a restart cannot honestly
claim — continuous coverage between two runs — is recorded as an
explicit gap on the first record of the new run. A gap is never silent.

Key custody (the trust boundary, stated plainly):
  - The driver holds NO VIRP key: not the chain-signing key, not the
    O-Key, not an obskey. Chain entries are signed by the O-node at
    ingest with keys that never leave the daemon host.
  - The driver holds only its own PRODUCER key, an Ed25519 keypair
    generated on the capture host (`keygen`). Each body carries
    producer_sig over the canonical body-without-sig. This proves the
    record originated at the holder of that key, verified OUT OF BAND
    by `verify-segment`/`audit` against the pinned public key — Docket
    does not verify it and reaches its verdicts without it.
  - What all this proves: the footage is unaltered SINCE capture-side
    ingest. It says nothing about scene authenticity or injection
    upstream of the capture host. Tamper-EVIDENT, not tamper-proof.
  - AND IT BINDS A KEY, NOT A HOST. The wording above ("generated on the
    capture host", "the capture host's key") describes the intended
    shape, not an enforced one. A producer signature identifies a host
    only if that key is on exactly ONE host, and nothing here checks
    that. Measured 2026-09-03: producer key 008353cf is on TWO machines
    — the laptop, in three byte-identical copies, and the Spark — and
    2537 camera_segment/1 records on the home node's chain are signed
    under it. Those records prove a body was signed by the holder of
    008353cf and is unaltered; they do NOT say which machine produced
    it, and no later key rotation can make them say so, because a
    signature cannot be retroactively narrowed. Issuing per-machine keys
    fixes what FUTURE records bind. Any claim about the existing ones
    has to be the weaker statement regardless. See
    deploy/keys/registry.json, which records custody per key.
  - RTSP credentials (live mode) come from the environment or a 0600
    config file only, and never appear in bodies, logs, or reports.
    Replay mode touches no credentials at all.

This producer submits OBSERVATION-CLASS evidence only: its entire
action vocabulary is `chain_append` of artifact_type=evidence_item
(pinned by test). It never constructs gate_execution / gate_rejection /
proposal / approval entries and never imitates the gate.

Copyright (c) 2026 Third Level IT LLC. All rights reserved.
"""

import argparse
import base64
import fcntl
import glob
import hashlib
import json
import os
import re
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import time

SCHEMA_V1 = "camera_segment/1"
SCHEMA_V2 = "camera_segment/2"
SCHEMA_V3 = "camera_segment/3"
SCHEMA_V4 = "camera_segment/4"
SCHEMA_V5 = "camera_segment/5"
# What this producer emits when a capture policy is declared (always,
# from the CLI). SCHEMA_V1 remains emitted only by callers that pass no
# policy, and remains READABLE forever: 2553 live records carry it and
# nothing here may re-sign or rewrite them. SCHEMA_V2 is /1 plus the
# signed capture_policy; SCHEMA_V3 is /2 plus the sensor_signature —
# what the CAMERA asserts about its own video, which is a different
# fact from anything this host can observe.
SCHEMA = SCHEMA_V5
# SCHEMAS, POLICY_SCHEMAS and SENSOR_KEYS_BY_SCHEMA are all DERIVED, from
# the one table below — see SCHEMA_TABLE, after the sensor field sets it
# needs. Nothing in this module may hand-type a set of schema names.

# ── The sensor's own claim ─────────────────────────────────────────────
#
# A signing camera (Axis signed video) asserts that the bitstream is the
# one its sensor emitted, and stamps its OWN clock on the first and last
# frame. Both are the camera's claim and are labelled as such
# everywhere: the M3085-V in the lab has a wrong clock and stamps
# 2024-08-15 onto 2026 footage. capture_end_utc_ns stays this host's
# observation and the chain entry's own timestamp stays the O-node's
# receipt; the three are never collapsed.
#
# The verdict vocabulary is CLOSED, and no failure may leave the object
# out. "The validator was missing" and "the video verified" must never
# be the same shape on the wire, because a verifier that tests for the
# field's presence would read the first as the second.
SENSOR_VALID = "VALID"
SENSOR_INVALID = "INVALID"
SENSOR_UNSIGNED = "UNSIGNED"          # this camera does not sign at all
SENSOR_UNVERIFIED = "UNVERIFIED"      # we could not judge; see ruling #1
SENSOR_VERDICTS = (SENSOR_VALID, SENSOR_INVALID, SENSOR_UNSIGNED,
                   SENSOR_UNVERIFIED)

# The field set IS the schema, one level down: every key is present in
# every record, and an unavailable value is null. Nothing optional.
# The field set IS the schema one level down, so GROWING THIS OBJECT IS
# A VERSION BUMP. /3 records are already signed and on the chain with
# the 13-key form; they can never gain a field, and a verifier that
# quietly accepted both sizes would have given up the very rule that
# stops anyone appending a verdict to frozen history. /4 adds the leaf
# pin. /3 stays READABLE forever and is never emitted again.
SENSOR_SIGNATURE_KEYS_V3 = (
    "vendor", "validator", "verdict", "public_key",
    "gops_valid", "gops_valid_with_missing", "gops_invalid",
    "gops_unsigned", "device_serial", "device_firmware",
    "asserted_first_frame", "asserted_last_frame",
    "validator_output_sha256",
)
SENSOR_SIGNATURE_KEYS_V4 = SENSOR_SIGNATURE_KEYS_V3 + (
    "public_key_pin", "sensor_key_sha256",
)
SENSOR_SIGNATURE_KEYS = SENSOR_SIGNATURE_KEYS_V4 + ("device_chain",)

# ── The schema table: ONE row per version, and every set derived ───────
#
# What each version carries, stated once. Before this table the same
# facts were spelled out as hand-typed tuples in five places, and the /5
# bump reached four of them: `_body_policy` still tested
# `schema in (V2, V3, V4)`, so every /5 record graded UNDECLARED while
# carrying a perfectly good capture_policy, and audit reported them as
# `camera_segment/1` — the one version that legitimately has none. The
# audit disagreed with virp-verify about coverage on live records for as
# long as that tuple was stale, and the tool reading the producer's own
# records was the wrong one.
#
# So a version bump is ADDING A ROW HERE. If a set has to be updated
# somewhere else too, that place is a bug waiting for the next bump —
# which is the whole reason the /5 omission was possible.
#
#   policy: the body carries capture_policy (the signed cadence)
#   sensor: the sensor_signature field set at that version, or None for
#           the versions from before the camera's own claim existed
SCHEMA_TABLE = {
    SCHEMA_V1: {"policy": False, "sensor": None},
    SCHEMA_V2: {"policy": True, "sensor": None},
    SCHEMA_V3: {"policy": True, "sensor": SENSOR_SIGNATURE_KEYS_V3},
    SCHEMA_V4: {"policy": True, "sensor": SENSOR_SIGNATURE_KEYS_V4},
    SCHEMA_V5: {"policy": True, "sensor": SENSOR_SIGNATURE_KEYS},
}

# Every schema this auditor can read, oldest first. A schema absent here
# is one it will not judge, and says so rather than passing it.
SCHEMAS = tuple(SCHEMA_TABLE)
# The versions whose bodies carry a capture_policy. /1 is the only one
# that does not, and that is UNDECLARED coverage, not zero tolerance.
POLICY_SCHEMAS = frozenset(s for s, d in SCHEMA_TABLE.items()
                           if d["policy"])
# The sensor_signature field set REQUIRED at each version that has one.
# The field set IS the schema one level down: an exact match, never a
# subset, because reading the fields we recognise and ignoring the rest
# is how a record of an unexpected shape ends up inside a clean result.
SENSOR_KEYS_BY_SCHEMA = {s: frozenset(d["sensor"])
                         for s, d in SCHEMA_TABLE.items()
                         if d["sensor"] is not None}

# ── The device certificate chain, anchored at a CA WE pinned ───────────
#
# THE ANCHOR IS A KEY, NOT A CERTIFICATE. Axis has issued at least two
# certificates for `Axis Edge Vault Attestation CA ECC 1` — identical
# subject and identical public key, different serial numbers and
# different notAfter (2032-10-25 and 2055-06-01). Both are legitimate.
# Pinning certificate BYTES would reject a real device whose stream
# happens to carry the other one, so what is checked is the signature
# under the anchor's PUBLIC KEY. `anchor_sha256` still records the exact
# file pinned, because which bytes an operator installed is its own fact.
#
# WHAT THIS PROVES, AND WHAT IT DOES NOT. The anchor was taken from the
# camera's own stream: it is trust on first use one level up from the
# leaf. It detects a leaf issued by any other CA, and it survives leaf
# rotation within this CA — both real gains over pinning the leaf key
# alone. It is NOT a chain to a root delivered out of band, because Axis
# does not publish the Edge Vault Attestation root: the PKI repository
# carries only the Device ID hierarchy, and their own Certificate Policy
# names "Axis Edge Vault Root CA" as a separate CA it does not publish.
# The `anchor` field says which of those two things happened, and reads
# "root" only when a genuinely out-of-band root is pinned.
ANCHOR_INTERMEDIATE = "intermediate_pinned"
ANCHOR_ROOT = "root"
DEVICE_CHAIN_KEYS = (
    "anchor", "anchor_sha256", "chain_to_anchor_verified",
    "leaf_serial_matches_device", "leaf_not_after",
)
SENSOR_ANCHOR_FILE = os.path.join("trust", "axis-edge-vault-attestation-ca.pem")
_PEM_CERT = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)

# The leaf pin. `public_key` is the FRAMEWORK's opinion of the key it
# used; `public_key_pin` is OURS — whether the key in the stream is the
# one we pinned out of band for this camera. They are separate questions
# and a record carries both.
#
# A MISMATCH IS NOT A TAMPER CLAIM. The bytes may be perfectly authentic
# footage from a camera we did not pin; calling that INVALID would accuse
# a device of tampering when the honest statement is "this is not the
# device we pinned". So a mismatch grades UNVERIFIED — we could not
# establish the source — and the key state is recorded either way.
PIN_MATCH = "MATCH"
PIN_MISMATCH = "MISMATCH"
PIN_NO_KEY_IN_STREAM = "NO_KEY_IN_STREAM"
PIN_UNREADABLE = "PIN_UNREADABLE"
SENSOR_PUBKEY_FILE = "sensor_pubkey.pem"

_PEM_PUBLIC_KEY = re.compile(
    rb"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----", re.S)

VALIDATOR_NAME = "signed-video-framework"
VALIDATOR_RESULTS_FILE = "validation_results.txt"
VALIDATOR_TIMEOUT_S = 300
ONODE_SOCKET = "/run/virp/onode.sock"
CHAIN_DB = "/var/lib/virp/chain.db"
DATA_DIR = "/var/lib/virp/camera"
ARTIFACT_LIMIT = 8192   # daemon artifact_content[8192]: at/past this the
                        # body would be stored truncated — refuse, never
                        # register an unverifiable record.

# The one artifact type this producer may ever submit. Pinned by test.
ARTIFACT_TYPE = "evidence_item"


# ── Canonical serialization ────────────────────────────────────────────
#
# ONE canonical form, used for the stored body AND the producer-sig
# payload: single line, sorted keys, no whitespace, ASCII. The bytes
# returned here are the bytes hashed, the bytes signed, the bytes
# submitted and the bytes stored — there is no second serialization.

def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


# ── Producer key (Ed25519, capture-host-only) ──────────────────────────

def _ed25519():
    """Import lazily so key-less paths (verify-segment against a body
    with no pinned pubkey, audit without --pubkey) run without the
    cryptography package."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    return ed25519


def producer_keygen(sk_path, pk_path):
    """Generate the producer keypair. Refuses to overwrite: an existing
    key is an identity — remove both files first to regenerate (a new
    key is a new producer identity, it does not re-sign old records)."""
    ed = _ed25519()
    sk = ed.Ed25519PrivateKey.generate()
    sk_raw = sk.private_bytes_raw()
    pk_raw = sk.public_key().public_bytes_raw()
    fd = os.open(sk_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(sk_raw)
    fd = os.open(pk_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(pk_raw)
    return producer_key_id(pk_raw)


def producer_key_id(pk_raw):
    """key_id = SHA-256(public_key)[:16] hex — the same convention as
    the obskey / approver-registry / federation keys."""
    return hashlib.sha256(pk_raw).hexdigest()[:32]


def producer_load_sk(sk_path):
    st = os.stat(sk_path)
    if st.st_mode & 0o077:
        raise SystemExit("producer key %s is group/world-accessible "
                         "(mode %o) — refusing to use it" %
                         (sk_path, st.st_mode & 0o777))
    with open(sk_path, "rb") as f:
        raw = f.read()
    if len(raw) != 32:
        raise SystemExit("producer key %s is not a 32-byte raw Ed25519 "
                         "seed" % sk_path)
    ed = _ed25519()
    return ed.Ed25519PrivateKey.from_private_bytes(raw)


def producer_sign(sk, body_without_sig):
    """Sign the canonical bytes of the body WITHOUT producer_sig, then
    return (body_bytes, body_dict) with the sig inserted — canonical
    serialization is deterministic, so any verifier can pop the sig,
    re-canonicalize, and check."""
    payload = canonical_bytes(body_without_sig)
    sig = sk.sign(payload)
    body = dict(body_without_sig)
    body["producer_sig"] = sig.hex()
    return canonical_bytes(body), body


def producer_verify(pk_raw, body_dict):
    """True iff producer_sig verifies over the canonical body-minus-sig
    under the given raw public key. Never raises on a bad sig."""
    if "producer_sig" not in body_dict:
        return False
    ed = _ed25519()
    try:
        pk = ed.Ed25519PublicKey.from_public_bytes(pk_raw)
        stripped = {k: v for k, v in body_dict.items()
                    if k != "producer_sig"}
        pk.verify(bytes.fromhex(body_dict["producer_sig"]),
                  canonical_bytes(stripped))
        return True
    except Exception:
        return False


# ── MP4 duration (no ffprobe dependency) ───────────────────────────────

def mp4_duration_s(path):
    """Duration in seconds from the moov/mvhd box. -c copy segments
    always carry a moov; a file without one raises ValueError rather
    than guessing."""
    with open(path, "rb") as f:
        data = f.read()
    try:
        moov = _find_box(data, 0, len(data), b"moov")
        if moov is None:
            raise ValueError("%s: no moov box" % path)
        mvhd = _find_box(data, moov[0], moov[1], b"mvhd")
        if mvhd is None:
            raise ValueError("%s: no mvhd box" % path)
        off = mvhd[0]
        version = data[off]
        if version == 1:
            timescale = struct.unpack(">I", data[off + 20:off + 24])[0]
            duration = struct.unpack(">Q", data[off + 24:off + 32])[0]
        else:
            timescale = struct.unpack(">I", data[off + 12:off + 16])[0]
            duration = struct.unpack(">I", data[off + 16:off + 20])[0]
    except (struct.error, IndexError):
        # a box header pointing past EOF: an open/torn file, not a
        # closed segment — the same "not attestable yet" answer as a
        # missing moov, never an unhandled crash
        raise ValueError("%s: truncated box structure" % path)
    if timescale == 0:
        raise ValueError("%s: mvhd timescale 0" % path)
    return duration / timescale


def _find_box(data, start, end, name):
    """Scan one box level for `name`; return (payload_start, payload_end)
    or None."""
    off = start
    while off + 8 <= end:
        size = struct.unpack(">I", data[off:off + 4])[0]
        typ = data[off + 4:off + 8]
        hdr = 8
        if size == 1:
            if off + 16 > end:
                return None
            size = struct.unpack(">Q", data[off + 8:off + 16])[0]
            hdr = 16
        elif size == 0:
            size = end - off
        if size < hdr:
            return None
        if typ == name:
            return (off + hdr, off + size)
        off += size
    return None


# ── O-Node socket client ───────────────────────────────────────────────

def onode_send(request, sock_path=ONODE_SOCKET, timeout=60):
    """v2 framing: send [4B len][0x02][JSON], receive [4B len][payload].
    Same protocol as autopilot/virp_evidence.py — this client's entire
    vocabulary is chain_append."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path)
        payload = json.dumps(request).encode()
        s.sendall(struct.pack(">I", 1 + len(payload)) + b"\x02" + payload)
        hdr = b""
        while len(hdr) < 4:
            c = s.recv(4 - len(hdr))
            if not c:
                raise IOError("short read on frame length")
            hdr += c
        n = struct.unpack(">I", hdr)[0]
        buf = b""
        while len(buf) < n:
            c = s.recv(n - len(buf))
            if not c:
                raise IOError("short read on frame body")
            buf += c
        return buf
    finally:
        s.close()


def chain_append_evidence(session_id, artifact_id, body_bytes,
                          sock_path=ONODE_SOCKET, send=onode_send):
    """Append one evidence_item committing to body_bytes. Returns
    (ok, receipt_or_error). The daemon's GATE 2 recomputes the hash
    over the received bytes; a refusal here means the record did NOT
    land — the caller must not advance its continuity state."""
    if len(body_bytes) >= ARTIFACT_LIMIT:
        return False, ("body is %d bytes, at/past the daemon's %d-byte "
                       "artifact field — would be stored truncated "
                       "(unverifiable); not submitted"
                       % (len(body_bytes), ARTIFACT_LIMIT))
    req = {
        "action": "chain_append",
        "session_id": session_id,
        "artifact_type": ARTIFACT_TYPE,
        "artifact_id": artifact_id,
        "artifact_hash": hashlib.sha256(body_bytes).hexdigest(),
        "artifact_content": body_bytes.decode("ascii"),
    }
    resp = send(req, sock_path=sock_path)
    if len(resp) == 4:
        code = struct.unpack(">i", resp)[0]
        return False, "O-Node error %d" % code
    return True, resp


# ── Driver state ───────────────────────────────────────────────────────
#
# The continuity ledger: last sequence number and last segment hash,
# persisted AFTER each successful chain append (atomic tmp+rename). A
# crash between submit and state write re-submits that segment on
# restart (two entries, same body hash — visible, honest) rather than
# ever skipping one.

def state_load(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def state_save(path, state):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=1, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _fsync_dir(os.path.dirname(path))


def _fsync_dir(dirpath):
    """A rename or append is durable only once its DIRECTORY entry is —
    fsync the containing dir, not just the file."""
    fd = os.open(dirpath or ".", os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


# ── Durable submit checkpoint (Fix A) ──────────────────────────────────
#
# The record of what this capture host has HANDED OFF, one line per
# shipped RECORD: segment_seq, segment_sha256, capture_end_utc_ns,
# body_sha256 and the spool job name. Never keyed on a workdir
# filename, which ffmpeg reuses from seg_000000 after every restart.
# Append-only JSONL, fsynced before continuity advances, so it survives
# process death: startup consults this file, not a directory listing
# and not process memory. state.json remains the fast-path continuity
# cursor; where the two disagree (a crash between checkpoint_append and
# state_save) the checkpoint is authoritative — see _resume_state — so
# a sequence number is never reused.
#
# IDENTITY (Sep 1 review, Task 1). A record is identified by
# (segment_sha256, capture_end_utc_ns) — the content AND the capture
# end, which is the segment file's mtime and is immutable across
# re-offers (Fix E). Content alone is NOT an identity: two closed
# segments with byte-identical footage (a static scene, an idle frame
# repeated) are two segments and ship as two records with consecutive
# sequence numbers. Keying on segment_sha256 alone deleted the second
# one as "already attested" — a silent drop. What the identity still
# catches is the SAME FILE seen again (crash between checkpoint_append
# and the workdir unlink, or a reused name carrying the old bytes with
# the old mtime): same content, same capture end, same record — settled
# as residue, never re-shipped. body_sha256 is recorded per line for
# audit (the handoff sidecar carries the bytes); it is not the lookup
# key because a re-seen file's seq is unknown until the record is
# found, and the body embeds the seq.
#
# Named open item, deliberately NOT designed here: the checkpoint marks
# ship-acknowledged, not chain-append-acknowledged — there is no ack
# path from the O-node back to the capture host. Until one exists, the
# spool-side chain-keyed idempotency (_on_chain in submit_one) is the
# backstop that makes any re-offer a no-op instead of a duplicate.

def shipped_key(segment_sha256, capture_end_utc_ns):
    """Record identity: content + capture end. See the IDENTITY note."""
    return (segment_sha256, int(capture_end_utc_ns))


def shipped_record(shipped, segment_sha256, capture_end_utc_ns):
    """The checkpoint record for THIS file (content + mtime), or None.
    A different file with the same bytes is not a match."""
    return shipped.get(shipped_key(segment_sha256, capture_end_utc_ns))


def checkpoint_load(path):
    """{(segment_sha256, capture_end_utc_ns): record} from the shipped
    checkpoint. A crash mid-append can leave one torn final line;
    complete records are kept, the torn tail is ignored. A record with
    no capture_end_utc_ns cannot be identified and is skipped."""
    if not path or not os.path.exists(path):
        return {}
    out = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if "segment_sha256" not in rec or "capture_end_utc_ns" not in rec:
                continue
            out[shipped_key(rec["segment_sha256"],
                            rec["capture_end_utc_ns"])] = rec
    return out


def checkpoint_append(path, rec):
    """Append one shipped record and fsync file AND directory before
    returning: the marker must be durable before continuity state may
    advance past it."""
    with open(path, "a") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())
    _fsync_dir(os.path.dirname(path))


def _resume_state(state, shipped, camera_id):
    """Resume point across process death. The checkpoint tail wins when
    it is ahead of state.json (crash after checkpoint_append, before
    state_save): adopting it keeps seq/prev-hash continuity aligned with
    what actually shipped."""
    if not shipped:
        return state
    tail = max(shipped.values(), key=lambda r: r["segment_seq"])
    if state is not None and state["segment_seq"] >= tail["segment_seq"]:
        return state
    return {
        "camera_id": camera_id,
        "segment_seq": tail["segment_seq"],
        "last_segment_sha256": tail["segment_sha256"],
        "last_session_id": session_for(camera_id,
                                       tail["capture_end_utc_ns"]),
        "last_end_ns": tail["capture_end_utc_ns"],
    }


# ── Single-instance lock (Fix F) ───────────────────────────────────────
#
# One driver per camera/spool: two live captures into the same workdir
# would interleave segment files; two submit-spools over the same
# incoming/ would race jobs. flock(2) is the primitive because the lock
# DIES WITH ITS HOLDER — a stale lock after an unclean exit can never
# require manual intervention. The pid written inside is diagnostic
# only: found non-empty on a successful acquire, it means the previous
# holder exited uncleanly, and the recovery is logged.

def acquire_instance_lock(path, label):
    """Take the exclusive instance lock or die. Returns the open fd —
    keep it for the life of the process (closing it releases the
    lock)."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        try:
            holder = os.read(fd, 64).decode("ascii", "replace").strip()
        except OSError:
            holder = ""
        os.close(fd)
        raise SystemExit(
            "%s: another instance%s holds %s — refusing to run twice "
            "against the same camera/spool"
            % (label, " (pid %s)" % holder if holder else "", path))
    prev = os.read(fd, 64).decode("ascii", "replace").strip()
    if prev:
        sys.stderr.write("%s: recovered stale instance lock %s (unclean "
                         "exit of pid %s); proceeding\n"
                         % (label, path, prev))
    os.lseek(fd, 0, os.SEEK_SET)
    os.ftruncate(fd, 0)
    os.write(fd, ("%d\n" % os.getpid()).encode("ascii"))
    return fd


def release_instance_lock(fd):
    """Clean release: empty the pid (so the next acquire logs no stale
    recovery) and let the close drop the flock."""
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
    finally:
        os.close(fd)


# ── Gap validity — the producer's copy of the verifier's rule ──────────
#
# A `gap` is the producer's signed statement that continuity is NOT
# claimed at this point in the stream. Because it is the one thing that
# excuses a continuity break, it is exactly the field a malformed or
# invented value must not be able to abuse.
#
# Docket grades a record FAILED unless a present gap is an OBJECT
# carrying an integer after_seq that cites the previous record for the
# same camera, plus a nonempty, bounded reason. This file used to excuse
# a break on `gap is not None` — a truthy scalar, an empty object, an
# after_seq pointing anywhere at all would do. That was a live
# divergence: this producer could sign, and this auditor could pass, a
# record the verifier rejects. The rule below is that rule, re-derived
# from the record format, and it is applied on BOTH sides here — at
# emission (build_body refuses to build such a body) and at every point
# that grades one (audit continuity, coverage, content reuse).
#
# The external-predecessor case: on a camera's FIRST record carried in
# the corpus there is no previous record to cite, but the stream itself
# may legitimately begin mid-run — a sliced export, a session-boundary
# rollover. A gap whose after_seq is segment_seq - 1 names that absent
# predecessor and is valid. Segment 0 has no predecessor at all,
# external or otherwise, so any gap there is a defect.
#
# That form is accepted wherever it appears, not only on the first
# record, because THIS auditor is handed filtered corpora on purpose
# (--session-prefix, and the frozen two-block Aug-24 fixture) while
# Docket grades whole chains. On a complete corpus the two citations are
# the same number, so a complete chain grades identically here and in
# Docket; they differ only where the corpus itself is incomplete, and
# there the record is not the thing at fault. Refusing the form
# mid-corpus would make a valid signed record grade FAILED because the
# operator filtered the query — a defect invented by the auditor.
#
# Extra keys are refused. `build_body` states the field set IS the
# schema, nothing optional and nothing extra; the same holds one level
# down, and an unrecognised key inside a gap is a body this auditor
# cannot claim to have judged.
GAP_REASON_MAX = 128


def gap_defect(gap, segment_seq, prev_seq):
    """None if `gap` is a valid gap record for the segment at
    segment_seq, whose previous carried record for the same camera is
    at prev_seq (None when this is the first carried record for that
    camera). Otherwise a one-line statement of what is wrong with it.

    gap is None — the ordinary no-gap case — is valid."""
    if gap is None:
        return None
    if not isinstance(gap, dict):
        return "gap is %s, not an object" % type(gap).__name__
    extra = sorted(set(gap) - {"reason", "after_seq"})
    if extra:
        return "gap carries unexpected key(s): %s" % ", ".join(extra)
    if "after_seq" not in gap:
        return "gap carries no after_seq"
    after = gap["after_seq"]
    # bool is an int in Python; a flag is not a sequence number.
    if isinstance(after, bool) or not isinstance(after, int):
        return ("gap after_seq is %s, not an integer"
                % type(after).__name__)
    if "reason" not in gap:
        return "gap carries no reason"
    reason = gap["reason"]
    if not isinstance(reason, str):
        return "gap reason is %s, not a string" % type(reason).__name__
    if not reason:
        return "gap reason is empty"
    if len(reason) > GAP_REASON_MAX:
        return ("gap reason is %d characters, over the %d-character "
                "bound" % (len(reason), GAP_REASON_MAX))
    if segment_seq == 0:
        return "gap on segment 0, which has no predecessor to cite"
    # Two citations are valid, and on a COMPLETE corpus they are the
    # same number: the previous record carried for this camera, or this
    # segment's immediate predecessor at segment_seq - 1. The second is
    # the external-predecessor form — the record cited a predecessor
    # this corpus does not carry. It is the only form available to a
    # camera's first carried record, and a sliced export or a
    # session-boundary rollover produces it legitimately anywhere a
    # block of the stream opens. Anything else points nowhere real.
    if after not in (segment_seq - 1, prev_seq):
        if prev_seq is None:
            return ("gap after_seq %d does not cite the external "
                    "predecessor (%d) of this camera's first carried "
                    "record" % (after, segment_seq - 1))
        return ("gap after_seq %d cites neither the previous record "
                "carried for this camera (%d) nor this segment's "
                "immediate predecessor (%d)"
                % (after, prev_seq, segment_seq - 1))
    return None


# ── The sensor signature: parse the FILE, never the console ────────────
#
# The validator prints a per-BU trace to stdout and writes a summary to
# validation_results.txt. Only the file is parsed. A verdict scraped
# from a log is a verdict that silently changes the next time logging
# changes, and the trace lines carry no stable interface promise.
#
# Every branch the tool can write is handled explicitly
# (apps/validator/main.c:464-526). An unrecognised file raises, and the
# caller turns that into UNVERIFIED — it never guesses.

def _sensor_blank():
    """The object with every key present and nothing asserted, in the
    shape this producer currently emits (%s)."""
    return {k: None for k in SENSOR_SIGNATURE_KEYS}


def sensor_signature_unsigned():
    """A camera that does not sign its video at all (Tapo, Reolink).
    vendor is null and the verdict is UNSIGNED — an explicit statement,
    not an omission."""
    s = _sensor_blank()
    s["verdict"] = SENSOR_UNSIGNED
    return s


def sensor_signature_unverified(vendor, validator_version=None):
    """Ruling #1: a missing validator, a crash, or an unparseable result
    all land here. The record still ships; the verdict never upgrades."""
    s = _sensor_blank()
    s["vendor"] = vendor
    s["verdict"] = SENSOR_UNVERIFIED
    s["validator"] = {"name": VALIDATOR_NAME, "version": validator_version}
    return s


_VIDEO_VERDICTS = {
    "VIDEO IS VALID!": SENSOR_VALID,
    "VIDEO IS VALID, BUT HAS MISSING FRAMES!": SENSOR_VALID,
    "VIDEO IS INVALID!": SENSOR_INVALID,
    "VIDEO IS NOT SIGNED!": SENSOR_UNSIGNED,
    # too short to hold one complete GOP: not judged, and NOT the same
    # statement as "this video carries no signature"
    "NO COMPLETE GOPS FOUND!": SENSOR_UNVERIFIED,
}

_KEY_STATES = {
    "PUBLIC KEY IS VALID!": "VALID",
    "PUBLIC KEY IS NOT VALID!": "NOT_VALID",
    "PUBLIC KEY COULD NOT BE VALIDATED!": "COULD_NOT_BE_VALIDATED",
}

_COUNT_FIELDS = (
    ("Number of valid GOPs with missing BUs:", "gops_valid_with_missing"),
    ("Number of valid GOPs:", "gops_valid"),
    ("Number of invalid GOPs:", "gops_invalid"),
    ("Number of GOPs without signature:", "gops_unsigned"),
)

_TEXT_FIELDS = (
    ("Serial Number:", "device_serial"),
    ("Firmware version:", "device_firmware"),
    ("First frame:", "asserted_first_frame"),
    ("Last validated frame:", "asserted_last_frame"),
)


def extract_sensor_public_key(path):
    """The signing public key as carried in the stream's SEI, PEM text,
    or None. Axis writes it in the clear once per signed GOP; every copy
    in a segment is the same key, and this returns the first.

    This is deliberately OUR OWN read of the bitstream rather than
    something asked of the framework: the validation API has no getter
    for the key it used, so a producer that wanted to know WHICH key
    verified would otherwise have to take the framework's word for it."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    m = _PEM_PUBLIC_KEY.search(data)
    return m.group(0).decode("ascii", "replace") if m else None


def extract_sensor_cert_chain(path):
    """Every distinct certificate the stream's SEI carries, PEM text, in
    the order first seen (leaf, then issuing CA). Empty when the stream
    carries no chain — some signing implementations ship only a bare
    public key, and that is a different situation from a broken chain."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return []
    out = []
    for m in _PEM_CERT.finditer(data):
        pem = m.group(0).decode("ascii", "replace")
        if pem not in out:
            out.append(pem)
    return out


def _x509():
    from cryptography import x509
    return x509


def _load_anchor(anchor_path):
    """(anchor_certificate, sha256_of_the_pinned_file) or (None, None).
    Never raises: an unreadable anchor is a state to report, not a crash,
    and it must NEVER fall back to the CA the stream itself supplies —
    that would check the evidence against itself."""
    if not anchor_path:
        return None, None
    try:
        with open(anchor_path, "rb") as f:
            raw = f.read()
    except OSError:
        return None, None
    try:
        cert = _x509().load_pem_x509_certificate(raw)
    except Exception:
        return None, None
    return cert, hashlib.sha256(raw).hexdigest()


def _leaf_serial(cert):
    """The device serial the leaf asserts (X.520 serialNumber in the
    subject), or None."""
    x509 = _x509()
    try:
        vals = cert.subject.get_attributes_for_oid(
            x509.oid.NameOID.SERIAL_NUMBER)
    except Exception:
        return None
    return vals[0].value if vals else None


def device_chain_check(seg_path, anchor_path, device_serial):
    """Grade the SEI's certificate chain against the pinned anchor.
    Returns the device_chain object; never raises, never omits a key."""
    dc = {k: None for k in DEVICE_CHAIN_KEYS}
    dc["anchor"] = ANCHOR_INTERMEDIATE
    dc["chain_to_anchor_verified"] = False
    dc["leaf_serial_matches_device"] = False

    anchor, anchor_sha = _load_anchor(anchor_path)
    dc["anchor_sha256"] = anchor_sha
    if anchor is None:
        return dc

    chain = extract_sensor_cert_chain(seg_path)
    if not chain:
        return dc
    try:
        leaf = _x509().load_pem_x509_certificate(chain[0].encode())
    except Exception:
        return dc

    try:
        dc["leaf_not_after"] = leaf.not_valid_after_utc.strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except AttributeError:                       # cryptography < 42
        dc["leaf_not_after"] = leaf.not_valid_after.strftime(
            "%Y-%m-%dT%H:%M:%SZ")

    # The leaf must be signed by the anchor's KEY. One signature check,
    # not a path build: there is exactly one hop between them.
    try:
        from cryptography.hazmat.primitives.asymmetric import ec, padding
        pub = anchor.public_key()
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(leaf.signature, leaf.tbs_certificate_bytes,
                       ec.ECDSA(leaf.signature_hash_algorithm))
        else:
            pub.verify(leaf.signature, leaf.tbs_certificate_bytes,
                       padding.PKCS1v15(), leaf.signature_hash_algorithm)
        dc["chain_to_anchor_verified"] = True
    except Exception:
        dc["chain_to_anchor_verified"] = False

    serial = _leaf_serial(leaf)
    dc["leaf_serial_matches_device"] = bool(
        serial and device_serial
        and serial.strip().upper() == str(device_serial).strip().upper())
    return dc


def _pin_state(observed_pem, pin_path):
    """(pin_state, pinned_pem_or_None). Never raises."""
    if pin_path is None:
        return None, None
    try:
        with open(pin_path, "r") as f:
            pinned = f.read()
    except OSError:
        return PIN_UNREADABLE, None
    if _PEM_PUBLIC_KEY.search(pinned.encode()) is None:
        return PIN_UNREADABLE, None
    if observed_pem is None:
        return PIN_NO_KEY_IN_STREAM, pinned
    a = "".join(observed_pem.split())
    b = "".join(pinned.split())
    return (PIN_MATCH if a == b else PIN_MISMATCH), pinned


def parse_validation_results(text):
    """Parse a validation_results.txt into the sensor_signature object
    (vendor and validator_output_sha256 left for the caller). Raises
    ValueError when the file carries no recognisable verdict — the
    caller must not guess one."""
    out = _sensor_blank()
    key_state = None
    video = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line in _KEY_STATES:
            key_state = _KEY_STATES[line]
            continue
        if line in _VIDEO_VERDICTS:
            video = _VIDEO_VERDICTS[line]
            continue
        for prefix, field in _COUNT_FIELDS:
            if line.startswith(prefix):
                try:
                    out[field] = int(line[len(prefix):].strip())
                except ValueError:
                    pass
                break
        else:
            for prefix, field in _TEXT_FIELDS:
                if line.startswith(prefix):
                    val = line[len(prefix):].strip()
                    out[field] = None if val in ("", "N/A") else val
                    break
            else:
                if line.startswith("Validator (") and " runs:" in line:
                    ver = line.split(" runs:", 1)[1].strip()
                    out["validator"] = {
                        "name": VALIDATOR_NAME,
                        "version": ver[1:] if ver.startswith("v") else ver}
    if video is None:
        raise ValueError("no recognisable verdict line in validator output")
    if out["validator"] is None:
        out["validator"] = {"name": VALIDATOR_NAME, "version": None}
    out["public_key"] = key_state

    # The key state can only ever DOWNGRADE the video verdict. Signatures
    # checked against a key the framework rejected prove nothing, and a
    # key that could not be validated cannot support a clean VALID.
    if key_state == "NOT_VALID":
        video = SENSOR_INVALID
    elif key_state == "COULD_NOT_BE_VALIDATED" and video == SENSOR_VALID:
        video = SENSOR_UNVERIFIED
    out["verdict"] = video
    return out


def run_sensor_validator(seg_path, vendor=None, validator=None,
                         lib_path=None, log=None, sensor_pubkey=None,
                         sensor_anchor=None, device_serial=None):
    """Validate ONE segment before its record is signed. Returns
    (sensor_signature, raw_validation_text_or_None).

    RULING #1 (Aug 28) is the whole contract: a missing validator, a
    validator that crashes, and a result that cannot be parsed each
    yield UNVERIFIED and the record still ships. This function never
    raises, never returns None, and never omits the object."""
    if vendor is None:
        return sensor_signature_unsigned(), None

    # Our own read of the stream's key, decided BEFORE the framework is
    # asked anything — so a wrong-camera clip is never mistaken for a
    # tampered one.
    observed = extract_sensor_public_key(seg_path)
    key_sha = (hashlib.sha256(observed.encode()).hexdigest()
               if observed else None)
    pin, _pinned = _pin_state(observed, sensor_pubkey)
    chain = (device_chain_check(seg_path, sensor_anchor, device_serial)
             if sensor_anchor else None)

    def _unverified(why):
        if log:
            log("sensor-signature UNVERIFIED (%s): %s"
                % (os.path.basename(seg_path), why))
        s = sensor_signature_unverified(vendor)
        s["public_key_pin"] = pin
        s["sensor_key_sha256"] = key_sha
        s["device_chain"] = chain
        return s, None

    # Identity questions are decided HERE, before the validator is asked
    # anything, and they downgrade to UNVERIFIED — never INVALID. A leaf
    # from another CA, or a genuine camera that is not this one, is not
    # tampered footage; saying INVALID would accuse a device of altering
    # video it signed honestly.
    if chain is not None:
        if not chain["chain_to_anchor_verified"]:
            return _unverified(
                "the segment's certificate chain does not verify to the "
                "pinned anchor (%s)" % (sensor_anchor,))
        if not chain["leaf_serial_matches_device"]:
            return _unverified(
                "the chain verifies to the pinned anchor but the leaf is "
                "not this device (expected serial %r)" % (device_serial,))

    if pin == PIN_UNREADABLE:
        return _unverified("pinned key %r is missing or not a PEM public "
                           "key — refusing to fall back to whatever key "
                           "the stream carries" % sensor_pubkey)
    if pin == PIN_NO_KEY_IN_STREAM:
        return _unverified("a key is pinned for this camera but the "
                           "segment carries none")
    if pin == PIN_MISMATCH:
        # NOT INVALID: authentic footage from an unpinned device looks
        # exactly like this, and we will not call that tampering.
        return _unverified("the segment is signed by a key that is not "
                           "the one pinned for this camera (observed "
                           "sha256 %s)" % (key_sha or "none"))

    if not validator or not os.path.exists(validator):
        return _unverified("no validator at %r" % validator)

    env = dict(os.environ)
    if lib_path:
        env["LD_LIBRARY_PATH"] = (
            lib_path + os.pathsep + env.get("LD_LIBRARY_PATH", ""))

    import tempfile as _tempfile
    with _tempfile.TemporaryDirectory() as work:
        # the tool writes validation_results.txt into its CWD, so give it
        # a private one rather than whatever directory we happen to be in
        try:
            argv = [validator, "-c", "h264"]
            if sensor_pubkey:
                # verify against the key WE hold, not one the framework
                # lifted out of the stream it is judging
                argv += ["-p", os.path.abspath(sensor_pubkey)]
            argv.append(os.path.abspath(seg_path))
            subprocess.run(argv,
                           cwd=work, env=env,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL,
                           timeout=VALIDATOR_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            return _unverified("validator timed out after %ds"
                               % VALIDATOR_TIMEOUT_S)
        except OSError as e:
            return _unverified("validator could not be run: %s" % e)
        # a nonzero / signalled exit is NOT itself a verdict: the tool
        # exits nonzero for an invalid video too. What matters is whether
        # it left a parseable result.
        results = os.path.join(work, VALIDATOR_RESULTS_FILE)
        if not os.path.exists(results):
            return _unverified("validator wrote no %s"
                               % VALIDATOR_RESULTS_FILE)
        with open(results, "rb") as f:
            raw_bytes = f.read()

    digest = hashlib.sha256(raw_bytes).hexdigest()
    try:
        text = raw_bytes.decode("utf-8", "replace")
        sensor = parse_validation_results(text)
    except ValueError as e:
        # the bytes exist and are kept: that is what makes this
        # UNVERIFIED auditable after the fact
        s = sensor_signature_unverified(vendor)
        s["validator_output_sha256"] = digest
        s["public_key_pin"] = pin
        s["sensor_key_sha256"] = key_sha
        s["device_chain"] = chain
        if log:
            log("sensor-signature UNVERIFIED (%s): %s"
                % (os.path.basename(seg_path), e))
        return s, raw_bytes.decode("utf-8", "replace")
    sensor["vendor"] = vendor
    sensor["validator_output_sha256"] = digest
    sensor["public_key_pin"] = pin
    sensor["sensor_key_sha256"] = key_sha
    sensor["device_chain"] = chain
    return sensor, text


def sensor_for_segment(path, cfg, log=None):
    """The sensor claim for one segment, or (None, None) for a producer
    that emits pre-/3 bodies (no capture policy declared)."""
    if not cfg.get("capture_policy"):
        return None, None
    return run_sensor_validator(
        path, vendor=cfg.get("sensor_vendor"),
        validator=cfg.get("validator"),
        lib_path=cfg.get("validator_lib_path"),
        sensor_pubkey=cfg.get("sensor_pubkey"),
        sensor_anchor=cfg.get("sensor_anchor"),
        device_serial=cfg.get("sensor_device_serial"), log=log)


def sensor_defect(sensor, schema=SCHEMA_V5):
    """Why this object may not be signed into (or read out of) a body at
    `schema`, or None. Each version has ONE permitted field set."""
    if not isinstance(sensor, dict):
        return "sensor_signature must be an object"
    want = SENSOR_KEYS_BY_SCHEMA.get(schema)
    if want is None:
        return "%s carries no sensor_signature field set" % schema
    if set(sensor) != want:
        missing = sorted(want - set(sensor))
        extra = sorted(set(sensor) - want)
        return ("sensor_signature field set is the schema at %s "
                "(missing=%s extra=%s)" % (schema, missing, extra))
    if sensor.get("verdict") not in SENSOR_VERDICTS:
        return ("sensor_signature verdict %r is not one of %s"
                % (sensor.get("verdict"), ", ".join(SENSOR_VERDICTS)))
    return None


# ── Body construction ──────────────────────────────────────────────────

def build_body(camera_id, device, seq, seg_sha, prev_sha, byte_len,
               duration_s, start_ns, end_ns, time_source, mode, gap,
               key_id, policy=None, sensor=None):
    """The camera_segment record, WITHOUT producer_sig (added by
    producer_sign). Field set is the schema — nothing optional, nothing
    extra, no credentials, no URLs.

    policy None  → camera_segment/1, exactly the bytes this producer has
                   always built (2553 live records depend on that form).
    policy dict  → camera_segment/2: the same fields plus
                   capture_policy, the producer's OWN signed statement
                   of the cadence it intends to keep. It is inside the
                   signed bytes precisely so that no one — operator
                   included — can loosen the gap tolerance afterwards to
                   make a bad window look clean; doing so would require
                   the producer key and would produce a different
                   record.
    + sensor     → camera_segment/3: /2 plus sensor_signature, what the
                   CAMERA claims about its own video. It is signed for
                   the same reason the policy is: an operator who could
                   edit a verdict afterwards could launder INVALID
                   footage into VALID footage without touching a pixel.
                   There is no version carrying the sensor claim but not
                   the cadence declaration."""
    # The producer always cites the record it just emitted, so the
    # external-predecessor form and the ordinary form coincide here at
    # segment_seq - 1. A body whose gap would grade FAILED is never
    # built, let alone signed and submitted.
    defect = gap_defect(gap, seq, seq - 1)
    if defect:
        raise ValueError("refusing to build a camera_segment body: %s"
                         % defect)
    if sensor is not None and policy is None:
        raise ValueError("refusing to build a camera_segment body: a "
                         "sensor_signature needs a capture_policy — "
                         "there is no schema with one and not the other")
    if policy is None:
        schema = SCHEMA_V1
    elif sensor is None:
        schema = SCHEMA_V2
    else:
        schema = SCHEMA_V5
    if sensor is not None:
        # judged against the version this body will actually claim
        defect = sensor_defect(sensor, schema)
        if defect:
            raise ValueError("refusing to build a camera_segment body: %s"
                             % defect)
    body = {
        "schema": schema,
        "camera_id": camera_id,
        "device": device,
        "segment_seq": seq,
        "segment_sha256": seg_sha,
        "prev_segment_sha256": prev_sha,
        "byte_len": byte_len,
        "duration_s": duration_s,
        "capture_start_utc_ns": start_ns,
        "capture_end_utc_ns": end_ns,
        "encoder": "copy",
        "time_source": time_source,
        "mode": mode,
        "gap": gap,
        "producer_key_id": key_id,
    }
    if policy is not None:
        body["capture_policy"] = policy
    if sensor is not None:
        body["sensor_signature"] = sensor
    return body


# ── Capture-session policy (the signed cadence declaration) ────────────
#
# WHERE IT LIVES, and why: the authoritative copy is inside every signed
# body, because that is the only copy a verifier may trust — a file on
# the capture host can be edited after the fact, a verifier constant
# cannot describe two streams that legitimately differ (the Tapo cuts at
# 6 s, the Reolink sub at ~10 s), and a per-run CLI value alone would
# leave no stable statement across restarts of the same camera.
#
# The data_dir file is therefore a DEFAULTS file, not a policy: it is
# what the next run of THIS camera will declare unless the operator
# overrides it on the command line. Changing it changes only future
# records, and the change is visible per-record in the signed bytes.
#
# NO HEARTBEAT INTERVAL. It was considered and rejected: a heartbeat is
# a liveness promise, and a producer that has stopped cannot emit the
# signed bytes that would keep it. Declaring one would (a) put a promise
# in the signed record that the failure mode it covers guarantees will
# be broken, and (b) make the audit verdict depend on wall-clock time at
# audit, so the same corpus would grade differently on two runs. The
# trailing-silence question ("has this camera stopped?") is monitoring,
# and belongs to whatever watches the producer, not to an audit of
# fixed evidence.

CAPTURE_POLICY_FILE = "capture-policy.json"


def capture_policy_new(nominal_segment_s, jitter_s, max_unexplained_gap_s):
    """Validate and normalise a capture policy. A policy that cannot be
    met, or that tolerates everything, is a signed lie — refuse it here
    rather than sign it."""
    try:
        nominal = float(nominal_segment_s)
        jitter = float(jitter_s)
        max_gap = float(max_unexplained_gap_s)
    except (TypeError, ValueError):
        raise SystemExit("capture policy values must be numbers")
    if not (nominal > 0):
        raise SystemExit("capture policy: nominal_segment_s must be > 0")
    if jitter < 0 or max_gap < 0:
        raise SystemExit("capture policy: jitter_s and "
                         "max_unexplained_gap_s must be >= 0")
    if jitter >= nominal:
        raise SystemExit("capture policy: jitter_s (%g) >= "
                         "nominal_segment_s (%g) would tolerate a whole "
                         "missing segment as continuous coverage"
                         % (jitter, nominal))
    return {"nominal_segment_s": round(nominal, 3),
            "jitter_s": round(jitter, 3),
            "max_unexplained_gap_s": round(max_gap, 3)}


def capture_policy_resolve(data_dir, nominal_segment_s=None, jitter_s=None,
                           max_unexplained_gap_s=None,
                           default_nominal_s=6.0):
    """The policy this run will declare: the data_dir defaults file,
    with any explicitly given CLI value overriding it. The resolved
    policy is written back, so the next run of this camera declares the
    same cadence without being told again."""
    path = os.path.join(data_dir, CAPTURE_POLICY_FILE)
    stored = {}
    if os.path.exists(path):
        try:
            with open(path) as f:
                stored = json.load(f)
        except ValueError:
            raise SystemExit("%s is not valid JSON — refusing to guess "
                             "the capture policy" % path)
        if not isinstance(stored, dict):
            raise SystemExit("%s does not hold a capture policy object"
                             % path)
    policy = capture_policy_new(
        nominal_segment_s if nominal_segment_s is not None
        else stored.get("nominal_segment_s", default_nominal_s),
        jitter_s if jitter_s is not None
        else stored.get("jitter_s", CAPTURE_GAP_TOLERANCE_NS / 1e9),
        max_unexplained_gap_s if max_unexplained_gap_s is not None
        else stored.get("max_unexplained_gap_s", 0.0))
    if policy != stored:
        os.makedirs(data_dir, mode=0o700, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(policy, f, indent=1, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    return policy


# Fix D: gap records come from capture-time continuity, not only from
# restarts. Tolerance for the hole between one segment's capture_end and
# the next segment's capture_start:
#
#   - healthy ~6 s boundaries in the 2026-08-24 record jitter within
#     about ±0.5 s (poll pacing + keyframe-aligned cuts; extremes there:
#     −1.8 s overlap to +0.43 s hole), so 2 s is > 4x the largest
#     healthy hole ever observed — no false positives on a live cadence;
#   - one wholly missing 6 s segment opens a hole of >= ~5.5 s, so 2 s
#     is comfortably below the smallest real loss — no false negatives.
#
# The 69.1 s gap:null hole at seg 77 of that record is the defect this
# closes: it must produce a gap under this rule.
CAPTURE_GAP_TOLERANCE_NS = 2_000_000_000


def continuity_gap(state, start_ns, pending_gap):
    """The gap record (or None) for a segment whose capture starts at
    start_ns. A pending driver-restart gap wins — it already disclaims
    coverage across the restart. Otherwise, a hole beyond
    CAPTURE_GAP_TOLERANCE_NS since the previous segment's capture_end is
    stated explicitly, restart or no restart; the two reasons stay
    distinguishable."""
    if pending_gap:
        return pending_gap
    if state is not None and (start_ns - state["last_end_ns"]
                              > CAPTURE_GAP_TOLERANCE_NS):
        return {"reason": "capture-discontinuity",
                "after_seq": state["segment_seq"]}
    return None


def session_for(camera_id, end_ns):
    """Daily sessions: camera:<id>:<UTC date of capture end>. Fresh and
    post-D-1 by construction; the prev-hash chain runs ACROSS the day
    boundary (the first record of a day cites yesterday's last
    segment)."""
    day = time.strftime("%Y-%m-%d", time.gmtime(end_ns / 1e9))
    return "camera:%s:%s" % (camera_id, day)


# ── Segment processing ─────────────────────────────────────────────────

def process_segment(path, cfg, state, gap, send=onode_send):
    """Hash, content-address, build, sign, submit ONE closed segment.
    Returns the updated state. Raises SubmitError if the chain refused
    the append (state is NOT advanced)."""
    with open(path, "rb") as f:
        seg_bytes = f.read()
    seg_sha = hashlib.sha256(seg_bytes).hexdigest()

    art_dir = os.path.join(cfg["data_dir"], "artifacts")
    os.makedirs(art_dir, mode=0o700, exist_ok=True)
    art_path = os.path.join(art_dir, seg_sha + ".mp4")
    if not os.path.exists(art_path):
        tmp = art_path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(seg_bytes)
        os.replace(tmp, art_path)

    duration = mp4_duration_s(path)
    # Replay has no live clock to attest: the honest time source is the
    # file's mtime (when the segment was closed — or, honestly visible
    # in the record, when the file was copied), stated as such in the
    # body. There is deliberately no other arm (Fix E): this path is
    # only ever replay, and stamping a replayed file with the clock of
    # the moment it happened to be processed is exactly the re-stamp
    # defect of the 2026-08-24 session.
    end_ns = os.stat(path).st_mtime_ns
    time_source = "file-mtime"
    start_ns = end_ns - int(duration * 1e9)

    seq = (state["segment_seq"] + 1) if state else 0
    prev = state["last_segment_sha256"] if state else None
    gap = continuity_gap(state, start_ns, gap)

    # The sensor claim is established BEFORE the record is signed: a
    # verdict that arrived after the signature would be a verdict nobody
    # could bind to these bytes.
    sensor, sensor_raw = sensor_for_segment(
        path, cfg, log=lambda m: print(m, flush=True))
    if sensor_raw is not None:
        with open(os.path.join(art_dir, seg_sha + ".validation.txt"),
                  "w") as f:
            f.write(sensor_raw)

    body_nosig = build_body(cfg["camera_id"], cfg["device"], seq, seg_sha,
                            prev, len(seg_bytes), duration, start_ns,
                            end_ns, time_source, cfg["mode"], gap,
                            cfg["key_id"], cfg.get("capture_policy"),
                            sensor)
    body_bytes, body = producer_sign(cfg["sk"], body_nosig)

    session_id = session_for(cfg["camera_id"], end_ns)
    artifact_id = "camseg:%s:%d:%d" % (cfg["camera_id"], seq, end_ns)
    ok, receipt = chain_append_evidence(session_id, artifact_id,
                                        body_bytes,
                                        sock_path=cfg["sock"], send=send)
    if not ok:
        raise SubmitError("%s: %s" % (os.path.basename(path), receipt))

    # Sidecar: the exact stored body plus the signed receipt, for audit
    # independent of the chain database.
    import base64
    sidecar = {
        "artifact_id": artifact_id,
        "session_id": session_id,
        "body": body_bytes.decode("ascii"),
        "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
        "chain_receipt_b64": base64.b64encode(receipt).decode(),
        "source_file": os.path.basename(path),
    }
    with open(os.path.join(art_dir, seg_sha + ".json"), "w") as f:
        json.dump(sidecar, f, indent=1, sort_keys=True)
        f.write("\n")

    new_state = {
        "camera_id": cfg["camera_id"],
        "segment_seq": seq,
        "last_segment_sha256": seg_sha,
        "last_session_id": session_id,
        "last_end_ns": end_ns,
    }
    state_save(cfg["state_path"], new_state)
    print("attested seq=%d sha256=%.16s… session=%s%s"
          % (seq, seg_sha, session_id,
             "  GAP(%s)" % gap["reason"] if gap else ""))
    return new_state


class SubmitError(Exception):
    pass


def run_replay(replay_dir, cfg, send=onode_send):
    """Process an existing directory of closed segments exactly as if
    each had just closed, in name order. Segments whose bytes were
    already attested (sidecar present) are skipped, so a re-run is
    idempotent rather than double-submitting."""
    names = sorted(n for n in os.listdir(replay_dir)
                   if n.endswith(".mp4"))
    if not names:
        raise SystemExit("no .mp4 segments in %s" % replay_dir)

    # replay shares state.json with live capture, so it takes the SAME
    # instance lock: a replay racing a live run would corrupt continuity
    lock_fd = (acquire_instance_lock(cfg["lock_path"], "replay")
               if cfg.get("lock_path") else None)
    try:
        _run_replay_locked(replay_dir, names, cfg, send)
    finally:
        if lock_fd is not None:
            release_instance_lock(lock_fd)


def _run_replay_locked(replay_dir, names, cfg, send):
    state = state_load(cfg["state_path"])
    # A prior run means this run cannot attest continuous coverage in
    # between: the first record of THIS run carries an explicit gap.
    pending_gap = None
    if state is not None:
        pending_gap = {"reason": "driver-restart",
                       "after_seq": state["segment_seq"]}

    art_dir = os.path.join(cfg["data_dir"], "artifacts")
    done = 0
    for name in names:
        path = os.path.join(replay_dir, name)
        with open(path, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        if os.path.exists(os.path.join(art_dir, sha + ".json")):
            print("skip %s: already attested (%.16s…)" % (name, sha))
            continue
        state = process_segment(path, cfg, state, pending_gap, send=send)
        pending_gap = None
        done += 1
    print("replay complete: %d segment(s) attested, last seq=%s"
          % (done, state["segment_seq"] if state else "-"))


# ── verify-segment: recompute-and-compare, not a second judge ──────────

# ── What a camera_segment body commits to by hash, and under which name ─
#
# A /3-and-later record cites TWO artifacts by digest: the video, and the
# validator's own output about that video. Checking only the first is
# what made this command useless on the second: a validation_results.txt
# read NO MATCH whether it had been tampered with or not, because it was
# being compared against segment_sha256, which it was never going to
# equal. An answer that is identical for clean and altered input is
# worse than no answer, since it has the shape of one.
#
# The field name goes in the verdict. "MATCH" alone would not say WHICH
# of a record's commitments the file satisfied.
CITED_SEGMENT = "segment_sha256"
CITED_VALIDATOR_OUTPUT = "sensor_signature.validator_output_sha256"


def _cited_digests(body):
    """{field: digest} for every artifact this body commits to by hash.

    The sensor object is read through _body_sensor, so a record whose
    sensor_signature does not match its own version's field set cites
    nothing here — a malformed object is not a digest to check against.
    """
    out = {}
    if body.get(CITED_SEGMENT):
        out[CITED_SEGMENT] = body[CITED_SEGMENT]
    sensor = _body_sensor(body)
    if sensor and sensor.get("validator_output_sha256"):
        out[CITED_VALIDATOR_OUTPUT] = sensor["validator_output_sha256"]
    return out


def verify_segment(file_path, db_path, pubkey_path=None):
    """Recompute sha256 over the file's CURRENT bytes and report whether
    any camera_segment body stored on the chain commits to that hash —
    as its segment, or as its validator output. This helper renders the
    verdict from the signed body: it recomputes ONE hash and compares
    against both cited digests. It does not verify chain entry
    signatures or sequencing; that is Docket's job. Returns process exit
    code.

    If a pubkey was asked for, it is established FIRST: a trust root
    that cannot be loaded raises TrustRootError before the file is read,
    so a broken --pubkey can never end in a MATCH verdict that silently
    checked no signature."""
    pk = None
    if pubkey_path is not None:
        _, pk = load_trust_root(pubkey_path)
    with open(file_path, "rb") as f:
        file_sha = hashlib.sha256(f.read()).hexdigest()
    print("file: %s" % file_path)
    print("sha256 of current file bytes: %s" % file_sha)

    rows = _camera_bodies(db_path)
    # segment first: a file handed to this command is far more often the
    # video than the validator's note about it. Both are checked either
    # way; the order only decides which is reported when a digest
    # collision would otherwise be ambiguous.
    match = None
    for field in (CITED_SEGMENT, CITED_VALIDATOR_OUTPUT):
        for session_id, artifact_id, body_raw, body in rows:
            if _cited_digests(body).get(field) == file_sha:
                match = (field, session_id, artifact_id, body_raw, body)
                break
        if match:
            break

    if match is None:
        print("VERDICT: NO MATCH — no camera_segment body on this chain "
              "commits to the file's current bytes, as a segment or as a "
              "validator output.")
        _print_filename_hint(file_path, rows)
        print("checked: sha256 recompute of the file vs the %s and %s "
              "fields of every camera_segment body in %s (schemas %s). "
              "Nothing more."
              % (CITED_SEGMENT, CITED_VALIDATOR_OUTPUT, db_path,
                 ", ".join(SCHEMAS)))
        return 1

    field, session_id, artifact_id, body_raw, body = match
    what = ("segment" if field == CITED_SEGMENT else "validator_output")
    print("VERDICT: MATCH %s — the file's current bytes are exactly the "
          "bytes committed by a chain-stored body's %s:" % (what, field))
    print("  session=%s seq=%s artifact_id=%s"
          % (session_id, body["segment_seq"], artifact_id))
    if pk is not None:
        ok = producer_verify(pk, body)
        print("  producer_sig: %s (out-of-band check against %s; not a "
              "chain verdict)" % ("VALID" if ok else "INVALID",
                                  pubkey_path))
        if not ok:
            return 1
    print("checked: sha256 recompute of the file vs the signed body's "
          "%s%s. Chain entry signatures and sequencing are Docket's "
          "verdict, not this tool's."
          % (field,
             ", plus the body's producer signature" if pubkey_path
             else ""))
    return 0


def _print_filename_hint(file_path, rows):
    """On NO MATCH, say whether the FILENAME points at a record anyway.

    The outbox names both artifacts after the segment digest
    (<camera>.<seq>.<segment_sha256>.mp4 and .validation.txt), and the
    content-addressed layout names the segment <sha>.mp4. Either way a
    16-hex-digit prefix appearing in the basename identifies the record
    the file CLAIMS to be part of, which is what turns a bare NO MATCH
    into "these bytes changed since that record was made"."""
    base = os.path.basename(file_path)
    for _, _, _, b in rows:
        sha = b.get(CITED_SEGMENT) or ""
        if len(sha) < 16 or sha[:16] not in base:
            continue
        cited = _cited_digests(b)
        print("  (a chain body DOES commit to the segment named by this "
              "FILENAME: seq=%s — the file's bytes are not any artifact "
              "that record cites, so they have changed since it was "
              "made)" % b["segment_seq"])
        for field, digest in sorted(cited.items()):
            print("    that record's %s = %s" % (field, digest))
        return


def _camera_bodies(db_path):
    """(session_id, artifact_id, raw_body, parsed_body) for every
    camera_segment/1 evidence_item on the chain, read-only."""
    conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    try:
        rows = conn.execute(
            "SELECT e.session_id, e.artifact_id, a.artifact_content "
            "FROM chain_entries e JOIN artifacts a "
            "  ON a.artifact_hash = e.artifact_hash "
            " AND a.artifact_id = e.artifact_id "
            "WHERE e.artifact_type = ? AND e.session_id LIKE 'camera:%'",
            (ARTIFACT_TYPE,)).fetchall()
    finally:
        conn.close()
    out = []
    for session_id, artifact_id, content in rows:
        try:
            body = json.loads(content)
        except ValueError:
            continue
        if body.get("schema") in SCHEMAS:
            out.append((session_id, artifact_id, content, body))
    return out


# ── audit: the anti-chainwalk-bug regression, runnable ─────────────────

class TrustRootError(Exception):
    """A trust root the caller ASKED FOR could not be established.

    The invariant this type exists to enforce: failure to establish a
    requested trust root must never degrade into successful
    verification. It is raised before any evidence is read, is never
    caught to continue, and reaches the CLI only as an abort.
    """


ED25519_PUBKEY_LEN = 32


def load_trust_root(path):
    """Establish ONE pinned trust root from a file. Returns
    (key_id, pk_raw); every way of failing raises TrustRootError.

    Each check below was a way to end up with either no key or a
    non-key while the caller believed a key had been pinned:
      - a path that is not a file (missing, or a directory)
      - a file that cannot be read (permissions)
      - an empty file (zero bytes hashes fine and pins nothing)
      - the wrong length for a raw Ed25519 public key (a PEM, a hex
        dump, a truncated copy)
      - 32 bytes the Ed25519 implementation will not accept as a point
      - the cryptography package missing, so nothing could be verified
        even with a good key
    """
    if not isinstance(path, str) or not path:
        raise TrustRootError("empty trust-root path")
    if os.path.isdir(path):
        raise TrustRootError("%s is a directory, not an Ed25519 public "
                             "key file" % path)
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise TrustRootError("cannot read trust root %s: %s"
                             % (path, e.strerror or e))
    if not raw:
        raise TrustRootError("trust root %s is empty (0 bytes) — an "
                             "empty file pins no key" % path)
    if len(raw) != ED25519_PUBKEY_LEN:
        raise TrustRootError("trust root %s is %d bytes, not a %d-byte "
                             "raw Ed25519 public key (a PEM or hex file "
                             "is not accepted here)"
                             % (path, len(raw), ED25519_PUBKEY_LEN))
    try:
        ed = _ed25519()
    except ImportError as e:
        raise TrustRootError("a trust root was requested but the "
                             "cryptography package is unavailable, so "
                             "no signature could be checked: %s" % e)
    try:
        ed.Ed25519PublicKey.from_public_bytes(raw)
    except Exception as e:
        raise TrustRootError("trust root %s is not a valid Ed25519 "
                             "public key: %s" % (path, e))
    return producer_key_id(raw), raw


def _load_pubkeys(pubkey_paths):
    """Return {key_id: pk_raw} for a list of pinned public-key files. An
    Option B chain legitimately carries more than one producer identity
    (the capture host's key differs from a bootstrap replay key); each
    body names its producer_key_id, so a body is checked against the
    pinned key that matches it.

    Every path must resolve to a usable key, and the resulting set must
    be non-empty: a caller that asked for trust roots and got none must
    not proceed to verify anything.
    """
    keys = {}
    for p in pubkey_paths or []:
        key_id, raw = load_trust_root(p)
        keys[key_id] = raw
    if pubkey_paths and not keys:
        raise TrustRootError("trust roots were requested but the pinned "
                             "set is empty — nothing to verify against")
    return keys


def audit_chain(db_path, session_prefix="camera:", pubkey_path=None,
                report=None):
    """For every camera_segment entry: recompute sha256 over the body
    bytes AS STORED in the chain and match artifact_hash (the
    chainwalk_summary defect was exactly this failing); check the
    in-body prev-hash chain per camera; optionally verify every
    producer_sig against the pinned key(s). pubkey_path may be a single
    path or a list of paths (multi-producer chains). Returns
    (checked, failures:list).

    If `report` is a dict it is filled in with the two axes that are NOT
    chain integrity — coverage completeness and content reuse — which
    are reported separately because they are different properties: a
    chain can be perfectly intact across an outage it never claimed to
    cover.

    The pinned keys are established FIRST, before a single row is read:
    a requested trust root that cannot be established raises
    TrustRootError and no evidence is judged at all."""
    if isinstance(pubkey_path, (list, tuple)):
        pubkeys = _load_pubkeys(pubkey_path)
    elif pubkey_path:
        pubkeys = _load_pubkeys([pubkey_path])
    else:
        pubkeys = {}

    conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    try:
        rows = conn.execute(
            "SELECT e.session_id, e.sequence, e.artifact_id, "
            "       e.artifact_hash, a.artifact_content "
            "FROM chain_entries e JOIN artifacts a "
            "  ON a.artifact_hash = e.artifact_hash "
            " AND a.artifact_id = e.artifact_id "
            "WHERE e.artifact_type = ? AND e.session_id LIKE ? "
            "ORDER BY e.timestamp_ns",
            (ARTIFACT_TYPE, session_prefix + "%")).fetchall()
    finally:
        conn.close()

    failures = []
    checked = 0
    verified = 0
    cam_bodies = []   # (session_id, artifact_id, body) in seq order

    # Pass 1 — the hash invariant, order-independent (the chainwalk
    # regression): every stored body must hash to its recorded
    # artifact_hash. Also collect the camera bodies to walk by seq.
    for session_id, seq, artifact_id, ahash, content in rows:
        stored = content.encode("ascii")
        checked += 1
        recomputed = hashlib.sha256(stored).hexdigest()
        if recomputed != ahash:
            failures.append("%s %s: sha256(stored body) %s != "
                            "artifact_hash %s"
                            % (session_id, artifact_id, recomputed, ahash))
            continue
        try:
            body = json.loads(content)
        except ValueError:
            failures.append("%s %s: body is not JSON"
                            % (session_id, artifact_id))
            continue
        schema = body.get("schema")
        if schema not in SCHEMAS:
            # An unrecognised camera_segment/N must never be skipped in
            # silence: skipping is exactly how an unverified record ends
            # up counted inside a clean verdict.
            if isinstance(schema, str) and schema.startswith("camera_segment/"):
                failures.append("%s %s: unrecognised schema %s — this "
                                "auditor cannot judge it, and will not "
                                "pass it"
                                % (session_id, artifact_id, schema))
            continue
        if schema in POLICY_SCHEMAS and _body_policy(body) is None:
            failures.append("%s %s: %s carries no usable capture_policy"
                            % (session_id, artifact_id, schema))
        # The camera_id/capture_policy precedent: the object is REQUIRED
        # at its own version and REQUIRED ABSENT at every earlier one. A
        # /1 body that has grown a sensor_signature was not built by this
        # producer, and grading it as though it were would let anyone
        # append a verdict to frozen history.
        if schema in SENSOR_KEYS_BY_SCHEMA:
            if _body_sensor(body) is None:
                failures.append("%s %s: %s carries no usable "
                                "sensor_signature"
                                % (session_id, artifact_id, schema))
        elif "sensor_signature" in body:
            failures.append("%s %s: %s carries a sensor_signature, which "
                            "exists only at %s and later — this record "
                            "was not built by this producer"
                            % (session_id, artifact_id, schema, SCHEMA_V3))
        cam_bodies.append((session_id, artifact_id, body))

    # Pass 2 — the prev-hash continuity chain, walked in segment_seq
    # order per camera (the canonical order of the stream), NOT chain
    # append order: an Option B record is appended when its ship is
    # relayed, which need not match capture order. A seq that does not
    # follow its predecessor, or a prev-hash that does not cite it, is a
    # break — unless the record itself carries a gap, which is the
    # explicit, signed statement that continuity is not claimed there.
    if pubkeys and cam_bodies:
        present = {b.get("producer_key_id") for _, _, b in cam_bodies}
        if not (present & set(pubkeys)):
            # 32 arbitrary bytes are a syntactically valid Ed25519 public
            # key, so a junk file of the right length loads. What it
            # cannot do is match anything — and a pinned set that
            # describes none of the corpus is a trust root that was never
            # really established.
            failures.append(
                "none of the %d pinned key(s) %s matches the "
                "producer_key_id of any of the %d records (%s) — the "
                "pinned set does not describe this corpus"
                % (len(pubkeys), sorted(pubkeys), len(cam_bodies),
                   sorted(k for k in present if k)))

    chains = {}
    for session_id, artifact_id, body in sorted(
            cam_bodies, key=lambda t: (t[2]["camera_id"],
                                       t[2]["segment_seq"])):
        cam = body["camera_id"]
        gap = body.get("gap")
        defect = gap_defect(body.get("gap"), body["segment_seq"],
                            chains[cam][0] if cam in chains else None)
        if defect:
            failures.append("%s %s: %s"
                            % (session_id, artifact_id, defect))
        # Fail closed: a gap that does not grade valid excuses nothing.
        gapped = gap is not None and defect is None
        if cam in chains:
            last_seq, last_sha = chains[cam]
            if body["segment_seq"] != last_seq + 1 and not gapped:
                failures.append("%s %s: segment_seq %s does not follow "
                                "%s (and carries no valid gap record)"
                                % (session_id, artifact_id,
                                   body["segment_seq"], last_seq))
            if body["prev_segment_sha256"] != last_sha and not gapped:
                failures.append("%s %s: prev_segment_sha256 does not "
                                "cite the previous segment (and carries "
                                "no valid gap record)" % (session_id, artifact_id))
        else:
            if body["prev_segment_sha256"] is not None and not gapped:
                failures.append("%s %s: first record for %s has non-null "
                                "prev_segment_sha256"
                                % (session_id, artifact_id, cam))
        chains[cam] = (body["segment_seq"], body["segment_sha256"])
        if pubkeys:
            kid = body.get("producer_key_id")
            pk = pubkeys.get(kid)
            if pk is None:
                failures.append("%s %s: producer_key_id %s is not among "
                                "the pinned keys" % (session_id,
                                                     artifact_id, kid))
            elif not producer_verify(pk, body):
                failures.append("%s %s: producer_sig INVALID"
                                % (session_id, artifact_id))
            else:
                verified += 1

    if report is not None:
        report["camera_bodies"] = len(cam_bodies)
        report["verified_sigs"] = verified
        report["pinned_key_ids"] = sorted(pubkeys)
        report["coverage"] = grade_coverage(cam_bodies)
        report["reuse_axis"], report["reuse"] = \
            grade_content_reuse(cam_bodies)
        report["sensor"] = grade_sensor(cam_bodies)
    return checked, failures


# ═══════════════════════════════════════════════════════════════════════
# Coverage completeness — a SEPARATE axis from chain integrity
# ═══════════════════════════════════════════════════════════════════════
#
# The chain answers "are these records unaltered and in order". It
# cannot answer "was the camera recording the whole time", because
# nothing in a camera_segment/1 record says what "the whole time" was
# meant to look like. camera_segment/2 carries the producer's own signed
# capture_policy, and only then can an outage be graded.
#
# A signed gap record makes an outage ACCOUNTED FOR. It does not make
# coverage COMPLETE, and the grader never collapses the two: the verdict
# for a stream with signed gaps is INTERRUPTED / ACCOUNTED, never
# CONTINUOUS.

COVERAGE_UNDECLARED = "UNDECLARED"
COVERAGE_CONTINUOUS = "CONTINUOUS"
COVERAGE_ACCOUNTED = "INTERRUPTED / ACCOUNTED"
COVERAGE_UNEXPLAINED = "INTERRUPTED / UNEXPLAINED"

_COVERAGE_RANK = {COVERAGE_CONTINUOUS: 0, COVERAGE_ACCOUNTED: 1,
                  COVERAGE_UNEXPLAINED: 2, COVERAGE_UNDECLARED: 3}


def _body_policy(body):
    """The usable capture_policy of a body, or None. A /1 record has
    none by construction — that is UNDECLARED, not zero tolerance."""
    if body.get("schema") not in POLICY_SCHEMAS:
        return None
    p = body.get("capture_policy")
    if not isinstance(p, dict):
        return None
    try:
        nominal = float(p["nominal_segment_s"])
        jitter = float(p["jitter_s"])
        max_gap = float(p["max_unexplained_gap_s"])
    except (KeyError, TypeError, ValueError):
        return None
    if nominal <= 0 or jitter < 0 or max_gap < 0 or jitter >= nominal:
        return None
    return {"nominal_segment_s": nominal, "jitter_s": jitter,
            "max_unexplained_gap_s": max_gap}


SENSOR_AXIS_NONE = "NONE CLAIMED (no /3 records in scope)"


def sensor_axis(sensor):
    """One line for the whole scope. Worst verdict wins, and UNVERIFIED
    is never folded into VALID: `we could not check` is not `it passed`."""
    if not sensor:
        return SENSOR_AXIS_NONE
    tot = {v: 0 for v in SENSOR_VERDICTS}
    for c in sensor.values():
        for v, n in c["verdicts"].items():
            tot[v] = tot.get(v, 0) + n
    if tot[SENSOR_INVALID]:
        return "INVALID (%d record(s))" % tot[SENSOR_INVALID]
    if tot[SENSOR_UNVERIFIED]:
        return "UNVERIFIED (%d record(s) could not be checked)" \
            % tot[SENSOR_UNVERIFIED]
    if tot[SENSOR_VALID] and not tot[SENSOR_UNSIGNED]:
        return "VALID (%d record(s), camera-asserted)" % tot[SENSOR_VALID]
    if tot[SENSOR_UNSIGNED] and not tot[SENSOR_VALID]:
        return "UNSIGNED (%d record(s); this camera does not sign)" \
            % tot[SENSOR_UNSIGNED]
    return "MIXED (valid=%d unsigned=%d)" % (tot[SENSOR_VALID],
                                             tot[SENSOR_UNSIGNED])


def grade_sensor(cam_bodies):
    """{camera_id: {...}} over the /3 records in scope. Records at older
    versions are not counted as UNSIGNED — they predate the question."""
    out = {}
    for _, _, body in cam_bodies:
        s = _body_sensor(body)
        if s is None:
            continue
        cam = body.get("camera_id")
        c = out.setdefault(cam, {
            "verdicts": {v: 0 for v in SENSOR_VERDICTS},
            "vendor": None, "device_serial": None,
            "device_firmware": None, "validator": None,
            "asserted_first_frame": None, "asserted_last_frame": None})
        c["verdicts"][s["verdict"]] += 1
        for k in ("vendor", "device_serial", "device_firmware"):
            if s.get(k) and not c[k]:
                c[k] = s[k]
        v = s.get("validator") or {}
        if v.get("name") and not c["validator"]:
            c["validator"] = "%s %s" % (v.get("name"), v.get("version"))
        # the span of what the CAMERA claims, in the camera's own words
        if s.get("asserted_first_frame") and not c["asserted_first_frame"]:
            c["asserted_first_frame"] = s["asserted_first_frame"]
        if s.get("asserted_last_frame"):
            c["asserted_last_frame"] = s["asserted_last_frame"]
    return out


def _body_sensor(body):
    """The usable sensor_signature of a body, or None, judged against the
    field set of the body's OWN version. A /1 or /2 record has none by
    construction — that is not "unsigned video", it is a record from
    before the question was asked."""
    schema = body.get("schema")
    if schema not in SENSOR_KEYS_BY_SCHEMA:
        return None
    s = body.get("sensor_signature")
    return None if sensor_defect(s, schema) else s


def grade_coverage(cam_bodies):
    """cam_bodies: [(session_id, artifact_id, body)] — grade each camera
    separately. Returns {camera_id: {...}}.

    Per adjacent pair of segments in segment_seq order, the hole is
    next.capture_start − prev.capture_end (negative = overlap, which the
    -c copy keyframe cuts produce routinely and which covers the window
    either way). It is graded against the LATER record's own policy,
    because that is the record making the continuity claim:

      hole <= jitter_s                         → covered. Every overlap
                                                 is covered: overlapping
                                                 windows leave no time
                                                 unrecorded. An overlap
                                                 deeper than the declared
                                                 jitter is still reported,
                                                 as a timing observation
                                                 that does not move the
                                                 verdict.
      hole  >  jitter_s, record carries a gap  → ACCOUNTED outage
      hole  >  jitter_s, no gap, within
                    max_unexplained_gap_s      → tolerated outage
      otherwise                                → UNEXPLAINED outage

    A camera with even one record that declares no policy grades
    UNDECLARED: a /1 record cannot be shown to be continuous, and
    guessing a cadence for it would be the verifier constant this
    design exists to avoid."""
    by_cam = {}
    for session_id, artifact_id, body in cam_bodies:
        by_cam.setdefault(body["camera_id"], []).append(
            (session_id, artifact_id, body))
    out = {}
    for cam, lst in by_cam.items():
        lst.sort(key=lambda t: t[2]["segment_seq"])
        undeclared = [b for _, _, b in lst if _body_policy(b) is None]
        info = {
            "records": len(lst),
            "undeclared_records": len(undeclared),
            "seq_first": lst[0][2]["segment_seq"],
            "seq_last": lst[-1][2]["segment_seq"],
            "policies": [],
            "outages": [],
            "overlaps": [],
            "outage_s": 0.0,
            "span_s": (lst[-1][2]["capture_end_utc_ns"]
                       - lst[0][2]["capture_start_utc_ns"]) / 1e9,
        }
        seen = []
        for _, _, b in lst:
            p = _body_policy(b)
            if p is not None and p not in seen:
                seen.append(p)
        info["policies"] = seen
        if undeclared:
            info["verdict"] = COVERAGE_UNDECLARED
            # Name the versions actually seen rather than asserting /1.
            # The hardcoded "(camera_segment/1)" told a reader the four
            # /5 records in front of it were /1 records, which is how a
            # stale schema tuple reads from the outside: not as a bug,
            # as a fact about the evidence.
            seen_schemas = sorted({str(b.get("schema")) for b in undeclared})
            info["reason"] = ("%d of %d records declare no capture "
                              "policy (%s)"
                              % (len(undeclared), len(lst),
                                 ", ".join(seen_schemas)))
            out[cam] = info
            continue
        worst = COVERAGE_CONTINUOUS
        for i in range(1, len(lst)):
            prev = lst[i - 1][2]
            cur = lst[i][2]
            pol = _body_policy(cur)
            hole_s = (cur["capture_start_utc_ns"]
                      - prev["capture_end_utc_ns"]) / 1e9
            if hole_s <= pol["jitter_s"]:
                if hole_s < -pol["jitter_s"]:
                    # the windows overlap by more than the declared
                    # jitter: no footage is missing, but the two records'
                    # claimed times cannot both be tight. Reported, never
                    # graded as an interruption.
                    info["overlaps"].append({
                        "after_seq": prev["segment_seq"],
                        "seq": cur["segment_seq"],
                        "overlap_s": round(-hole_s, 3),
                        "artifact_id": lst[i][1],
                    })
                continue
            gap = cur.get("gap")
            if gap is not None and gap_defect(
                    gap, cur["segment_seq"], prev["segment_seq"]):
                # a gap that would grade FAILED accounts for nothing
                gap = None
            if gap:
                cls, verdict = "ACCOUNTED", COVERAGE_ACCOUNTED
            elif hole_s <= pol["max_unexplained_gap_s"]:
                cls, verdict = "TOLERATED", COVERAGE_ACCOUNTED
            else:
                cls, verdict = "UNEXPLAINED", COVERAGE_UNEXPLAINED
            info["outages"].append({
                "after_seq": prev["segment_seq"],
                "seq": cur["segment_seq"],
                "hole_s": round(hole_s, 3),
                "gap_reason": (gap or {}).get("reason"),
                "class": cls,
                "artifact_id": lst[i][1],
            })
            info["outage_s"] += hole_s
            if _COVERAGE_RANK[verdict] > _COVERAGE_RANK[worst]:
                worst = verdict
        info["outage_s"] = round(info["outage_s"], 3)
        info["verdict"] = worst
        if worst == COVERAGE_CONTINUOUS:
            info["reason"] = ("no uncovered time; %d boundary/ies beyond "
                              "the declared jitter, all overlaps"
                              % len(info["overlaps"])
                              if info["overlaps"] else
                              "every segment boundary within the "
                              "declared jitter")
        else:
            info["reason"] = ("%d outage(s), %.1f s not covered"
                              % (len(info["outages"]), info["outage_s"]))
        out[cam] = info
    return out


def coverage_axis(coverage):
    """The one-line worst-case across cameras."""
    if not coverage:
        return COVERAGE_UNDECLARED
    return max((c["verdict"] for c in coverage.values()),
               key=lambda v: _COVERAGE_RANK[v])


# ═══════════════════════════════════════════════════════════════════════
# Content reuse — an OBSERVATION, never a verdict of forgery
# ═══════════════════════════════════════════════════════════════════════
#
# Identical segment bytes under two sequence numbers are NOT proof of
# anything on their own. This corpus holds 18 such pairs (36 records)
# that are artifacts of a producer replay defect fixed 2026-08-25, and a
# static scene will legitimately re-encode to identical bytes. So
# duplication is reported with the facts that bear on it — same camera
# or not, sequence delta, claimed capture-time delta — and graded on its
# own axis, which never fails the audit.
#
# THE RULE IMPLEMENTED, and why each arm:
#
#   EXPECTED              same camera, consecutive segments (Δseq == 1)
#                         whose windows abut within the declared jitter.
#                         A static 640x360 scene producing byte-identical
#                         back-to-back segments is ordinary, and there is
#                         no missing footage to explain: both records
#                         cover their own distinct window.
#
#   DUPLICATE/EXPLAINED   same camera, Δseq > 1, and the producer's own
#                         SIGNED bytes carry a gap record somewhere in
#                         (lo_seq, hi_seq]. The producer stated a
#                         discontinuity across the interval in which the
#                         bytes reappear; a re-ship after a restart is
#                         exactly that, and it is attested, not asserted
#                         by the auditor.
#
#   DUPLICATE/UNEXPLAINED everything else, and ALWAYS when the same bytes
#                         appear under two different camera_ids — two
#                         cameras cannot legitimately produce identical
#                         files, so no static-scene argument applies.
#
# EXPLAINED is a policy judgement about the producer, not a
# cryptographic fact: it says a signed statement exists that accounts
# for the reuse. It does not say the reuse was harmless.

REUSE_NONE = "NONE"
REUSE_EXPECTED = "EXPECTED"
REUSE_EXPLAINED = "DUPLICATE / EXPLAINED"
REUSE_UNEXPLAINED = "DUPLICATE / UNEXPLAINED"

_REUSE_RANK = {REUSE_NONE: 0, REUSE_EXPECTED: 1,
               REUSE_EXPLAINED: 2, REUSE_UNEXPLAINED: 3}


def grade_content_reuse(cam_bodies):
    """Returns (axis, groups). groups is one entry per repeated
    segment_sha256, carrying the supporting facts."""
    by_hash = {}
    by_cam = {}
    for session_id, artifact_id, body in cam_bodies:
        by_hash.setdefault(body["segment_sha256"], []).append(
            (session_id, artifact_id, body))
        by_cam.setdefault(body["camera_id"], []).append(body)

    # Only a gap that grades VALID may explain a reuse. Deciding that
    # needs each record's predecessor for its own camera, so the gaps
    # are collected on a per-camera walk in segment_seq order rather
    # than in one pass over the corpus.
    gaps_by_cam = {}
    for cam, bodies in by_cam.items():
        bodies.sort(key=lambda b: b["segment_seq"])
        prev_seq = None
        for body in bodies:
            gap = body.get("gap")
            if gap is not None and gap_defect(
                    gap, body["segment_seq"], prev_seq) is None:
                gaps_by_cam.setdefault(cam, []).append(
                    (body["segment_seq"], gap.get("reason")))
            prev_seq = body["segment_seq"]

    groups = []
    axis = REUSE_NONE
    for sha, lst in by_hash.items():
        if len(lst) < 2:
            continue
        lst.sort(key=lambda t: t[2]["segment_seq"])
        cams = sorted({b["camera_id"] for _, _, b in lst})
        seqs = [b["segment_seq"] for _, _, b in lst]
        first, last = lst[0][2], lst[-1][2]
        facts = {
            "segment_sha256": sha,
            "cameras": cams,
            "sessions": sorted({s for s, _, _ in lst}),
            "occurrences": len(lst),
            "segment_seqs": seqs,
            "seq_delta": seqs[-1] - seqs[0],
            "byte_len": sorted({b["byte_len"] for _, _, b in lst}),
            "capture_start_delta_s": round(
                (last["capture_start_utc_ns"]
                 - first["capture_start_utc_ns"]) / 1e9, 3),
            "artifact_ids": [a for _, a, _ in lst],
        }
        if len(cams) > 1:
            facts["class"] = REUSE_UNEXPLAINED
            facts["basis"] = ("identical bytes under %d different "
                              "camera_ids — no static-scene explanation "
                              "applies" % len(cams))
        else:
            cls = REUSE_EXPECTED
            basis = ("consecutive segments with abutting capture "
                     "windows — a static scene re-encoding identically")
            for i in range(1, len(lst)):
                lo, hi = lst[i - 1][2], lst[i][2]
                pol = _body_policy(hi) or {
                    "jitter_s": CAPTURE_GAP_TOLERANCE_NS / 1e9}
                hole = (hi["capture_start_utc_ns"]
                        - lo["capture_end_utc_ns"]) / 1e9
                if (hi["segment_seq"] - lo["segment_seq"] == 1
                        and abs(hole) <= pol["jitter_s"]):
                    pair_cls, pair_basis = REUSE_EXPECTED, basis
                else:
                    spanning = [g for g in gaps_by_cam.get(cams[0], [])
                                if lo["segment_seq"] < g[0]
                                <= hi["segment_seq"]]
                    if spanning:
                        pair_cls = REUSE_EXPLAINED
                        pair_basis = ("a signed gap record (%s) sits at "
                                      "seq %d, inside the interval in "
                                      "which the bytes reappear"
                                      % (spanning[0][1], spanning[0][0]))
                    else:
                        pair_cls = REUSE_UNEXPLAINED
                        pair_basis = ("bytes repeat %d sequence numbers "
                                      "later with no signed gap record "
                                      "in between"
                                      % (hi["segment_seq"]
                                         - lo["segment_seq"]))
                if _REUSE_RANK[pair_cls] >= _REUSE_RANK[cls]:
                    cls, basis = pair_cls, pair_basis
            facts["class"] = cls
            facts["basis"] = basis
        groups.append(facts)
        if _REUSE_RANK[facts["class"]] > _REUSE_RANK[axis]:
            axis = facts["class"]
    groups.sort(key=lambda g: (-_REUSE_RANK[g["class"]],
                               g["segment_seqs"][0]))
    return axis, groups


# ═══════════════════════════════════════════════════════════════════════
# Phase 2 — live capture over the Option B split
# ═══════════════════════════════════════════════════════════════════════
#
# The capture host (ffmpeg, producer key, continuity state) and the
# O-node (the socket, the chain-signing key, chain_append authority) are
# two different machines connected by ONE ssh path. Neither the daemon
# nor a live ffmpeg can be moved across that boundary, so:
#
#   capture host  ─ build camera_segment/1 body, producer-sign, ship the
#                   {segment, signed-body} pair to a chrooted spool ─┐
#                                                                    │  ssh
#   O-node host   ─ submit-spool watches the spool and relays each ──┘
#                   body VERBATIM into chain_append (as the identity
#                   that Phase 1 used). It never builds or signs a body;
#                   it only carries already-signed bytes to the daemon,
#                   which re-derives artifact_hash (GATE 2) and D-1 signs
#                   the chain entry.
#
# The producer key lives ONLY on the capture host: the submitter needs
# no key and can forge nothing — a body it did not receive intact fails
# GATE 2 at the daemon and its own segment-hash check here. Continuity
# (segment_seq, prev_segment_sha256) is owned by the capture host, since
# that is where the body — which commits to them — is built and signed.


# ── RTSP source (credentials never touch a body, a log or a report) ────

def rtsp_url_from_config(env_var="VIRP_CAMERA_RTSP_URL", config_path=None):
    """The live RTSP URL comes from the environment or a 0600 config file
    (one line, the full rtsp://user:pass@host:port/path). It is used only
    to open the stream; it is never placed in a body (the schema has no
    URL field at all), never printed, never logged. Returns the URL or
    None if unconfigured."""
    url = os.environ.get(env_var)
    if url:
        return url.strip()
    if config_path and os.path.exists(config_path):
        st = os.stat(config_path)
        if st.st_mode & 0o077:
            raise SystemExit("rtsp config %s is group/world-readable "
                             "(mode %o) — refusing to read a credential "
                             "from it" % (config_path, st.st_mode & 0o777))
        with open(config_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
    return None


def ffmpeg_cmd(cfg):
    """The capture child. Real camera: copy stream1 (720p H.264) with no
    audio into wall-clock-closed segments, exactly as Phase 0 proved
    (-an -c copy). No RTSP URL configured but --test-source given: a
    real-time synthetic 720p H.264 source, so the whole ship→submit→
    chain→docket path can be exercised without the rotated credential.
    The pixels differ; every attested fact (bytes, timing, continuity)
    is produced identically."""
    pat = os.path.join(cfg["workdir"], "seg_%06d.mp4")
    st = str(cfg["segment_time"])
    common = ["-f", "segment", "-segment_time", st,
              "-reset_timestamps", "1", "-segment_format", "mp4",
              "-movflags", "+faststart", pat]
    if cfg.get("rtsp_url"):
        return (["ffmpeg", "-nostdin", "-loglevel", "error",
                 "-rtsp_transport", "tcp", "-i", cfg["rtsp_url"],
                 "-an", "-c", "copy"] + common)
    # synthetic real-time source (no camera credential required). A live
    # wall-clock overlay is burned in, so — like a real scene — no two
    # runs and no two segments ever produce byte-identical frames; the
    # content-addressed store never coincidentally collapses distinct
    # captures. Falls back to the bare pattern if the font is absent.
    gop = str(int(cfg["segment_time"]) * 15)
    vf = None
    font = cfg.get("overlay_font")
    if font and os.path.exists(font):
        vf = ("drawtext=fontfile=%s:text='%%{localtime}':x=24:y=24:"
              "fontsize=40:fontcolor=white:box=1:boxcolor=black@0.5" % font)
    cmd = ["ffmpeg", "-nostdin", "-loglevel", "error",
           "-re", "-f", "lavfi",
           "-i", "testsrc2=size=1280x720:rate=15"]
    if vf:
        cmd += ["-vf", vf]
    return (cmd + ["-an", "-c:v", "libx264", "-preset", "veryfast",
                   "-pix_fmt", "yuv420p", "-g", gop] + common)


# ── Capture-host delivery: ship the {segment, signed body} pair ────────

def sftp_ship(spool_target, ssh_key=None, extra_opts=None,
              known_hosts=None):
    """Return ship(seg_file, body_file, name) -> bool. Uploads to the
    chrooted spool as <name>.mp4/.body via .part staging + rename, then
    a <name>.done marker LAST, so the submitter only ever sees complete
    jobs. One ssh path, key-only, sftp-only (the account is chrooted to
    internal-sftp on the far end).

    The spool host's key is PINNED (Sep 1 review, Task 4): `known_hosts`
    is a provisioned file naming the spool host, StrictHostKeyChecking
    is `yes`, and the user's own known_hosts is not consulted. The
    previous `accept-new` trusted whichever host answered first and
    then pinned THAT — a first-contact attacker became the trusted
    spool for the life of the file. Refused at construction (before any
    capture starts) when the file is absent or unreadable."""
    if not known_hosts:
        raise ValueError("sftp_ship: a provisioned known_hosts file is "
                         "required (the spool host key is pinned, never "
                         "accepted on first contact)")
    if not os.path.isfile(known_hosts) or not os.access(known_hosts, os.R_OK):
        raise ValueError("sftp_ship: known_hosts file %s is missing or "
                         "unreadable" % known_hosts)
    opts = ["-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=%s" % known_hosts]
    if ssh_key:
        opts += ["-o", "IdentitiesOnly=yes", "-i", ssh_key]
    if extra_opts:
        opts += list(extra_opts)

    def _batch(script):
        p = subprocess.run(["sftp"] + opts + ["-b", "-", spool_target],
                           input=script.encode(), capture_output=True)
        if p.returncode != 0:
            sys.stderr.write("sftp: %s\n" % p.stderr.decode(errors="replace"))
        return p.returncode == 0

    def ship(seg_file, body_file, name):
        rd = "/incoming"
        if not _batch("\n".join([
                "put %s %s/%s.mp4.part" % (seg_file, rd, name),
                "put %s %s/%s.body.part" % (body_file, rd, name),
                "rename %s/%s.mp4.part %s/%s.mp4" % (rd, name, rd, name),
                "rename %s/%s.body.part %s/%s.body" % (rd, name, rd, name),
                ])):
            return False
        marker = body_file + ".done"
        open(marker, "wb").close()
        try:
            ok = _batch("put %s %s/%s.done" % (marker, rd, name))
        finally:
            os.unlink(marker)
        return ok

    return ship


def process_live_segment(path, cfg, state, gap, ship):
    """Hash a CLOSED live segment, build+producer-sign the body with a
    host-clock timestamp, stage it, and ship the pair to the spool. State
    advances only after a durable handoff (ship ok); a failed ship raises
    SubmitError and continuity is NOT advanced — the segment is retried,
    never skipped."""
    # Fix E: the capture window is a function of the SEGMENT, never of
    # when this code happens to run. capture_end is the file's mtime —
    # the host clock as sampled by the kernel when ffmpeg finalized the
    # segment — and duration_s comes from the moov/mvhd of the attested
    # bytes themselves (the one consistent source: any verifier can
    # recompute it from the artifact). Both are fixed at capture and
    # immutable across re-offers and late submission, which makes the
    # body deterministic: a re-offered segment rebuilds byte-identical
    # signed bytes, and the spool's body-keyed dedup is exact. A late
    # submission's DELAY is already recorded without any new field: the
    # chain entry's own timestamp is the append time; delay = append
    # time minus capture_end.
    st = os.stat(path)
    with open(path, "rb") as f:
        seg_bytes = f.read()
    seg_sha = hashlib.sha256(seg_bytes).hexdigest()
    duration = mp4_duration_s(path)          # raises on a partial (no moov)

    end_ns = st.st_mtime_ns
    time_source = "host-clock"               # mtime IS the host clock,
                                             # sampled at finalize
    start_ns = end_ns - int(duration * 1e9)

    seq = (state["segment_seq"] + 1) if state else 0
    prev = state["last_segment_sha256"] if state else None
    gap = continuity_gap(state, start_ns, gap)

    # Established BEFORE the signature, for the same reason as above.
    # Whatever it says — including "the validator was missing" — the
    # segment is still attested and still ships (ruling #1).
    sensor, sensor_raw = sensor_for_segment(
        path, cfg, log=lambda m: print(m, flush=True))

    body_nosig = build_body(cfg["camera_id"], cfg["device"], seq, seg_sha,
                            prev, len(seg_bytes), duration, start_ns,
                            end_ns, time_source, "live", gap, cfg["key_id"],
                            cfg.get("capture_policy"), sensor)
    body_bytes, body = producer_sign(cfg["sk"], body_nosig)
    if len(body_bytes) >= ARTIFACT_LIMIT:
        raise SubmitError("%s: body is %d bytes, at/past the daemon's "
                          "%d-byte artifact field — not shipped"
                          % (os.path.basename(path), len(body_bytes),
                             ARTIFACT_LIMIT))

    session_id = session_for(cfg["camera_id"], end_ns)
    artifact_id = "camseg:%s:%d:%d" % (cfg["camera_id"], seq, end_ns)

    out = cfg["outbox"]
    os.makedirs(out, mode=0o700, exist_ok=True)
    name = spool_job_name(cfg["camera_id"], seq, seg_sha)
    seg_out = os.path.join(out, name + ".mp4")
    body_out = os.path.join(out, name + ".body")
    with open(seg_out + ".tmp", "wb") as f:
        f.write(seg_bytes)
    os.replace(seg_out + ".tmp", seg_out)
    with open(body_out + ".tmp", "wb") as f:
        f.write(body_bytes)
    os.replace(body_out + ".tmp", body_out)
    # The raw validator output, kept beside the segment it judged: the
    # body carries only its sha256, so the bytes have to survive
    # somewhere for that hash to be checkable.
    if sensor_raw is not None:
        val_out = os.path.join(out, name + ".validation.txt")
        with open(val_out + ".tmp", "w") as f:
            f.write(sensor_raw)
        os.replace(val_out + ".tmp", val_out)

    if not ship(seg_out, body_out, name):
        raise SubmitError("%s: ship to spool failed (continuity not "
                          "advanced)" % os.path.basename(path))

    # Capture-side handoff record: the exact bytes shipped, for audit of
    # what left this host independent of what the far end did with it.
    handoff = {
        "artifact_id": artifact_id,
        "session_id": session_id,
        "segment_sha256": seg_sha,
        "body": body_bytes.decode("ascii"),
        "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
        "shipped_as": name,
        "source_file": os.path.basename(path),
    }
    with open(os.path.join(out, name + ".handoff.json"), "w") as f:
        json.dump(handoff, f, indent=1, sort_keys=True)
        f.write("\n")

    # Durable checkpoint BEFORE the continuity cursor moves: if we die
    # between the two, _resume_state adopts the checkpoint tail.
    if cfg.get("checkpoint_path"):
        checkpoint_append(cfg["checkpoint_path"], {
            "segment_seq": seq,
            "segment_sha256": seg_sha,
            "capture_end_utc_ns": end_ns,
            "body_sha256": handoff["body_sha256"],
            "shipped_as": name,
        })

    new_state = {
        "camera_id": cfg["camera_id"],
        "segment_seq": seq,
        "last_segment_sha256": seg_sha,
        "last_session_id": session_id,
        "last_end_ns": end_ns,
    }
    state_save(cfg["state_path"], new_state)
    print("live seq=%d sha256=%.16s… shipped session=%s%s"
          % (seq, seg_sha, session_id,
             "  GAP(%s)" % gap["reason"] if gap else ""), flush=True)
    return new_state


# ── Spool job naming ───────────────────────────────────────────────────
#
# A shipped job is <camera>.<seq>.<segment-sha256>. It used to be
# <seq>.<sha>, which is camera-blind: both live cameras have written
# 000000. through 000008. into the same incoming/, told apart only by
# the hash. Nothing broke — the bodies carry camera_id, submit_one
# derives every chain-bound value from the body and never parses the
# name, and the sha makes a true collision a content collision. But it
# is the same collision class already fixed in three places on the
# detection side, and this was the last layer still carrying it.
#
# The camera token reaches a FILESYSTEM PATH — an sftp `put` into a
# chrooted spool — which the old name never did, so it is bounded to a
# charset that cannot traverse, hide, or start an option: ASCII
# letters, digits, '_' and '-', first character alphanumeric. Refused
# at config time, where an operator sees it, and again here, where the
# invariant actually matters.
SPOOL_CAMERA_MAX = 64
_SPOOL_CAMERA_OK = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")


def spool_camera_token(camera_id):
    """The camera_id as it may appear in a spool filename, or
    ValueError. Never rewrites: a silently sanitized id would map two
    distinct cameras onto one token, which is the collision this
    naming exists to remove."""
    if (not isinstance(camera_id, str) or not camera_id
            or len(camera_id) > SPOOL_CAMERA_MAX
            or not (camera_id[0].isascii() and camera_id[0].isalnum())
            or any(c not in _SPOOL_CAMERA_OK for c in camera_id)):
        raise ValueError(
            "camera-id %r cannot be used in a spool filename: 1-%d "
            "characters, ASCII letters/digits/underscore/hyphen only, "
            "first character a letter or digit"
            % (camera_id, SPOOL_CAMERA_MAX))
    return camera_id


def spool_job_name(camera_id, seq, seg_sha):
    """The spool job name for one shipped segment."""
    return "%s.%06d.%s" % (spool_camera_token(camera_id), seq, seg_sha)


def _segment_names(workdir):
    return sorted(n for n in os.listdir(workdir) if n.endswith(".mp4"))


def _stat_sig(path):
    """(size, mtime_ns) — the cheap change signature that tells a file
    apart from what previously occupied its NAME. ffmpeg restarts its
    numbering at seg_000000 after every driver restart, so a filename
    identifies nothing; content does (Fix B)."""
    st = os.stat(path)
    return (st.st_size, st.st_mtime_ns)


def _staged_pair(outbox, sha, end_ns):
    """The staged {segment, signed body} pair for THIS segment, if a
    previous run built one before dying: (seg_path, body_path) or None.
    Matched on content AND capture end: two identical-content segments
    stage two pairs, and the one that belongs to this file is the one
    whose signed body names this file's capture_end_utc_ns."""
    bodies = sorted(glob.glob(os.path.join(outbox, "*.%s.body" % sha)))
    for body_path in reversed(bodies):
        seg_path = body_path[:-len(".body")] + ".mp4"
        if not os.path.exists(seg_path):
            continue
        try:
            with open(body_path, "rb") as f:
                body = json.loads(f.read())
        except (OSError, ValueError):
            continue
        if body.get("segment_sha256") == sha and \
                int(body.get("capture_end_utc_ns", -1)) == int(end_ns):
            return seg_path, body_path
    return None


def _reconcile_workdir(cfg, state, shipped, ship):
    """Startup reconciliation (Fix C), run BEFORE the capture child
    spawns and renumbers into these names. The shutdown handler is
    correct and unchanged — it finalizes and drains the in-progress
    segment; what no shutdown path can do is settle files for a process
    that dies without one. So every start walks the workdir and settles
    each file by CONTENT:

      already in the shipped checkpoint (same content AND same
        capture end — the same file, not merely the same bytes) ->
        residue of a handled segment: remove it (never replay it)
      closed but never shipped -> footage that closed and then the
        process died: attest and ship it NOW, before any new capture,
        so segment_seq order stays capture order (the 2026-08-24
        session's ten-minute ingest inversion is what draining stale
        work late looks like). If the previous run already staged and
        signed the body in the outbox, those exact bytes are re-shipped
        — byte-identical, so any true re-offer is a spool-side no-op.
      unfinalized partial (no moov) -> not attestable: removed, the
        loss logged plainly.

    The driver-restart gap is NOT attached here: residue belongs to the
    previous run's continuity, and the gap rides the first segment of
    NEW capture. If the spool refuses while unshipped residue exists,
    this raises SubmitError rather than starting a capture that would
    bury real footage. Returns the (possibly advanced) state."""
    names = _segment_names(cfg["workdir"])
    names.sort(key=lambda n: os.stat(
        os.path.join(cfg["workdir"], n)).st_mtime_ns)
    for name in names:
        path = os.path.join(cfg["workdir"], name)
        with open(path, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        end_ns = os.stat(path).st_mtime_ns
        prior = shipped_record(shipped, sha, end_ns)
        if prior is not None:
            sys.stderr.write("reconcile %s: already attested as seq=%s "
                             "(%.16s… end=%d); removing residue\n"
                             % (name, prior["segment_seq"], sha, end_ns))
            _unlink_quiet(path)
            continue
        try:
            mp4_duration_s(path)
        except ValueError as e:
            sys.stderr.write("reconcile %s: unfinalized partial (%s); "
                             "removing — this footage is lost\n"
                             % (name, e))
            _unlink_quiet(path)
            continue
        staged = _staged_pair(cfg["outbox"], sha, end_ns)
        if staged:
            seg_out, body_out = staged
            job = os.path.basename(body_out)[:-len(".body")]
            with open(body_out, "rb") as f:
                body_bytes = f.read()
            body = json.loads(body_bytes)
            if not ship(seg_out, body_out, job):
                raise SubmitError("%s: re-ship of staged pair %s failed "
                                  "(unshipped residue; refusing to start "
                                  "capture over it)" % (name, job))
            rec = {
                "segment_seq": body["segment_seq"],
                "segment_sha256": sha,
                "capture_end_utc_ns": body["capture_end_utc_ns"],
                "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
                "shipped_as": job,
            }
            if cfg.get("checkpoint_path"):
                checkpoint_append(cfg["checkpoint_path"], rec)
            key = shipped_key(sha, body["capture_end_utc_ns"])
            shipped[key] = rec
            state = _resume_state(state, {key: rec}, cfg["camera_id"])
            state_save(cfg["state_path"], state)
            sys.stderr.write("reconcile %s: re-shipped staged pair %s "
                             "(seq=%d, original body bytes)\n"
                             % (name, job, body["segment_seq"]))
        else:
            state = process_live_segment(path, cfg, state, None, ship)
            shipped[shipped_key(state["last_segment_sha256"],
                                state["last_end_ns"])] = {
                "segment_seq": state["segment_seq"],
                "segment_sha256": state["last_segment_sha256"],
                "capture_end_utc_ns": state["last_end_ns"],
            }
        _unlink_quiet(path)
    return state


def run_live(cfg, ship, stop_after_s=None, poll_s=0.5,
             _spawn=None, _clock=time.time):
    """Spawn the capture child, and as each segment closes, attest+ship it
    in order. A prior run means this run cannot claim continuous coverage
    across the restart: the first record carries an explicit gap — the
    same honesty rule as replay, now across a live kill/restart. SIGINT/
    SIGTERM stop the child and drain the segments already closed."""
    lock_fd = (acquire_instance_lock(cfg["lock_path"], "live")
               if cfg.get("lock_path") else None)
    try:
        return _run_live_locked(cfg, ship, stop_after_s, poll_s,
                                _spawn, _clock)
    finally:
        if lock_fd is not None:
            release_instance_lock(lock_fd)


def _run_live_locked(cfg, ship, stop_after_s, poll_s, _spawn, _clock):
    os.makedirs(cfg["workdir"], mode=0o700, exist_ok=True)
    os.makedirs(cfg["outbox"], mode=0o700, exist_ok=True)
    shipped = checkpoint_load(cfg.get("checkpoint_path"))
    state = _resume_state(state_load(cfg["state_path"]), shipped,
                          cfg["camera_id"])
    state = _reconcile_workdir(cfg, state, shipped, ship)
    # A prior run (including late-settled residue above) means this run
    # cannot claim continuous coverage across the restart: the first
    # segment of NEW capture carries the explicit gap.
    pending_gap = None
    if state is not None:
        pending_gap = {"reason": "driver-restart",
                       "after_seq": state["segment_seq"]}

    proc = (_spawn or _spawn_ffmpeg)(cfg)
    stop = {"flag": False}

    def _sig(_signo, _frame):
        stop["flag"] = True
    old_int = signal.signal(signal.SIGINT, _sig)
    old_term = signal.signal(signal.SIGTERM, _sig)

    # Per-file bookkeeping is keyed on (name, stat signature) so a name
    # ffmpeg reuses with NEW bytes is seen as new work, and on record
    # identity (`shipped`: content + capture end) so a file already
    # attested is never re-offered while a NEW file with the same bytes
    # still is. The old name-keyed set silently dropped ~72 s of real
    # footage when a restarted ffmpeg renumbered into just-drained names
    # (the gap:null hole at seg 77 of the 2026-08-24 session); the
    # content-only key that replaced it dropped every segment whose
    # bytes repeated an earlier one (Sep 1 review, Task 1).
    handled = {}    # name -> sig it was handled at (attested or skipped)
    tried = {}      # name -> sig that failed to parse (retry on change)
    seen = {}       # name -> last observed sig (quiescence gate)
    done = 0
    start = _clock()
    try:
        while True:
            ffmpeg_done = proc.poll() is not None
            for name in _segment_names(cfg["workdir"]):
                path = os.path.join(cfg["workdir"], name)
                try:
                    sig = _stat_sig(path)
                except OSError:
                    continue
                if handled.get(name) == sig:
                    continue
                if tried.get(name) == sig and not ffmpeg_done:
                    continue                 # unparseable and unchanged
                if not ffmpeg_done and seen.get(name) != sig:
                    # first sight, or still growing: a segment is closed
                    # when its size+mtime hold still across two polls
                    # (an open segment grows every poll; a stalled one
                    # has no moov and fails the parse below). Once the
                    # child has exited every file is final.
                    seen[name] = sig
                    continue
                try:
                    with open(path, "rb") as f:
                        sha = hashlib.sha256(f.read()).hexdigest()
                except OSError:
                    continue
                prior = shipped_record(shipped, sha, sig[1])
                if prior is not None:
                    sys.stderr.write("skip %s: already attested as seq=%s "
                                     "(%.16s… end=%d)\n"
                                     % (name, prior["segment_seq"], sha,
                                        sig[1]))
                    handled[name] = sig
                    _unlink_quiet(path)
                    continue
                try:
                    state = process_live_segment(path, cfg, state,
                                                 pending_gap, ship)
                except ValueError as e:      # no moov: open or a partial
                    if ffmpeg_done:
                        sys.stderr.write("skip %s: %s (unfinalized "
                                         "partial; footage lost)\n"
                                         % (name, e))
                        handled[name] = sig
                    else:
                        tried[name] = sig    # retry when the file changes
                    continue
                except SubmitError as e:
                    sys.stderr.write("SUBMIT REFUSED: %s\n" % e)
                    break                    # retry this segment next poll
                shipped[shipped_key(state["last_segment_sha256"],
                                    state["last_end_ns"])] = {
                    "segment_seq": state["segment_seq"],
                    "segment_sha256": state["last_segment_sha256"],
                    "capture_end_utc_ns": state["last_end_ns"],
                }
                handled[name] = sig
                _unlink_quiet(path)          # attested+checkpointed: the
                                             # workdir copy is done
                pending_gap = None
                done += 1
            if ffmpeg_done:
                break
            if stop["flag"]:
                proc.terminate()             # ffmpeg finalizes current seg
                try:
                    proc.wait(timeout=8)
                except Exception:
                    proc.kill()
                continue                     # loop once more: drain closed
            if stop_after_s is not None and (_clock() - start) >= stop_after_s:
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except Exception:
                    proc.kill()
                continue
            time.sleep(poll_s)
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except Exception:
                proc.kill()
    print("live capture stopped: %d segment(s) attested+shipped, last "
          "seq=%s" % (done, state["segment_seq"] if state else "-"),
          flush=True)
    return state


def _unlink_quiet(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def _spawn_ffmpeg(cfg):
    return subprocess.Popen(ffmpeg_cmd(cfg))


# ── O-node side: submit-spool (runs as the Phase 1 identity) ───────────

def _on_chain(db_path, artifact_hash):
    """True iff a chain entry committing to these exact body bytes
    already exists. Read-only; ANY failure (no db, locked, schema)
    returns False — the worst case is then the pre-existing behavior,
    a duplicate append, never a dropped record."""
    if not db_path or not os.path.exists(db_path):
        return False
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
        try:
            row = conn.execute(
                "SELECT 1 FROM chain_entries WHERE artifact_hash = ? "
                "LIMIT 1", (artifact_hash,)).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return False
    return row is not None


def submit_one(cfg, name, seg_path, body_path, send=onode_send):
    """Relay ONE shipped job into the chain. Reads the producer's exact
    signed bytes and submits them verbatim; the daemon re-derives
    artifact_hash. Verifies the shipped segment file matches the hash the
    body commits to. Idempotent: a job whose segment is already attested
    (sidecar present) is a no-op success. Returns True if the record is
    on the chain (now or already), False if the daemon refused (leave the
    job to retry)."""
    with open(body_path, "rb") as f:
        body_bytes = f.read()
    body = json.loads(body_bytes)            # must parse; bytes go verbatim
    if body.get("schema") not in SCHEMAS:
        raise ValueError("%s: body schema is %r, not one of %s"
                         % (name, body.get("schema"), ", ".join(SCHEMAS)))
    with open(seg_path, "rb") as f:
        seg_bytes = f.read()
    seg_sha = hashlib.sha256(seg_bytes).hexdigest()
    if seg_sha != body.get("segment_sha256"):
        raise ValueError("%s: shipped segment sha256 %s != body "
                         "segment_sha256 %s — refusing to submit a body "
                         "whose file does not match"
                         % (name, seg_sha, body.get("segment_sha256")))

    # session_id / artifact_id are pure functions of body fields, derived
    # here EXACTLY as the producer derived them — identical ids to replay.
    cam = body["camera_id"]
    seq = body["segment_seq"]
    end_ns = body["capture_end_utc_ns"]
    session_id = session_for(cam, end_ns)
    artifact_id = "camseg:%s:%d:%d" % (cam, seq, end_ns)

    art_dir = os.path.join(cfg["data_dir"], "artifacts")
    os.makedirs(art_dir, mode=0o700, exist_ok=True)

    # Idempotency is keyed on the BODY, not the segment bytes: two
    # distinct records (different seq / capture time) may legitimately
    # carry identical video, and dropping the second because its pixels
    # already appeared would be exactly the kind of SILENT discontinuity
    # this system refuses. Only a true re-submission of the same signed
    # body — same body_sha256 — is a no-op.
    body_sha = hashlib.sha256(body_bytes).hexdigest()
    sidecar_path = os.path.join(art_dir, body_sha + ".json")
    if os.path.exists(sidecar_path):
        print("skip %s: this exact record already attested (body %.16s…)"
              % (name, body_sha), flush=True)
        return True

    # Chain-keyed backstop (Fix A): the sidecar can be lost to a crash
    # between append-ack and sidecar write. Before appending, ask the
    # chain itself: artifact_hash IS sha256(body_bytes), so one lookup
    # answers whether these exact bytes already landed. On a hit the
    # sidecar is reconstructed so the fast-path key exists again.
    if _on_chain(cfg.get("db"), body_sha):
        sidecar = {
            "artifact_id": artifact_id,
            "session_id": session_id,
            "body": body_bytes.decode("ascii"),
            "body_sha256": body_sha,
            "source_file": name + ".mp4",
            "submitted_via": "spool",
            "note": "sidecar reconstructed: body already on chain "
                    "(chain-keyed idempotency); receipt not retained",
        }
        with open(sidecar_path, "w") as f:
            json.dump(sidecar, f, indent=1, sort_keys=True)
            f.write("\n")
        print("skip %s: body already on chain (%.16s…); sidecar "
              "reconstructed" % (name, body_sha), flush=True)
        return True

    # The segment FILE is still content-addressed by its own sha (files
    # with identical bytes are stored once); only the receipt is per-body.
    # Durable BEFORE the chain append (Sep 1 review, Task 4), the same
    # temp -> fsync -> rename -> fsync-dir order state_save uses: once the
    # chain commits to this segment the bytes it commits to must already
    # be on disk, or a crash between the append and the writeback leaves
    # a signed entry whose evidence this host cannot produce.
    art_path = os.path.join(art_dir, seg_sha + ".mp4")
    if not os.path.exists(art_path):
        with open(art_path + ".tmp", "wb") as f:
            f.write(seg_bytes)
            f.flush()
            os.fsync(f.fileno())
        os.replace(art_path + ".tmp", art_path)
        _fsync_dir(art_dir)

    ok, receipt = chain_append_evidence(session_id, artifact_id, body_bytes,
                                        sock_path=cfg["sock"], send=send)
    if not ok:
        sys.stderr.write("chain refused %s: %s\n" % (name, receipt))
        return False

    sidecar = {
        "artifact_id": artifact_id,
        "session_id": session_id,
        "body": body_bytes.decode("ascii"),
        "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
        "chain_receipt_b64": base64.b64encode(receipt).decode(),
        "source_file": name + ".mp4",
        "submitted_via": "spool",
    }
    with open(sidecar_path, "w") as f:
        json.dump(sidecar, f, indent=1, sort_keys=True)
        f.write("\n")
    print("appended seq=%d sha256=%.16s… session=%s"
          % (seq, seg_sha, session_id), flush=True)
    return True


def submit_spool(cfg, once=False, send=onode_send, _clock=time.time):
    """Watch the spool for complete jobs (a .done marker with its .mp4 and
    .body present) and relay each into the chain in seq order. A refused
    append leaves the job in place to retry; a completed one is moved to
    done/. Runs until SIGINT/SIGTERM, or one pass with once=True."""
    incoming = cfg["incoming"]
    done_dir = cfg["done"]
    os.makedirs(done_dir, mode=0o770, exist_ok=True)
    lock_fd = (acquire_instance_lock(cfg["lock_path"], "submit-spool")
               if cfg.get("lock_path") else None)
    try:
        return _submit_spool_locked(cfg, once, send, incoming, done_dir)
    finally:
        if lock_fd is not None:
            release_instance_lock(lock_fd)


def _submit_spool_locked(cfg, once, send, incoming, done_dir):
    stop = {"flag": False}
    if not once:
        signal.signal(signal.SIGINT, lambda *_a: stop.update(flag=True))
        signal.signal(signal.SIGTERM, lambda *_a: stop.update(flag=True))

    appended = 0
    while True:
        markers = sorted(n for n in os.listdir(incoming)
                         if n.endswith(".done"))
        for m in markers:
            name = m[:-len(".done")]
            seg = os.path.join(incoming, name + ".mp4")
            body = os.path.join(incoming, name + ".body")
            marker = os.path.join(incoming, m)
            if not (os.path.exists(seg) and os.path.exists(body)):
                continue                     # marker raced ahead; wait
            try:
                landed = submit_one(cfg, name, seg, body, send=send)
            except (ValueError, OSError) as e:
                sys.stderr.write("submit %s: %s\n" % (name, e))
                continue                     # malformed; leave for a human
            if landed:
                for p in (seg, body, marker):
                    try:
                        os.replace(p, os.path.join(done_dir,
                                                   os.path.basename(p)))
                    except OSError:
                        pass
                appended += 1
        if once or stop["flag"]:
            break
        time.sleep(cfg.get("interval", 1.0))
    return appended


# ── CLI ────────────────────────────────────────────────────────────────

def main(argv=None):
    p = argparse.ArgumentParser(prog="virp_camera",
                                description=__doc__.split("\n")[1])
    sub = p.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen", help="generate the producer keypair")
    kg.add_argument("--data-dir", default=DATA_DIR)

    rp = sub.add_parser("replay",
                        help="attest an existing directory of segments")
    rp.add_argument("dir")
    rp.add_argument("--camera-id", default="tapo-c100")
    rp.add_argument("--device", default=None,
                    help="device name in bodies (default: camera-id)")
    rp.add_argument("--data-dir", default=DATA_DIR)
    rp.add_argument("--sock", default=ONODE_SOCKET)
    _add_policy_args(rp)
    _add_sensor_args(rp)

    lv = sub.add_parser("live",
                        help="CAPTURE HOST: capture live segments, "
                             "producer-sign and ship them to the O-node "
                             "spool (Option B)")
    lv.add_argument("--camera-id", default="tapo-c100")
    lv.add_argument("--device", default=None)
    lv.add_argument("--data-dir", default=DATA_DIR,
                    help="producer key + continuity state live here")
    lv.add_argument("--workdir", default=None,
                    help="ffmpeg segment dir (default: <data-dir>/work)")
    lv.add_argument("--spool", required=True,
                    help="sftp target of the chrooted spool, "
                         "e.g. virp-capture@10.0.0.13")
    lv.add_argument("--ssh-key", default=None,
                    help="identity for the spool account (key-only)")
    lv.add_argument("--known-hosts", required=True,
                    help="provisioned known_hosts file naming the spool "
                         "host (its key is pinned: StrictHostKeyChecking="
                         "yes, no first-contact accept)")
    lv.add_argument("--segment-time", type=float, default=6.0)
    lv.add_argument("--minutes", type=float, default=None,
                    help="stop after N minutes (default: until signalled)")
    lv.add_argument("--rtsp-config", default=None,
                    help="0600 file holding the rtsp:// URL (else "
                         "$VIRP_CAMERA_RTSP_URL)")
    _add_policy_args(lv)
    _add_sensor_args(lv)
    lv.add_argument("--test-source", action="store_true",
                    help="no camera credential: capture a real-time "
                         "synthetic 720p source to exercise the path")

    sp = sub.add_parser("submit-spool",
                        help="O-NODE HOST: watch the spool and relay "
                             "shipped bodies into chain_append (run as "
                             "the Phase 1 identity)")
    sp.add_argument("--data-dir", default=DATA_DIR)
    sp.add_argument("--sock", default=ONODE_SOCKET)
    sp.add_argument("--db", default=CHAIN_DB,
                    help="chain database for the chain-keyed idempotency "
                         "backstop (read-only; unreadable degrades to "
                         "sidecar-only dedup)")
    sp.add_argument("--incoming", required=True,
                    help="spool incoming dir, e.g. "
                         "/var/spool/virp-capture/incoming")
    sp.add_argument("--done", default=None,
                    help="archive dir for processed jobs "
                         "(default: <incoming>/../done)")
    sp.add_argument("--interval", type=float, default=1.0)
    sp.add_argument("--once", action="store_true",
                    help="drain one pass and exit (else poll until "
                         "signalled)")

    vs = sub.add_parser("verify-segment",
                        help="recompute a file's sha256 and compare it "
                             "with the chain-stored signed bodies")
    vs.add_argument("file")
    vs.add_argument("--db", default=CHAIN_DB)
    vs.add_argument("--pubkey", default=None,
                    help="also check the body's producer_sig (out of "
                         "band)")

    au = sub.add_parser("audit",
                        help="recompute sha256 over every stored camera "
                             "body vs artifact_hash; check prev chain")
    au.add_argument("--db", default=CHAIN_DB)
    au.add_argument("--session-prefix", default="camera:")
    au.add_argument("--pubkey", action="append", default=None,
                    help="pinned producer public key; repeat for a "
                         "multi-producer chain (each body is checked "
                         "against the key matching its producer_key_id)")
    au.add_argument("--fail-on-coverage", action="store_true",
                    help="also exit nonzero when coverage grades "
                         "INTERRUPTED / UNEXPLAINED (chain integrity and "
                         "coverage are separate properties; by default "
                         "only integrity drives the exit code)")

    args = p.parse_args(argv)

    if args.cmd == "keygen":
        os.makedirs(args.data_dir, mode=0o700, exist_ok=True)
        sk = os.path.join(args.data_dir, "producer.key")
        pk = os.path.join(args.data_dir, "producer.pub")
        key_id = producer_keygen(sk, pk)
        print("producer keypair generated (Ed25519):")
        print("  secret: %s (0600 — capture host only)" % sk)
        print("  public: %s (pin this for out-of-band verification)" % pk)
        print("  key_id: %s" % key_id)
        return 0

    if args.cmd == "replay":
        sk_path = os.path.join(args.data_dir, "producer.key")
        pk_path = os.path.join(args.data_dir, "producer.pub")
        try:
            key_id, sk = _producer_identity(sk_path, pk_path)
        except TrustRootError as e:
            print("TRUST ROOT NOT ESTABLISHED: %s" % e, file=sys.stderr)
            return 2
        policy = capture_policy_resolve(
            args.data_dir, args.nominal_segment_s, args.jitter_s,
            args.max_unexplained_gap_s)
        cfg = {
            "camera_id": args.camera_id,
            "device": args.device or args.camera_id,
            "data_dir": args.data_dir,
            "state_path": os.path.join(args.data_dir, "state.json"),
            "lock_path": os.path.join(args.data_dir, "instance.lock"),
            "sock": args.sock,
            "mode": "replay",
            "sk": sk,
            "key_id": key_id,
            "capture_policy": policy,
            "sensor_vendor": args.sensor_vendor,
            "validator": args.validator,
            "validator_lib_path": args.validator_lib_path,
            "sensor_pubkey": _resolve_sensor_pubkey(args),
            "sensor_anchor": _resolve_sensor_anchor(args),
            "sensor_device_serial": args.sensor_device_serial,
        }
        try:
            run_replay(args.dir, cfg)
        except SubmitError as e:
            print("SUBMIT REFUSED: %s" % e, file=sys.stderr)
            print("continuity state NOT advanced; fix and re-run.",
                  file=sys.stderr)
            return 1
        return 0

    if args.cmd == "live":
        sk_path = os.path.join(args.data_dir, "producer.key")
        pk_path = os.path.join(args.data_dir, "producer.pub")
        try:
            key_id, sk = _producer_identity(sk_path, pk_path)
        except TrustRootError as e:
            print("TRUST ROOT NOT ESTABLISHED: %s" % e, file=sys.stderr)
            return 2
        rtsp_url = rtsp_url_from_config(config_path=args.rtsp_config)
        if not rtsp_url and not args.test_source:
            raise SystemExit("no RTSP URL: set $VIRP_CAMERA_RTSP_URL or "
                             "--rtsp-config <0600 file>, or pass "
                             "--test-source to capture a synthetic feed")
        workdir = args.workdir or os.path.join(args.data_dir, "work")
        # before the capture child spawns: a camera-id that cannot be a
        # spool filename must fail here, not after footage exists
        spool_camera_token(args.camera_id)
        cfg = {
            "camera_id": args.camera_id,
            "device": args.device or args.camera_id,
            "data_dir": args.data_dir,
            "state_path": os.path.join(args.data_dir, "state.json"),
            "checkpoint_path": os.path.join(args.data_dir, "shipped.jsonl"),
            "lock_path": os.path.join(args.data_dir, "instance.lock"),
            "workdir": workdir,
            "outbox": os.path.join(args.data_dir, "outbox"),
            "segment_time": args.segment_time,
            "rtsp_url": rtsp_url,            # None → synthetic source
            "mode": "live",
            "overlay_font": os.environ.get(
                "VIRP_CAMERA_OVERLAY_FONT",
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
            "sk": sk,
            "key_id": key_id,
            "capture_policy": capture_policy_resolve(
                args.data_dir,
                args.nominal_segment_s
                if args.nominal_segment_s is not None
                else args.segment_time,
                args.jitter_s, args.max_unexplained_gap_s),
            "sensor_vendor": args.sensor_vendor,
            "validator": args.validator,
            "validator_lib_path": args.validator_lib_path,
            "sensor_pubkey": _resolve_sensor_pubkey(args),
            "sensor_anchor": _resolve_sensor_anchor(args),
            "sensor_device_serial": args.sensor_device_serial,
        }
        try:
            ship = sftp_ship(args.spool, ssh_key=args.ssh_key,
                             known_hosts=args.known_hosts)
        except ValueError as e:
            raise SystemExit(str(e))
        stop_after = args.minutes * 60 if args.minutes else None
        print("live capture: source=%s segment_time=%ss spool=%s"
              % ("rtsp(configured)" if rtsp_url else "synthetic-test",
                 args.segment_time, args.spool), flush=True)
        run_live(cfg, ship, stop_after_s=stop_after)
        return 0

    if args.cmd == "submit-spool":
        done = args.done or os.path.join(os.path.dirname(args.incoming),
                                         "done")
        cfg = {
            "data_dir": args.data_dir,
            "sock": args.sock,
            "incoming": args.incoming,
            "done": done,
            "interval": args.interval,
            "db": args.db,
            "lock_path": os.path.join(args.incoming,
                                      ".submit-spool.lock"),
        }
        n = submit_spool(cfg, once=args.once)
        print("submit-spool: %d job(s) appended this run" % n, flush=True)
        return 0

    if args.cmd == "verify-segment":
        try:
            return verify_segment(args.file, args.db, args.pubkey)
        except TrustRootError as e:
            print("TRUST ROOT NOT ESTABLISHED: %s" % e, file=sys.stderr)
            print("no evidence was evaluated.", file=sys.stderr)
            return 2

    if args.cmd == "audit":
        report = {}
        try:
            checked, failures = audit_chain(args.db, args.session_prefix,
                                            args.pubkey, report=report)
        except TrustRootError as e:
            print("TRUST ROOT NOT ESTABLISHED: %s" % e, file=sys.stderr)
            print("no evidence was evaluated; this is NOT a clean audit.",
                  file=sys.stderr)
            return 2
        print("audited %d camera evidence entr%s"
              % (checked, "y" if checked == 1 else "ies"))
        if checked == 0:
            # An empty scope is not a clean audit: it is a scope that was
            # never established. Saying "intact" here was the same class
            # of fail-open as an unloadable trust root.
            print("SCOPE NOT ESTABLISHED: no camera evidence matched "
                  "session prefix %r in %s — nothing was verified."
                  % (args.session_prefix, args.db), file=sys.stderr)
            return 2
        for f in failures:
            print("FAIL: %s" % f)
        print(_audit_axes_text(report, bool(args.pubkey)))
        if not failures:
            print("INTEGRITY: OK — all %d stored bodies hash to their "
                  "recorded artifact_hash; prev-hash chain intact%s"
                  % (checked,
                     "; %d/%d producer signature(s) verified against %d "
                     "pinned key(s)"
                     % (report.get("verified_sigs", 0),
                        report.get("camera_bodies", 0),
                        len(report.get("pinned_key_ids", [])))
                     if args.pubkey else
                     "; NO producer signature was checked (no --pubkey)"))
        else:
            print("INTEGRITY: FAILED — %d failure(s)" % len(failures))
        if failures:
            return 1
        if (args.fail_on_coverage
                and coverage_axis(report["coverage"]) == COVERAGE_UNEXPLAINED):
            return 3
        return 0

    return 2


def _resolve_sensor_pubkey(args):
    """--sensor-pubkey, else the data_dir's pinned key if one is there.
    A pin that exists is never ignored just because it was not named on
    the command line."""
    if args.sensor_pubkey:
        return args.sensor_pubkey
    default = os.path.join(args.data_dir, SENSOR_PUBKEY_FILE)
    return default if os.path.exists(default) else None


def _resolve_sensor_anchor(args):
    """--sensor-anchor, else the data_dir's pinned CA if one is there. An
    anchor that exists is never ignored for want of a flag."""
    if args.sensor_anchor:
        return args.sensor_anchor
    default = os.path.join(args.data_dir, SENSOR_ANCHOR_FILE)
    return default if os.path.exists(default) else None


def _add_sensor_args(sp):
    """Where the per-segment sensor validator lives. Absent --sensor-
    vendor the producer states UNSIGNED (Tapo, Reolink); present but
    unrunnable it states UNVERIFIED (ruling #1). It never states
    nothing."""
    sp.add_argument("--sensor-vendor", default=None,
                    help="vendor whose signed-video the camera emits, "
                         "e.g. `axis`. Omit for a camera that does not "
                         "sign (the record then says UNSIGNED).")
    sp.add_argument("--validator", default=None,
                    help="signed-video-framework validator binary; run "
                         "per segment BEFORE the record is signed")
    sp.add_argument("--validator-lib-path", default=None,
                    help="prepended to LD_LIBRARY_PATH for the validator")
    sp.add_argument("--sensor-pubkey", default=None,
                    help="PEM public key PINNED for this camera, obtained "
                         "out of band (default: <data-dir>/%s if present). "
                         "The validator verifies against THIS key, and a "
                         "segment signed by any other grades UNVERIFIED — "
                         "never INVALID, which would call an unpinned "
                         "camera a tampered one." % SENSOR_PUBKEY_FILE)
    sp.add_argument("--sensor-anchor", default=None,
                    help="PEM certificate of the CA the device's leaf must "
                         "chain to (default: <data-dir>/%s if present). The "
                         "anchor's KEY is what is checked, so a re-issued "
                         "certificate for the same CA still verifies."
                         % SENSOR_ANCHOR_FILE)
    sp.add_argument("--sensor-device-serial", default=None,
                    help="serial the leaf certificate must assert for this "
                         "camera, e.g. B8A44FDD572C")


def _add_policy_args(sp):
    """The signed capture-session policy, declared per run and remembered
    per data_dir (see capture_policy_resolve)."""
    sp.add_argument("--nominal-segment-s", type=float, default=None,
                    help="declared nominal segment duration (default: "
                         "--segment-time for live, else the data_dir "
                         "policy or 6.0)")
    sp.add_argument("--jitter-s", type=float, default=None,
                    help="declared permitted boundary jitter in seconds "
                         "(default: the data_dir policy or 2.0)")
    sp.add_argument("--max-unexplained-gap-s", type=float, default=None,
                    help="largest hole tolerated WITHOUT a signed gap "
                         "record before coverage grades UNEXPLAINED "
                         "(default: the data_dir policy or 0.0)")


def _producer_identity(sk_path, pk_path):
    """The producing side's own trust root: the data_dir public key must
    be a real Ed25519 key AND must be the public half of the secret this
    run will sign with. A mismatch would produce records stamped with a
    producer_key_id that verifies against nothing — evidence that looks
    signed and can never be checked."""
    key_id, pk_raw = load_trust_root(pk_path)
    sk = producer_load_sk(sk_path)
    if sk.public_key().public_bytes_raw() != pk_raw:
        raise TrustRootError(
            "%s is not the public half of %s — refusing to sign records "
            "under a producer_key_id nobody can verify"
            % (pk_path, sk_path))
    return key_id, sk


def _audit_axes_text(report, have_pubkey):
    """The two axes that are not chain integrity, always printed, always
    separately — a chain can be intact across an outage it never claimed
    to cover, and identical bytes are an observation, not a verdict."""
    lines = []
    cov = report.get("coverage") or {}
    lines.append("COVERAGE: %s" % coverage_axis(cov))
    for cam in sorted(cov):
        c = cov[cam]
        lines.append("  %-24s %-24s %s (seq %d..%d, %d record(s))"
                     % (cam, c["verdict"], c["reason"], c["seq_first"],
                        c["seq_last"], c["records"]))
        for o in c["outages"]:
            lines.append("      %-12s seq %d→%d  hole %.1fs  gap=%s"
                         % (o["class"], o["after_seq"], o["seq"],
                            o["hole_s"], o["gap_reason"] or "none"))
        for o in c.get("overlaps") or []:
            lines.append("      %-12s seq %d→%d  windows overlap %.1fs "
                         "(no time uncovered)"
                         % ("OVERLAP", o["after_seq"], o["seq"],
                            o["overlap_s"]))
    sensor = report.get("sensor") or {}
    if sensor:
        lines.append("SENSOR SIGNATURE: %s" % sensor_axis(sensor))
        for cam in sorted(sensor):
            c = sensor[cam]
            lines.append("  %-24s %s"
                         % (cam, "  ".join(
                             "%s=%d" % (v.lower(), c["verdicts"][v])
                             for v in SENSOR_VERDICTS
                             if c["verdicts"].get(v))))
            if c["vendor"] or c["device_serial"]:
                lines.append("      vendor=%s serial=%s firmware=%s "
                             "validator=%s"
                             % (c["vendor"], c["device_serial"],
                                c["device_firmware"], c["validator"]))
            if c["asserted_first_frame"] or c["asserted_last_frame"]:
                # NEVER presented as a time this node observed. The
                # camera's clock is the camera's claim; the O-node's
                # receipt time is a different fact and lives elsewhere.
                lines.append("      CAMERA-ASSERTED frame times (the "
                             "camera's own clock, NOT observed here, "
                             "NOT the O-node receipt time):")
                lines.append("        first=%s  last=%s"
                             % (c["asserted_first_frame"],
                                c["asserted_last_frame"]))
    lines.append("CONTENT REUSE: %s" % report.get("reuse_axis", REUSE_NONE))
    for g in report.get("reuse") or []:
        lines.append("  %-22s %.16s… x%d  cam=%s seqs=%s Δseq=%d "
                     "Δcapture_start=%.1fs bytes=%s"
                     % (g["class"], g["segment_sha256"], g["occurrences"],
                        ",".join(g["cameras"]), g["segment_seqs"],
                        g["seq_delta"], g["capture_start_delta_s"],
                        ",".join(str(b) for b in g["byte_len"])))
        lines.append("      basis: %s" % g["basis"])
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
