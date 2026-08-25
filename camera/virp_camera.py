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
import glob
import hashlib
import json
import os
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import time

SCHEMA = "camera_segment/1"
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
# The record of what this capture host has HANDED OFF, keyed on content
# (segment_sha256) plus the segment_seq it shipped under — never on a
# workdir filename, which ffmpeg reuses from seg_000000 after every
# restart. Append-only JSONL, fsynced before continuity advances, so it
# survives process death: startup consults this file, not a directory
# listing and not process memory. state.json remains the fast-path
# continuity cursor; where the two disagree (a crash between
# checkpoint_append and state_save) the checkpoint is authoritative —
# see _resume_state — so a sequence number is never reused.
#
# Named open item, deliberately NOT designed here: the checkpoint marks
# ship-acknowledged, not chain-append-acknowledged — there is no ack
# path from the O-node back to the capture host. Until one exists, the
# spool-side chain-keyed idempotency (_on_chain in submit_one) is the
# backstop that makes any re-offer a no-op instead of a duplicate.

def checkpoint_load(path):
    """{segment_sha256: record} from the shipped checkpoint. A crash
    mid-append can leave one torn final line; complete records are kept,
    the torn tail is ignored."""
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
            out[rec["segment_sha256"]] = rec
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


# ── Body construction ──────────────────────────────────────────────────

def build_body(camera_id, device, seq, seg_sha, prev_sha, byte_len,
               duration_s, start_ns, end_ns, time_source, mode, gap,
               key_id):
    """The camera_segment/1 record, WITHOUT producer_sig (added by
    producer_sign). Field set is the schema — nothing optional, nothing
    extra, no credentials, no URLs."""
    return {
        "schema": SCHEMA,
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
    if cfg["mode"] == "replay":
        # Replay has no live clock to attest: the honest time source is
        # the file's mtime (when ffmpeg closed the segment), stated as
        # such in the body rather than dressed up as host-clock.
        end_ns = os.stat(path).st_mtime_ns
        time_source = "file-mtime"
    else:
        end_ns = time.time_ns()
        time_source = "host-clock"
    start_ns = end_ns - int(duration * 1e9)

    seq = (state["segment_seq"] + 1) if state else 0
    prev = state["last_segment_sha256"] if state else None

    body_nosig = build_body(cfg["camera_id"], cfg["device"], seq, seg_sha,
                            prev, len(seg_bytes), duration, start_ns,
                            end_ns, time_source, cfg["mode"], gap,
                            cfg["key_id"])
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

def verify_segment(file_path, db_path, pubkey_path=None):
    """Recompute sha256 over the file's CURRENT bytes and report whether
    any camera_segment/1 body stored on the chain commits to that hash.
    This helper renders the verdict from the signed body — it recomputes
    ONE hash and compares. It does not verify chain entry signatures or
    sequencing; that is Docket's job. Returns process exit code."""
    with open(file_path, "rb") as f:
        file_sha = hashlib.sha256(f.read()).hexdigest()
    print("file: %s" % file_path)
    print("sha256 of current file bytes: %s" % file_sha)

    rows = _camera_bodies(db_path)
    match = None
    for session_id, artifact_id, body_raw, body in rows:
        if body.get("segment_sha256") == file_sha:
            match = (session_id, artifact_id, body_raw, body)
            break
    if match is None:
        claimed = [b for _, _, _, b in rows
                   if os.path.basename(file_path).startswith(
                       b.get("segment_sha256", "")[:16])]
        print("VERDICT: NO MATCH — no camera_segment body on this chain "
              "commits to the file's current bytes.")
        if claimed:
            b = claimed[0]
            print("  (a chain body DOES commit to a segment whose hash "
                  "matches this FILENAME: seq=%s segment_sha256=%s —\n"
                  "   the file's bytes have changed since that record "
                  "was made)" % (b["segment_seq"], b["segment_sha256"]))
        print("checked: sha256 recompute of the file vs the "
              "segment_sha256 field of every camera_segment/1 body in "
              "%s. Nothing more." % db_path)
        return 1

    session_id, artifact_id, body_raw, body = match
    print("VERDICT: MATCH — the file's current bytes are exactly the "
          "bytes committed by a chain-stored body:")
    print("  session=%s seq=%s artifact_id=%s"
          % (session_id, body["segment_seq"], artifact_id))
    if pubkey_path:
        with open(pubkey_path, "rb") as f:
            pk = f.read()
        ok = producer_verify(pk, body)
        print("  producer_sig: %s (out-of-band check against %s; not a "
              "chain verdict)" % ("VALID" if ok else "INVALID",
                                  pubkey_path))
        if not ok:
            return 1
    print("checked: sha256 recompute of the file vs the signed body's "
          "segment_sha256%s. Chain entry signatures and sequencing are "
          "Docket's verdict, not this tool's."
          % (", plus the body's producer signature" if pubkey_path
             else ""))
    return 0


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
        if body.get("schema") == SCHEMA:
            out.append((session_id, artifact_id, content, body))
    return out


# ── audit: the anti-chainwalk-bug regression, runnable ─────────────────

def _load_pubkeys(pubkey_paths):
    """Return {key_id: pk_raw} for a list of pinned public-key files. An
    Option B chain legitimately carries more than one producer identity
    (the capture host's key differs from a bootstrap replay key); each
    body names its producer_key_id, so a body is checked against the
    pinned key that matches it."""
    keys = {}
    for p in pubkey_paths or []:
        with open(p, "rb") as f:
            raw = f.read()
        keys[producer_key_id(raw)] = raw
    return keys


def audit_chain(db_path, session_prefix="camera:", pubkey_path=None):
    """For every camera_segment entry: recompute sha256 over the body
    bytes AS STORED in the chain and match artifact_hash (the
    chainwalk_summary defect was exactly this failing); check the
    in-body prev-hash chain per camera; optionally verify every
    producer_sig against the pinned key(s). pubkey_path may be a single
    path or a list of paths (multi-producer chains). Returns
    (checked, failures:list)."""
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

    if isinstance(pubkey_path, (list, tuple)):
        pubkeys = _load_pubkeys(pubkey_path)
    elif pubkey_path:
        pubkeys = _load_pubkeys([pubkey_path])
    else:
        pubkeys = {}

    failures = []
    checked = 0
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
        if body.get("schema") != SCHEMA:
            continue
        cam_bodies.append((session_id, artifact_id, body))

    # Pass 2 — the prev-hash continuity chain, walked in segment_seq
    # order per camera (the canonical order of the stream), NOT chain
    # append order: an Option B record is appended when its ship is
    # relayed, which need not match capture order. A seq that does not
    # follow its predecessor, or a prev-hash that does not cite it, is a
    # break — unless the record itself carries a gap, which is the
    # explicit, signed statement that continuity is not claimed there.
    chains = {}
    for session_id, artifact_id, body in sorted(
            cam_bodies, key=lambda t: (t[2]["camera_id"],
                                       t[2]["segment_seq"])):
        cam = body["camera_id"]
        gapped = body.get("gap") is not None
        if cam in chains:
            last_seq, last_sha = chains[cam]
            if body["segment_seq"] != last_seq + 1 and not gapped:
                failures.append("%s %s: segment_seq %s does not follow "
                                "%s (and carries no gap record)"
                                % (session_id, artifact_id,
                                   body["segment_seq"], last_seq))
            if body["prev_segment_sha256"] != last_sha and not gapped:
                failures.append("%s %s: prev_segment_sha256 does not "
                                "cite the previous segment (and carries "
                                "no gap record)" % (session_id, artifact_id))
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
    return checked, failures


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

def sftp_ship(spool_target, ssh_key=None, extra_opts=None):
    """Return ship(seg_file, body_file, name) -> bool. Uploads to the
    chrooted spool as <name>.mp4/.body via .part staging + rename, then
    a <name>.done marker LAST, so the submitter only ever sees complete
    jobs. One ssh path, key-only, sftp-only (the account is chrooted to
    internal-sftp on the far end)."""
    opts = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
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
    with open(path, "rb") as f:
        seg_bytes = f.read()
    seg_sha = hashlib.sha256(seg_bytes).hexdigest()
    duration = mp4_duration_s(path)          # raises on a partial (no moov)

    end_ns = time.time_ns()
    time_source = "host-clock"
    start_ns = end_ns - int(duration * 1e9)

    seq = (state["segment_seq"] + 1) if state else 0
    prev = state["last_segment_sha256"] if state else None

    body_nosig = build_body(cfg["camera_id"], cfg["device"], seq, seg_sha,
                            prev, len(seg_bytes), duration, start_ns,
                            end_ns, time_source, "live", gap, cfg["key_id"])
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
    name = "%06d.%s" % (seq, seg_sha)
    seg_out = os.path.join(out, name + ".mp4")
    body_out = os.path.join(out, name + ".body")
    with open(seg_out + ".tmp", "wb") as f:
        f.write(seg_bytes)
    os.replace(seg_out + ".tmp", seg_out)
    with open(body_out + ".tmp", "wb") as f:
        f.write(body_bytes)
    os.replace(body_out + ".tmp", body_out)

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


def _segment_names(workdir):
    return sorted(n for n in os.listdir(workdir) if n.endswith(".mp4"))


def _stat_sig(path):
    """(size, mtime_ns) — the cheap change signature that tells a file
    apart from what previously occupied its NAME. ffmpeg restarts its
    numbering at seg_000000 after every driver restart, so a filename
    identifies nothing; content does (Fix B)."""
    st = os.stat(path)
    return (st.st_size, st.st_mtime_ns)


def run_live(cfg, ship, stop_after_s=None, poll_s=0.5,
             _spawn=None, _clock=time.time):
    """Spawn the capture child, and as each segment closes, attest+ship it
    in order. A prior run means this run cannot claim continuous coverage
    across the restart: the first record carries an explicit gap — the
    same honesty rule as replay, now across a live kill/restart. SIGINT/
    SIGTERM stop the child and drain the segments already closed."""
    os.makedirs(cfg["workdir"], mode=0o700, exist_ok=True)
    os.makedirs(cfg["outbox"], mode=0o700, exist_ok=True)
    shipped = checkpoint_load(cfg.get("checkpoint_path"))
    state = _resume_state(state_load(cfg["state_path"]), shipped,
                          cfg["camera_id"])
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
    # ffmpeg reuses with NEW bytes is seen as new work, and on content
    # (`shipped`) so bytes already attested are never re-offered. The
    # old name-keyed set silently dropped ~72 s of real footage when a
    # restarted ffmpeg renumbered into just-drained names (the gap:null
    # hole at seg 77 of the 2026-08-24 session).
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
                if sha in shipped:
                    sys.stderr.write("skip %s: content already attested "
                                     "(%.16s… seq=%s)\n"
                                     % (name, sha,
                                        shipped[sha]["segment_seq"]))
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
                shipped[state["last_segment_sha256"]] = {
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
    if body.get("schema") != SCHEMA:
        raise ValueError("%s: body schema is %r, not %s"
                         % (name, body.get("schema"), SCHEMA))
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
    art_path = os.path.join(art_dir, seg_sha + ".mp4")
    if not os.path.exists(art_path):
        with open(art_path + ".tmp", "wb") as f:
            f.write(seg_bytes)
        os.replace(art_path + ".tmp", art_path)

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
    lv.add_argument("--segment-time", type=float, default=6.0)
    lv.add_argument("--minutes", type=float, default=None,
                    help="stop after N minutes (default: until signalled)")
    lv.add_argument("--rtsp-config", default=None,
                    help="0600 file holding the rtsp:// URL (else "
                         "$VIRP_CAMERA_RTSP_URL)")
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
        with open(pk_path, "rb") as f:
            key_id = producer_key_id(f.read())
        cfg = {
            "camera_id": args.camera_id,
            "device": args.device or args.camera_id,
            "data_dir": args.data_dir,
            "state_path": os.path.join(args.data_dir, "state.json"),
            "sock": args.sock,
            "mode": "replay",
            "sk": producer_load_sk(sk_path),
            "key_id": key_id,
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
        with open(pk_path, "rb") as f:
            key_id = producer_key_id(f.read())
        rtsp_url = rtsp_url_from_config(config_path=args.rtsp_config)
        if not rtsp_url and not args.test_source:
            raise SystemExit("no RTSP URL: set $VIRP_CAMERA_RTSP_URL or "
                             "--rtsp-config <0600 file>, or pass "
                             "--test-source to capture a synthetic feed")
        workdir = args.workdir or os.path.join(args.data_dir, "work")
        cfg = {
            "camera_id": args.camera_id,
            "device": args.device or args.camera_id,
            "data_dir": args.data_dir,
            "state_path": os.path.join(args.data_dir, "state.json"),
            "checkpoint_path": os.path.join(args.data_dir, "shipped.jsonl"),
            "workdir": workdir,
            "outbox": os.path.join(args.data_dir, "outbox"),
            "segment_time": args.segment_time,
            "rtsp_url": rtsp_url,            # None → synthetic source
            "mode": "live",
            "overlay_font": os.environ.get(
                "VIRP_CAMERA_OVERLAY_FONT",
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
            "sk": producer_load_sk(sk_path),
            "key_id": key_id,
        }
        ship = sftp_ship(args.spool, ssh_key=args.ssh_key)
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
        }
        n = submit_spool(cfg, once=args.once)
        print("submit-spool: %d job(s) appended this run" % n, flush=True)
        return 0

    if args.cmd == "verify-segment":
        return verify_segment(args.file, args.db, args.pubkey)

    if args.cmd == "audit":
        checked, failures = audit_chain(args.db, args.session_prefix,
                                        args.pubkey)
        print("audited %d camera evidence entr%s"
              % (checked, "y" if checked == 1 else "ies"))
        for f in failures:
            print("FAIL: %s" % f)
        if not failures:
            print("all stored bodies hash to their recorded "
                  "artifact_hash; prev-hash chain intact%s"
                  % ("; producer signatures valid" if args.pubkey
                     else ""))
        return 1 if failures else 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
