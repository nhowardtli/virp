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
import hashlib
import json
import os
import socket
import sqlite3
import struct
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
    os.replace(tmp, path)


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

def audit_chain(db_path, session_prefix="camera:", pubkey_path=None):
    """For every camera_segment entry: recompute sha256 over the body
    bytes AS STORED in the chain and match artifact_hash (the
    chainwalk_summary defect was exactly this failing); check the
    in-body prev-hash chain per camera; optionally verify every
    producer_sig. Returns (checked, failures:list)."""
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

    pk = None
    if pubkey_path:
        with open(pubkey_path, "rb") as f:
            pk = f.read()

    failures = []
    chains = {}   # camera_id -> (last_seq, last_sha)
    checked = 0
    for session_id, seq, artifact_id, ahash, content in rows:
        stored = content.encode("ascii")
        checked += 1
        recomputed = hashlib.sha256(stored).hexdigest()
        if recomputed != ahash:
            failures.append("%s %s: sha256(stored body) %s != "
                            "artifact_hash %s"
                            % (session_id, artifact_id, recomputed,
                               ahash))
            continue
        try:
            body = json.loads(content)
        except ValueError:
            failures.append("%s %s: body is not JSON"
                            % (session_id, artifact_id))
            continue
        if body.get("schema") != SCHEMA:
            continue
        cam = body["camera_id"]
        if cam in chains:
            last_seq, last_sha = chains[cam]
            if body["segment_seq"] != last_seq + 1:
                failures.append("%s %s: segment_seq %s does not follow "
                                "%s" % (session_id, artifact_id,
                                        body["segment_seq"], last_seq))
            if body["prev_segment_sha256"] != last_sha:
                failures.append("%s %s: prev_segment_sha256 does not "
                                "cite the previous segment"
                                % (session_id, artifact_id))
        else:
            if body["prev_segment_sha256"] is not None:
                failures.append("%s %s: first record for %s has non-null "
                                "prev_segment_sha256"
                                % (session_id, artifact_id, cam))
        chains[cam] = (body["segment_seq"], body["segment_sha256"])
        if pk is not None and not producer_verify(pk, body):
            failures.append("%s %s: producer_sig INVALID"
                            % (session_id, artifact_id))
    return checked, failures


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
    au.add_argument("--pubkey", default=None)

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
