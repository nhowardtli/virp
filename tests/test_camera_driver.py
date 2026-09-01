#!/usr/bin/env python3
"""Tests for the camera driver (camera/virp_camera.py).

Pure python against fakes: no daemon, no camera, no chain database
beyond throwaway sqlite files. Pins, per the module's contract:

  - ONE canonical serialization: the submitted artifact_hash is the
    sha256 of exactly the bytes stored, and `audit` recomputing from
    the stored rows agrees (the anti-chainwalk-summary regression —
    a pretty-printed stored body MUST fail the audit)
  - the producer signature verifies over the canonical body-minus-sig
    and dies on any byte of tampering
  - prev_segment_sha256 chains every segment to its predecessor,
    across runs; segment_seq is monotonic
  - a restart is never silent: the first record of a second run
    carries an explicit gap record
  - a refused chain append does NOT advance continuity state
  - the driver's entire submit vocabulary is chain_append of
    artifact_type=evidence_item — it can produce no other entry
  - a body at/past the daemon's 8192-byte artifact field is refused
    locally, never submitted to be stored truncated
  - verify-segment recomputes and compares, honestly reporting a
    tampered file as NO MATCH
"""

import hashlib
import json
import os
import shutil
import sqlite3
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "camera"))
import virp_camera as vc


def make_mp4(duration_s=10.0, timescale=1000, pad=b"x" * 64):
    """Minimal ftyp+moov(mvhd v0)+mdat file the duration parser and
    hasher can treat as a segment."""
    dur = int(duration_s * timescale)
    mvhd_payload = bytes([0, 0, 0, 0])            # version 0 + flags
    mvhd_payload += struct.pack(">III", 0, 0, timescale)
    mvhd_payload += struct.pack(">I", dur)
    mvhd_payload += b"\x00" * 80                  # rate..next_track_id
    mvhd = struct.pack(">I", 8 + len(mvhd_payload)) + b"mvhd" + mvhd_payload
    moov = struct.pack(">I", 8 + len(mvhd)) + b"moov" + mvhd
    ftyp = struct.pack(">I", 16) + b"ftyp" + b"isom" + b"\x00\x00\x02\x00"
    mdat = struct.pack(">I", 8 + len(pad)) + b"mdat" + pad
    return ftyp + moov + mdat


def make_keypair(tmp):
    sk = os.path.join(tmp, "producer.key")
    pk = os.path.join(tmp, "producer.pub")
    vc.producer_keygen(sk, pk)
    return sk, pk


def make_cfg(tmp, sk_path, pk_path, mode="replay"):
    with open(pk_path, "rb") as f:
        key_id = vc.producer_key_id(f.read())
    return {
        "camera_id": "cam-test",
        "device": "cam-test",
        "data_dir": tmp,
        "state_path": os.path.join(tmp, "state.json"),
        "sock": "/nonexistent",
        "mode": mode,
        "sk": vc.producer_load_sk(sk_path),
        "key_id": key_id,
    }


class FakeSend:
    """Records every request; answers success unless told to refuse."""

    def __init__(self, refuse=False):
        self.requests = []
        self.refuse = refuse

    def __call__(self, request, sock_path=None):
        self.requests.append(request)
        if self.refuse:
            return struct.pack(">i", -18)
        return b"SIGNED-RECEIPT-BYTES"


def fake_chain_db(path, rows):
    """(session_id, sequence, artifact_id, artifact_hash, content)"""
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE chain_entries (session_id TEXT, "
                 "sequence INTEGER, artifact_type TEXT, artifact_id TEXT,"
                 " artifact_hash TEXT, timestamp_ns INTEGER)")
    conn.execute("CREATE TABLE artifacts (artifact_id TEXT, "
                 "artifact_hash TEXT, artifact_content TEXT)")
    for i, (sid, seq, aid, ahash, content) in enumerate(rows):
        conn.execute("INSERT INTO chain_entries VALUES (?,?,?,?,?,?)",
                     (sid, seq, "evidence_item", aid, ahash, i))
        conn.execute("INSERT INTO artifacts VALUES (?,?,?)",
                     (aid, ahash, content))
    conn.commit()
    conn.close()


class CanonicalTests(unittest.TestCase):

    def test_single_line_sorted_no_spaces(self):
        b = vc.canonical_bytes({"b": 1, "a": [2, None], "z": "s"})
        self.assertEqual(b, b'{"a":[2,null],"b":1,"z":"s"}')
        self.assertNotIn(b"\n", b)

    def test_deterministic(self):
        d = {"x": 1.5, "y": {"k": "v"}, "n": None}
        self.assertEqual(vc.canonical_bytes(d),
                         vc.canonical_bytes(json.loads(
                             vc.canonical_bytes(d))))


class ProducerKeyTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.sk_path, self.pk_path = make_keypair(self.tmp)

    def test_keygen_modes_and_no_overwrite(self):
        self.assertEqual(os.stat(self.sk_path).st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            vc.producer_keygen(self.sk_path, self.pk_path)

    def test_loose_mode_refused(self):
        os.chmod(self.sk_path, 0o644)
        with self.assertRaises(SystemExit):
            vc.producer_load_sk(self.sk_path)

    def test_sign_verify_and_tamper(self):
        sk = vc.producer_load_sk(self.sk_path)
        with open(self.pk_path, "rb") as f:
            pk = f.read()
        body_bytes, body = vc.producer_sign(sk, {"schema": vc.SCHEMA,
                                                 "segment_seq": 0})
        self.assertTrue(vc.producer_verify(pk, body))
        # verification survives a canonical-bytes round trip
        self.assertTrue(vc.producer_verify(pk, json.loads(body_bytes)))
        # any field tamper dies
        evil = dict(body)
        evil["segment_seq"] = 1
        self.assertFalse(vc.producer_verify(pk, evil))
        # sig tamper dies
        evil = dict(body)
        evil["producer_sig"] = "00" * 64
        self.assertFalse(vc.producer_verify(pk, evil))
        # missing sig is not valid
        self.assertFalse(vc.producer_verify(
            pk, {k: v for k, v in body.items() if k != "producer_sig"}))


class Mp4DurationTests(unittest.TestCase):

    def test_duration_v0(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        p = os.path.join(tmp, "s.mp4")
        with open(p, "wb") as f:
            f.write(make_mp4(duration_s=12.5, timescale=1000))
        self.assertAlmostEqual(vc.mp4_duration_s(p), 12.5)

    def test_no_moov_refused(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        p = os.path.join(tmp, "s.mp4")
        with open(p, "wb") as f:
            f.write(b"\x00\x00\x00\x08mdat")
        with self.assertRaises(ValueError):
            vc.mp4_duration_s(p)


class ReplayTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.sk_path, self.pk_path = make_keypair(self.tmp)
        self.cfg = make_cfg(self.tmp, self.sk_path, self.pk_path)
        self.seg_dir = os.path.join(self.tmp, "segs")
        os.makedirs(self.seg_dir)

    def write_segs(self, n, start=0):
        for i in range(start, start + n):
            with open(os.path.join(self.seg_dir,
                                   "seg_%03d.mp4" % i), "wb") as f:
                f.write(make_mp4(pad=b"seg%03d" % i * 32))

    def test_replay_submits_chained_evidence_items(self):
        self.write_segs(3)
        send = FakeSend()
        vc.run_replay(self.seg_dir, self.cfg, send=send)
        self.assertEqual(len(send.requests), 3)
        prev = None
        for i, req in enumerate(send.requests):
            # vocabulary pin: chain_append of evidence_item, nothing else
            self.assertEqual(req["action"], "chain_append")
            self.assertEqual(req["artifact_type"], "evidence_item")
            body_bytes = req["artifact_content"].encode("ascii")
            self.assertEqual(hashlib.sha256(body_bytes).hexdigest(),
                             req["artifact_hash"])
            body = json.loads(req["artifact_content"])
            self.assertEqual(body["schema"], "camera_segment/1")
            self.assertEqual(body["segment_seq"], i)
            self.assertEqual(body["prev_segment_sha256"], prev)
            self.assertIsNone(body["gap"])
            self.assertEqual(body["encoder"], "copy")
            self.assertEqual(body["time_source"], "file-mtime")
            with open(self.pk_path, "rb") as f:
                self.assertTrue(vc.producer_verify(f.read(), body))
            self.assertTrue(req["session_id"].startswith(
                "camera:cam-test:"))
            prev = body["segment_sha256"]
        # content-addressed artifacts + sidecars exist
        art = os.path.join(self.tmp, "artifacts")
        self.assertEqual(len([n for n in os.listdir(art)
                              if n.endswith(".mp4")]), 3)

    def test_second_run_gap_and_cross_run_prev(self):
        self.write_segs(2)
        send = FakeSend()
        vc.run_replay(self.seg_dir, self.cfg, send=send)
        last_body = json.loads(send.requests[-1]["artifact_content"])
        self.write_segs(2, start=2)
        send2 = FakeSend()
        vc.run_replay(self.seg_dir, self.cfg, send=send2)
        # the two already-attested segments are skipped, not re-submitted
        self.assertEqual(len(send2.requests), 2)
        first_new = json.loads(send2.requests[0]["artifact_content"])
        self.assertEqual(first_new["segment_seq"], 2)
        self.assertEqual(first_new["prev_segment_sha256"],
                         last_body["segment_sha256"])
        self.assertEqual(first_new["gap"],
                         {"reason": "driver-restart", "after_seq": 1})
        # gap is on the FIRST record of the run only
        second_new = json.loads(send2.requests[1]["artifact_content"])
        self.assertIsNone(second_new["gap"])

    def test_refused_append_does_not_advance_state(self):
        self.write_segs(1)
        with self.assertRaises(vc.SubmitError):
            vc.run_replay(self.seg_dir, self.cfg,
                          send=FakeSend(refuse=True))
        self.assertIsNone(vc.state_load(self.cfg["state_path"]))
        # and no sidecar claims the segment was attested
        art = os.path.join(self.tmp, "artifacts")
        self.assertEqual([n for n in os.listdir(art)
                          if n.endswith(".json")], [])

    def test_oversize_body_refused_locally(self):
        ok, why = vc.chain_append_evidence("camera:x:2026-01-01", "id",
                                           b"x" * 8192,
                                           send=FakeSend())
        self.assertFalse(ok)
        self.assertIn("truncated", why)


class AuditTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.sk_path, self.pk_path = make_keypair(self.tmp)
        self.sk = vc.producer_load_sk(self.sk_path)
        with open(self.pk_path, "rb") as f:
            self.key_id = vc.producer_key_id(f.read())
        self.db = os.path.join(self.tmp, "chain.db")

    def body_row(self, seq, prev, seg_sha, aid=None):
        nosig = vc.build_body("cam-a", "cam-a", seq, seg_sha, prev,
                              100, 10.0, 0, 10 ** 10, "file-mtime",
                              "replay", None, self.key_id)
        body_bytes, _ = vc.producer_sign(self.sk, nosig)
        content = body_bytes.decode("ascii")
        return ("camera:cam-a:2026-08-24", seq,
                aid or ("camseg:cam-a:%d:%d" % (seq, seq)),
                hashlib.sha256(body_bytes).hexdigest(), content)

    def test_clean_chain_passes(self):
        s0, s1 = "a" * 64, "b" * 64
        fake_chain_db(self.db, [self.body_row(0, None, s0),
                                self.body_row(1, s0, s1)])
        checked, failures = vc.audit_chain(self.db,
                                           pubkey_path=self.pk_path)
        self.assertEqual(checked, 2)
        self.assertEqual(failures, [])

    def test_pretty_printed_body_fails(self):
        # THE chainwalk_summary regression: body stored re-serialized
        # (pretty) no longer hashes to the recorded artifact_hash.
        sid, seq, aid, ahash, content = self.body_row(0, None, "a" * 64)
        pretty = json.dumps(json.loads(content), indent=2)
        fake_chain_db(self.db, [(sid, seq, aid, ahash, pretty)])
        checked, failures = vc.audit_chain(self.db)
        self.assertEqual(checked, 1)
        self.assertEqual(len(failures), 1)
        self.assertIn("!= artifact_hash", failures[0])

    def test_broken_prev_chain_fails(self):
        s0, s1 = "a" * 64, "b" * 64
        fake_chain_db(self.db, [self.body_row(0, None, s0),
                                self.body_row(1, "f" * 64, s1)])
        _, failures = vc.audit_chain(self.db)
        self.assertTrue(any("prev_segment_sha256" in f
                            for f in failures))

    def test_tampered_sig_fails_with_pubkey(self):
        sid, seq, aid, ahash, content = self.body_row(0, None, "a" * 64)
        body = json.loads(content)
        body["producer_sig"] = "00" * 64
        evil = vc.canonical_bytes(body).decode("ascii")
        fake_chain_db(self.db, [
            (sid, seq, aid, hashlib.sha256(evil.encode()).hexdigest(),
             evil)])
        _, failures = vc.audit_chain(self.db, pubkey_path=self.pk_path)
        self.assertTrue(any("producer_sig INVALID" in f
                            for f in failures))


class VerifySegmentTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.sk_path, self.pk_path = make_keypair(self.tmp)
        self.sk = vc.producer_load_sk(self.sk_path)
        with open(self.pk_path, "rb") as f:
            self.key_id = vc.producer_key_id(f.read())
        self.db = os.path.join(self.tmp, "chain.db")
        self.seg = os.path.join(self.tmp, "seg.mp4")
        with open(self.seg, "wb") as f:
            f.write(make_mp4())
        with open(self.seg, "rb") as f:
            self.seg_sha = hashlib.sha256(f.read()).hexdigest()
        nosig = vc.build_body("cam-a", "cam-a", 0, self.seg_sha, None,
                              100, 10.0, 0, 10 ** 10, "file-mtime",
                              "replay", None, self.key_id)
        body_bytes, _ = vc.producer_sign(self.sk, nosig)
        fake_chain_db(self.db, [
            ("camera:cam-a:2026-08-24", 0, "camseg:cam-a:0:1",
             hashlib.sha256(body_bytes).hexdigest(),
             body_bytes.decode("ascii"))])

    def test_intact_file_matches(self):
        rc = vc.verify_segment(self.seg, self.db,
                               pubkey_path=self.pk_path)
        self.assertEqual(rc, 0)

    def test_flipped_byte_is_no_match(self):
        with open(self.seg, "rb") as f:
            data = bytearray(f.read())
        data[len(data) // 2] ^= 0x01
        flipped = os.path.join(self.tmp, self.seg_sha[:16] + ".mp4")
        with open(flipped, "wb") as f:
            f.write(bytes(data))
        rc = vc.verify_segment(flipped, self.db)
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
