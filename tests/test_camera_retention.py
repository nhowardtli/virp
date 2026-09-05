#!/usr/bin/env python3
"""Tests for retention-as-a-signed-record (camera_retention/1).

Pure python against fakes: no daemon, no camera, no network. Pins, per
the module's contract:

  - the record is a frozen exact field set (the field set IS the
    schema): any extra, missing or malformed field is a named defect
  - the producer signature covers the canonical body-minus-sig and the
    counts inside the body are claims that must equal the list they
    describe
  - ORDER: the record is delivered BEFORE any byte is deleted; a failed
    delivery deletes nothing, and a resumed journal replays to
    byte-identical bodies (delivery dedup makes the replay a no-op)
  - only files older than the policy age are touched, every deleted
    file's digest is declared, and unknown file kinds are declared as
    "other" — never skipped
  - the spool gate accepts a record-only job for camera_retention/1
    ONLY: a segment job with a racing .mp4 still waits, and a malformed
    retention body is left for a human, never appended
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "camera"))
import virp_camera as vc

DAY_NS = 86400 * 10**9


def _mk(path, data, age_days=0):
    with open(path, "wb") as f:
        f.write(data)
    if age_days:
        old = time.time() - age_days * 86400
        os.utime(path, (old, old))


def _ok_send(req, sock_path=None):
    _ok_send.calls.append(req)
    return b"RECEIPT-OK"


class RetentionBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="virp-retention-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.data_dir = os.path.join(self.tmp, "data")
        os.makedirs(self.data_dir)
        sk_path = os.path.join(self.data_dir, "producer.key")
        pk_path = os.path.join(self.data_dir, "producer.pub")
        vc.producer_keygen(sk_path, pk_path)
        self.key_id, self.sk = vc._producer_identity(sk_path, pk_path)
        with open(pk_path, "rb") as f:
            self.pk_raw = f.read()
        _ok_send.calls = []

    def signed_body(self, removed=None, **over):
        removed = removed if removed is not None else [
            {"sha256": "ab" * 32, "kind": "segment", "byte_len": 10}]
        body = vc.build_retention_body(
            over.pop("camera_id", "cam-a"), over.pop("tier", "spool"),
            over.pop("policy_days", 14),
            over.pop("deleted_at_utc_ns", 1700000000 * 10**9),
            removed, self.key_id)
        body.update(over)
        return vc.producer_sign(self.sk, body)


class TestRetentionRecord(RetentionBase):
    def test_roundtrip_valid_and_signed(self):
        body_bytes, body = self.signed_body()
        self.assertIsNone(vc.retention_defect(body))
        self.assertTrue(vc.producer_verify(self.pk_raw, body))
        # the exact bytes reparse to the exact dict
        self.assertEqual(json.loads(body_bytes), body)

    def test_signature_dies_on_tamper(self):
        _, body = self.signed_body()
        body["removed"][0]["sha256"] = "cd" * 32
        self.assertFalse(vc.producer_verify(self.pk_raw, body))

    def test_field_set_is_exact(self):
        _, body = self.signed_body()
        extra = dict(body, note="benign-looking addition")
        self.assertIn("field set", vc.retention_defect(extra))
        missing = {k: v for k, v in body.items() if k != "tier"}
        self.assertIn("field set", vc.retention_defect(missing))

    def test_counts_are_checked_claims(self):
        _, body = self.signed_body()
        wrong_count = dict(body, removed_count=body["removed_count"] + 1)
        self.assertIn("removed_count", vc.retention_defect(wrong_count))
        wrong_bytes = dict(body, removed_bytes=body["removed_bytes"] + 1)
        self.assertIn("removed_bytes", vc.retention_defect(wrong_bytes))

    def test_item_shape_and_vocabulary(self):
        for bad, why in (
            ([{"sha256": "zz" * 32, "kind": "segment", "byte_len": 1}],
             "sha256"),
            ([{"sha256": "ab" * 32, "kind": "video", "byte_len": 1}],
             "kind"),
            ([{"sha256": "ab" * 32, "kind": "segment", "byte_len": -1}],
             "byte_len"),
            ([{"sha256": "ab" * 32, "kind": "segment", "byte_len": 1,
               "path": "/leak"}], "triple"),
            ([], "non-empty"),
        ):
            _, body = self.signed_body(removed=bad or None)
            if bad == []:
                body = dict(body, removed=[], removed_count=0,
                            removed_bytes=0)
            defect = vc.retention_defect(body)
            self.assertIsNotNone(defect, bad)
            self.assertIn(why, defect)

    def test_tier_vocabulary_closed(self):
        _, body = self.signed_body()
        self.assertIn("tier", vc.retention_defect(dict(body,
                                                       tier="archive")))

    def test_kind_from_suffix(self):
        job = "cam-a.000007.%s" % ("ab" * 32)
        self.assertEqual(vc.retention_kind(job + ".mp4"), "segment")
        self.assertEqual(vc.retention_kind(job + ".body"), "record_body")
        self.assertEqual(vc.retention_kind(job + ".validation.txt"),
                         "validator_output")
        self.assertEqual(vc.retention_kind(job + ".leaf.der"), "leaf_der")
        self.assertEqual(vc.retention_kind(job + ".handoff.json"),
                         "handoff")
        self.assertEqual(vc.retention_kind(job + ".done"), "marker")
        self.assertEqual(vc.retention_kind(job + ".mystery"), "other")

    def test_chunks_keep_every_item_and_fit(self):
        items = [(("/f%d" % i), {"sha256": ("%064x" % i), "kind": "segment",
                                 "byte_len": i}) for i in range(500)]
        chunks = vc._retention_chunks(items, vc.ARTIFACT_LIMIT)
        self.assertGreater(len(chunks), 1)
        flat = [it for ch in chunks for it in ch]
        self.assertEqual(flat, items)          # nothing lost, order kept
        for ch in chunks:
            body = vc.build_retention_body("cam-a", "spool", 14,
                                           1700000000 * 10**9,
                                           [i for _, i in ch],
                                           self.key_id)
            body_bytes, _ = vc.producer_sign(self.sk, body)
            self.assertLess(len(body_bytes), vc.ARTIFACT_LIMIT)


class TestRunRetention(RetentionBase):
    def setUp(self):
        super().setUp()
        self.store = os.path.join(self.tmp, "outbox")
        os.makedirs(self.store)
        sha = "ab" * 32
        self.aged = []
        for suffix in ("mp4", "body", "validation.txt", "leaf.der"):
            p = os.path.join(self.store,
                             "cam-a.000001.%s.%s" % (sha, suffix))
            _mk(p, ("old %s" % suffix).encode(), age_days=40)
            self.aged.append(p)
        self.fresh = os.path.join(self.store,
                                  "cam-a.000002.%s.mp4" % ("cd" * 32))
        _mk(self.fresh, b"fresh segment", age_days=1)
        # aged .body carries the camera's own claim of its id
        _mk(self.aged[1], json.dumps(
            {"schema": "camera_segment/6",
             "camera_id": "cam-a"}).encode(), age_days=40)
        self.cfg = {
            "data_dir": self.data_dir, "dir": self.store,
            "tier": "capture-host", "policy_days": 30,
            "camera_id": "cam-a", "sk": self.sk, "key_id": self.key_id,
            "sock": None, "db": None,
        }

    def test_declare_then_delete(self):
        delivered = []

        def deliver(c, body_bytes):
            # every file named in the record still EXISTS at delivery
            for p in c["files"]:
                self.assertTrue(os.path.exists(p))
            delivered.append(json.loads(body_bytes))
            return True

        n = vc.run_retention(self.cfg, deliver)
        self.assertEqual(n, len(self.aged))
        self.assertEqual(len(delivered), 1)
        body = delivered[0]
        self.assertIsNone(vc.retention_defect(body))
        self.assertTrue(vc.producer_verify(self.pk_raw, body))
        self.assertEqual(body["camera_id"], "cam-a")
        self.assertEqual(body["tier"], "capture-host")
        self.assertEqual(body["policy_days"], 30)
        self.assertEqual(body["removed_count"], len(self.aged))
        kinds = sorted(i["kind"] for i in body["removed"])
        self.assertEqual(kinds, ["leaf_der", "record_body", "segment",
                                 "validator_output"])
        for p in self.aged:
            self.assertFalse(os.path.exists(p))
        self.assertTrue(os.path.exists(self.fresh))
        self.assertFalse(os.path.exists(
            os.path.join(self.data_dir, vc.RETENTION_JOURNAL)))
        # a second pass finds nothing and writes nothing
        self.assertEqual(vc.run_retention(
            self.cfg, lambda *_: self.fail("no record expected")), 0)

    def test_failed_delivery_deletes_nothing(self):
        with self.assertRaises(vc.SubmitError):
            vc.run_retention(self.cfg, lambda c, b: False)
        for p in self.aged:
            self.assertTrue(os.path.exists(p))
        journal = os.path.join(self.data_dir, vc.RETENTION_JOURNAL)
        self.assertTrue(os.path.exists(journal))
        # the retry resumes the SAME journal: byte-identical body
        bodies = []
        vc.run_retention(self.cfg, lambda c, b: bodies.append(b) or True)
        self.assertEqual(len(bodies), 1)
        self.assertFalse(os.path.exists(journal))
        for p in self.aged:
            self.assertFalse(os.path.exists(p))

    def test_replay_is_deterministic(self):
        first = []
        with self.assertRaises(vc.SubmitError):
            vc.run_retention(self.cfg,
                             lambda c, b: first.append(b) or False)
        second = []
        vc.run_retention(self.cfg, lambda c, b: second.append(b) or True)
        self.assertEqual(first, second)

    def test_dry_run_touches_nothing(self):
        n = vc.run_retention(self.cfg,
                             lambda *_: self.fail("dry-run delivered"),
                             dry_run=True)
        self.assertEqual(n, 0)
        for p in self.aged:
            self.assertTrue(os.path.exists(p))
        self.assertFalse(os.path.exists(
            os.path.join(self.data_dir, vc.RETENTION_JOURNAL)))

    def test_spool_tier_camera_from_body(self):
        cfg = dict(self.cfg, tier="spool", camera_id=None)
        delivered = []
        vc.run_retention(cfg, lambda c, b: delivered.append(
            json.loads(b)) or True)
        self.assertEqual(delivered[0]["camera_id"], "cam-a")
        self.assertEqual(delivered[0]["tier"], "spool")


class TestSpoolGate(RetentionBase):
    def setUp(self):
        super().setUp()
        self.incoming = os.path.join(self.tmp, "incoming")
        self.done = os.path.join(self.tmp, "done")
        os.makedirs(self.incoming)
        self.cfg = {
            "data_dir": self.data_dir, "sock": "unused",
            "incoming": self.incoming, "done": self.done,
            "interval": 0.01, "db": None,
            "lock_path": os.path.join(self.incoming, ".lock"),
        }

    def _job(self, name, body_bytes):
        _mk(os.path.join(self.incoming, name + ".body"), body_bytes)
        _mk(os.path.join(self.incoming, name + ".done"), b"")

    def test_record_only_retention_job_lands(self):
        body_bytes, body = self.signed_body(tier="capture-host")
        name = "cam-a.retention.%d.0" % body["deleted_at_utc_ns"]
        self._job(name, body_bytes)
        n = vc.submit_spool(self.cfg, once=True, send=_ok_send)
        self.assertEqual(n, 1)
        self.assertEqual(len(_ok_send.calls), 1)
        req = _ok_send.calls[0]
        self.assertEqual(req["session_id"],
                         vc.retention_session_for(
                             "cam-a", body["deleted_at_utc_ns"]))
        self.assertTrue(req["artifact_id"].startswith("camret:cam-a:"))
        self.assertEqual(req["artifact_content"].encode(), body_bytes)
        self.assertTrue(os.path.exists(
            os.path.join(self.done, name + ".body")))
        self.assertFalse(os.path.exists(
            os.path.join(self.incoming, name + ".body")))

    def test_segment_job_without_mp4_still_waits(self):
        body = json.dumps({"schema": "camera_segment/6",
                           "camera_id": "cam-a"}).encode()
        self._job("cam-a.000003.%s" % ("ab" * 32), body)
        n = vc.submit_spool(self.cfg, once=True, send=_ok_send)
        self.assertEqual(n, 0)
        self.assertEqual(_ok_send.calls, [])
        self.assertTrue(os.path.exists(os.path.join(
            self.incoming, "cam-a.000003.%s.body" % ("ab" * 32))))

    def test_malformed_retention_left_for_a_human(self):
        body_bytes, body = self.signed_body()
        bad = dict(body, removed_count=99)     # a lying count
        name = "cam-a.retention.%d.0" % body["deleted_at_utc_ns"]
        self._job(name, vc.canonical_bytes(bad))
        n = vc.submit_spool(self.cfg, once=True, send=_ok_send)
        self.assertEqual(n, 0)
        self.assertEqual(_ok_send.calls, [])
        self.assertTrue(os.path.exists(
            os.path.join(self.incoming, name + ".body")))

    def test_record_only_dedup_by_body(self):
        body_bytes, body = self.signed_body(tier="capture-host")
        name = "cam-a.retention.%d.0" % body["deleted_at_utc_ns"]
        self._job(name, body_bytes)
        vc.submit_spool(self.cfg, once=True, send=_ok_send)
        self._job(name, body_bytes)            # the same bytes again
        vc.submit_spool(self.cfg, once=True, send=_ok_send)
        self.assertEqual(len(_ok_send.calls), 1)   # appended exactly once


if __name__ == "__main__":
    unittest.main()
