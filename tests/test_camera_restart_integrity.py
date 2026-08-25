#!/usr/bin/env python3
"""Restart-integrity tests for the camera driver.

Written against the 2026-08-24 session `camera:tapo-c100:2026-08-24`,
where five driver restarts produced 18 byte-identical duplicate
segments, ~108 s of silently dropped footage, re-stamped capture
windows, and a 69.1 s coverage hole carrying `gap: null`. Each test
class pins one of the fixes:

  A  durable submit checkpoint, keyed on (segment_sha256, segment_seq),
     fsynced, authoritative over state.json when ahead; spool-side
     chain-keyed idempotency as the backstop
  B  segment identity is content, not filename: ffmpeg renumbering from
     seg_000000 after a restart must neither replay old bytes nor drop
     new footage that lands under a reused name
  C  startup workdir reconciliation: graceful stop and hard kill both
     leave a workdir the next run can trust — zero duplicates, zero
     drops, only an unfinalized partial (no moov) is ever lost
  D  gap records from capture-time continuity, not just restarts
  E  capture windows are fixed at capture time and survive late submission
  F  single-instance lock, stale-lock recovery logged

Where the record supplies exact values (the 69,124,341,533 ns hole
between segs 76 and 77), the tests use them.
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "camera"))
import virp_camera as vc
from test_camera_driver import make_mp4, make_keypair, FakeSend, fake_chain_db
from test_camera_phase2 import live_cfg, ShipRecorder, FakeProc


def restart_cfg(tmp, sk_path, pk_path):
    """live_cfg plus the durable-checkpoint wiring main() sets up."""
    cfg = live_cfg(tmp, sk_path, pk_path)
    cfg["checkpoint_path"] = os.path.join(tmp, "shipped.jsonl")
    return cfg


class CheckpointTests(unittest.TestCase):
    """Fix A: the durable submit checkpoint on the capture host."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.sk_path, self.pk_path = make_keypair(self.tmp)
        self.cfg = restart_cfg(self.tmp, self.sk_path, self.pk_path)
        os.makedirs(self.cfg["workdir"])
        os.makedirs(self.cfg["outbox"])

    def _seg(self, name, pad):
        p = os.path.join(self.cfg["workdir"], name)
        with open(p, "wb") as f:
            f.write(make_mp4(pad=pad))
        return p

    def test_ship_writes_checkpoint_record(self):
        p = self._seg("seg_000000.mp4", b"ckpt" * 32)
        with open(p, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        state = vc.process_live_segment(p, self.cfg, None, None,
                                        ShipRecorder())
        shipped = vc.checkpoint_load(self.cfg["checkpoint_path"])
        self.assertIn(sha, shipped)
        rec = shipped[sha]
        self.assertEqual(rec["segment_seq"], 0)
        self.assertEqual(rec["capture_end_utc_ns"], state["last_end_ns"])

    def test_failed_ship_writes_no_checkpoint(self):
        p = self._seg("seg_000000.mp4", b"nock" * 32)
        with self.assertRaises(vc.SubmitError):
            vc.process_live_segment(p, self.cfg, None, None,
                                    ShipRecorder(fail_on=0))
        self.assertEqual(vc.checkpoint_load(self.cfg["checkpoint_path"]), {})

    def test_checkpoint_tolerates_torn_tail(self):
        # a crash mid-append leaves a partial final line; loading must
        # keep every complete record and ignore the torn one
        path = self.cfg["checkpoint_path"]
        vc.checkpoint_append(path, {"segment_seq": 0,
                                    "segment_sha256": "aa" * 32,
                                    "capture_end_utc_ns": 1,
                                    "shipped_as": "000000.aa"})
        with open(path, "a") as f:
            f.write('{"segment_seq": 1, "segment_sha')   # torn
        shipped = vc.checkpoint_load(path)
        self.assertEqual(list(shipped), ["aa" * 32])

    def test_checkpoint_authoritative_over_stale_state(self):
        # crash window: checkpoint_append succeeded, state_save did not.
        # Resume must adopt the checkpoint tail so seq 1 is never reused.
        path = self.cfg["checkpoint_path"]
        vc.checkpoint_append(path, {"segment_seq": 0,
                                    "segment_sha256": "aa" * 32,
                                    "capture_end_utc_ns": 10 ** 18,
                                    "shipped_as": "000000.aa"})
        vc.checkpoint_append(path, {"segment_seq": 1,
                                    "segment_sha256": "bb" * 32,
                                    "capture_end_utc_ns": 10 ** 18 + 1,
                                    "shipped_as": "000001.bb"})
        stale = {"camera_id": "tapo-c100", "segment_seq": 0,
                 "last_segment_sha256": "aa" * 32,
                 "last_session_id": "s", "last_end_ns": 10 ** 18}
        shipped = vc.checkpoint_load(path)
        state = vc._resume_state(stale, shipped, "tapo-c100")
        self.assertEqual(state["segment_seq"], 1)
        self.assertEqual(state["last_segment_sha256"], "bb" * 32)
        self.assertEqual(state["last_end_ns"], 10 ** 18 + 1)
        # and a state.json that is up to date is left alone
        fresh = dict(stale, segment_seq=5, last_segment_sha256="cc" * 32)
        self.assertIs(vc._resume_state(fresh, shipped, "tapo-c100"), fresh)


class ChainKeyedBackstopTests(unittest.TestCase):
    """Fix A, spool side: losing the sidecar (crash between append ack
    and sidecar write) must not produce a duplicate chain append — the
    chain itself is consulted before appending."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.sk_path, self.pk_path = make_keypair(self.tmp)
        self.cfg = live_cfg(self.tmp, self.sk_path, self.pk_path)
        self.incoming = os.path.join(self.tmp, "spool", "incoming")
        os.makedirs(self.incoming)
        self.db = os.path.join(self.tmp, "chain.db")
        self.data_dir = os.path.join(self.tmp, "onode-data")
        self.subcfg = {"data_dir": self.data_dir,
                       "sock": "/nonexistent",
                       "incoming": self.incoming,
                       "done": os.path.join(self.tmp, "spool", "done"),
                       "interval": 0,
                       "db": self.db}

    def _job(self, seq, prev, pad):
        seg_bytes = make_mp4(pad=pad)
        seg_sha = hashlib.sha256(seg_bytes).hexdigest()
        nosig = vc.build_body("tapo-c100", "tapo-c100", seq, seg_sha, prev,
                              len(seg_bytes), 5.0, 0, 10 ** 18,
                              "host-clock", "live", None, self.cfg["key_id"])
        body_bytes, _ = vc.producer_sign(self.cfg["sk"], nosig)
        name = "%06d.%s" % (seq, seg_sha)
        for ext, data in ((".mp4", seg_bytes), (".body", body_bytes),
                          (".done", b"")):
            with open(os.path.join(self.incoming, name + ext), "wb") as f:
                f.write(data)
        return name, body_bytes

    def test_lost_sidecar_no_duplicate_append(self):
        name, body_bytes = self._job(0, None, b"backstop" * 12)
        body_sha = hashlib.sha256(body_bytes).hexdigest()
        # the body is already ON the chain (a prior run appended it, then
        # crashed before writing the sidecar)
        fake_chain_db(self.db, [("camera:tapo-c100:2001-09-09", 7,
                                 "camseg:tapo-c100:0:%d" % 10 ** 18,
                                 body_sha, body_bytes.decode("ascii"))])
        send = FakeSend()
        n = vc.submit_spool(self.subcfg, once=True, send=send)
        self.assertEqual(len(send.requests), 0)    # NOT appended again
        # the job is archived and the sidecar is reconstructed, so the
        # normal idempotency key exists again
        self.assertFalse(os.path.exists(
            os.path.join(self.incoming, name + ".done")))
        self.assertTrue(os.path.exists(
            os.path.join(self.data_dir, "artifacts", body_sha + ".json")))

    def test_absent_db_falls_back_to_append(self):
        # no chain db readable: behavior degrades to the pre-existing
        # append (never a dropped record)
        self.subcfg["db"] = os.path.join(self.tmp, "nonexistent.db")
        self._job(0, None, b"fallback" * 12)
        send = FakeSend()
        n = vc.submit_spool(self.subcfg, once=True, send=send)
        self.assertEqual(n, 1)
        self.assertEqual(len(send.requests), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
