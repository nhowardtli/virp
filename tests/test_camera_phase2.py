#!/usr/bin/env python3
"""Phase 2 tests: the Option B split — capture-host live path (build,
sign, ship, continuity) and the O-node submit-spool relay.

Pins added on top of the Phase 1 contract:
  - a live body is producer-signed, mode="live", time_source="host-clock"
  - continuity is advanced only after a durable ship; a failed ship does
    NOT advance state (segment retried, never skipped)
  - the first record of a live run after a prior run carries a gap; the
    prev chain crosses the restart (cites the last segment of the prior
    run)
  - submit-spool relays the producer's exact bytes verbatim: the request
    artifact_content equals the shipped body byte-for-byte, and
    artifact_hash = sha256 of exactly those bytes
  - submit-spool refuses a job whose segment file does not match the
    body's segment_sha256
  - submit-spool is idempotent (a re-shipped, already-attested job is a
    no-op success) and a daemon refusal leaves the job to retry
  - the whole path is chain_append of evidence_item only
"""

import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "camera"))
import virp_camera as vc
from test_camera_driver import make_mp4, make_keypair, FakeSend


def live_cfg(tmp, sk_path, pk_path):
    with open(pk_path, "rb") as f:
        key_id = vc.producer_key_id(f.read())
    return {
        "camera_id": "tapo-c100",
        "device": "tapo-c100",
        "data_dir": tmp,
        "state_path": os.path.join(tmp, "state.json"),
        "workdir": os.path.join(tmp, "work"),
        "outbox": os.path.join(tmp, "outbox"),
        "segment_time": 5.0,
        "rtsp_url": None,
        "mode": "live",
        "sk": vc.producer_load_sk(sk_path),
        "key_id": key_id,
    }


class ShipRecorder:
    """Fake ship(): records every (seg_file, body_file, name) and returns
    ok, or fails on a chosen call index."""

    def __init__(self, fail_on=None):
        self.calls = []
        self.fail_on = fail_on

    def __call__(self, seg_file, body_file, name):
        with open(body_file, "rb") as f:
            body_bytes = f.read()
        self.calls.append({"name": name, "body_bytes": body_bytes})
        if self.fail_on is not None and len(self.calls) - 1 == self.fail_on:
            return False
        return True


class FakeProc:
    """Minimal Popen stand-in: exits immediately (poll() truthy)."""

    def __init__(self, rc=0):
        self._rc = rc

    def poll(self):
        return self._rc

    def wait(self, timeout=None):
        return self._rc

    def terminate(self):
        pass

    def kill(self):
        pass


class LiveSegmentTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.sk_path, self.pk_path = make_keypair(self.tmp)
        self.cfg = live_cfg(self.tmp, self.sk_path, self.pk_path)
        os.makedirs(self.cfg["workdir"])
        os.makedirs(self.cfg["outbox"])

    def _seg(self, name, pad):
        p = os.path.join(self.cfg["workdir"], name)
        with open(p, "wb") as f:
            f.write(make_mp4(pad=pad))
        return p

    def test_live_body_shape_and_ship(self):
        p = self._seg("seg_000000.mp4", b"live0" * 32)
        ship = ShipRecorder()
        state = vc.process_live_segment(p, self.cfg, None, None, ship)
        self.assertEqual(state["segment_seq"], 0)
        self.assertEqual(len(ship.calls), 1)
        body = json.loads(ship.calls[0]["body_bytes"])
        self.assertEqual(body["schema"], "camera_segment/1")
        self.assertEqual(body["mode"], "live")
        self.assertEqual(body["time_source"], "host-clock")
        self.assertEqual(body["encoder"], "copy")
        self.assertIsNone(body["prev_segment_sha256"])
        self.assertIsNone(body["gap"])
        with open(self.pk_path, "rb") as f:
            self.assertTrue(vc.producer_verify(f.read(), body))
        # handoff record written
        self.assertTrue(any(n.endswith(".handoff.json")
                            for n in os.listdir(self.cfg["outbox"])))

    def test_failed_ship_does_not_advance_state(self):
        p = self._seg("seg_000000.mp4", b"x" * 32)
        with self.assertRaises(vc.SubmitError):
            vc.process_live_segment(p, self.cfg, None, None,
                                    ShipRecorder(fail_on=0))
        self.assertIsNone(vc.state_load(self.cfg["state_path"]))
        self.assertFalse(any(n.endswith(".handoff.json")
                             for n in os.listdir(self.cfg["outbox"])))

    def test_run_live_restart_gap_and_cross_run_prev(self):
        # first run: two closed segments (ffmpeg already exited)
        s0 = self._seg("seg_000000.mp4", b"a" * 40)
        s1 = self._seg("seg_000001.mp4", b"b" * 40)
        ship = ShipRecorder()
        vc.run_live(self.cfg, ship, _spawn=lambda cfg: FakeProc())
        self.assertEqual(len(ship.calls), 2)
        last = json.loads(ship.calls[-1]["body_bytes"])
        self.assertEqual(last["segment_seq"], 1)

        # first run's segments were shipped, so the driver itself removed
        # them from the workdir (the old version of this test had to
        # delete them by hand — doing manually what the driver now does)
        self.assertEqual([n for n in os.listdir(self.cfg["workdir"])
                          if n.endswith(".mp4")], [])

        # second run: ffmpeg renumbers from seg_000000 and writes NEW
        # capture mid-run -> its first record carries gap + cross-run prev
        class CapturesOneThenExits:
            def __init__(proc):
                proc.n = 0

            def poll(proc):
                proc.n += 1
                if proc.n == 1:
                    self._seg("seg_000000.mp4", b"c" * 40)
                return None if proc.n <= 3 else 0

            def wait(proc, timeout=None):
                return 0

            def terminate(proc):
                pass

            def kill(proc):
                pass

        ship2 = ShipRecorder()
        vc.run_live(self.cfg, ship2, poll_s=0,
                    _spawn=lambda cfg: CapturesOneThenExits())
        self.assertEqual(len(ship2.calls), 1)
        first = json.loads(ship2.calls[0]["body_bytes"])
        self.assertEqual(first["segment_seq"], 2)
        self.assertEqual(first["gap"],
                         {"reason": "driver-restart", "after_seq": 1})
        self.assertEqual(first["prev_segment_sha256"],
                         last["segment_sha256"])

    def test_open_segment_not_attested_while_running(self):
        # An OPEN segment is one ffmpeg is still writing: it has no moov
        # yet and its bytes keep changing. It must not be attested until
        # finalized. (This test used to model "open" as "the highest
        # name", which is exactly the assumption a renumbering ffmpeg
        # breaks — openness is now a property of the file, not its name.)
        full = make_mp4(pad=b"z" * 40)
        p = os.path.join(self.cfg["workdir"], "seg_000000.mp4")
        with open(p, "wb") as f:
            f.write(full[:32])                     # growing: no moov yet

        class RunningThenDone:
            def __init__(self):
                self.n = 0

            def poll(self):
                self.n += 1
                if self.n == 4:                    # ffmpeg finalizes...
                    with open(p, "wb") as f:
                        f.write(full)
                return None if self.n <= 4 else 0  # ...then exits

            def wait(self, timeout=None):
                return 0

            def terminate(self):
                pass

            def kill(self):
                pass

        ship = ShipRecorder()
        vc.run_live(self.cfg, ship, poll_s=0,
                    _spawn=lambda cfg: RunningThenDone())
        # attested exactly once — only the finalized bytes
        self.assertEqual(len(ship.calls), 1)
        body = json.loads(ship.calls[0]["body_bytes"])
        self.assertEqual(body["segment_sha256"],
                         hashlib.sha256(full).hexdigest())


class SubmitSpoolTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.sk_path, self.pk_path = make_keypair(self.tmp)
        self.cfg = live_cfg(self.tmp, self.sk_path, self.pk_path)
        self.spool = os.path.join(self.tmp, "spool")
        self.incoming = os.path.join(self.spool, "incoming")
        self.done = os.path.join(self.spool, "done")
        os.makedirs(self.incoming)
        self.data_dir = os.path.join(self.tmp, "onode-data")
        self.subcfg = {"data_dir": self.data_dir,
                       "sock": "/nonexistent",
                       "incoming": self.incoming,
                       "done": self.done,
                       "interval": 0}

    def _ship_job(self, seq, prev, pad=b"seg" * 32, corrupt_seg=False,
                  camera="tapo-c100", scheme="old"):
        """Build+sign a live body just like the capture host, drop the
        {name.mp4, name.body, name.done} triple into incoming.

        scheme="old" names the job <seq>.<sha>, the camera-blind form
        that ~7600 files in the live done/ carry and that the capture
        host wrote until this change; scheme="new" names it the way
        spool_job_name does now. Both are exercised, because a real
        incoming/ will hold both during a rollover."""
        seg_bytes = make_mp4(pad=pad)
        seg_sha = hashlib.sha256(seg_bytes).hexdigest()
        nosig = vc.build_body(camera, camera, seq, seg_sha, prev,
                              len(seg_bytes), 5.0, 0, 10 ** 18,
                              "host-clock", "live", None, self.cfg["key_id"])
        body_bytes, _ = vc.producer_sign(self.cfg["sk"], nosig)
        name = ("%06d.%s" % (seq, seg_sha) if scheme == "old"
                else vc.spool_job_name(camera, seq, seg_sha))
        stored_seg = seg_bytes if not corrupt_seg else (seg_bytes + b"X")
        with open(os.path.join(self.incoming, name + ".mp4"), "wb") as f:
            f.write(stored_seg)
        with open(os.path.join(self.incoming, name + ".body"), "wb") as f:
            f.write(body_bytes)
        open(os.path.join(self.incoming, name + ".done"), "wb").close()
        return name, seg_sha, body_bytes

    def test_relays_bytes_verbatim(self):
        _, seg_sha, body_bytes = self._ship_job(0, None)
        send = FakeSend()
        n = vc.submit_spool(self.subcfg, once=True, send=send)
        self.assertEqual(n, 1)
        self.assertEqual(len(send.requests), 1)
        req = send.requests[0]
        self.assertEqual(req["action"], "chain_append")
        self.assertEqual(req["artifact_type"], "evidence_item")
        # verbatim: submitted bytes == shipped body bytes, exactly
        self.assertEqual(req["artifact_content"].encode("ascii"), body_bytes)
        self.assertEqual(req["artifact_hash"],
                         hashlib.sha256(body_bytes).hexdigest())
        # derived ids match the producer convention
        self.assertEqual(req["session_id"],
                         vc.session_for("tapo-c100", 10 ** 18))
        self.assertTrue(req["artifact_id"].startswith("camseg:tapo-c100:0:"))
        # job archived, sidecar written (keyed by body_sha256, per-record)
        body_sha = hashlib.sha256(body_bytes).hexdigest()
        self.assertTrue(os.path.exists(
            os.path.join(self.data_dir, "artifacts", body_sha + ".json")))
        self.assertEqual([n for n in os.listdir(self.incoming)
                          if not n.endswith(".part")], [])

    def test_segment_mismatch_refused(self):
        self._ship_job(0, None, corrupt_seg=True)
        send = FakeSend()
        # malformed job: submit_one raises -> submit_spool logs, no submit
        vc.submit_spool(self.subcfg, once=True, send=send)
        self.assertEqual(len(send.requests), 0)

    def test_idempotent_reship(self):
        self._ship_job(0, None, pad=b"idem" * 20)
        send = FakeSend()
        vc.submit_spool(self.subcfg, once=True, send=send)
        # re-ship the identical job
        self._ship_job(0, None, pad=b"idem" * 20)
        send2 = FakeSend()
        vc.submit_spool(self.subcfg, once=True, send=send2)
        self.assertEqual(len(send2.requests), 0)   # already attested

    def test_daemon_refusal_leaves_job(self):
        name, seg_sha, body_bytes = self._ship_job(0, None)
        body_sha = hashlib.sha256(body_bytes).hexdigest()
        vc.submit_spool(self.subcfg, once=True, send=FakeSend(refuse=True))
        # job stays in incoming for a retry; the "attested" marker (the
        # per-body sidecar, the idempotency key) is NOT written on refusal
        self.assertTrue(os.path.exists(
            os.path.join(self.incoming, name + ".done")))
        self.assertFalse(os.path.exists(
            os.path.join(self.data_dir, "artifacts", body_sha + ".json")))
        # a later successful pass lands it
        n = vc.submit_spool(self.subcfg, once=True, send=FakeSend())
        self.assertEqual(n, 1)
        self.assertTrue(os.path.exists(
            os.path.join(self.data_dir, "artifacts", body_sha + ".json")))

    # ── mixed-convention spool ──────────────────────────
    #
    # A real incoming/ holds both conventions during a rollover, and
    # done/ holds ~7600 files under the old one that are NOT renamed.
    # Nothing lists or parses done/ — submit_spool only os.replace()s
    # into it — and incoming/ is drained by pairing suffixes off the
    # .done marker, so the two conventions simply coexist. The only thing
    # the name decides is the sorted() drain ORDER, and ASCII puts every
    # digit-leading old name ahead of every letter-leading new one, so a
    # backlog drains before new work.

    def test_both_conventions_drain_in_one_pass(self):
        old_name, _, _ = self._ship_job(0, None, pad=b"old" * 20,
                                        scheme="old")
        new_name, _, _ = self._ship_job(1, None, pad=b"new" * 20,
                                        scheme="new")
        self.assertTrue(old_name[0].isdigit())
        self.assertTrue(new_name.startswith("tapo-c100."))
        send = FakeSend()
        self.assertEqual(vc.submit_spool(self.subcfg, once=True, send=send),
                         2)
        self.assertEqual(len(send.requests), 2)
        self.assertEqual([n for n in os.listdir(self.incoming)
                          if not n.endswith(".part")], [])
        for n in os.listdir(self.done):
            self.assertTrue(n.startswith(old_name) or
                            n.startswith(new_name), n)

    def test_the_old_backlog_drains_first(self):
        self._ship_job(5, None, pad=b"newer" * 20, scheme="new")
        self._ship_job(2, None, pad=b"older" * 20, scheme="old")
        send = FakeSend()
        vc.submit_spool(self.subcfg, once=True, send=send)
        seqs = [json.loads(r["artifact_content"])["segment_seq"]
                for r in send.requests]
        self.assertEqual(seqs, [2, 5])

    def test_the_chain_record_does_not_depend_on_the_name(self):
        # the same signed body under both names produces the same
        # session_id, artifact_id and artifact_hash — the name is not
        # an input to anything that reaches the chain
        _, _, body_bytes = self._ship_job(0, None, pad=b"same" * 20,
                                          scheme="old")
        send_old = FakeSend()
        vc.submit_spool(self.subcfg, once=True, send=send_old)

        shutil.rmtree(self.data_dir, ignore_errors=True)
        _, _, body2 = self._ship_job(0, None, pad=b"same" * 20,
                                     scheme="new")
        self.assertEqual(body2, body_bytes)
        send_new = FakeSend()
        vc.submit_spool(self.subcfg, once=True, send=send_new)

        a, b = send_old.requests[0], send_new.requests[0]
        for k in ("session_id", "artifact_id", "artifact_hash",
                  "artifact_type", "artifact_content"):
            self.assertEqual(a[k], b[k], k)


class SpoolJobNamingTests(unittest.TestCase):
    """<camera>.<seq>.<sha>, and what still holds because of what the
    name is NOT used for.

    The old name was <seq>.<sha>. Both live cameras wrote 000000.
    through 000008. into one incoming/, told apart only by the hash —
    the same collision class already fixed in three places on the
    detection side, and the last layer still carrying it. Nothing broke
    then and nothing changes on the chain now, because submit_one never
    parses the name: camera_id, segment_seq, capture_end, session_id,
    artifact_id and every hash come from the signed body. The name is
    an operator-facing handle and a uniqueness key in one directory."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_the_name_carries_the_camera(self):
        self.assertEqual(vc.spool_job_name("tapo-c100", 8, "a" * 64),
                         "tapo-c100.000008." + "a" * 64)

    def test_two_cameras_at_the_same_seq_no_longer_collide(self):
        a = vc.spool_job_name("tapo-c100", 0, "a" * 64)
        b = vc.spool_job_name("reolink-rlc810a-sub", 0, "a" * 64)
        self.assertNotEqual(a, b)
        # ... and under the old scheme they were the same name
        self.assertEqual("%06d.%s" % (0, "a" * 64),
                         "%06d.%s" % (0, "a" * 64))

    def test_the_camera_token_cannot_reach_out_of_the_spool(self):
        # the token now lands in an sftp put path inside a chroot
        for bad in ("../etc/passwd", "a/b", "a.b", "-rf", "", "a b",
                    "caf\u00e9", "x" * 65, "_lead", None, 7):
            with self.subTest(camera=bad):
                with self.assertRaises(ValueError):
                    vc.spool_job_name(bad, 0, "a" * 64)

    def test_the_live_camera_ids_are_all_accepted(self):
        for good in ("tapo-c100", "tapo-c100-accept",
                     "synthetic-restart-accept", "reolink-rlc810a-sub"):
            with self.subTest(camera=good):
                self.assertEqual(vc.spool_camera_token(good), good)

    def test_a_staged_pair_is_still_found_under_the_new_name(self):
        # _staged_pair globs *.<sha>.body, so the camera prefix is
        # transparent to restart reconciliation
        out = os.path.join(self.tmp, "outbox")
        os.makedirs(out)
        sha = "b" * 64
        name = vc.spool_job_name("tapo-c100", 3, sha)
        open(os.path.join(out, name + ".mp4"), "wb").close()
        with open(os.path.join(out, name + ".body"), "w") as f:
            json.dump({"segment_sha256": sha, "capture_end_utc_ns": 5}, f)
        # matched on content AND capture end (Task 1: record identity)
        pair = vc._staged_pair(out, sha, 5)
        self.assertIsNotNone(pair)
        self.assertEqual(os.path.basename(pair[1]), name + ".body")
        # a different segment with the same bytes is not this pair
        self.assertIsNone(vc._staged_pair(out, sha, 6))


class MultiProducerAuditTests(unittest.TestCase):
    """An Option B chain carries two producer identities across the
    replay->live boundary; audit must verify each body under the key
    matching its producer_key_id, and both keys together must pass."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        import sqlite3
        from test_camera_driver import fake_chain_db
        self._fake_db = fake_chain_db
        # two producers
        self.a_sk = os.path.join(self.tmp, "a.key")
        self.a_pk = os.path.join(self.tmp, "a.pub")
        vc.producer_keygen(self.a_sk, self.a_pk)
        self.b_sk = os.path.join(self.tmp, "b.key")
        self.b_pk = os.path.join(self.tmp, "b.pub")
        vc.producer_keygen(self.b_sk, self.b_pk)
        self.db = os.path.join(self.tmp, "chain.db")

    def _row(self, sk, pk, seq, prev, seg_sha, mode):
        with open(pk, "rb") as f:
            kid = vc.producer_key_id(f.read())
        nosig = vc.build_body("cam", "cam", seq, seg_sha, prev, 100, 5.0,
                              0, 10 ** 18, "host-clock", mode, None, kid)
        body_bytes, _ = vc.producer_sign(vc.producer_load_sk(sk), nosig)
        return ("camera:cam:2026-08-24", seq,
                "camseg:cam:%d:1" % seq,
                hashlib.sha256(body_bytes).hexdigest(),
                body_bytes.decode("ascii"))

    def test_two_keys_pass_together(self):
        s = ["%02d" % i * 32 for i in range(3)]
        rows = [self._row(self.a_sk, self.a_pk, 0, None, s[0], "replay"),
                self._row(self.b_sk, self.b_pk, 1, s[0], s[1], "live"),
                self._row(self.b_sk, self.b_pk, 2, s[1], s[2], "live")]
        self._fake_db(self.db, rows)
        # both pinned -> clean
        checked, failures = vc.audit_chain(
            self.db, pubkey_path=[self.a_pk, self.b_pk])
        self.assertEqual(checked, 3)
        self.assertEqual(failures, [])
        # only one pinned -> the other producer's entries are flagged as
        # unpinned (honest: not verified, not silently passed)
        _, failures2 = vc.audit_chain(self.db, pubkey_path=[self.a_pk])
        self.assertTrue(any("not among the pinned keys" in f
                            for f in failures2))


class NoSilentDropTests(unittest.TestCase):
    """The regression that a deterministic source exposed: two DISTINCT
    records (different seq/capture time) that carry byte-identical video
    must BOTH be appended — the submitter must never drop one because its
    pixels already appeared."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.sk_path, self.pk_path = make_keypair(self.tmp)
        self.cfg = live_cfg(self.tmp, self.sk_path, self.pk_path)
        self.incoming = os.path.join(self.tmp, "spool", "incoming")
        os.makedirs(self.incoming)
        self.subcfg = {"data_dir": os.path.join(self.tmp, "od"),
                       "sock": "/nonexistent", "incoming": self.incoming,
                       "done": os.path.join(self.tmp, "spool", "done"),
                       "interval": 0}

    def _job(self, seq, prev, seg_bytes):
        seg_sha = hashlib.sha256(seg_bytes).hexdigest()
        nosig = vc.build_body("cam", "cam", seq, seg_sha, prev,
                              len(seg_bytes), 5.0, 0, 10 ** 18 + seq,
                              "host-clock", "live", None, self.cfg["key_id"])
        bb, _ = vc.producer_sign(self.cfg["sk"], nosig)
        name = "%06d.%s" % (seq, seg_sha)
        with open(os.path.join(self.incoming, name + ".mp4"), "wb") as f:
            f.write(seg_bytes)
        with open(os.path.join(self.incoming, name + ".body"), "wb") as f:
            f.write(bb)
        open(os.path.join(self.incoming, name + ".done"), "wb").close()
        return seg_sha

    def test_identical_video_two_records_both_land(self):
        video = make_mp4(pad=b"same-pixels" * 8)
        s0 = self._job(0, None, video)
        self._job(1, s0, video)            # identical bytes, different seq
        send = FakeSend()
        n = vc.submit_spool(self.subcfg, once=True, send=send)
        self.assertEqual(n, 2)
        self.assertEqual(len(send.requests), 2)   # BOTH appended
        seqs = sorted(json.loads(r["artifact_content"])["segment_seq"]
                      for r in send.requests)
        self.assertEqual(seqs, [0, 1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
