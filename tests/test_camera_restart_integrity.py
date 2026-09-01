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
        # keyed on record identity: content + capture end (Task 1)
        key = vc.shipped_key(sha, state["last_end_ns"])
        self.assertIn(key, shipped)
        rec = shipped[key]
        self.assertEqual(rec["segment_seq"], 0)
        self.assertEqual(rec["capture_end_utc_ns"], state["last_end_ns"])
        with open(os.path.join(self.cfg["outbox"],
                               rec["shipped_as"] + ".handoff.json")) as f:
            self.assertEqual(rec["body_sha256"], json.load(f)["body_sha256"])

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
        self.assertEqual(list(shipped), [vc.shipped_key("aa" * 32, 1)])

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


class ScriptedProc:
    """Popen stand-in whose poll() runs a per-call script: each entry is
    (returncode_or_None, side_effect_callable_or_None). The last entry
    repeats."""

    def __init__(self, script):
        self.script = list(script)
        self.n = 0

    def poll(self):
        i = min(self.n, len(self.script) - 1)
        self.n += 1
        rc, effect = self.script[i]
        if effect:
            effect()
        return rc

    def wait(self, timeout=None):
        return 0

    def terminate(self):
        pass

    def kill(self):
        pass


class ContentIdentityTests(unittest.TestCase):
    """Fix B: the silent-drop defect. In the 2026-08-24 record, a
    restart drained stale workdir files under names seg_000000..11,
    marked those NAMES handled, and then silently skipped ~72 s of new
    footage ffmpeg wrote under the same names — the 69.1 s gap:null hole
    before seg 77. Identity must be content, never filename."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.sk_path, self.pk_path = make_keypair(self.tmp)
        self.cfg = restart_cfg(self.tmp, self.sk_path, self.pk_path)
        os.makedirs(self.cfg["workdir"])
        os.makedirs(self.cfg["outbox"])

    def _write(self, name, data):
        p = os.path.join(self.cfg["workdir"], name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_reused_name_old_bytes_skipped_new_footage_lands(self):
        old_a = make_mp4(pad=b"old-a" * 40)
        old_b = make_mp4(pad=b"old-b" * 40)
        new = make_mp4(pad=b"new-frames" * 40)
        # a prior run shipped old_a/old_b (durable checkpoint says so),
        # but died before removing them from the workdir. The checkpoint
        # records name the FILES: their capture end is the file mtime
        # (Fix E), so the fixture pins the mtimes to what was recorded.
        for i, data in enumerate((old_a, old_b)):
            sha = hashlib.sha256(data).hexdigest()
            vc.checkpoint_append(self.cfg["checkpoint_path"],
                                 {"segment_seq": i, "segment_sha256": sha,
                                  "capture_end_utc_ns": 10 ** 18 + i,
                                  "shipped_as": "%06d.%s" % (i, sha)})
        for i, name in enumerate(("seg_000000.mp4", "seg_000001.mp4")):
            p = self._write(name, (old_a, old_b)[i])
            os.utime(p, ns=(10 ** 18 + i, 10 ** 18 + i))

        # the restarted ffmpeg renumbers from seg_000000 and reuses the
        # name for NEW footage mid-run
        proc = ScriptedProc([
            (None, None), (None, None),
            (None, lambda: self._write("seg_000000.mp4", new)),
            (None, None), (None, None),
            (0, None),
        ])
        ship = ShipRecorder()
        vc.run_live(self.cfg, ship, poll_s=0, _spawn=lambda cfg: proc)

        # exactly one attestation: the NEW footage — the stale bytes were
        # not replayed, and the reused name did not shadow the new bytes
        self.assertEqual(len(ship.calls), 1)
        body = json.loads(ship.calls[0]["body_bytes"])
        self.assertEqual(body["segment_sha256"],
                         hashlib.sha256(new).hexdigest())
        self.assertEqual(body["segment_seq"], 2)

    def test_growing_open_segment_not_attested_until_finalized(self):
        full = make_mp4(pad=b"grow" * 40)
        p = self._write("seg_000000.mp4", full[:40])   # open: no moov yet
        proc = ScriptedProc([
            (None, None), (None, None), (None, None),
            (None, lambda: self._write("seg_000000.mp4", full)),
            (0, None),
        ])
        ship = ShipRecorder()
        vc.run_live(self.cfg, ship, poll_s=0, _spawn=lambda cfg: proc)
        self.assertEqual(len(ship.calls), 1)
        body = json.loads(ship.calls[0]["body_bytes"])
        self.assertEqual(body["segment_sha256"],
                         hashlib.sha256(full).hexdigest())

    def test_shipped_segment_leaves_the_workdir(self):
        # once attested+shipped (checkpoint durable), the workdir copy is
        # removed: nothing is left for a later run to mistake for new
        self._write("seg_000000.mp4", make_mp4(pad=b"leave" * 30))
        ship = ShipRecorder()
        vc.run_live(self.cfg, ship, _spawn=lambda cfg: FakeProc())
        self.assertEqual(len(ship.calls), 1)
        self.assertEqual(
            [n for n in os.listdir(self.cfg["workdir"])
             if n.endswith(".mp4")], [])


class ReconcileTests(unittest.TestCase):
    """Fix C: startup workdir reconciliation. Whatever a previous run
    left behind — attested residue, closed-but-never-shipped footage, an
    unfinalized partial — the next run settles it by content BEFORE new
    capture begins, so restarts of either kind (graceful or hard kill)
    produce zero duplicates and zero drops. The committed shutdown
    handler is correct and unchanged; the graceful-versus-hard-kill
    replay asymmetry in the 2026-08-24 record was an artifact of
    uncommitted WIP, so these tests assert the SAME invariants for
    both endings."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.sk_path, self.pk_path = make_keypair(self.tmp)
        self.cfg = restart_cfg(self.tmp, self.sk_path, self.pk_path)
        os.makedirs(self.cfg["workdir"])
        os.makedirs(self.cfg["outbox"])

    def _write(self, name, data):
        p = os.path.join(self.cfg["workdir"], name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def _shas(self, ship):
        return [json.loads(c["body_bytes"])["segment_sha256"]
                for c in ship.calls]

    def _bodies(self, ship):
        return [json.loads(c["body_bytes"]) for c in ship.calls]

    def test_graceful_restart_zero_duplicates(self):
        # modeled on run B: full segments then a truncated final segment
        # the shutdown handler finalized and drained (1.067 s in the
        # record), then a restart where ffmpeg renumbers from 000000
        self._write("seg_000000.mp4", make_mp4(pad=b"b7" * 64))
        self._write("seg_000001.mp4", make_mp4(pad=b"b8" * 64))
        self._write("seg_000002.mp4",
                    make_mp4(duration_s=1.067, pad=b"b9" * 16))
        ship1 = ShipRecorder()
        vc.run_live(self.cfg, ship1, _spawn=lambda cfg: FakeProc())
        self.assertEqual(len(ship1.calls), 3)

        new = make_mp4(pad=b"c-run" * 40)
        # the restarted ffmpeg renumbers from seg_000000 and captures new
        # footage mid-run (a pre-existing file would rightly be settled
        # as residue of the PREVIOUS run and carry no gap)
        proc = ScriptedProc([
            (None, lambda: self._write("seg_000000.mp4", new)),
            (None, None), (None, None),
            (0, None),
        ])
        ship2 = ShipRecorder()
        vc.run_live(self.cfg, ship2, poll_s=0, _spawn=lambda cfg: proc)

        all_shas = self._shas(ship1) + self._shas(ship2)
        self.assertEqual(len(all_shas), len(set(all_shas)),
                         "duplicate segment_sha256 across a graceful "
                         "restart: %s" % all_shas)
        b = self._bodies(ship2)[0]
        self.assertEqual(b["segment_sha256"], hashlib.sha256(new).hexdigest())
        self.assertEqual(b["gap"]["reason"], "driver-restart")
        self.assertEqual(b["gap"]["after_seq"], 2)
        # prev cites the truncated final segment of the previous run
        self.assertEqual(b["prev_segment_sha256"], self._shas(ship1)[-1])

    def test_hard_kill_residue_settled_before_new_capture(self):
        # modeled on run D's ending: the process died leaving in the
        # workdir (a) a closed segment that never shipped and (b) an
        # unfinalized partial (no moov). The record for that shape must
        # be: residue attested FIRST (capture order == seq order — the
        # record's ten-minute ingest inversion is the counterexample),
        # the partial logged+removed, the restart gap riding the first
        # NEW segment, zero duplicates, zero drops.
        self._write("seg_000000.mp4", make_mp4(pad=b"d0" * 64))
        ship1 = ShipRecorder()
        vc.run_live(self.cfg, ship1, _spawn=lambda cfg: FakeProc())
        self.assertEqual(len(ship1.calls), 1)       # seq 0 shipped

        # the hard kill's leavings:
        residue = make_mp4(pad=b"d1-closed-never-shipped" * 8)
        self._write("seg_000001.mp4", residue)      # closed, unshipped
        partial_path = self._write("seg_000002.mp4",
                                   make_mp4(pad=b"d2" * 64)[:48])

        new = make_mp4(pad=b"e-run" * 40)
        proc = ScriptedProc([
            (None, None), (None, None),
            (None, lambda: self._write("seg_000000.mp4", new)),
            (None, None), (None, None),
            (0, None),
        ])
        ship2 = ShipRecorder()
        vc.run_live(self.cfg, ship2, poll_s=0, _spawn=lambda cfg: proc)

        bodies = self._bodies(ship2)
        shas = [b["segment_sha256"] for b in bodies]
        # zero drops: both the residue and the new footage landed
        self.assertIn(hashlib.sha256(residue).hexdigest(), shas)
        self.assertIn(hashlib.sha256(new).hexdigest(), shas)
        # zero duplicates across both runs
        all_shas = self._shas(ship1) + shas
        self.assertEqual(len(all_shas), len(set(all_shas)))
        # residue settled BEFORE new capture: seq order == capture order
        self.assertEqual(shas[0], hashlib.sha256(residue).hexdigest())
        self.assertEqual([b["segment_seq"] for b in bodies], [1, 2])
        # the restart gap rides the first NEW segment, not the residue
        self.assertIsNone(bodies[0]["gap"])
        self.assertEqual(bodies[1]["gap"]["reason"], "driver-restart")
        self.assertEqual(bodies[1]["gap"]["after_seq"], 1)
        # prev chain: residue cites run 1, new cites residue
        self.assertEqual(bodies[0]["prev_segment_sha256"],
                         self._shas(ship1)[-1])
        self.assertEqual(bodies[1]["prev_segment_sha256"], shas[0])
        # the unfinalized partial is gone: removed at reconcile, lost
        # honestly, never attested
        self.assertFalse(os.path.exists(partial_path))
        self.assertNotIn(hashlib.sha256(
            make_mp4(pad=b"d2" * 64)[:48]).hexdigest(), shas)

    def test_staged_outbox_pair_reshipped_byte_identical(self):
        # crash window: the body was built, signed and staged in the
        # outbox, but the process died around the ship. Reconcile must
        # re-ship those EXACT bytes (a re-offer is then a spool-side
        # no-op), not build and sign a fresh body.
        p = self._write("seg_000000.mp4", make_mp4(pad=b"staged" * 20))
        with self.assertRaises(vc.SubmitError):
            vc.process_live_segment(p, self.cfg, None, None,
                                    ShipRecorder(fail_on=0))
        staged_bodies = [n for n in os.listdir(self.cfg["outbox"])
                         if n.endswith(".body")]
        self.assertEqual(len(staged_bodies), 1)
        with open(os.path.join(self.cfg["outbox"], staged_bodies[0]),
                  "rb") as f:
            staged = f.read()

        ship = ShipRecorder()
        vc.run_live(self.cfg, ship, _spawn=lambda cfg: FakeProc())
        self.assertEqual(len(ship.calls), 1)
        self.assertEqual(ship.calls[0]["body_bytes"], staged)
        # and the checkpoint now covers it, under the record's identity
        shipped = vc.checkpoint_load(self.cfg["checkpoint_path"])
        sb = json.loads(staged)
        self.assertIn(vc.shipped_key(sb["segment_sha256"],
                                     sb["capture_end_utc_ns"]), shipped)

    def test_unshippable_residue_refuses_to_start(self):
        # unshipped residue + a dead spool: starting capture would bury
        # real footage under new work — refuse loudly instead
        self._write("seg_000000.mp4", make_mp4(pad=b"stuck" * 20))
        with self.assertRaises(vc.SubmitError):
            vc.run_live(self.cfg, ShipRecorder(fail_on=0),
                        _spawn=lambda cfg: FakeProc())


# The hole between segs 76 and 77 of camera:tapo-c100:2026-08-24:
# capture_start 1787614325523357095 minus capture_end 1787614256399015562.
# It carried gap: null. Under Fix D it must not.
SEG77_HOLE_NS = 1787614325523357095 - 1787614256399015562


class ContinuityGapTests(unittest.TestCase):
    """Fix D: a gap record comes from capture-time continuity, not only
    from restarts. The 69.1 s hole at seg 77 must be flagged; healthy
    ~6 s boundaries (which jitter within about ±0.5 s in the record)
    must not."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.sk_path, self.pk_path = make_keypair(self.tmp)
        self.cfg = restart_cfg(self.tmp, self.sk_path, self.pk_path)
        os.makedirs(self.cfg["workdir"])
        os.makedirs(self.cfg["outbox"])

    def _seg(self, name, pad=b"gap" * 40, duration_s=10.0):
        p = os.path.join(self.cfg["workdir"], name)
        with open(p, "wb") as f:
            f.write(make_mp4(duration_s=duration_s, pad=pad))
        return p

    def _state_ending(self, end_ns, seq=76):
        return {"camera_id": "tapo-c100", "segment_seq": seq,
                "last_segment_sha256": "aa" * 32,
                "last_session_id": "camera:tapo-c100:2026-08-24",
                "last_end_ns": end_ns}

    def _attest(self, path, state, gap=None):
        ship = ShipRecorder()
        vc.process_live_segment(path, self.cfg, state, gap, ship)
        return json.loads(ship.calls[0]["body_bytes"])

    def test_69s_hole_produces_continuity_gap(self):
        p = self._seg("seg_000000.mp4")
        # place the predecessor's capture_end exactly SEG77_HOLE_NS
        # before this segment's capture_start
        dur_ns = int(vc.mp4_duration_s(p) * 1e9)
        # same arithmetic the driver uses: start = end - duration
        end_ns = os.stat(p).st_mtime_ns
        body = self._attest(p, self._state_ending(
            end_ns - dur_ns - SEG77_HOLE_NS))
        self.assertIsNotNone(body["gap"], "69.1 s capture hole was not "
                                          "flagged (the seg-77 defect)")
        self.assertEqual(body["gap"]["reason"], "capture-discontinuity")
        self.assertEqual(body["gap"]["after_seq"], 76)

    def test_normal_boundary_no_gap(self):
        p = self._seg("seg_000000.mp4")
        dur_ns = int(vc.mp4_duration_s(p) * 1e9)
        end_ns = os.stat(p).st_mtime_ns
        # predecessor ended 0.3 s before this capture began — the normal
        # jitter of a healthy 6 s cadence
        body = self._attest(p, self._state_ending(
            end_ns - dur_ns - int(0.3e9)))
        self.assertIsNone(body["gap"])

    def test_restart_gap_takes_precedence(self):
        # a pending driver-restart gap already disclaims coverage; the
        # hole does not demote or duplicate it
        p = self._seg("seg_000000.mp4")
        dur_ns = int(vc.mp4_duration_s(p) * 1e9)
        end_ns = os.stat(p).st_mtime_ns
        body = self._attest(
            p, self._state_ending(end_ns - dur_ns - SEG77_HOLE_NS),
            gap={"reason": "driver-restart", "after_seq": 76})
        self.assertEqual(body["gap"]["reason"], "driver-restart")

    def test_replay_path_flags_capture_hole(self):
        # replay stamps from file mtime; a 69 s hole between the files'
        # capture windows must be flagged there too
        rdir = os.path.join(self.tmp, "replay")
        os.makedirs(rdir)
        a = os.path.join(rdir, "seg_000.mp4")
        b = os.path.join(rdir, "seg_001.mp4")
        for p, pad in ((a, b"ra" * 40), (b, b"rb" * 40)):
            with open(p, "wb") as f:
                f.write(make_mp4(duration_s=10.0, pad=pad))
        t0 = os.stat(a).st_mtime_ns
        # b's capture window starts exactly SEG77_HOLE_NS after a's ends:
        # start_b = mtime_b - dur = t0 + SEG77_HOLE_NS
        os.utime(b, ns=(t0, t0 + SEG77_HOLE_NS + int(10e9)))
        from test_camera_driver import make_cfg
        cfg = make_cfg(self.tmp, self.sk_path, self.pk_path)
        send = FakeSend()
        vc.run_replay(rdir, cfg, send=send)
        bodies = [json.loads(r["artifact_content"])
                  for r in send.requests]
        self.assertEqual(len(bodies), 2)
        self.assertIsNone(bodies[0]["gap"])
        self.assertEqual(bodies[1]["gap"],
                         {"reason": "capture-discontinuity",
                          "after_seq": 0})


class NoRestampTests(unittest.TestCase):
    """Fix E: the capture window is fixed at capture time — a function
    of the segment file (finalize mtime + moov duration) — and is
    immutable thereafter. Late submission keeps the original window
    exactly; a re-offer rebuilds the byte-identical signed body, so
    the spool's body-keyed dedup catches every duplicate. (Both replay
    incidents in the 2026-08-24 record presented old media as new
    capture moments because stamps were taken at processing time.)"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.sk_path, self.pk_path = make_keypair(self.tmp)
        self.cfg = restart_cfg(self.tmp, self.sk_path, self.pk_path)
        os.makedirs(self.cfg["workdir"])
        os.makedirs(self.cfg["outbox"])

    def test_late_submission_keeps_exact_capture_window(self):
        # a segment that closed long ago and is only submitted now must
        # carry its ORIGINAL window, to the nanosecond. Values from the
        # record: seg 12 of the damaged session ended at
        # 1787611801697990689 with duration 6.0 — its clone seg 19
        # claimed 1787612005299300617 instead.
        end_ns = 1787611801697990689
        p = os.path.join(self.cfg["workdir"], "seg_000000.mp4")
        with open(p, "wb") as f:
            f.write(make_mp4(duration_s=6.0, pad=b"late" * 40))
        os.utime(p, ns=(end_ns, end_ns))
        ship = ShipRecorder()
        vc.process_live_segment(p, self.cfg, None, None, ship)
        body = json.loads(ship.calls[0]["body_bytes"])
        self.assertEqual(body["capture_end_utc_ns"], end_ns)
        self.assertEqual(body["capture_start_utc_ns"],
                         end_ns - int(6.0 * 1e9))
        self.assertEqual(body["duration_s"], 6.0)
        self.assertEqual(body["time_source"], "host-clock")

    def test_reoffer_rebuilds_byte_identical_body(self):
        # crash between ship-ack and checkpoint: the segment is offered
        # again. The rebuilt body must be the SAME bytes — same window,
        # same seq, same signature — so the spool-side dedup (keyed on
        # body sha) is exact, and duplicates are structurally impossible.
        p = os.path.join(self.cfg["workdir"], "seg_000000.mp4")
        with open(p, "wb") as f:
            f.write(make_mp4(pad=b"again" * 30))
        ship1, ship2 = ShipRecorder(), ShipRecorder()
        vc.process_live_segment(p, self.cfg, None, None, ship1)
        vc.process_live_segment(p, self.cfg, None, None, ship2)
        self.assertEqual(ship1.calls[0]["body_bytes"],
                         ship2.calls[0]["body_bytes"])

    def test_replay_never_stamps_host_clock(self):
        # the replay path's only honest time source is the file mtime,
        # stated as such; the old host-clock else-branch is gone
        rdir = os.path.join(self.tmp, "replay")
        os.makedirs(rdir)
        p = os.path.join(rdir, "seg_000.mp4")
        with open(p, "wb") as f:
            f.write(make_mp4(pad=b"rp" * 40))
        end_ns = 1787609824949255966          # run A's mtime, from the record
        os.utime(p, ns=(end_ns, end_ns))
        from test_camera_driver import make_cfg
        cfg = make_cfg(self.tmp, self.sk_path, self.pk_path)
        send = FakeSend()
        vc.run_replay(rdir, cfg, send=send)
        body = json.loads(send.requests[0]["artifact_content"])
        self.assertEqual(body["time_source"], "file-mtime")
        self.assertEqual(body["capture_end_utc_ns"], end_ns)


class InstanceLockTests(unittest.TestCase):
    """Fix F: one driver instance per camera/spool. flock-based, so a
    stale lock (unclean exit) can never wedge the next start — the lock
    dies with its holder — and the recovery is logged."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.lock = os.path.join(self.tmp, "instance.lock")

    def test_second_instance_refused_then_recoverable(self):
        fd = vc.acquire_instance_lock(self.lock, "live")
        with self.assertRaises(SystemExit) as cm:
            vc.acquire_instance_lock(self.lock, "live")
        self.assertIn("another instance", str(cm.exception))
        self.assertIn(str(os.getpid()), str(cm.exception))
        vc.release_instance_lock(fd)
        fd2 = vc.acquire_instance_lock(self.lock, "live")
        vc.release_instance_lock(fd2)

    def test_stale_lock_recovered_without_intervention_and_logged(self):
        # an unclean exit leaves the pid behind but no live flock; the
        # next start must recover on its own and say so
        with open(self.lock, "w") as f:
            f.write("54321\n")
        import io
        err, real = io.StringIO(), sys.stderr
        sys.stderr = err
        try:
            fd = vc.acquire_instance_lock(self.lock, "live")
        finally:
            sys.stderr = real
        self.assertIn("recovered stale", err.getvalue())
        self.assertIn("54321", err.getvalue())
        vc.release_instance_lock(fd)
        # clean release empties the pid: the NEXT start logs no recovery
        err2 = io.StringIO()
        sys.stderr = err2
        try:
            fd2 = vc.acquire_instance_lock(self.lock, "live")
        finally:
            sys.stderr = real
        self.assertNotIn("recovered", err2.getvalue())
        vc.release_instance_lock(fd2)

    def test_run_live_refuses_second_instance(self):
        sk_path, pk_path = make_keypair(self.tmp)
        cfg = restart_cfg(self.tmp, sk_path, pk_path)
        cfg["lock_path"] = self.lock
        os.makedirs(cfg["workdir"])
        os.makedirs(cfg["outbox"])
        fd = vc.acquire_instance_lock(self.lock, "other-driver")
        try:
            with self.assertRaises(SystemExit):
                vc.run_live(cfg, ShipRecorder(),
                            _spawn=lambda cfg: FakeProc())
        finally:
            vc.release_instance_lock(fd)
        # and with the lock free, the same cfg runs (and releases: a
        # second run afterwards also succeeds)
        vc.run_live(cfg, ShipRecorder(), _spawn=lambda cfg: FakeProc())
        vc.run_live(cfg, ShipRecorder(), _spawn=lambda cfg: FakeProc())



class RecordIdentityTests(unittest.TestCase):
    """Sep 1 review, Task 1: attestation identity is the RECORD, not the
    content hash alone. Two closed segments with byte-identical content
    (a static scene, a test pattern, a camera that repeats its idle
    frame) are two segments of footage and must ship as two records with
    consecutive sequence numbers. Before this fix checkpoint_load,
    the live loop and reconcile all keyed on segment_sha256 only, so the
    second identical segment was deleted as "already attested" — a
    silent drop dressed up as a dedup. What dedup MUST still catch is the
    SAME FILE seen again after a crash between checkpoint_append and the
    workdir unlink: same bytes AND the same capture end (the file's
    mtime, immutable across re-offers per Fix E)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.sk_path, self.pk_path = make_keypair(self.tmp)
        self.cfg = restart_cfg(self.tmp, self.sk_path, self.pk_path)
        os.makedirs(self.cfg["workdir"])
        os.makedirs(self.cfg["outbox"])

    def _write(self, name, data, mtime_ns=None):
        p = os.path.join(self.cfg["workdir"], name)
        with open(p, "wb") as f:
            f.write(data)
        if mtime_ns is not None:
            os.utime(p, ns=(mtime_ns, mtime_ns))
        return p

    def _bodies(self, ship):
        return [json.loads(c["body_bytes"]) for c in ship.calls]

    def test_two_identical_closed_segments_ship_as_two_records(self):
        # reconcile path: both files closed and present at startup,
        # different names, different mtimes, identical bytes
        same = make_mp4(pad=b"static-scene" * 20)
        t0 = 10 ** 18
        self._write("seg_000000.mp4", same, t0)
        self._write("seg_000001.mp4", same, t0 + 6 * 10 ** 9)
        ship = ShipRecorder()
        vc.run_live(self.cfg, ship, _spawn=lambda cfg: FakeProc())
        bodies = self._bodies(ship)
        self.assertEqual(len(bodies), 2,
                         "second identical segment was dropped as "
                         "'already attested'")
        self.assertEqual([b["segment_seq"] for b in bodies], [0, 1])
        sha = hashlib.sha256(same).hexdigest()
        self.assertEqual([b["segment_sha256"] for b in bodies], [sha, sha])
        self.assertEqual([b["capture_end_utc_ns"] for b in bodies],
                         [t0, t0 + 6 * 10 ** 9])
        # two distinct records in the durable checkpoint, and nothing
        # left in the workdir
        shipped = vc.checkpoint_load(self.cfg["checkpoint_path"])
        self.assertEqual(sorted(r["segment_seq"] for r in shipped.values()),
                         [0, 1])
        self.assertEqual(
            [n for n in os.listdir(self.cfg["workdir"]) if n.endswith(".mp4")],
            [])

    def test_identical_segment_arriving_live_is_a_new_record(self):
        # live-loop path: seq 0 ships at startup (reconcile), then ffmpeg
        # closes a NEW file with the same bytes mid-run
        same = make_mp4(pad=b"idle-frame" * 24)
        t0 = 10 ** 18
        self._write("seg_000000.mp4", same, t0)
        proc = ScriptedProc([
            (None, None), (None, None),
            (None, lambda: self._write("seg_000001.mp4", same,
                                       t0 + 6 * 10 ** 9)),
            (None, None), (None, None),
            (0, None),
        ])
        ship = ShipRecorder()
        vc.run_live(self.cfg, ship, poll_s=0, _spawn=lambda cfg: proc)
        bodies = self._bodies(ship)
        self.assertEqual(len(bodies), 2,
                         "identical live segment was skipped")
        self.assertEqual([b["segment_seq"] for b in bodies], [0, 1])
        self.assertEqual(bodies[1]["prev_segment_sha256"],
                         bodies[0]["segment_sha256"])

    def test_same_file_reseen_after_restart_is_not_reshipped(self):
        # crash window: checkpoint_append succeeded, the workdir unlink
        # did not. The next start sees the SAME file (same bytes, same
        # mtime) and must settle it as residue, not ship it again.
        data = make_mp4(pad=b"once" * 32)
        p = self._write("seg_000000.mp4", data, 10 ** 18)
        ship1 = ShipRecorder()
        vc.process_live_segment(p, self.cfg, None, None, ship1)
        self.assertEqual(len(ship1.calls), 1)
        self.assertTrue(os.path.exists(p))       # no unlink: the crash
        ship2 = ShipRecorder()
        state = vc.run_live(self.cfg, ship2, _spawn=lambda cfg: FakeProc())
        self.assertEqual(ship2.calls, [], "same file re-shipped after "
                                          "restart (dedup broken)")
        self.assertFalse(os.path.exists(p))
        self.assertEqual(state["segment_seq"], 0)
        self.assertEqual(
            len(vc.checkpoint_load(self.cfg["checkpoint_path"])), 1)

    def test_same_file_reseen_live_is_skipped(self):
        # the live-loop guard for the same window: a checkpointed file
        # that reappears under a reused name with the same bytes AND the
        # same capture end is the same file, not new footage
        data = make_mp4(pad=b"twice" * 32)
        p = self._write("seg_000000.mp4", data, 10 ** 18)
        vc.process_live_segment(p, self.cfg, None, None, ShipRecorder())
        os.unlink(p)
        proc = ScriptedProc([
            (None, None), (None, None),
            (None, lambda: self._write("seg_000000.mp4", data, 10 ** 18)),
            (None, None), (None, None),
            (0, None),
        ])
        ship = ShipRecorder()
        vc.run_live(self.cfg, ship, poll_s=0, _spawn=lambda cfg: proc)
        self.assertEqual(ship.calls, [])
        self.assertEqual(
            [n for n in os.listdir(self.cfg["workdir"]) if n.endswith(".mp4")],
            [])



class SpoolHostKeyPinningTests(unittest.TestCase):
    """Sep 1 review, Task 4a: the capture host must never accept the spool
    host's key on first contact. StrictHostKeyChecking=yes against a
    provisioned known_hosts file, or no ship function at all."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.kh = os.path.join(self.tmp, "known_hosts")
        with open(self.kh, "w") as f:
            f.write("spool ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPINNED\n")

    def _capture_argv(self):
        calls = []

        class P:
            returncode = 0
            stderr = b""

        def fake_run(argv, **kw):
            calls.append(list(argv))
            return P()
        orig = vc.subprocess.run
        vc.subprocess.run = fake_run
        self.addCleanup(setattr, vc.subprocess, "run", orig)
        return calls

    def test_refuses_without_a_known_hosts_file(self):
        with self.assertRaises(ValueError):
            vc.sftp_ship("virp-capture@spool")
        with self.assertRaises(ValueError):
            vc.sftp_ship("virp-capture@spool",
                         known_hosts=os.path.join(self.tmp, "absent"))

    def test_sftp_pins_the_host_key(self):
        calls = self._capture_argv()
        ship = vc.sftp_ship("virp-capture@spool", ssh_key="/k",
                            known_hosts=self.kh)
        seg = os.path.join(self.tmp, "a.mp4")
        body = os.path.join(self.tmp, "a.body")
        open(seg, "wb").close()
        open(body, "wb").close()
        self.assertTrue(ship(seg, body, "job"))
        self.assertTrue(calls)
        for argv in calls:
            opts = [argv[i + 1] for i, a in enumerate(argv) if a == "-o"]
            self.assertIn("StrictHostKeyChecking=yes", opts, argv)
            self.assertIn("UserKnownHostsFile=%s" % self.kh, opts, argv)
            self.assertNotIn("StrictHostKeyChecking=accept-new", opts)
            self.assertNotIn("StrictHostKeyChecking=no", opts)


class ArtifactWritebackDurabilityTests(unittest.TestCase):
    """Sep 1 review, Task 4b: the content-addressed segment copy is
    fsynced (file, then directory entry) BEFORE the chain append, so a
    signed entry never commits to bytes this host may not have."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.sk_path, self.pk_path = make_keypair(self.tmp)
        self.cfg = live_cfg(self.tmp, self.sk_path, self.pk_path)
        self.incoming = os.path.join(self.tmp, "spool", "incoming")
        os.makedirs(self.incoming)
        self.data_dir = os.path.join(self.tmp, "onode-data")
        self.subcfg = {"data_dir": self.data_dir, "sock": "/nonexistent",
                       "incoming": self.incoming,
                       "done": os.path.join(self.tmp, "spool", "done"),
                       "interval": 0,
                       "db": os.path.join(self.tmp, "nonexistent.db")}

    def test_segment_copy_is_durable_before_the_append(self):
        seg_bytes = make_mp4(pad=b"durable" * 16)
        seg_sha = hashlib.sha256(seg_bytes).hexdigest()
        nosig = vc.build_body("tapo-c100", "tapo-c100", 0, seg_sha, None,
                              len(seg_bytes), 5.0, 0, 10 ** 18,
                              "host-clock", "live", None, self.cfg["key_id"])
        body_bytes, _ = vc.producer_sign(self.cfg["sk"], nosig)
        seg = os.path.join(self.incoming, "j.mp4")
        body = os.path.join(self.incoming, "j.body")
        with open(seg, "wb") as f:
            f.write(seg_bytes)
        with open(body, "wb") as f:
            f.write(body_bytes)

        events = []
        real_fsync = os.fsync

        def rec_fsync(fd):
            try:
                target = os.readlink("/proc/self/fd/%d" % fd)
            except OSError:
                target = "?"
            events.append(("fsync", target))
            return real_fsync(fd)
        os.fsync = rec_fsync
        self.addCleanup(setattr, os, "fsync", real_fsync)

        inner = FakeSend()

        def send(request, sock_path=None):
            events.append(("send", None))
            return inner(request, sock_path)

        self.assertTrue(vc.submit_one(self.subcfg, "j", seg, body, send=send))
        art_dir = os.path.join(self.data_dir, "artifacts")
        art = os.path.join(art_dir, seg_sha + ".mp4")
        self.assertTrue(os.path.exists(art))
        kinds = [e[0] for e in events]
        self.assertIn("send", kinds)
        before = events[:kinds.index("send")]
        synced = [t for k, t in before if k == "fsync"]
        self.assertTrue(any(t.startswith(art) for t in synced),
                        "segment copy not fsynced before append: %s" % events)
        self.assertIn(art_dir, synced,
                      "artifact directory not fsynced before append: %s"
                      % events)
        # and the temp name is gone
        self.assertFalse(os.path.exists(art + ".tmp"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
