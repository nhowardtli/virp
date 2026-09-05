#!/usr/bin/env python3
"""Tests for two capture-host defects found live on 2026-09-05.

1. SPOOL MODE. `sftp put` stamps the destination with the LOCAL file's
   mode. The capture units write segments and bodies 0600, so every job
   landed 0600 on the O-node spool. That spool's default ACL grants the
   submitter `u:virp:rwx` — but the POSIX ACL mask is taken from the
   mode's GROUP bits, so a 0600 file drives the mask to `---` and every
   named entry collapses to `#effective:---`. The submitter was locked
   out by the ACL that exists to admit it, and 26 Axis jobs wedged in
   incoming/ with EACCES. `ship()` now chmods each landed path 640 in
   the same all-or-nothing batch, before the .done marker.

2. CREDENTIAL LEAK. ffmpeg is handed the RTSP URL with credentials
   inline and echoes it back on stderr when a stream cannot be opened.
   Inherited stderr put that into the journal in cleartext, readable by
   the `adm` group, and a unit that cannot reach its camera reprinted it
   on every restart. stderr is now captured and the userinfo redacted.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "camera"))
import virp_camera as vc


def _acl_of(path):
    """(mask, {uid: effective}) parsed from getfacl, numeric."""
    out = subprocess.run(["getfacl", "-pn", path], capture_output=True)
    if out.returncode != 0:
        raise unittest.SkipTest("getfacl failed on %s" % path)
    mask, named = None, {}
    for line in out.stdout.decode().splitlines():
        line = line.strip()
        if line.startswith("mask::"):
            mask = line.split("::", 1)[1].split("\t")[0]
        elif line.startswith("user:") and not line.startswith("user::"):
            _, uid, rest = line.split(":", 2)
            perms = rest.split("\t")[0]
            eff = perms
            if "#effective:" in rest:
                eff = rest.split("#effective:", 1)[1].strip()
            named[uid] = eff
    return mask, named


class ShipModeTests(unittest.TestCase):
    """The chmod goes in the SAME batch as the puts and renames, after
    the renames, and always before the .done marker — otherwise a job
    could be visible to the submitter before it was readable by it."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.kh = os.path.join(self.tmp, "known_hosts")
        with open(self.kh, "w") as f:
            f.write("spool ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPINNED\n")
        self.batches = []

        class P:
            returncode = 0
            stderr = b""

        def fake_run(argv, **kw):
            self.batches.append(kw["input"].decode())
            return P()
        orig = vc.subprocess.run
        vc.subprocess.run = fake_run
        self.addCleanup(setattr, vc.subprocess, "run", orig)

    def _touch(self, name):
        p = os.path.join(self.tmp, name)
        open(p, "wb").close()
        return p

    def _ship_a_job(self, cited=None):
        ship = vc.sftp_ship("virp-capture@spool", ssh_key="/k",
                            known_hosts=self.kh)
        self.assertTrue(ship(self._touch("a.mp4"), self._touch("a.body"),
                             "job", cited=cited))

    def test_every_landed_path_is_chmod_640(self):
        self._ship_a_job(cited=[(self._touch("a.txt"), "validation.txt"),
                                (self._touch("a.der"), "leaf.der")])
        main = self.batches[0]
        for path in ("/incoming/job.mp4", "/incoming/job.body",
                     "/incoming/job.validation.txt", "/incoming/job.leaf.der"):
            self.assertIn("chmod 640 %s" % path, main,
                          "%s landed without a chmod" % path)

    def test_chmod_follows_its_rename_and_precedes_the_marker(self):
        self._ship_a_job()
        main = self.batches[0]
        self.assertLess(main.index("rename /incoming/job.body.part"),
                        main.index("chmod 640 /incoming/job.body"),
                        "chmod must name the FINAL path, after the rename")
        # The marker is its own later batch: all-or-nothing is preserved.
        self.assertNotIn(".done", main)
        self.assertIn("put %s/a.body.done /incoming/job.done" % self.tmp,
                      self.batches[1])

    def test_record_only_job_chmods_the_body_and_has_no_segment(self):
        """A camera_retention/1 job ships body + marker only. The body
        still has to be readable by the submitter."""
        ship = vc.sftp_ship("virp-capture@spool", ssh_key="/k",
                            known_hosts=self.kh)
        self.assertTrue(ship(None, self._touch("r.body"), "ret"))
        main = self.batches[0]
        self.assertIn("chmod 640 /incoming/ret.body", main)
        self.assertNotIn(".mp4", main)

    def test_a_failed_batch_ships_no_marker(self):
        class P:
            returncode = 1
            stderr = b"boom"
        vc.subprocess.run = lambda argv, **kw: (
            self.batches.append(kw["input"].decode()), P())[1]
        ship = vc.sftp_ship("virp-capture@spool", ssh_key="/k",
                            known_hosts=self.kh)
        self.assertFalse(ship(self._touch("b.mp4"), self._touch("b.body"),
                              "job2"))
        self.assertEqual(len(self.batches), 1)
        self.assertNotIn(".done", self.batches[0])


class SpoolAclMaskTests(unittest.TestCase):
    """The defect and the fix, against a real filesystem carrying the
    same default ACL the O-node spool does."""

    NAMED_UID = "65534"          # nobody: stands in for the submitter

    def setUp(self):
        if not shutil.which("setfacl") or not shutil.which("getfacl"):
            self.skipTest("acl tools not installed")
        # $HOME rather than /tmp: tmpfs often has no ACL support.
        self.tmp = tempfile.mkdtemp(dir=os.path.expanduser("~"))
        self.addCleanup(shutil.rmtree, self.tmp)
        if subprocess.run(["setfacl", "-d", "-m",
                           "u:%s:rwx" % self.NAMED_UID, self.tmp],
                          capture_output=True).returncode != 0:
            self.skipTest("filesystem does not support ACLs")

    def _land(self, name, mode):
        """A file as `sftp put` leaves it: created, then chmod-ed to the
        mode the client asked for."""
        p = os.path.join(self.tmp, name)
        open(p, "wb").close()
        os.chmod(p, mode)
        return p

    def test_0600_locks_the_submitter_out(self):
        """The defect. This is what 26 jobs looked like on 313."""
        mask, named = _acl_of(self._land("stuck.body", 0o600))
        self.assertEqual(mask, "---")
        self.assertEqual(named[self.NAMED_UID], "---",
                         "a 0600 file must reproduce the EACCES wedge")

    def test_640_restores_the_submitter_grant(self):
        """The fix: exactly the mode ship() now sends."""
        mask, named = _acl_of(self._land("fixed.body", 0o640))
        self.assertNotEqual(mask, "---", "the mask must come back")
        self.assertIn("r", named[self.NAMED_UID],
                      "the submitter must regain read")

    def test_640_grants_read_not_write_and_that_is_enough(self):
        """640 leaves the named entry `r--`, not `rw-`: the mask is taken
        from the mode's GROUP bits, so read is what 640 can give. It is
        sufficient — submit-spool reads the segment and the body, and the
        move into done/ is a rename, authorized by the DIRECTORY's perms.
        Pinned so a later change to 660 is a deliberate act, not a drift."""
        _, named = _acl_of(self._land("r.body", 0o640))
        self.assertEqual(named[self.NAMED_UID], "r--")
        _, named660 = _acl_of(self._land("rw.body", 0o660))
        self.assertEqual(named660[self.NAMED_UID], "rw-")


class StreamCredentialRedactionTests(unittest.TestCase):

    def test_userinfo_is_removed_and_the_host_survives(self):
        line = ("Error opening input file "
                "rtsp://admin:s3cr3t@10.0.0.34:554/Preview_01_sub.")
        got = vc.redact_stream_credentials(line)
        self.assertNotIn("s3cr3t", got)
        self.assertNotIn("admin", got)
        self.assertIn("rtsp://REDACTED@10.0.0.34:554/Preview_01_sub", got)

    def test_the_host_is_kept_because_it_is_the_diagnostic(self):
        """A unit dialling the wrong camera's address is found by reading
        this line; blanking the host would have hidden the live defect."""
        got = vc.redact_stream_credentials(
            "[rtsp @ 0x1] rtsp://admin:pw@10.0.0.37:554/x 401 Unauthorized")
        self.assertIn("10.0.0.37", got)
        self.assertNotIn("pw@", got)

    def test_credential_free_text_is_untouched(self):
        for line in ("rtsp://10.0.0.34:554/stream2",
                     "[in#0 @ 0xabc] Error opening input: 401 Unauthorized",
                     ""):
            self.assertEqual(vc.redact_stream_credentials(line), line)

    def test_every_occurrence_on_a_line_is_redacted(self):
        got = vc.redact_stream_credentials(
            "rtsp://a:b@h1/x and rtsp://c:d@h2/y")
        self.assertNotIn(":b@", got)
        self.assertNotIn(":d@", got)
        self.assertEqual(got.count("REDACTED"), 2)

    def test_pump_redacts_what_it_forwards(self):
        import io as _io

        class Out:
            def __init__(self): self.buf = []
            def write(self, s): self.buf.append(s)
            def flush(self): pass
        out = Out()
        pipe = _io.BytesIO(b"rtsp://admin:s3cr3t@h/s failed\nsecond line\n")
        vc._pump_redacted(pipe, out=out)
        joined = "".join(out.buf)
        self.assertNotIn("s3cr3t", joined)
        self.assertIn("REDACTED", joined)
        self.assertIn("second line", joined)

    def test_spawn_captures_stderr_rather_than_inheriting_it(self):
        """Inherited stderr is the leak. Pinning the pipe is the fix."""
        seen = {}

        class FakeProc:
            stderr = None

        def fake_popen(argv, **kw):
            seen.update(kw)
            return FakeProc()

        class FakeThread:
            def __init__(self, **kw): pass
            def start(self): pass
        orig_p, orig_t = vc.subprocess.Popen, vc.threading.Thread
        vc.subprocess.Popen = fake_popen
        vc.threading.Thread = lambda *a, **kw: FakeThread()
        self.addCleanup(setattr, vc.subprocess, "Popen", orig_p)
        self.addCleanup(setattr, vc.threading, "Thread", orig_t)
        vc._spawn_ffmpeg({"rtsp_url": "rtsp://admin:pw@h/s",
                          "workdir": "/tmp", "segment_time": 6.0})
        self.assertEqual(seen.get("stderr"), subprocess.PIPE)


if __name__ == "__main__":
    unittest.main()
