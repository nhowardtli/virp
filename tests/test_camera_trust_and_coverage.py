#!/usr/bin/env python3
"""Fail-closed tests for the camera driver's trust roots, and tests for
the two axes an intact chain cannot answer on its own.

ONE INVARIANT holds this file together:

    NO PREREQUISITE FAILURE MAY INCREASE THE APPARENT STRENGTH OF THE
    VERDICT.

Everything a verifier needs before it can judge evidence — a pinned
public key, a scope that matches something, a schema it understands, a
declared cadence — is a prerequisite. When one cannot be established the
only permitted outcomes are a loud abort and a nonzero exit. Reporting
"clean" is never one of them, and neither is quietly checking less.

The fixtures under tests/fixtures/ are REAL history, frozen verbatim
from the live chain (2553 entries, 5 sessions, 3 producer keys), not
synthetic vectors:
  - the 7 Aug-24 Tapo bodies signed by a2d2dc0fac250b722c6a77c87be9e341,
    a producer identity whose public key was nearly lost;
  - the 18 byte-identical duplicate pairs left by the producer replay
    defect fixed 2026-08-25.
"""

import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "camera"))
import virp_camera as vc
from test_camera_driver import make_keypair, fake_chain_db

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

POLICY_6S = {"nominal_segment_s": 6.0, "jitter_s": 2.0,
             "max_unexplained_gap_s": 0.0}


def load_fixture(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return json.load(f)


def run_main(argv):
    """(exit_code, stdout, stderr) for one CLI invocation."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = vc.main(argv)
        except SystemExit as e:                     # argparse / raise SystemExit
            rc = e.code if isinstance(e.code, int) else 2
    return rc, out.getvalue(), err.getvalue()


_UNSET = object()


class SignedChain:
    """A throwaway chain DB of producer-signed bodies, built the way the
    driver builds them (no re-serialization anywhere)."""

    def __init__(self, tmp, camera="cam-a"):
        self.tmp = tmp
        self.camera = camera
        keydir = tempfile.mkdtemp(dir=tmp)
        self.sk_path, self.pk_path = make_keypair(keydir)
        self.sk = vc.producer_load_sk(self.sk_path)
        with open(self.pk_path, "rb") as f:
            self.key_id = vc.producer_key_id(f.read())
        self.rows = []
        self.seq = -1
        self.prev = None
        self.end_ns = 1_700_000_000_000_000_000

    def add(self, policy=POLICY_6S, gap=None, hole_s=0.0, duration_s=6.0,
            seg_sha=None, camera=None, bump_seq=1, raw_gap=_UNSET,
            sensor=None):
        """raw_gap substitutes the gap AFTER build_body, bypassing the
        emission guard — the only way to produce the signed-but-invalid
        record the pre-hardening producer could emit.

        sensor promotes the record to the version that carries a
        sensor_signature (/5), which is how a chain of CURRENT records
        is built here rather than of /2 ones."""
        cam = camera or self.camera
        self.seq += bump_seq
        start_ns = self.end_ns + int(hole_s * 1e9)
        end_ns = start_ns + int(duration_s * 1e9)
        sha = seg_sha or hashlib.sha256(
            ("seg-%s-%d" % (cam, self.seq)).encode()).hexdigest()
        nosig = vc.build_body(cam, cam, self.seq, sha, self.prev, 1000,
                              duration_s, start_ns, end_ns, "host-clock",
                              "live", None if raw_gap is not _UNSET else gap,
                              self.key_id, policy, sensor)
        if raw_gap is not _UNSET:
            nosig["gap"] = raw_gap
        body_bytes, body = vc.producer_sign(self.sk, nosig)
        content = body_bytes.decode("ascii")
        ahash = hashlib.sha256(body_bytes).hexdigest()
        aid = "camseg:%s:%d:%d" % (cam, self.seq, end_ns)
        self.rows.append(("camera:%s:2026-08-29" % cam, len(self.rows),
                          aid, ahash, content))
        self.prev = sha
        self.end_ns = end_ns
        return body

    def write(self, name="chain.db"):
        path = os.path.join(self.tmp, name)
        fake_chain_db(path, self.rows)
        return path


# ═══════════════════════════════════════════════════════════════════════
# Item 1 — a requested trust root that cannot be established
# ═══════════════════════════════════════════════════════════════════════

class TrustRootLoadTests(unittest.TestCase):
    """Every way of failing to establish a pinned key raises, loudly."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _p(self, name, data=None, mode=None):
        p = os.path.join(self.tmp, name)
        if data is not None:
            with open(p, "wb") as f:
                f.write(data)
        if mode is not None:
            os.chmod(p, mode)
        return p

    def test_missing_file(self):
        with self.assertRaises(vc.TrustRootError) as cm:
            vc.load_trust_root(os.path.join(self.tmp, "nope.pub"))
        self.assertIn("cannot read trust root", str(cm.exception))

    def test_directory_instead_of_file(self):
        d = os.path.join(self.tmp, "adir.pub")
        os.mkdir(d)
        with self.assertRaises(vc.TrustRootError) as cm:
            vc.load_trust_root(d)
        self.assertIn("directory", str(cm.exception))

    def test_unreadable_file(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores the permission bits")
        p = self._p("noperm.pub", b"x" * 32, mode=0o000)
        with self.assertRaises(vc.TrustRootError):
            vc.load_trust_root(p)

    def test_empty_file(self):
        with self.assertRaises(vc.TrustRootError) as cm:
            vc.load_trust_root(self._p("empty.pub", b""))
        self.assertIn("empty", str(cm.exception))

    def test_malformed_content(self):
        # a PEM-ish text file: readable, non-empty, not a raw key
        with self.assertRaises(vc.TrustRootError) as cm:
            vc.load_trust_root(
                self._p("pem.pub", b"-----BEGIN PUBLIC KEY-----\n"))
        self.assertIn("not a 32-byte", str(cm.exception))

    def test_wrong_length_for_ed25519(self):
        for n in (16, 31, 33, 64):
            with self.assertRaises(vc.TrustRootError):
                vc.load_trust_root(self._p("k%d.pub" % n, b"k" * n))

    def test_empty_path_string(self):
        with self.assertRaises(vc.TrustRootError):
            vc.load_trust_root("")

    def test_valid_key_returns_its_key_id(self):
        sk_path, pk_path = make_keypair(self.tmp)
        with open(pk_path, "rb") as f:
            raw = f.read()
        key_id, pk = vc.load_trust_root(pk_path)
        self.assertEqual(pk, raw)
        self.assertEqual(key_id, vc.producer_key_id(raw))

    def test_pinned_set_may_not_end_up_empty(self):
        # the guard for "every --pubkey resolved but nothing is pinned"
        class Sentinel(list):
            def __bool__(self):
                return True
        with self.assertRaises(vc.TrustRootError) as cm:
            vc._load_pubkeys(Sentinel())
        self.assertIn("pinned set is empty", str(cm.exception))


class AuditFailsClosedTests(unittest.TestCase):
    """`audit --pubkey <broken>` must abort BEFORE evidence is judged,
    with a nonzero exit and no clean verdict anywhere in its output."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        chain = SignedChain(self.tmp)
        for _ in range(3):
            chain.add()
        self.db = chain.write()
        self.good_pk = chain.pk_path

    def _broken_paths(self):
        d = os.path.join(self.tmp, "adir.pub")
        os.mkdir(d)
        empty = os.path.join(self.tmp, "empty.pub")
        open(empty, "wb").close()
        short = os.path.join(self.tmp, "short.pub")
        with open(short, "wb") as f:
            f.write(b"k" * 16)
        pem = os.path.join(self.tmp, "pem.pub")
        with open(pem, "wb") as f:
            f.write(b"-----BEGIN PUBLIC KEY-----\n"
                    b"MCowBQYDK2VwAyEA\n"
                    b"-----END PUBLIC KEY-----\n")
        cases = {
            "missing": os.path.join(self.tmp, "nope.pub"),
            "directory": d,
            "empty": empty,
            "wrong-length": short,
            "malformed-pem": pem,
        }
        if os.geteuid() != 0:
            noperm = os.path.join(self.tmp, "noperm.pub")
            with open(noperm, "wb") as f:
                f.write(b"k" * 32)
            os.chmod(noperm, 0o000)
            cases["unreadable"] = noperm
        return cases

    def test_baseline_good_key_audits_clean(self):
        rc, out, err = run_main(["audit", "--db", self.db, "--pubkey",
                                 self.good_pk])
        self.assertEqual(rc, 0, out + err)
        self.assertIn("INTEGRITY: OK", out)
        self.assertIn("3/3 producer signature(s) verified", out)

    def test_every_broken_trust_root_fails_closed(self):
        for label, path in self._broken_paths().items():
            with self.subTest(case=label):
                rc, out, err = run_main(["audit", "--db", self.db,
                                         "--pubkey", path])
                self.assertNotEqual(rc, 0, "%s: exited 0" % label)
                self.assertIn("TRUST ROOT NOT ESTABLISHED", err)
                self.assertNotIn("INTEGRITY: OK", out)
                # nothing was judged at all
                self.assertNotIn("audited", out)

    def test_32_bytes_of_junk_pins_nothing_and_says_so(self):
        """A raw Ed25519 public key is 32 arbitrary bytes, so a junk file
        of the right length LOADS. What it cannot do is match anything —
        and the audit must say the pinned set describes none of the
        corpus, not quietly verify fewer signatures."""
        junk = os.path.join(self.tmp, "junk32.pub")
        with open(junk, "wb") as f:
            f.write(bytes(range(32)))
        rc, out, err = run_main(["audit", "--db", self.db,
                                 "--pubkey", junk])
        self.assertEqual(rc, 1)
        self.assertIn("does not describe this corpus", out)
        self.assertNotIn("INTEGRITY: OK", out)

    def test_one_bad_key_among_good_ones_still_fails_closed(self):
        rc, out, err = run_main(["audit", "--db", self.db,
                                 "--pubkey", self.good_pk,
                                 "--pubkey", os.path.join(self.tmp,
                                                          "nope.pub")])
        self.assertNotEqual(rc, 0)
        self.assertIn("TRUST ROOT NOT ESTABLISHED", err)
        self.assertNotIn("INTEGRITY: OK", out)

    def test_empty_scope_is_not_a_clean_audit(self):
        rc, out, err = run_main(["audit", "--db", self.db,
                                 "--session-prefix", "camera:nothing:"])
        self.assertEqual(rc, 2)
        self.assertIn("SCOPE NOT ESTABLISHED", err)
        self.assertNotIn("INTEGRITY: OK", out)

    def test_audit_without_pubkey_never_claims_signatures_checked(self):
        rc, out, err = run_main(["audit", "--db", self.db])
        self.assertEqual(rc, 0)
        self.assertIn("NO producer signature was checked", out)

    def test_unrecognised_camera_schema_is_a_failure_not_a_skip(self):
        chain = SignedChain(self.tmp, camera="cam-future")
        chain.add()
        sid, seq, aid, _, content = chain.rows[0]
        body = json.loads(content)
        body["schema"] = "camera_segment/99"
        raw = vc.canonical_bytes(body).decode("ascii")
        db = os.path.join(self.tmp, "future.db")
        fake_chain_db(db, [(sid, seq, aid,
                            hashlib.sha256(raw.encode()).hexdigest(), raw)])
        rc, out, err = run_main(["audit", "--db", db])
        self.assertEqual(rc, 1)
        self.assertIn("unrecognised schema camera_segment/99", out)

    def test_v2_without_capture_policy_is_a_failure(self):
        chain = SignedChain(self.tmp, camera="cam-nopolicy")
        chain.add()
        sid, seq, aid, _, content = chain.rows[0]
        body = json.loads(content)
        del body["capture_policy"]
        raw = vc.canonical_bytes(body).decode("ascii")
        db = os.path.join(self.tmp, "nopolicy.db")
        fake_chain_db(db, [(sid, seq, aid,
                            hashlib.sha256(raw.encode()).hexdigest(), raw)])
        rc, out, err = run_main(["audit", "--db", db])
        self.assertEqual(rc, 1)
        self.assertIn("no usable capture_policy", out)


class VerifySegmentFailsClosedTests(unittest.TestCase):
    """`verify-segment --pubkey <broken>` may never reach MATCH."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.seg = os.path.join(self.tmp, "seg.mp4")
        with open(self.seg, "wb") as f:
            f.write(b"segment-bytes")
        seg_sha = hashlib.sha256(b"segment-bytes").hexdigest()
        chain = SignedChain(self.tmp)
        chain.add(seg_sha=seg_sha)
        self.db = chain.write()
        self.good_pk = chain.pk_path

    def test_baseline_match_with_good_key(self):
        rc, out, err = run_main(["verify-segment", self.seg, "--db",
                                 self.db, "--pubkey", self.good_pk])
        self.assertEqual(rc, 0, out + err)
        self.assertIn("VERDICT: MATCH", out)
        self.assertIn("producer_sig: VALID", out)

    def test_broken_key_aborts_before_the_file_is_even_read(self):
        for label, path in (("missing",
                             os.path.join(self.tmp, "nope.pub")),
                            ("empty", self.tmp + "/e.pub")):
            if label == "empty":
                open(path, "wb").close()
            with self.subTest(case=label):
                rc, out, err = run_main(["verify-segment", self.seg,
                                         "--db", self.db,
                                         "--pubkey", path])
                self.assertEqual(rc, 2)
                self.assertIn("TRUST ROOT NOT ESTABLISHED", err)
                self.assertNotIn("VERDICT", out)


class ProducerIdentityFailsClosedTests(unittest.TestCase):
    """The producing side has a trust root too: the data_dir public key
    must be the public half of the secret this run signs with, or the
    run produces records nobody can ever verify."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_matching_pair_is_accepted(self):
        sk_path, pk_path = make_keypair(self.tmp)
        key_id, sk = vc._producer_identity(sk_path, pk_path)
        self.assertEqual(
            key_id,
            vc.producer_key_id(sk.public_key().public_bytes_raw()))

    def test_mismatched_pub_refuses_to_sign(self):
        sk_path, pk_path = make_keypair(self.tmp)
        other = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other)
        _, other_pk = make_keypair(other)
        shutil.copy(other_pk, pk_path)
        with self.assertRaises(vc.TrustRootError) as cm:
            vc._producer_identity(sk_path, pk_path)
        self.assertIn("not the public half", str(cm.exception))

    def test_truncated_pub_refuses_to_sign(self):
        sk_path, pk_path = make_keypair(self.tmp)
        with open(pk_path, "wb") as f:
            f.write(b"short")
        with self.assertRaises(vc.TrustRootError):
            vc._producer_identity(sk_path, pk_path)


# ═══════════════════════════════════════════════════════════════════════
# Item 2 — capture coverage, graded only against a SIGNED policy
# ═══════════════════════════════════════════════════════════════════════

class CapturePolicyTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_policy_is_inside_the_signed_bytes(self):
        sk_path, pk_path = make_keypair(self.tmp)
        sk = vc.producer_load_sk(sk_path)
        with open(pk_path, "rb") as f:
            pk_raw = f.read()
        nosig = vc.build_body("cam", "cam", 0, "a" * 64, None, 1, 6.0,
                              1, 2, "host-clock", "live", None,
                              vc.producer_key_id(pk_raw), POLICY_6S)
        _, body = vc.producer_sign(sk, nosig)
        self.assertEqual(body["schema"], "camera_segment/2")
        self.assertTrue(vc.producer_verify(pk_raw, body))
        # loosening the tolerance after the fact breaks the signature:
        # an operator cannot retroactively make a bad window look clean
        tampered = json.loads(json.dumps(body))
        tampered["capture_policy"]["max_unexplained_gap_s"] = 99999.0
        self.assertFalse(vc.producer_verify(pk_raw, tampered))

    def test_no_policy_still_builds_a_v1_body(self):
        nosig = vc.build_body("cam", "cam", 0, "a" * 64, None, 1, 6.0,
                              1, 2, "host-clock", "live", None, "k")
        self.assertEqual(nosig["schema"], "camera_segment/1")
        self.assertNotIn("capture_policy", nosig)

    def test_resolve_writes_and_remembers_per_data_dir(self):
        p1 = vc.capture_policy_resolve(self.tmp, 10.0, 1.5, 0.0)
        self.assertEqual(p1["nominal_segment_s"], 10.0)
        self.assertTrue(os.path.exists(
            os.path.join(self.tmp, vc.CAPTURE_POLICY_FILE)))
        p2 = vc.capture_policy_resolve(self.tmp)      # no CLI values
        self.assertEqual(p1, p2)
        p3 = vc.capture_policy_resolve(self.tmp, jitter_s=0.25)
        self.assertEqual(p3["jitter_s"], 0.25)
        self.assertEqual(p3["nominal_segment_s"], 10.0)

    def test_a_policy_that_tolerates_a_whole_segment_is_refused(self):
        with self.assertRaises(SystemExit):
            vc.capture_policy_new(6.0, 6.0, 0.0)
        with self.assertRaises(SystemExit):
            vc.capture_policy_new(0.0, 1.0, 0.0)
        with self.assertRaises(SystemExit):
            vc.capture_policy_new(6.0, 1.0, -1.0)


class SchemaTableTests(unittest.TestCase):
    """One table decides what every version carries. These tests exist
    because the /5 bump did not reach a hand-typed tuple in
    `_body_policy`, so four live records carrying a perfectly good
    capture_policy graded UNDECLARED and were reported as /1."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _schema_constants(self):
        """Every SCHEMA_V<n> the module defines, by introspection — so a
        /6 added tomorrow is caught by this test on the day it appears,
        not on the day someone notices a wrong verdict."""
        return {name: getattr(vc, name) for name in dir(vc)
                if re.fullmatch(r"SCHEMA_V\d+", name)}

    def test_every_schema_constant_is_classified(self):
        consts = self._schema_constants()
        self.assertGreaterEqual(len(consts), 5)
        for name, value in sorted(consts.items()):
            with self.subTest(schema=name):
                self.assertIn(value, vc.SCHEMA_TABLE,
                              "%s is not classified in SCHEMA_TABLE — a "
                              "version this module cannot say whether it "
                              "carries a policy" % name)
                row = vc.SCHEMA_TABLE[value]
                self.assertIsInstance(row["policy"], bool)
                self.assertIn("sensor", row)
                self.assertIn(value, vc.SCHEMAS)

    def test_derived_sets_are_derived_and_not_retyped(self):
        self.assertEqual(set(vc.SCHEMAS), set(vc.SCHEMA_TABLE))
        self.assertEqual(
            vc.POLICY_SCHEMAS,
            frozenset(s for s, d in vc.SCHEMA_TABLE.items() if d["policy"]))
        self.assertEqual(
            set(vc.SENSOR_KEYS_BY_SCHEMA),
            {s for s, d in vc.SCHEMA_TABLE.items() if d["sensor"] is not None})

    def test_only_v1_declares_no_capture_policy(self):
        self.assertEqual(set(vc.SCHEMAS) - vc.POLICY_SCHEMAS,
                         {vc.SCHEMA_V1})
        self.assertIn(vc.SCHEMA_V5, vc.POLICY_SCHEMAS)

    def test_the_current_schema_is_classified(self):
        # the bump that started this: whatever this producer emits today
        # must be a version the auditor can grade
        self.assertIn(vc.SCHEMA, vc.SCHEMA_TABLE)
        self.assertIn(vc.SCHEMA, vc.POLICY_SCHEMAS)

    def test_a_v5_body_declares_its_policy(self):
        chain = SignedChain(self.tmp, camera="v5cam")
        body = chain.add(sensor=vc.sensor_signature_unsigned())
        self.assertEqual(body["schema"], vc.SCHEMA_V5)
        self.assertEqual(vc._body_policy(body), POLICY_6S)

    def test_v5_records_grade_accounted_not_undeclared(self):
        """The lab case, in miniature: /5 records across a signed gap.
        Before the table this read UNDECLARED and disagreed with
        virp-verify about the same records."""
        s = vc.sensor_signature_unsigned()
        chain = SignedChain(self.tmp, camera="v5cam")
        for _ in range(3):
            chain.add(hole_s=0.3, sensor=s)
        chain.add(hole_s=400.0, gap={"after_seq": 2, "reason": "driver-restart"},
                  sensor=s)
        chain.add(hole_s=0.3, sensor=s)
        bodies = [(sid, aid, json.loads(content))
                  for sid, _, aid, _, content in chain.rows]
        info = vc.grade_coverage(bodies)["v5cam"]
        self.assertEqual(info["verdict"], vc.COVERAGE_ACCOUNTED)
        self.assertEqual(info["undeclared_records"], 0)

    def test_the_undeclared_reason_names_the_versions_it_saw(self):
        chain = SignedChain(self.tmp, camera="mixed")
        chain.add()
        chain.add(policy=None)
        bodies = [(sid, aid, json.loads(content))
                  for sid, _, aid, _, content in chain.rows]
        info = vc.grade_coverage(bodies)["mixed"]
        self.assertEqual(info["verdict"], vc.COVERAGE_UNDECLARED)
        # names the version actually seen, never asserts /1 on faith
        self.assertIn(vc.SCHEMA_V1, info["reason"])
        self.assertNotIn(vc.SCHEMA_V5, info["reason"])

    def test_a_v5_body_with_a_broken_policy_is_still_flagged(self):
        """The second stale tuple: audit's own policy check skipped /5
        too, so a /5 record with an unusable capture_policy would have
        passed silently."""
        chain = SignedChain(self.tmp, camera="v5cam")
        chain.add(sensor=vc.sensor_signature_unsigned())
        sid, seq, aid, _, content = chain.rows[0]
        body = json.loads(content)
        body["capture_policy"]["nominal_segment_s"] = 0.0   # unusable
        content = json.dumps(body)
        # rehash so the body-hash check passes and the POLICY check is
        # what this test is actually reading
        ahash = hashlib.sha256(content.encode()).hexdigest()
        chain.rows[0] = (sid, seq, aid, ahash, content)
        db = chain.write("broken.db")
        rc, out, _ = run_main(["audit", "--db", db,
                               "--session-prefix", "camera:"])
        self.assertNotEqual(rc, 0)
        self.assertIn("carries no usable capture_policy", out)


class CoverageGradingTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _grade(self, chain, cam=None):
        bodies = [(sid, aid, json.loads(content))
                  for sid, _, aid, _, content in chain.rows]
        cov = vc.grade_coverage(bodies)
        return cov[cam or chain.camera]

    def test_v1_records_report_undeclared_never_continuous(self):
        chain = SignedChain(self.tmp, camera="legacy")
        for _ in range(5):
            chain.add(policy=None)
        info = self._grade(chain)
        self.assertEqual(info["verdict"], vc.COVERAGE_UNDECLARED)
        self.assertNotEqual(info["verdict"], vc.COVERAGE_CONTINUOUS)

    def test_one_v1_record_undeclares_the_whole_camera(self):
        chain = SignedChain(self.tmp, camera="mixed")
        chain.add()
        chain.add(policy=None)
        chain.add()
        self.assertEqual(self._grade(chain)["verdict"],
                         vc.COVERAGE_UNDECLARED)

    def test_v2_within_jitter_is_continuous(self):
        chain = SignedChain(self.tmp, camera="steady")
        for _ in range(6):
            chain.add(hole_s=0.3)
        info = self._grade(chain)
        self.assertEqual(info["verdict"], vc.COVERAGE_CONTINUOUS)
        self.assertEqual(info["outages"], [])

    def test_overlapping_windows_are_continuous(self):
        # -c copy keyframe cuts routinely overlap; coverage is still total
        chain = SignedChain(self.tmp, camera="overlap")
        for _ in range(4):
            chain.add(hole_s=-1.5)
        self.assertEqual(self._grade(chain)["verdict"],
                         vc.COVERAGE_CONTINUOUS)

    def test_deep_overlap_is_reported_but_never_an_interruption(self):
        # the 2026-08-24 replay records overlap by 4-6 s (file-mtime
        # windows + moov-derived durations). Overlapping windows leave no
        # time unrecorded, so coverage stays CONTINUOUS and the timing
        # anomaly is reported on its own.
        chain = SignedChain(self.tmp, camera="deepoverlap")
        chain.add()
        chain.add(hole_s=-5.0)
        info = self._grade(chain)
        self.assertEqual(info["verdict"], vc.COVERAGE_CONTINUOUS)
        self.assertEqual(info["outages"], [])
        self.assertEqual(len(info["overlaps"]), 1)
        self.assertAlmostEqual(info["overlaps"][0]["overlap_s"], 5.0,
                               places=1)

    def test_gap_with_signed_record_is_accounted_not_complete(self):
        chain = SignedChain(self.tmp, camera="acct")
        chain.add()
        chain.add()
        chain.add(hole_s=300.0,
                  gap={"reason": "driver-restart", "after_seq": 1})
        chain.add()
        info = self._grade(chain)
        self.assertEqual(info["verdict"], vc.COVERAGE_ACCOUNTED)
        # the distinction that is the point of the item
        self.assertNotEqual(info["verdict"], vc.COVERAGE_CONTINUOUS)
        self.assertEqual(len(info["outages"]), 1)
        self.assertEqual(info["outages"][0]["class"], "ACCOUNTED")
        self.assertEqual(info["outages"][0]["gap_reason"], "driver-restart")
        self.assertAlmostEqual(info["outage_s"], 300.0, places=1)

    def test_gap_without_signed_record_is_unexplained(self):
        chain = SignedChain(self.tmp, camera="unexp")
        chain.add()
        chain.add()
        chain.add(hole_s=300.0)                     # no gap record
        info = self._grade(chain)
        self.assertEqual(info["verdict"], vc.COVERAGE_UNEXPLAINED)
        self.assertEqual(info["outages"][0]["class"], "UNEXPLAINED")
        self.assertIsNone(info["outages"][0]["gap_reason"])

    def test_arbitrarily_long_outage_can_never_grade_continuous(self):
        for hole in (10.0, 600.0, 86_400.0):
            chain = SignedChain(self.tmp, camera="long%d" % hole)
            chain.add()
            chain.add(hole_s=hole)
            self.assertEqual(self._grade(chain)["verdict"],
                             vc.COVERAGE_UNEXPLAINED)

    def test_declared_tolerance_absorbs_only_up_to_its_own_bound(self):
        pol = {"nominal_segment_s": 6.0, "jitter_s": 1.0,
               "max_unexplained_gap_s": 5.0}
        chain = SignedChain(self.tmp, camera="tol")
        chain.add(policy=pol)
        chain.add(policy=pol, hole_s=4.0)
        self.assertEqual(self._grade(chain)["verdict"],
                         vc.COVERAGE_ACCOUNTED)
        chain2 = SignedChain(self.tmp, camera="tol2")
        chain2.add(policy=pol)
        chain2.add(policy=pol, hole_s=6.0)
        self.assertEqual(self._grade(chain2)["verdict"],
                         vc.COVERAGE_UNEXPLAINED)

    def test_worst_camera_drives_the_axis(self):
        chain = SignedChain(self.tmp, camera="a")
        chain.add()
        chain.add()
        bodies = [(sid, aid, json.loads(c))
                  for sid, _, aid, _, c in chain.rows]
        cov = vc.grade_coverage(bodies)
        self.assertEqual(vc.coverage_axis(cov), vc.COVERAGE_CONTINUOUS)
        chain.add(hole_s=999.0)
        bodies = [(sid, aid, json.loads(c))
                  for sid, _, aid, _, c in chain.rows]
        self.assertEqual(vc.coverage_axis(vc.grade_coverage(bodies)),
                         vc.COVERAGE_UNEXPLAINED)

    def test_coverage_is_reported_separately_from_integrity(self):
        chain = SignedChain(self.tmp, camera="sep")
        chain.add()
        chain.add(hole_s=900.0)                     # unexplained outage
        db = chain.write()
        rc, out, err = run_main(["audit", "--db", db, "--pubkey",
                                 chain.pk_path])
        # the chain is intact; the coverage is not complete. Both stated.
        self.assertEqual(rc, 0, out + err)
        self.assertIn("INTEGRITY: OK", out)
        self.assertIn("COVERAGE: INTERRUPTED / UNEXPLAINED", out)
        rc2, _, _ = run_main(["audit", "--db", db, "--pubkey",
                              chain.pk_path, "--fail-on-coverage"])
        self.assertEqual(rc2, 3)


# ═══════════════════════════════════════════════════════════════════════
# Item 3 — content reuse is an observation, never a FAILED verdict
# ═══════════════════════════════════════════════════════════════════════

class ContentReuseTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _axis(self, chain):
        bodies = [(sid, aid, json.loads(c))
                  for sid, _, aid, _, c in chain.rows]
        return vc.grade_content_reuse(bodies)

    def test_no_repeats_is_none(self):
        chain = SignedChain(self.tmp, camera="uniq")
        for _ in range(4):
            chain.add()
        axis, groups = self._axis(chain)
        self.assertEqual(axis, vc.REUSE_NONE)
        self.assertEqual(groups, [])

    def test_static_scene_back_to_back_is_expected(self):
        chain = SignedChain(self.tmp, camera="static")
        sha = "d" * 64
        chain.add(seg_sha=sha)
        chain.add(seg_sha=sha, hole_s=0.1)
        axis, groups = self._axis(chain)
        self.assertEqual(axis, vc.REUSE_EXPECTED)
        self.assertEqual(groups[0]["seq_delta"], 1)

    def test_reappearance_across_a_signed_gap_is_explained(self):
        chain = SignedChain(self.tmp, camera="reship")
        sha = "e" * 64
        chain.add(seg_sha=sha)
        chain.add()
        chain.add(hole_s=200.0,
                  gap={"reason": "driver-restart", "after_seq": 1})
        chain.add(seg_sha=sha)
        axis, groups = self._axis(chain)
        self.assertEqual(axis, vc.REUSE_EXPLAINED)
        self.assertIn("signed gap record", groups[0]["basis"])

    def test_reappearance_with_no_signed_gap_is_unexplained(self):
        chain = SignedChain(self.tmp, camera="silent")
        sha = "f" * 64
        chain.add(seg_sha=sha)
        chain.add()
        chain.add()
        chain.add(seg_sha=sha)
        axis, groups = self._axis(chain)
        self.assertEqual(axis, vc.REUSE_UNEXPLAINED)
        self.assertIn("no signed gap record", groups[0]["basis"])

    def test_same_bytes_under_two_cameras_is_always_unexplained(self):
        chain = SignedChain(self.tmp, camera="cam-x")
        sha = "1" * 64
        chain.add(seg_sha=sha)
        chain.add(seg_sha=sha, camera="cam-y",
                  gap={"reason": "driver-restart", "after_seq": 0})
        axis, groups = self._axis(chain)
        self.assertEqual(axis, vc.REUSE_UNEXPLAINED)
        self.assertIn("camera_ids", groups[0]["basis"])

    def test_duplicate_hash_never_fails_the_audit(self):
        chain = SignedChain(self.tmp, camera="dupok")
        sha = "2" * 64
        chain.add(seg_sha=sha)
        chain.add()
        chain.add(hole_s=200.0,
                  gap={"reason": "driver-restart", "after_seq": 1})
        chain.add(seg_sha=sha)
        db = chain.write()
        rc, out, err = run_main(["audit", "--db", db, "--pubkey",
                                 chain.pk_path])
        self.assertEqual(rc, 0, out + err)
        self.assertIn("INTEGRITY: OK", out)
        self.assertIn("CONTENT REUSE: DUPLICATE / EXPLAINED", out)

    def test_supporting_facts_are_reported(self):
        chain = SignedChain(self.tmp, camera="facts")
        sha = "3" * 64
        chain.add(seg_sha=sha)
        chain.add()
        chain.add(seg_sha=sha)
        _, groups = self._axis(chain)
        g = groups[0]
        for k in ("segment_seqs", "seq_delta", "capture_start_delta_s",
                  "cameras", "byte_len", "artifact_ids", "basis"):
            self.assertIn(k, g)
        self.assertEqual(g["seq_delta"], 2)
        self.assertGreater(g["capture_start_delta_s"], 0)


# ═══════════════════════════════════════════════════════════════════════
# Item 4 — the real oddities, frozen
# ═══════════════════════════════════════════════════════════════════════

class Aug24RecoveredKeyFixtureTests(unittest.TestCase):
    """The 7 Aug-24 Tapo bodies signed by a2d2dc0fac250b722c6a77c87be9e341.

    Real history: this producer identity's public key survived the
    session that made it only as a copy, and these bodies are the only
    evidence on the chain that names it. Frozen so that a future change
    to canonicalisation, key-id derivation or signature verification is
    caught against records that actually exist rather than against
    vectors written to pass."""

    @classmethod
    def setUpClass(cls):
        cls.fx = load_fixture("camera_aug24_tapo_a2d2dc.json")
        cls.pk = bytes.fromhex(cls.fx["producer_pubkey_hex"])

    def test_key_id_derivation_is_stable(self):
        self.assertEqual(vc.producer_key_id(self.pk),
                         "a2d2dc0fac250b722c6a77c87be9e341")
        self.assertEqual(vc.producer_key_id(self.pk),
                         self.fx["producer_key_id"])

    def test_seven_records(self):
        self.assertEqual(len(self.fx["records"]), 7)

    def test_stored_bytes_still_hash_to_their_artifact_hash(self):
        for r in self.fx["records"]:
            self.assertEqual(
                hashlib.sha256(r["body"].encode("ascii")).hexdigest(),
                r["artifact_hash"], r["artifact_id"])

    def test_producer_signatures_verify_under_the_recovered_key(self):
        for r in self.fx["records"]:
            body = json.loads(r["body"])
            self.assertEqual(body["producer_key_id"],
                             self.fx["producer_key_id"])
            self.assertTrue(vc.producer_verify(self.pk, body),
                            r["artifact_id"])

    def test_canonical_form_round_trips_byte_for_byte(self):
        # the stored bytes ARE canonical_bytes of the parsed body
        for r in self.fx["records"]:
            self.assertEqual(
                vc.canonical_bytes(json.loads(r["body"])),
                r["body"].encode("ascii"), r["artifact_id"])

    def test_they_are_v1_and_therefore_grade_undeclared(self):
        bodies = [(r["session_id"], r["artifact_id"], json.loads(r["body"]))
                  for r in self.fx["records"]]
        for _, _, b in bodies:
            self.assertEqual(b["schema"], "camera_segment/1")
        cov = vc.grade_coverage(bodies)
        self.assertEqual(cov["tapo-c100"]["verdict"],
                         vc.COVERAGE_UNDECLARED)

    def test_a_wrong_pinned_key_never_passes_them(self):
        other = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other)
        _, pk_path = make_keypair(other)
        with open(pk_path, "rb") as f:
            wrong = f.read()
        for r in self.fx["records"]:
            self.assertFalse(vc.producer_verify(wrong,
                                                json.loads(r["body"])))


class Aug24DuplicatePairFixtureTests(unittest.TestCase):
    """The 18 real duplicate pairs, and the named seq 52/65 one.

    A producer replay defect (fixed 2026-08-25) re-shipped whole blocks
    of already-attested segments after a restart. The records are
    genuine, signed, and intact — the reuse axis must say so with its
    facts, and must not degrade the audit to FAILED."""

    @classmethod
    def setUpClass(cls):
        cls.fx = load_fixture("camera_aug24_duplicate_pairs.json")

    def test_eighteen_pairs_thirtysix_records(self):
        self.assertEqual(len(self.fx["pairs"]), 18)
        self.assertEqual(sum(len(p["segment_seqs"])
                             for p in self.fx["pairs"]), 36)

    def test_the_named_52_65_pair_is_present_with_its_facts(self):
        p = [x for x in self.fx["pairs"]
             if x["segment_seqs"] == [52, 65]]
        self.assertEqual(len(p), 1)
        p = p[0]
        self.assertEqual(p["camera_ids"], ["tapo-c100"])
        self.assertEqual(len(p["byte_len"]), 1)      # identical bytes
        self.assertGreater(p["capture_start_delta_s"], 1000.0)

    def test_verbatim_bodies_still_hash_and_are_canonical(self):
        for r in self.fx["verbatim_bodies"]:
            self.assertEqual(
                hashlib.sha256(r["body"].encode("ascii")).hexdigest(),
                r["artifact_hash"], r["artifact_id"])
            self.assertEqual(vc.canonical_bytes(json.loads(r["body"])),
                             r["body"].encode("ascii"))

    def test_the_gap_records_that_explain_the_reuse_exist(self):
        gaps = {json.loads(r["body"])["segment_seq"]:
                json.loads(r["body"])["gap"]
                for r in self.fx["verbatim_bodies"]}
        # the four signed driver-restart gaps inside the frozen blocks;
        # seqs 14 and 65 are the ones that account for the re-shipped
        # bytes, and both re-shipped blocks themselves open on a gap
        self.assertEqual(sorted(k for k, v in gaps.items() if v),
                         [7, 14, 52, 65])
        for seq in (7, 14, 52, 65):
            self.assertEqual(gaps[seq]["reason"], "driver-restart")
        self.assertIsNone(gaps.get(8))
        self.assertIsNone(gaps.get(53))

    def test_the_frozen_blocks_are_whole_and_prev_chain_consistent(self):
        seqs = sorted(json.loads(r["body"])["segment_seq"]
                      for r in self.fx["verbatim_bodies"])
        self.assertEqual(seqs, list(range(7, 20)) + list(range(52, 77)))

    def test_all_eighteen_pairs_grade_duplicate_explained(self):
        bodies = [(r["session_id"], r["artifact_id"],
                   json.loads(r["body"]))
                  for r in self.fx["verbatim_bodies"]]
        axis, groups = vc.grade_content_reuse(bodies)
        self.assertEqual(axis, vc.REUSE_EXPLAINED)
        self.assertEqual(len(groups), 18)
        for g in groups:
            self.assertEqual(g["class"], vc.REUSE_EXPLAINED, g)

    def test_the_real_pair_grades_duplicate_explained(self):
        bodies = [(r["session_id"], r["artifact_id"],
                   json.loads(r["body"]))
                  for r in self.fx["verbatim_bodies"]]
        axis, groups = vc.grade_content_reuse(bodies)
        self.assertEqual(axis, vc.REUSE_EXPLAINED)
        g = [x for x in groups if x["segment_seqs"] == [52, 65]]
        self.assertEqual(len(g), 1)
        self.assertEqual(g[0]["class"], vc.REUSE_EXPLAINED)
        self.assertIn("signed gap record", g[0]["basis"])
        self.assertEqual(g[0]["cameras"], ["tapo-c100"])

    def test_the_real_pair_does_not_fail_an_audit(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        db = os.path.join(tmp, "dup.db")
        fake_chain_db(db, [(r["session_id"], i, r["artifact_id"],
                            r["artifact_hash"], r["body"])
                           for i, r in
                           enumerate(self.fx["verbatim_bodies"])])
        rc, out, err = run_main(["audit", "--db", db])
        self.assertEqual(rc, 0, out + err)
        self.assertIn("INTEGRITY: OK", out)
        self.assertIn("CONTENT REUSE: DUPLICATE / EXPLAINED", out)
        self.assertIn("COVERAGE: UNDECLARED", out)


# ═══════════════════════════════════════════════════════════════════════
# Producer gap strictness — the validity matrix, shared with the verifier
# ═══════════════════════════════════════════════════════════════════════
#
# A `gap` is the one field that excuses a continuity break, so it is
# exactly the field an invented value must not be able to abuse. Docket
# grades a record FAILED unless a present gap is an OBJECT carrying an
# integer after_seq that cites a real predecessor, plus a nonempty,
# bounded reason. This producer used to excuse a break on
# `gap is not None`: a truthy scalar, an empty object, an after_seq
# pointing anywhere would do. It could therefore SIGN, and this auditor
# could PASS, a record the verifier rejects.
#
# These are the six outcomes the record format admits, plus the
# external-predecessor case, graded here exactly as the verifier grades
# them. The rule is enforced at four points — emission (build_body) and
# the three graders (audit continuity, coverage, content reuse) — and
# every one of them is exercised below.

class GapValidityMatrixTests(unittest.TestCase):

    # (label, gap, segment_seq, prev_seq, valid)
    MATRIX = [
        # 1 — no gap at all: continuity is claimed, and that is valid
        ("absent", None, 5, 4, True),
        # 2 — not an object: the pre-hardening producer's whole hole
        ("truthy bool", True, 5, 4, False),
        ("bare string", "driver-restart", 5, 4, False),
        ("bare int", 4, 5, 4, False),
        ("list", [{"after_seq": 4, "reason": "r"}], 5, 4, False),
        # 3 — after_seq missing or not an integer
        ("no after_seq", {"reason": "driver-restart"}, 5, 4, False),
        ("after_seq str", {"after_seq": "4", "reason": "r"}, 5, 4, False),
        ("after_seq float", {"after_seq": 4.0, "reason": "r"}, 5, 4, False),
        ("after_seq bool", {"after_seq": True, "reason": "r"}, 5, 4, False),
        # 4 — after_seq cites nowhere real
        ("cites too early", {"after_seq": 2, "reason": "r"}, 5, 4, False),
        ("cites the future", {"after_seq": 9, "reason": "r"}, 5, 4, False),
        ("cites itself", {"after_seq": 5, "reason": "r"}, 5, 4, False),
        # 5 — reason missing, empty, mistyped or unbounded
        ("no reason", {"after_seq": 4}, 5, 4, False),
        ("empty reason", {"after_seq": 4, "reason": ""}, 5, 4, False),
        ("reason not a string", {"after_seq": 4, "reason": 7}, 5, 4, False),
        ("reason over bound",
         {"after_seq": 4, "reason": "x" * (vc.GAP_REASON_MAX + 1)},
         5, 4, False),
        ("reason at the bound",
         {"after_seq": 4, "reason": "x" * vc.GAP_REASON_MAX},
         5, 4, True),
        # 6 — well formed, citing the previous record for this camera
        ("cites the carried predecessor",
         {"after_seq": 4, "reason": "driver-restart"}, 5, 4, True),
        # the case Docket added after the fact: a corpus that begins
        # mid-run names an external predecessor at segment_seq - 1
        ("external predecessor, first carried record",
         {"after_seq": 4, "reason": "driver-restart"}, 5, None, True),
        ("first carried record citing nowhere",
         {"after_seq": 1, "reason": "driver-restart"}, 5, None, False),
        # ... and the Aug-24 fixture's shape: a two-block slice, so the
        # second block opens mid-corpus on its external predecessor
        ("external predecessor, mid-corpus block",
         {"after_seq": 51, "reason": "driver-restart"}, 52, 19, True),
        # segment 0 has no predecessor at all, external or otherwise
        ("gap on segment 0", {"after_seq": -1, "reason": "r"}, 0, None,
         False),
        ("gap on segment 0, citing 0", {"after_seq": 0, "reason": "r"},
         0, None, False),
        # the field set is the schema, one level down as well
        ("unexpected key",
         {"after_seq": 4, "reason": "r", "note": "x"}, 5, 4, False),
    ]

    def test_the_matrix(self):
        for label, gap, seq, prev, valid in self.MATRIX:
            with self.subTest(case=label):
                defect = vc.gap_defect(gap, seq, prev)
                if valid:
                    self.assertIsNone(defect, "%s should be valid" % label)
                else:
                    self.assertIsInstance(
                        defect, str, "%s should be a defect" % label)
                    self.assertTrue(defect, label)

    def test_every_defect_names_the_field(self):
        # a verdict a reader cannot act on is not a verdict
        for label, gap, seq, prev, valid in self.MATRIX:
            if valid:
                continue
            with self.subTest(case=label):
                self.assertIn("gap", vc.gap_defect(gap, seq, prev))


class GapEmissionGuardTests(unittest.TestCase):
    """The producer never builds a body whose gap would grade FAILED —
    the signature is applied to the body build_body returns, so refusing
    here is refusing to sign."""

    def _build(self, seq, gap):
        return vc.build_body("cam", "cam", seq, "a" * 64, None, 1, 6.0,
                             1, 2, "host-clock", "live", gap, "k")

    def test_a_well_formed_gap_still_builds(self):
        body = self._build(5, {"after_seq": 4, "reason": "driver-restart"})
        self.assertEqual(body["gap"],
                         {"after_seq": 4, "reason": "driver-restart"})

    def test_no_gap_still_builds(self):
        self.assertIsNone(self._build(0, None)["gap"])

    def test_every_invalid_shape_is_refused(self):
        for gap in (True, "driver-restart", 4, {}, {"after_seq": 4},
                    {"reason": "r"}, {"after_seq": "4", "reason": "r"},
                    {"after_seq": 4, "reason": ""},
                    {"after_seq": 3, "reason": "r"},
                    {"after_seq": 4, "reason": "r", "note": "x"}):
            with self.subTest(gap=gap):
                with self.assertRaises(ValueError) as cm:
                    self._build(5, gap)
                self.assertIn("refusing to build", str(cm.exception))

    def test_a_gap_on_segment_0_is_refused(self):
        with self.assertRaises(ValueError):
            self._build(0, {"after_seq": -1, "reason": "driver-restart"})


class InvalidGapExcusesNothingTests(unittest.TestCase):
    """The graders' side of the same rule. A gap that does not grade
    valid is not a gap: it fails the record, and it excuses neither a
    sequence break, nor an outage, nor a reappearance of bytes."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_a_signed_but_invalid_gap_fails_the_audit(self):
        chain = SignedChain(self.tmp, camera="badgap")
        chain.add()
        chain.add()
        chain.add(raw_gap=True)
        rc, out, err = run_main(["audit", "--db", chain.write(),
                                 "--pubkey", chain.pk_path])
        self.assertEqual(rc, 1, out + err)
        self.assertNotIn("INTEGRITY: OK", out)
        self.assertIn("gap is bool, not an object", out + err)

    def test_an_invalid_gap_no_longer_excuses_a_sequence_break(self):
        chain = SignedChain(self.tmp, camera="jump")
        chain.add()
        chain.add(bump_seq=3, raw_gap={"after_seq": 4, "reason": "r"})
        rc, out, err = run_main(["audit", "--db", chain.write(),
                                 "--pubkey", chain.pk_path])
        both = out + err
        self.assertEqual(rc, 1, both)
        self.assertIn("does not follow", both)
        self.assertIn("no valid gap record", both)

    def test_a_valid_gap_citing_the_carried_predecessor_still_excuses(self):
        # the Docket branch: after_seq names the previous record for
        # this camera, which is three sequence numbers back
        chain = SignedChain(self.tmp, camera="ok1")
        chain.add()
        chain.add(bump_seq=3, raw_gap={"after_seq": 0,
                                       "reason": "driver-restart"})
        rc, out, err = run_main(["audit", "--db", chain.write(),
                                 "--pubkey", chain.pk_path])
        self.assertEqual(rc, 0, out + err)
        self.assertIn("INTEGRITY: OK", out)

    def test_a_valid_external_predecessor_gap_still_excuses(self):
        # the sliced-corpus branch: after_seq names the immediate
        # predecessor, which this corpus does not carry
        chain = SignedChain(self.tmp, camera="ok2")
        chain.add()
        chain.add(bump_seq=3, raw_gap={"after_seq": 2,
                                       "reason": "driver-restart"})
        rc, out, err = run_main(["audit", "--db", chain.write(),
                                 "--pubkey", chain.pk_path])
        self.assertEqual(rc, 0, out + err)
        self.assertIn("INTEGRITY: OK", out)

    def test_an_invalid_gap_does_not_account_for_an_outage(self):
        chain = SignedChain(self.tmp, camera="cov")
        chain.add()
        chain.add()
        chain.add(hole_s=300.0, raw_gap=True)
        bodies = [(s, a, json.loads(c)) for s, _, a, _, c in chain.rows]
        info = vc.grade_coverage(bodies)["cov"]
        self.assertEqual(info["verdict"], vc.COVERAGE_UNEXPLAINED)
        self.assertEqual(info["outages"][0]["class"], "UNEXPLAINED")
        self.assertIsNone(info["outages"][0]["gap_reason"])

    def test_an_invalid_gap_does_not_explain_a_reappearance(self):
        chain = SignedChain(self.tmp, camera="reuse")
        sha = "d" * 64
        chain.add(seg_sha=sha)
        chain.add()
        chain.add(hole_s=200.0, raw_gap={"after_seq": 99, "reason": "r"})
        chain.add(seg_sha=sha)
        bodies = [(s, a, json.loads(c)) for s, _, a, _, c in chain.rows]
        axis, groups = vc.grade_content_reuse(bodies)
        self.assertEqual(axis, vc.REUSE_UNEXPLAINED)
        self.assertIn("no signed gap record", groups[0]["basis"])

    def test_the_same_reuse_is_explained_by_a_valid_gap(self):
        # the control for the test above: identical chain, valid gap
        chain = SignedChain(self.tmp, camera="reuse2")
        sha = "d" * 64
        chain.add(seg_sha=sha)
        chain.add()
        chain.add(hole_s=200.0, gap={"after_seq": 1,
                                     "reason": "driver-restart"})
        chain.add(seg_sha=sha)
        bodies = [(s, a, json.loads(c)) for s, _, a, _, c in chain.rows]
        axis, groups = vc.grade_content_reuse(bodies)
        self.assertEqual(axis, vc.REUSE_EXPLAINED)


# ═══════════════════════════════════════════════════════════════════════
# Item 5 — the umbrella invariant, stated as one test
# ═══════════════════════════════════════════════════════════════════════

class NoPrerequisiteFailureStrengthensTheVerdictTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        chain = SignedChain(self.tmp, camera="inv")
        for _ in range(3):
            chain.add()
        self.db = chain.write()
        self.pk = chain.pk_path

    def test_every_degraded_prerequisite_is_weaker_than_the_full_run(self):
        rc, full_out, _ = run_main(["audit", "--db", self.db,
                                    "--pubkey", self.pk])
        self.assertEqual(rc, 0)
        self.assertIn("INTEGRITY: OK", full_out)
        self.assertIn("3/3 producer signature(s) verified", full_out)

        missing = os.path.join(self.tmp, "gone.pub")
        degraded = [
            ["audit", "--db", self.db, "--pubkey", missing],
            ["audit", "--db", self.db, "--session-prefix", "camera:none:"],
            ["verify-segment", os.path.join(self.tmp, "seg.mp4"),
             "--db", self.db, "--pubkey", missing],
        ]
        for argv in degraded:
            with self.subTest(argv=" ".join(argv)):
                rc, out, err = run_main(argv)
                self.assertNotEqual(rc, 0)
                self.assertNotIn("INTEGRITY: OK", out)
                self.assertNotIn("VERDICT: MATCH", out)
                self.assertNotIn("signature(s) verified", out)

    def test_dropping_the_pubkey_weakens_the_claim_it_prints(self):
        _, with_key, _ = run_main(["audit", "--db", self.db,
                                   "--pubkey", self.pk])
        _, no_key, _ = run_main(["audit", "--db", self.db])
        self.assertIn("producer signature(s) verified", with_key)
        self.assertIn("NO producer signature was checked", no_key)


if __name__ == "__main__":
    unittest.main(verbosity=2)
