#!/usr/bin/env python3
"""Sensor-signature tests for the camera driver (camera_segment/3).

A camera that signs its own video asserts two things this producer
cannot otherwise check: that the pixels are the ones the sensor emitted,
and WHEN the sensor says it emitted them. Both are the CAMERA'S CLAIM.
Neither is the O-node's receipt time, and the two are never collapsed:
the M3085-V used to build these tests has a wrong clock and stamps
2024-08-15 onto footage captured in 2026.

ONE INVARIANT holds this file together (Aug 28 ruling #1):

    A PREREQUISITE THAT COULD NOT BE ESTABLISHED IS REPORTED, NEVER
    OMITTED AND NEVER UPGRADED — AND THE RECORD STILL SHIPS.

A missing validator, a validator that crashes, and a result that cannot
be parsed are three different failures with one verdict: UNVERIFIED.
None of them may drop the segment, and none of them may borrow the
credibility of VALID. The opposite failure is just as bad: a signed
record that quietly carries no sensor claim at all, so that "no
signature was checked" reads as "the signature was fine".

The fixture tests/fixtures/axis_validation_valid.txt is REAL output,
frozen verbatim from libsigned-video-framework v2.3.10 run against a
20 s -c copy pull off AXIS M3085-V serial B8A44FDD572C (18 GOPs, 0
invalid, 0 unsigned). The full end-to-end tests additionally need that
clip and the validator binary, and skip when either is absent.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "camera"))
import virp_camera as vc
from test_camera_driver import make_mp4, make_keypair, fake_chain_db
from test_camera_phase2 import live_cfg, ShipRecorder
from test_camera_restart_integrity import restart_cfg
from test_camera_trust_and_coverage import run_main

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
REAL_VALID = os.path.join(FIXTURES, "axis_validation_valid.txt")

# The real 20 s Axis clip and the real validator. Both live outside the
# repo (a 580 KB binary and a GStreamer build are not fixtures), so the
# end-to-end classes skip without them while the parse tests — which
# carry the same real bytes — always run.
AXIS_CLIP = os.environ.get(
    "VIRP_AXIS_CLIP", os.path.expanduser("~/axis-signed-test.mp4"))
VALIDATOR = os.environ.get(
    "VIRP_SVF_VALIDATOR",
    os.path.expanduser("~/svf-examples/build/apps/validator/validator"))
VALIDATOR_LIB = os.environ.get(
    "VIRP_SVF_LIB", "/usr/local/lib/x86_64-linux-gnu")
# a real signed clip whose signing key is NOT the camera's
OTHER_CLIP = os.environ.get(
    "VIRP_OTHER_CLIP",
    os.path.expanduser("~/svf-examples/test-files/signed_test_h264.mp4"))
have_other = os.path.exists(OTHER_CLIP)
# Real Axis-signed video from a DIFFERENT M-series camera: same Edge Vault
# attestation CA, serial B8A44F27E6D1. The genuine "right CA, wrong device"
# case, which no synthetic fixture would have caught as honestly.
# COMMITTED, so this runs everywhere. 131 KB of real Axis-signed H.264
# from a second M-series camera, and the CA certificate our M3085-V's own
# stream carries. Together they are the "right CA, wrong device" case,
# which is the one a hand-built fixture would be least likely to get
# right: the chain genuinely verifies and the device genuinely is not
# ours, and only the serial check separates them.
VENDOR_CLIP = os.path.join(FIXTURES, "axis_vendor_sample_B8A44F27E6D1.h264")
VENDOR_SERIAL = "B8A44F27E6D1"
# The pinned anchor, as a FIXTURE. The operational copy lives in the
# camera's data_dir (<data-dir>/trust/); this one exists so the chain
# tests need no machine-specific state.
ANCHOR = os.path.join(FIXTURES, "axis-edge-vault-attestation-ca.pem")
have_vendor = os.path.exists(VENDOR_CLIP)
have_anchor = os.path.exists(ANCHOR)
# our camera
DEVICE_SERIAL = "B8A44FDD572C"

have_clip = os.path.exists(AXIS_CLIP)
have_validator = os.path.exists(VALIDATOR)

POLICY_6S = {"nominal_segment_s": 6.0, "jitter_s": 1.5,
             "max_unexplained_gap_s": 0.0}


def results(video, key="PUBLIC KEY IS VALID!", valid=5, missing=0,
            invalid=0, unsigned=0, serial="B8A44FDD572C",
            firmware="12.5.68", first="Thu 2024-08-15 21:02:44 GMT",
            last="Thu 2024-08-15 21:03:04 GMT", counts=True):
    """Synthesise a validation_results.txt in the exact shape the
    validator writes (apps/validator/main.c:464-526)."""
    out = ["-----------------------------", key,
           "-----------------------------", video]
    if counts:
        out += ["Number of valid GOPs: %d" % valid,
                "Number of valid GOPs with missing BUs: %d" % missing,
                "Number of invalid GOPs: %d" % invalid,
                "Number of GOPs without signature: %d" % unsigned]
    out += ["-----------------------------", "",
            "Product Info", "-----------------------------",
            "Hardware ID:      932.4",
            "Serial Number:    %s" % serial,
            "Firmware version: %s" % firmware,
            "Manufacturer:     Axis Communications AB",
            "Address:          www.axis.com",
            "-----------------------------", "",
            "Signed Video timestamps", "-----------------------------",
            "First frame:           %s" % first,
            "Last validated frame:  %s" % last,
            "-----------------------------", "",
            "Versions of signed-video-framework",
            "-----------------------------",
            "Validator (v2.0.2) runs: v2.3.10",
            "Camera runs:             v2.2.1",
            "-----------------------------"]
    return "\n".join(out) + "\n"


# ── Parsing the file, never the console ────────────────────────────────

class ParseTests(unittest.TestCase):
    """The validator prints to stdout AND writes validation_results.txt.
    Only the file is parsed: the console carries per-BU trace lines whose
    format is not a stable interface, and a verdict scraped from a log is
    a verdict that changes when logging changes."""

    def test_real_axis_output_parses_to_valid_with_the_real_counts(self):
        with open(REAL_VALID) as f:
            got = vc.parse_validation_results(f.read())
        self.assertEqual(got["verdict"], vc.SENSOR_VALID)
        self.assertEqual(got["gops_valid"], 18)
        self.assertEqual(got["gops_invalid"], 0)
        self.assertEqual(got["gops_unsigned"], 0)
        self.assertEqual(got["gops_valid_with_missing"], 0)
        self.assertEqual(got["device_serial"], "B8A44FDD572C")
        self.assertEqual(got["device_firmware"], "12.5.68")
        self.assertEqual(got["asserted_first_frame"],
                         "Thu 2024-08-15 21:02:44 GMT")
        self.assertEqual(got["asserted_last_frame"],
                         "Thu 2024-08-15 21:03:04 GMT")
        self.assertEqual(got["validator"],
                         {"name": "signed-video-framework",
                          "version": "2.3.10"})

    def test_asserted_times_are_the_cameras_clock_not_ours(self):
        """The M3085-V's clock is wrong. The record must carry what the
        camera said, unaltered — not a correction, not our clock."""
        with open(REAL_VALID) as f:
            got = vc.parse_validation_results(f.read())
        self.assertIn("2024-08-15", got["asserted_first_frame"])
        self.assertNotIn("capture_end_utc_ns", got)
        self.assertNotIn("received", json.dumps(got))

    def test_invalid_video_is_invalid(self):
        got = vc.parse_validation_results(
            results("VIDEO IS INVALID!", valid=3, invalid=2))
        self.assertEqual(got["verdict"], vc.SENSOR_INVALID)
        self.assertEqual(got["gops_invalid"], 2)

    def test_unsigned_video_is_unsigned(self):
        got = vc.parse_validation_results(
            results("VIDEO IS NOT SIGNED!", counts=False))
        self.assertEqual(got["verdict"], vc.SENSOR_UNSIGNED)
        self.assertIsNone(got["gops_valid"])

    def test_valid_with_missing_frames_never_reads_as_a_clean_valid(self):
        """`VIDEO IS VALID, BUT HAS MISSING FRAMES!` is a real branch of
        the validator. Mapping it onto a bare VALID and dropping the
        missing-BU count would upgrade a lossy stream to a clean one."""
        got = vc.parse_validation_results(
            results("VIDEO IS VALID, BUT HAS MISSING FRAMES!",
                    valid=4, missing=2))
        self.assertEqual(got["gops_valid_with_missing"], 2)
        self.assertEqual(got["verdict"], vc.SENSOR_VALID)

    def test_public_key_not_valid_is_invalid_whatever_the_video_says(self):
        """Signatures checked against a key the framework rejects prove
        nothing. VALID here would be borrowed credibility."""
        got = vc.parse_validation_results(
            results("VIDEO IS VALID!", key="PUBLIC KEY IS NOT VALID!"))
        self.assertEqual(got["verdict"], vc.SENSOR_INVALID)
        self.assertEqual(got["public_key"], "NOT_VALID")

    def test_unvalidatable_public_key_downgrades_valid_to_unverified(self):
        got = vc.parse_validation_results(
            results("VIDEO IS VALID!",
                    key="PUBLIC KEY COULD NOT BE VALIDATED!"))
        self.assertEqual(got["verdict"], vc.SENSOR_UNVERIFIED)
        self.assertEqual(got["public_key"], "COULD_NOT_BE_VALIDATED")

    def test_unvalidatable_key_does_not_rescue_an_invalid_video(self):
        got = vc.parse_validation_results(
            results("VIDEO IS INVALID!",
                    key="PUBLIC KEY COULD NOT BE VALIDATED!"))
        self.assertEqual(got["verdict"], vc.SENSOR_INVALID)

    def test_no_complete_gops_is_unverified_not_unsigned(self):
        """A clip too short to hold one complete GOP was not judged. That
        is not the same statement as `this video carries no signature`."""
        got = vc.parse_validation_results(
            results("NO COMPLETE GOPS FOUND!", counts=False))
        self.assertEqual(got["verdict"], vc.SENSOR_UNVERIFIED)

    def test_garbage_is_unparseable(self):
        for junk in ("", "\n\n", "Segmentation fault", "{}",
                     "-----\nPUBLIC KEY IS VALID!\n-----\n"):
            with self.assertRaises(ValueError):
                vc.parse_validation_results(junk)


# ── Running the validator: the three UNVERIFIED paths ──────────────────

class RunValidatorTests(unittest.TestCase):
    """Aug 28 ruling #1, the three ways the prerequisite fails."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.seg = os.path.join(self.tmp, "seg.mp4")
        with open(self.seg, "wb") as f:
            f.write(make_mp4(pad=b"seg" * 32))

    def _stub(self, body):
        p = os.path.join(self.tmp, "stub-validator")
        with open(p, "w") as f:
            f.write("#!/bin/sh\n" + body)
        os.chmod(p, 0o755)
        return p

    def test_missing_validator_is_unverified_and_says_so(self):
        s, raw = vc.run_sensor_validator(
            self.seg, vendor="axis",
            validator=os.path.join(self.tmp, "does-not-exist"))
        self.assertEqual(s["verdict"], vc.SENSOR_UNVERIFIED)
        self.assertEqual(s["vendor"], "axis")
        self.assertIsNone(s["gops_valid"])
        self.assertIsNone(s["validator_output_sha256"])
        self.assertIsNone(raw)

    def test_validator_crash_is_unverified(self):
        crash = self._stub("echo boom >&2\nkill -SEGV $$\n")
        s, raw = vc.run_sensor_validator(self.seg, vendor="axis",
                                         validator=crash)
        self.assertEqual(s["verdict"], vc.SENSOR_UNVERIFIED)
        self.assertIsNone(s["validator_output_sha256"])

    def test_unparseable_result_is_unverified_but_the_bytes_are_kept(self):
        """The file existed and was hashed; it just could not be read as
        a verdict. Keeping it is how the UNVERIFIED is auditable later."""
        junk = self._stub("printf 'not a verdict\\n' > validation_results.txt\n")
        s, raw = vc.run_sensor_validator(self.seg, vendor="axis",
                                         validator=junk)
        self.assertEqual(s["verdict"], vc.SENSOR_UNVERIFIED)
        self.assertEqual(raw, "not a verdict\n")
        self.assertEqual(s["validator_output_sha256"],
                         hashlib.sha256(raw.encode()).hexdigest())

    def test_no_result_file_written_is_unverified(self):
        quiet = self._stub("exit 0\n")
        s, raw = vc.run_sensor_validator(self.seg, vendor="axis",
                                         validator=quiet)
        self.assertEqual(s["verdict"], vc.SENSOR_UNVERIFIED)
        self.assertIsNone(raw)

    def test_unverified_is_never_silently_omitted(self):
        """Every failure path still returns a complete object with every
        schema key present. A missing key would let a verifier that
        checks `if 'sensor_signature' in body` conclude nothing happened
        when in fact the check failed."""
        s, _ = vc.run_sensor_validator(
            self.seg, vendor="axis", validator="/nonexistent")
        self.assertEqual(set(s), set(vc.SENSOR_SIGNATURE_KEYS))

    def test_hash_is_over_the_raw_file_bytes(self):
        stub = self._stub(
            "cp %s validation_results.txt\n" % REAL_VALID)
        s, raw = vc.run_sensor_validator(self.seg, vendor="axis",
                                         validator=stub)
        with open(REAL_VALID, "rb") as f:
            want = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(s["validator_output_sha256"], want)
        self.assertEqual(s["verdict"], vc.SENSOR_VALID)
        self.assertEqual(s["gops_valid"], 18)


@unittest.skipUnless(have_clip and have_validator,
                     "needs the real Axis clip and validator binary")
class RealValidatorTests(unittest.TestCase):
    """(a) and (b): the real tool against real signed video."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_real_axis_clip_is_valid_with_the_real_counts(self):
        s, raw = vc.run_sensor_validator(
            AXIS_CLIP, vendor="axis", validator=VALIDATOR,
            lib_path=VALIDATOR_LIB)
        self.assertEqual(s["verdict"], vc.SENSOR_VALID)
        self.assertEqual(s["gops_valid"], 18)
        self.assertEqual(s["gops_invalid"], 0)
        self.assertEqual(s["gops_unsigned"], 0)
        self.assertEqual(s["device_serial"], "B8A44FDD572C")
        self.assertEqual(s["device_firmware"], "12.5.68")
        self.assertEqual(s["vendor"], "axis")
        self.assertIsNotNone(raw)

    def test_byte_flipped_clip_is_invalid(self):
        bad = os.path.join(self.tmp, "flipped.mp4")
        with open(AXIS_CLIP, "rb") as f:
            data = bytearray(f.read())
        # flip one bit deep inside the coded video, past the moov/header
        off = len(data) // 2
        data[off] ^= 0x40
        with open(bad, "wb") as f:
            f.write(data)
        s, _ = vc.run_sensor_validator(bad, vendor="axis",
                                       validator=VALIDATOR,
                                       lib_path=VALIDATOR_LIB)
        self.assertIn(s["verdict"],
                      (vc.SENSOR_INVALID, vc.SENSOR_UNVERIFIED))
        self.assertEqual(s["verdict"], vc.SENSOR_INVALID)


# ── The leaf pin: is this OUR camera's key? ────────────────────────────

class KeyExtractionTests(unittest.TestCase):
    """The signing public key travels in the clear in the SEI, once per
    signed GOP. Reading it is what lets the producer answer a question
    the framework does not: not "did this verify", but "did this verify
    under the key WE pinned, out of band, for THIS camera"."""

    @unittest.skipUnless(have_clip, "needs the real Axis clip")
    def test_the_key_is_recoverable_from_the_sei(self):
        pem = vc.extract_sensor_public_key(AXIS_CLIP)
        self.assertIsNotNone(pem)
        self.assertTrue(pem.startswith("-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(pem.rstrip().endswith("-----END PUBLIC KEY-----"))

    @unittest.skipUnless(have_clip and have_other,
                         "needs both signed clips")
    def test_two_cameras_two_keys(self):
        self.assertNotEqual(vc.extract_sensor_public_key(AXIS_CLIP),
                            vc.extract_sensor_public_key(OTHER_CLIP))

    def test_an_unsigned_file_yields_no_key(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        f = os.path.join(tmp, "plain.mp4")
        with open(f, "wb") as fh:
            fh.write(make_mp4(pad=b"nokey" * 40))
        self.assertIsNone(vc.extract_sensor_public_key(f))


@unittest.skipUnless(have_clip and have_validator,
                     "needs the real Axis clip and validator binary")
class LeafPinTests(unittest.TestCase):
    """A pin mismatch is NOT a tamper claim. The video may be perfectly
    authentic footage from a camera we did not pin — reporting INVALID
    would accuse a camera of tampering when the honest statement is
    `this is not the device we pinned`. So the producer decides the pin
    question ITSELF, from the key in the stream, and reports UNVERIFIED
    with the key state recorded rather than passing off the framework's
    INVALID as evidence of tampering."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.pin = os.path.join(self.tmp, "sensor_pubkey.pem")
        with open(self.pin, "w") as f:
            f.write(vc.extract_sensor_public_key(AXIS_CLIP) + "\n")

    def _run(self, clip, pin):
        return vc.run_sensor_validator(
            clip, vendor="axis", validator=VALIDATOR,
            lib_path=VALIDATOR_LIB, sensor_pubkey=pin)

    def test_the_pinned_key_matches_and_the_verdict_stands(self):
        s, _ = self._run(AXIS_CLIP, self.pin)
        self.assertEqual(s["public_key_pin"], "MATCH")
        self.assertEqual(s["verdict"], vc.SENSOR_VALID)
        self.assertEqual(s["gops_valid"], 18)

    @unittest.skipUnless(have_other, "needs the other-key clip")
    def test_a_clip_signed_by_a_different_key_reads_unverified(self):
        """The test you cannot skip: real signed video, real validator,
        wrong camera."""
        s, _ = self._run(OTHER_CLIP, self.pin)
        self.assertEqual(s["verdict"], vc.SENSOR_UNVERIFIED)
        self.assertEqual(s["public_key_pin"], "MISMATCH")
        # the key state is RECORDED, not just the downgrade
        self.assertIsNotNone(s["sensor_key_sha256"])
        self.assertNotEqual(
            s["sensor_key_sha256"],
            hashlib.sha256(
                (vc.extract_sensor_public_key(AXIS_CLIP) + "\n").encode()
            ).hexdigest())

    def test_a_mismatch_is_never_reported_as_tampering(self):
        s, _ = self._run(OTHER_CLIP, self.pin) if have_other else (None, None)
        if s is None:
            self.skipTest("needs the other-key clip")
        self.assertNotEqual(s["verdict"], vc.SENSOR_INVALID)

    def test_without_a_pin_the_key_is_recorded_but_not_judged(self):
        s, _ = self._run(AXIS_CLIP, None)
        self.assertIsNone(s["public_key_pin"])
        self.assertIsNotNone(s["sensor_key_sha256"])
        self.assertEqual(s["verdict"], vc.SENSOR_VALID)

    def test_a_missing_pin_file_is_unverified_not_a_silent_skip(self):
        s, _ = self._run(AXIS_CLIP, os.path.join(self.tmp, "absent.pem"))
        self.assertEqual(s["verdict"], vc.SENSOR_UNVERIFIED)
        self.assertEqual(s["public_key_pin"], "PIN_UNREADABLE")


# ── The certificate chain, anchored at a pinned CA ─────────────────────

# ── The committed second-camera fixture ────────────────────────────────

class VendorFixtureTests(unittest.TestCase):
    """Both inputs are COMMITTED, so this class runs anywhere — no lab
    machine, no reference clip, no validator binary.

    `axis_vendor_sample_B8A44F27E6D1.h264` is real Axis-signed H.264 from
    a second M-series camera, issued by the same Edge Vault attestation
    CA as ours. It is the case the whole anchored-chain design turns on:
    the certificate chain genuinely verifies and the device genuinely is
    not ours. A verifier that stopped at "the chain checks out" would
    accept another building's camera as this one."""

    def test_right_ca_wrong_device_fails_only_the_serial_check(self):
        dc = vc.device_chain_check(VENDOR_CLIP, ANCHOR, DEVICE_SERIAL)
        self.assertTrue(dc["chain_to_anchor_verified"],
                        "the fixture is issued by the pinned CA and must "
                        "verify under its key")
        self.assertFalse(dc["leaf_serial_matches_device"],
                         "serial %s is not our camera %s"
                         % (VENDOR_SERIAL, DEVICE_SERIAL))
        self.assertEqual(dc["anchor"], "intermediate_pinned")

    def test_the_fixture_is_that_other_camera_and_ours_is_not_it(self):
        """Both halves pinned, so neither can drift into agreeing by
        accident: the fixture's leaf asserts B8A44F27E6D1, and the same
        check against that serial passes."""
        dc_ours = vc.device_chain_check(VENDOR_CLIP, ANCHOR, DEVICE_SERIAL)
        dc_theirs = vc.device_chain_check(VENDOR_CLIP, ANCHOR, VENDOR_SERIAL)
        self.assertFalse(dc_ours["leaf_serial_matches_device"])
        self.assertTrue(dc_theirs["leaf_serial_matches_device"])
        self.assertTrue(dc_theirs["chain_to_anchor_verified"])

    def test_a_wrong_device_never_reads_as_tampering(self):
        """The rule this fixture is really here to defend. This camera
        signed its own footage honestly; INVALID would say it did not."""
        dc = vc.device_chain_check(VENDOR_CLIP, ANCHOR, DEVICE_SERIAL)
        self.assertFalse(dc["leaf_serial_matches_device"])
        s = vc.sensor_signature_unverified("axis")
        s["device_chain"] = dc
        self.assertEqual(s["verdict"], vc.SENSOR_UNVERIFIED)
        self.assertNotEqual(s["verdict"], vc.SENSOR_INVALID)

    def test_the_committed_anchor_is_the_ca_that_issued_the_fixture(self):
        """If the anchor fixture were ever replaced with an unrelated CA,
        the two tests above would pass vacuously (nothing verifies, and
        the serial check is what fails). Pin the positive direction."""
        self.assertTrue(
            vc.device_chain_check(
                VENDOR_CLIP, ANCHOR, VENDOR_SERIAL)["chain_to_anchor_verified"])


# ── The chain, against the lab reference clip ──────────────────────────

@unittest.skipUnless(have_clip and have_anchor,
                     "needs the Axis reference clip")
class DeviceChainTests(unittest.TestCase):
    """THE ANCHOR IS A KEY, NOT A CERTIFICATE. Axis has issued at least two
    certificates for `Axis Edge Vault Attestation CA ECC 1` — same subject,
    same public key, different serials and different notAfter (2032 vs
    2055). Pinning the certificate BYTES would reject a genuine device whose
    stream happens to carry the other one. What signs a leaf is the CA's
    key, so that is what the anchor means.

    An anchored chain is a weaker claim than a chain to a root we hold, and
    the record says so in the field itself: `anchor` reads
    "intermediate_pinned", never "root", until an Axis-published Edge Vault
    root exists to pin instead."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_the_reference_clip_chains_to_the_pinned_anchor(self):
        dc = vc.device_chain_check(AXIS_CLIP, ANCHOR, DEVICE_SERIAL)
        self.assertEqual(dc["anchor"], "intermediate_pinned")
        self.assertTrue(dc["chain_to_anchor_verified"])
        self.assertTrue(dc["leaf_serial_matches_device"])
        self.assertEqual(dc["leaf_not_after"], "2033-10-22T20:22:29Z")
        self.assertEqual(
            dc["anchor_sha256"],
            hashlib.sha256(open(ANCHOR, "rb").read()).hexdigest())
        self.assertEqual(set(dc), set(vc.DEVICE_CHAIN_KEYS))

    def test_the_committed_anchor_is_the_one_the_camera_stream_carries(self):
        """If these ever diverge the chain tests would be checking against
        something the device never presented."""
        chain = vc.extract_sensor_cert_chain(AXIS_CLIP)
        self.assertEqual(len(chain), 2)
        with open(ANCHOR) as f:
            self.assertEqual(chain[1].strip(), f.read().strip())

    @unittest.skipUnless(have_other, "needs the non-Axis signed clip")
    def test_a_clip_with_no_chain_does_not_reach_the_anchor(self):
        dc = vc.device_chain_check(OTHER_CLIP, ANCHOR, DEVICE_SERIAL)
        self.assertFalse(dc["chain_to_anchor_verified"])
        self.assertFalse(dc["leaf_serial_matches_device"])

    def test_a_missing_anchor_never_falls_back_to_in_stream_trust(self):
        """Aug 28 invariant. The stream carries its own CA certificate; a
        verifier that used it when the pinned one was unreadable would be
        checking the evidence against itself."""
        dc = vc.device_chain_check(
            AXIS_CLIP, os.path.join(self.tmp, "absent.pem"), DEVICE_SERIAL)
        self.assertFalse(dc["chain_to_anchor_verified"])
        self.assertIsNone(dc["anchor_sha256"])

    def test_an_unreadable_anchor_is_the_same_state_as_a_missing_one(self):
        junk = os.path.join(self.tmp, "junk.pem")
        with open(junk, "w") as f:
            f.write("not a certificate\n")
        dc = vc.device_chain_check(AXIS_CLIP, junk, DEVICE_SERIAL)
        self.assertFalse(dc["chain_to_anchor_verified"])
        self.assertIsNone(dc["anchor_sha256"])

    def test_the_anchor_is_the_ca_key_not_the_certificate_bytes(self):
        """Pin the OTHER Axis-issued certificate for the same CA; the
        reference clip must still chain, because the key is the same."""
        if not have_vendor:
            self.skipTest("needs the vendor sample clip")
        other_ca = os.path.join(self.tmp, "other-ca.pem")
        chain = vc.extract_sensor_cert_chain(VENDOR_CLIP)
        with open(other_ca, "w") as f:
            f.write(chain[1] + "\n")
        self.assertNotEqual(
            hashlib.sha256(open(other_ca, "rb").read()).hexdigest(),
            hashlib.sha256(open(ANCHOR, "rb").read()).hexdigest(),
            "fixtures must be different certificates")
        dc = vc.device_chain_check(AXIS_CLIP, other_ca, DEVICE_SERIAL)
        self.assertTrue(dc["chain_to_anchor_verified"])


@unittest.skipUnless(have_clip and have_anchor and have_validator,
                     "needs the Axis clip, anchor and validator")
class ChainVerdictTests(unittest.TestCase):
    """Rule 4: a chain that does not reach the anchor, or a leaf that is not
    this device, downgrades to UNVERIFIED. NEVER INVALID — tampering is the
    validator's word; identity is ours, and confusing the two would accuse a
    genuine camera of altering its own footage."""

    def _run(self, clip, anchor, serial=DEVICE_SERIAL):
        pin = os.path.join(os.path.dirname(ANCHOR), "..", "sensor_pubkey.pem")
        return vc.run_sensor_validator(
            clip, vendor="axis", validator=VALIDATOR, lib_path=VALIDATOR_LIB,
            sensor_pubkey=os.path.normpath(pin) if os.path.exists(
                os.path.normpath(pin)) else None,
            sensor_anchor=anchor, device_serial=serial)

    def test_a_good_chain_leaves_the_verdict_alone(self):
        s, _ = self._run(AXIS_CLIP, ANCHOR)
        self.assertEqual(s["verdict"], vc.SENSOR_VALID)
        self.assertTrue(s["device_chain"]["chain_to_anchor_verified"])
        self.assertEqual(set(s), set(vc.SENSOR_SIGNATURE_KEYS))

    @unittest.skipUnless(have_vendor, "needs the vendor sample clip")
    def test_wrong_device_downgrades_to_unverified_never_invalid(self):
        s, _ = self._run(VENDOR_CLIP, ANCHOR)
        self.assertEqual(s["verdict"], vc.SENSOR_UNVERIFIED)
        self.assertNotEqual(s["verdict"], vc.SENSOR_INVALID)
        self.assertFalse(s["device_chain"]["leaf_serial_matches_device"])

    def test_an_unreachable_anchor_downgrades_to_unverified(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        s, _ = self._run(AXIS_CLIP, os.path.join(tmp, "absent.pem"))
        self.assertEqual(s["verdict"], vc.SENSOR_UNVERIFIED)
        self.assertFalse(s["device_chain"]["chain_to_anchor_verified"])

    def test_without_an_anchor_configured_there_is_no_chain_claim(self):
        s, _ = self._run(AXIS_CLIP, None)
        self.assertIsNone(s["device_chain"])
        self.assertEqual(s["verdict"], vc.SENSOR_VALID)


# ── The schema bump ────────────────────────────────────────────────────

class SchemaV3Tests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.sk_path, self.pk_path = make_keypair(self.tmp)
        self.sk = vc.producer_load_sk(self.sk_path)
        with open(self.pk_path, "rb") as f:
            self.pk_raw = f.read()
        self.key_id = vc.producer_key_id(self.pk_raw)

    def _body(self, policy=POLICY_6S, sensor=None):
        return vc.build_body("cam", "cam", 0, "a" * 64, None, 1, 6.0,
                             1, 2, "host-clock", "live", None,
                             self.key_id, policy, sensor)

    def test_sensor_signature_makes_a_v5_body(self):
        s = vc.sensor_signature_unsigned()
        body = self._body(sensor=s)
        self.assertEqual(body["schema"], "camera_segment/5")
        self.assertEqual(body["sensor_signature"], s)

    def test_v5_is_what_this_producer_now_emits(self):
        self.assertEqual(vc.SCHEMA, "camera_segment/5")
        self.assertIn("camera_segment/5", vc.SCHEMAS)

    def test_every_sensor_version_keeps_its_own_field_set(self):
        self.assertEqual(len(vc.SENSOR_SIGNATURE_KEYS_V3), 13)
        self.assertEqual(len(vc.SENSOR_SIGNATURE_KEYS_V4), 15)
        self.assertEqual(len(vc.SENSOR_SIGNATURE_KEYS), 16)
        self.assertEqual(
            set(vc.SENSOR_SIGNATURE_KEYS) - set(vc.SENSOR_SIGNATURE_KEYS_V4),
            {"device_chain"})

    def test_a_v4_object_is_refused_at_v5(self):
        v4 = {k: None for k in vc.SENSOR_SIGNATURE_KEYS_V4}
        v4["verdict"] = vc.SENSOR_UNSIGNED
        self.assertIsNone(vc.sensor_defect(v4, "camera_segment/4"))
        self.assertIsNotNone(vc.sensor_defect(v4, "camera_segment/5"))

    def test_growing_the_object_was_a_version_bump(self):
        """/3 records are signed and on the chain with 13 fields. The
        leaf pin added two; accepting both sizes at one version would
        have surrendered the rule that keeps frozen history frozen."""
        self.assertEqual(len(vc.SENSOR_SIGNATURE_KEYS_V3), 13)
        self.assertEqual(len(vc.SENSOR_SIGNATURE_KEYS_V4), 15)
        self.assertEqual(
            set(vc.SENSOR_SIGNATURE_KEYS_V4) - set(vc.SENSOR_SIGNATURE_KEYS_V3),
            {"public_key_pin", "sensor_key_sha256"})

    def test_a_v3_object_is_refused_at_v4_and_vice_versa(self):
        v3 = {k: None for k in vc.SENSOR_SIGNATURE_KEYS_V3}
        v3["verdict"] = vc.SENSOR_UNSIGNED
        self.assertIsNone(vc.sensor_defect(v3, "camera_segment/3"))
        self.assertIsNotNone(vc.sensor_defect(v3, "camera_segment/5"))
        v5 = vc.sensor_signature_unsigned()
        self.assertIsNone(vc.sensor_defect(v5, "camera_segment/5"))
        self.assertIsNotNone(vc.sensor_defect(v5, "camera_segment/3"))

    def test_without_a_sensor_object_it_is_still_v2(self):
        body = self._body()
        self.assertEqual(body["schema"], "camera_segment/2")
        self.assertNotIn("sensor_signature", body)

    def test_without_a_policy_it_is_still_v1(self):
        body = self._body(policy=None)
        self.assertEqual(body["schema"], "camera_segment/1")
        self.assertNotIn("sensor_signature", body)

    def test_a_sensor_object_without_a_policy_is_refused(self):
        """/3 is /2 plus the sensor claim. There is no version that has
        the sensor object but not the cadence declaration."""
        with self.assertRaises(ValueError):
            self._body(policy=None, sensor=vc.sensor_signature_unsigned())

    def test_the_sensor_claim_is_inside_the_signed_bytes(self):
        s = vc.sensor_signature_unsigned()
        nosig = self._body(sensor=s)
        _, body = vc.producer_sign(self.sk, nosig)
        self.assertTrue(vc.producer_verify(self.pk_raw, body))
        tampered = json.loads(json.dumps(body))
        tampered["sensor_signature"]["verdict"] = vc.SENSOR_VALID
        self.assertFalse(vc.producer_verify(self.pk_raw, tampered))

    def test_unsigned_camera_carries_null_vendor_and_unsigned_verdict(self):
        """(d) Tapo and Reolink do not sign their video. At /3 they say
        so explicitly rather than leaving the field out."""
        s = vc.sensor_signature_unsigned()
        self.assertIsNone(s["vendor"])
        self.assertEqual(s["verdict"], vc.SENSOR_UNSIGNED)
        self.assertIsNone(s["gops_valid"])
        self.assertIsNone(s["device_serial"])
        self.assertIsNone(s["asserted_first_frame"])
        self.assertIsNone(s["validator_output_sha256"])
        self.assertIsNone(s["public_key_pin"])
        self.assertIsNone(s["sensor_key_sha256"])
        self.assertEqual(set(s), set(vc.SENSOR_SIGNATURE_KEYS))

    def test_a_v3_body_still_fits_the_daemon_artifact_field(self):
        s, _ = vc.run_sensor_validator("/nonexistent", vendor="axis",
                                       validator="/nonexistent")
        with open(REAL_VALID) as f:
            s = vc.parse_validation_results(f.read())
            s["vendor"] = "axis"
        body = vc.build_body("axis-m3085v-b8a44fdd572c", "axis-m3085v",
                             99999, "a" * 64, "b" * 64, 1, 6.0, 1, 2,
                             "host-clock", "live", None, self.key_id,
                             POLICY_6S, s)
        body_bytes, _ = vc.producer_sign(self.sk, body)
        self.assertLess(len(body_bytes), vc.ARTIFACT_LIMIT)


# ── The verifier's version gate ────────────────────────────────────────

class VersionGateTests(unittest.TestCase):
    """The camera_id/capture_policy precedent (Aug 28): the auditor
    REQUIRES the new object at the new version and REQUIRES ITS ABSENCE
    at the older ones. A /1 body that has grown a sensor_signature was
    not produced by this producer, and must not be graded as if it were."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _audit(self, body):
        raw = vc.canonical_bytes(body).decode("ascii")
        db = os.path.join(self.tmp, "g.db")
        if os.path.exists(db):
            os.unlink(db)
        fake_chain_db(db, [("camera:cam:2026-09-03", 0, "camseg:cam:0:1",
                            hashlib.sha256(raw.encode()).hexdigest(),
                            raw)])
        rc, out, _ = run_main(["audit", "--db", db])
        return rc, out

    def _base(self, schema):
        b = {"schema": schema, "camera_id": "cam", "device": "cam",
             "segment_seq": 0, "segment_sha256": "a" * 64,
             "prev_segment_sha256": None, "byte_len": 1,
             "duration_s": 6.0, "capture_start_utc_ns": 1,
             "capture_end_utc_ns": 2, "encoder": "copy",
             "time_source": "host-clock", "mode": "live", "gap": None,
             "producer_key_id": "k"}
        if schema in ("camera_segment/2", "camera_segment/3",
                      "camera_segment/5"):
            b["capture_policy"] = POLICY_6S
        return b

    def test_v4_without_the_sensor_object_is_a_failure(self):
        rc, out = self._audit(self._base("camera_segment/5"))
        self.assertEqual(rc, 1)
        self.assertIn("no usable sensor_signature", out)

    def test_v1_carrying_a_sensor_object_is_a_failure(self):
        b = self._base("camera_segment/1")
        b["sensor_signature"] = vc.sensor_signature_unsigned()
        rc, out = self._audit(b)
        self.assertEqual(rc, 1)
        self.assertIn("sensor_signature", out)

    def test_v2_carrying_a_sensor_object_is_a_failure(self):
        b = self._base("camera_segment/2")
        b["sensor_signature"] = vc.sensor_signature_unsigned()
        rc, out = self._audit(b)
        self.assertEqual(rc, 1)
        self.assertIn("sensor_signature", out)

    def test_an_unknown_verdict_is_a_failure(self):
        b = self._base("camera_segment/5")
        s = vc.sensor_signature_unsigned()
        s["verdict"] = "PROBABLY_FINE"
        b["sensor_signature"] = s
        rc, out = self._audit(b)
        self.assertEqual(rc, 1)
        self.assertIn("no usable sensor_signature", out)

    def test_a_well_formed_v4_body_audits_clean(self):
        b = self._base("camera_segment/5")
        b["sensor_signature"] = vc.sensor_signature_unsigned()
        rc, out = self._audit(b)
        self.assertEqual(rc, 0)

    def test_the_already_signed_v3_records_still_audit_clean(self):
        """The six /3 records on the live chain (seqs 6-11) carry the
        13-field object. They are immutable and must keep passing."""
        b = self._base("camera_segment/3")
        v3 = {k: None for k in vc.SENSOR_SIGNATURE_KEYS_V3}
        v3["verdict"] = vc.SENSOR_VALID
        v3["vendor"] = "axis"
        b["sensor_signature"] = v3
        rc, out = self._audit(b)
        self.assertEqual(rc, 0, out)

    def test_a_v3_body_carrying_a_later_object_is_a_failure(self):
        b = self._base("camera_segment/3")
        b["sensor_signature"] = vc.sensor_signature_unsigned()   # 15 keys
        rc, out = self._audit(b)
        self.assertEqual(rc, 1)
        self.assertIn("no usable sensor_signature", out)


# ── The record ships regardless ────────────────────────────────────────

class ShipsAnywayTests(unittest.TestCase):
    """(b) and (c) at the pipeline level: whatever the sensor verdict,
    the segment is attested and leaves the host. A producer that dropped
    footage because a validator was missing would be destroying evidence
    to protect a verdict."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.sk_path, self.pk_path = make_keypair(self.tmp)
        self.cfg = restart_cfg(self.tmp, self.sk_path, self.pk_path)
        self.cfg["capture_policy"] = POLICY_6S
        os.makedirs(self.cfg["workdir"])
        os.makedirs(self.cfg["outbox"])

    def _seg(self, pad=b"ship" * 32):
        p = os.path.join(self.cfg["workdir"], "seg_000000.mp4")
        with open(p, "wb") as f:
            f.write(make_mp4(pad=pad))
        return p

    def _run(self):
        ship = ShipRecorder()
        p = self._seg()
        vc.process_live_segment(p, self.cfg, None, None, ship)
        self.assertEqual(len(ship.calls), 1)
        return json.loads(ship.calls[0]["body_bytes"]), ship.calls[0]["name"]

    def test_missing_validator_still_ships_an_unverified_record(self):
        self.cfg["sensor_vendor"] = "axis"
        self.cfg["validator"] = "/nonexistent/validator"
        body, _ = self._run()
        self.assertEqual(body["schema"], "camera_segment/5")
        self.assertEqual(body["sensor_signature"]["verdict"],
                         vc.SENSOR_UNVERIFIED)

    def test_unconfigured_vendor_ships_an_unsigned_record(self):
        body, _ = self._run()
        self.assertEqual(body["schema"], "camera_segment/5")
        self.assertEqual(body["sensor_signature"]["verdict"],
                         vc.SENSOR_UNSIGNED)
        self.assertIsNone(body["sensor_signature"]["vendor"])

    def test_the_raw_validator_output_is_kept_beside_the_segment(self):
        stub = os.path.join(self.tmp, "stub")
        with open(stub, "w") as f:
            f.write("#!/bin/sh\ncp %s validation_results.txt\n" % REAL_VALID)
        os.chmod(stub, 0o755)
        self.cfg["sensor_vendor"] = "axis"
        self.cfg["validator"] = stub
        body, name = self._run()
        beside = os.path.join(self.cfg["outbox"], name + ".validation.txt")
        self.assertTrue(os.path.exists(beside), beside)
        with open(beside, "rb") as f:
            got = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(body["sensor_signature"]["validator_output_sha256"],
                         got)

    def test_the_onode_receipt_time_is_not_the_cameras_claim(self):
        """The two facts stay separate in the signed bytes: capture_end
        is this host's clock, asserted_last_frame is the camera's."""
        stub = os.path.join(self.tmp, "stub")
        with open(stub, "w") as f:
            f.write("#!/bin/sh\ncp %s validation_results.txt\n" % REAL_VALID)
        os.chmod(stub, 0o755)
        self.cfg["sensor_vendor"] = "axis"
        self.cfg["validator"] = stub
        body, _ = self._run()
        self.assertGreater(body["capture_end_utc_ns"], 1_700_000_000 * 10**9)
        self.assertEqual(body["sensor_signature"]["asserted_last_frame"],
                         "Thu 2024-08-15 21:03:04 GMT")


# ── Legacy stays legible ───────────────────────────────────────────────

class LegacyTests(unittest.TestCase):
    """(e) 2553 live /1 records and the /2 records after them are frozen
    history. The bump may not re-sign, rewrite, or fail any of them."""

    def setUp(self):
        with open(os.path.join(
                FIXTURES, "camera_aug24_tapo_a2d2dc.json")) as f:
            self.fx = json.load(f)
        self.pk_raw = bytes.fromhex(self.fx["producer_pubkey_hex"])

    def test_frozen_tapo_bodies_still_verify_byte_for_byte(self):
        self.assertEqual(len(self.fx["records"]), 7)
        for rec in self.fx["records"]:
            body = json.loads(rec["body"])
            self.assertEqual(body["schema"], "camera_segment/1")
            # the bump added a field; it must not have moved a byte of
            # what was already signed
            self.assertEqual(
                vc.canonical_bytes(body).decode("ascii"), rec["body"])
            self.assertEqual(
                hashlib.sha256(rec["body"].encode()).hexdigest(),
                rec["artifact_hash"])
            self.assertTrue(vc.producer_verify(self.pk_raw, body))

    def test_no_legacy_body_carries_a_sensor_signature(self):
        for rec in self.fx["records"]:
            self.assertNotIn("sensor_signature", json.loads(rec["body"]))

    def test_legacy_records_audit_clean_at_the_new_version(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        db = os.path.join(tmp, "legacy.db")
        fake_chain_db(db, [(r["session_id"], r["chain_sequence"],
                            r["artifact_id"], r["artifact_hash"],
                            r["body"]) for r in self.fx["records"]])
        pk = os.path.join(tmp, "producer.pub")
        with open(pk, "wb") as f:
            f.write(self.pk_raw)
        rc, out, _ = run_main(["audit", "--db", db, "--pubkey", pk])
        self.assertEqual(rc, 0, out)
        self.assertIn("INTEGRITY: OK", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
