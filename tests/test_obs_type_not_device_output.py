#!/usr/bin/env python3
"""
Audit §4.1 (Half B) — an intent/outcome signature must not render as
authenticated DEVICE OUTPUT.

parse_virp_message() used to unpack obs_length at offset 2 and never read
obs_type at offset 0. A SIGN_INTENT observation (0x08) therefore came back
shaped exactly like real device output (0x07), with `verified: True`,
because the HMAC over it genuinely IS valid — the O-Node signed it. What
the signature authenticates is the difference, and nothing on this surface
looked.

Combined with the unvalidated sign_intent handler (Half A), that let a
caller with socket access have its own text reported by the REST API as
verified output from a device — which is exactly the forgery the protocol
exists to prevent.

These tests force `verified = True` via a stub bridge, so they assert the
thing that actually matters: even a genuinely verified observation is not
device output unless obs_type says so.
"""

import os
import struct
import sys
import types
import unittest


def _stub_web_deps():
    """Let this run without fastapi/pydantic installed.

    Everything under test here is pure byte parsing; the web framework is
    an import-time dependency of server.py, not of the functions being
    exercised. virp-lab has no fastapi, so without this the suite could
    not run on the node where the finding was confirmed. Real modules are
    always preferred — stubs are installed only for what is missing.
    """
    def _mod(name, **attrs):
        m = types.ModuleType(name)
        for k, v in attrs.items():
            setattr(m, k, v)
        return m

    try:
        import fastapi  # noqa: F401
    except ModuleNotFoundError:
        class _Any:
            def __init__(self, *a, **k): pass
            def __call__(self, *a, **k): return self
            def __getattr__(self, _): return _Any()
        fa = _mod("fastapi", Depends=_Any(), FastAPI=_Any,
                  HTTPException=type("HTTPException", (Exception,), {}),
                  Request=_Any)
        sys.modules["fastapi"] = fa
        sys.modules["fastapi.middleware"] = _mod("fastapi.middleware")
        sys.modules["fastapi.middleware.cors"] = _mod(
            "fastapi.middleware.cors", CORSMiddleware=_Any)
        sys.modules["fastapi.responses"] = _mod(
            "fastapi.responses", JSONResponse=_Any)
        sys.modules["fastapi.staticfiles"] = _mod(
            "fastapi.staticfiles", StaticFiles=_Any)

    try:
        import pydantic  # noqa: F401
    except ModuleNotFoundError:
        class _BaseModel:
            def __init__(self, **kw):
                for k, v in kw.items():
                    setattr(self, k, v)

        def _field_validator(*a, **k):
            return lambda fn: fn

        sys.modules["pydantic"] = _mod(
            "pydantic", BaseModel=_BaseModel, ConfigDict=dict,
            field_validator=_field_validator)


_stub_web_deps()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import server as srv

VIRP_HEADER_SIZE = 56


class _AlwaysVerifies:
    """Stand-in for the C bridge: every message verifies."""

    def verify_observation(self, msg):
        return True


def _make_observation(obs_type: int, body: bytes = b"totally legitimate output",
                      tier: int = 0x01) -> bytes:
    """Build a well-formed OBSERVATION with the given sub-type.

    Sub-header is obs_type(1) + obs_scope(1) + obs_length(2 BE), matching
    virp_build_observation().
    """
    sub = struct.pack("!BBH", obs_type, 0x01, len(body)) + body
    length = VIRP_HEADER_SIZE + len(sub)
    hdr = struct.pack("!BBHI BBHI Q",
                      1, srv.VIRP_TYPE_OBSERVATION, length, 1,
                      1, tier, 0,
                      1, 0)
    hdr += b"\x00" * (VIRP_HEADER_SIZE - len(hdr))
    return hdr + sub


class TestObsTypeSurfaced(unittest.TestCase):

    def setUp(self):
        srv._virp_bridge = _AlwaysVerifies()
        srv.key_material = None
        srv.key_fingerprint = None

    def tearDown(self):
        srv._virp_bridge = None

    def test_device_output_is_device_output(self):
        """The legitimate case still works — 0x07 is device output."""
        r = srv.parse_virp_message(_make_observation(0x07))
        self.assertTrue(r["verified"])
        self.assertEqual(r["obs_type"], 0x07)
        self.assertEqual(r["obs_type_name"], "DEVICE_OUTPUT")
        self.assertTrue(r["is_device_output"])

    def test_intent_signed_is_not_device_output(self):
        """The finding: a verified 0x08 must not look like device output."""
        r = srv.parse_virp_message(
            _make_observation(0x08, b"router says everything is fine"))
        # The HMAC really is valid — that is the point.
        self.assertTrue(r["verified"])
        # ...but it is NOT something a device said.
        self.assertEqual(r["obs_type"], 0x08)
        self.assertEqual(r["obs_type_name"], "INTENT_SIGNED")
        self.assertFalse(r["is_device_output"])

    def test_outcome_signed_is_not_device_output(self):
        r = srv.parse_virp_message(_make_observation(0x09))
        self.assertTrue(r["verified"])
        self.assertFalse(r["is_device_output"])
        self.assertEqual(r["obs_type_name"], "OUTCOME_SIGNED")

    def test_obs_type_is_actually_read_not_assumed(self):
        """Every sub-type round-trips — the parser reads offset 0, not a
        constant. A hardcoded 0x07 would pass the two tests above."""
        for t, name in ((0x01, "PREFIX_REACHABLE"), (0x0F, "ERROR"),
                        (0x10, "VALIDATION_DECISION"), (0x12, "APPROVAL_RESULT")):
            r = srv.parse_virp_message(_make_observation(t))
            self.assertEqual(r["obs_type"], t)
            self.assertEqual(r["obs_type_name"], name)
            self.assertFalse(r["is_device_output"])

    def test_parse_error_is_never_device_output(self):
        """The reject path carries the same keys with safe defaults."""
        r = srv._parse_error("synthetic")
        self.assertFalse(r["verified"])
        self.assertIsNone(r["obs_type"])
        self.assertFalse(r["is_device_output"])


class TestExecutePathRejectsForgedTypes(unittest.TestCase):
    """_require_execute_observation() is the enforcement point: the execute
    action emits only DEVICE_OUTPUT or ERROR, so anything else on that path
    must fail closed rather than be reported as a device's output."""

    def setUp(self):
        srv._virp_bridge = _AlwaysVerifies()

    def tearDown(self):
        srv._virp_bridge = None

    def test_device_output_passes(self):
        obs = srv.parse_virp_message(_make_observation(0x07))
        self.assertIs(srv._require_execute_observation(obs), obs)

    def test_signed_error_passes(self):
        """Gate blocks and driver failures come back as signed 0x0F and must
        keep working — the fix must not break honest error reporting."""
        obs = srv.parse_virp_message(
            _make_observation(0x0F, b"ERROR: device not found"))
        self.assertIs(srv._require_execute_observation(obs), obs)

    def test_intent_signed_rejected(self):
        obs = srv.parse_virp_message(_make_observation(0x08, b"forged"))
        with self.assertRaises(ConnectionError) as cm:
            srv._require_execute_observation(obs)
        self.assertIn("INTENT_SIGNED", str(cm.exception))

    def test_outcome_signed_rejected(self):
        obs = srv.parse_virp_message(_make_observation(0x09))
        with self.assertRaises(ConnectionError):
            srv._require_execute_observation(obs)

    def test_unexpected_type_rejected(self):
        """Fail closed, not allowlist-by-omission."""
        for t in (0x01, 0x0A, 0x10, 0x12):
            obs = srv.parse_virp_message(_make_observation(t))
            with self.assertRaises(ConnectionError):
                srv._require_execute_observation(obs)


if __name__ == "__main__":
    unittest.main(verbosity=2)
