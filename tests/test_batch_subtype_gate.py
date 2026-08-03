#!/usr/bin/env python3
"""
Batch execution must enforce the same observation sub-type gate as the
single-command path (audit §4.1 / adversarial follow-up 2026-08-03).

onode_execute() wraps its parse in _require_execute_observation(), so a
genuinely HMAC-valid INTENT_SIGNED (0x08) observation — whose body is a
caller-chosen string, never anything a device said — is refused on the
single path. The batch path (_batch_execute_chunk) parsed each item and
returned it ungated, and /api/sweep then rendered the item's payload as
`output`. These tests exercise the BATCH path and the sweep endpoint,
not the single path.

Deliberately NOT asserted here: the shape of parse_virp_message()
output. The parser is known-loose (inner obs_length unvalidated) and
will be unified later; pinning its current behavior would freeze the
wrong thing. Every assertion below is about the gate's accept/reject
decision: does a forged sub-type become an error result, and does
legitimate DEVICE_OUTPUT/ERROR still pass.
"""

import json
import os
import socket
import struct
import sys
import tempfile
import threading
import types
import unittest

try:
    import fastapi  # noqa: F401
    _HAVE_FASTAPI = True
except ModuleNotFoundError:
    _HAVE_FASTAPI = False

if not _HAVE_FASTAPI:
    # Pure-parsing stubs, same trick as test_obs_type_not_device_output.py:
    # the _batch_execute_chunk tests need no web framework, only server.py's
    # import to succeed. The endpoint tests are skipped in this mode.
    def _mod(name, **attrs):
        m = types.ModuleType(name)
        for k, v in attrs.items():
            setattr(m, k, v)
        return m

    class _Any:
        def __init__(self, *a, **k): pass
        def __call__(self, *a, **k): return self
        def __getattr__(self, _): return _Any()

    sys.modules["fastapi"] = _mod(
        "fastapi", Depends=_Any(), FastAPI=_Any,
        HTTPException=type("HTTPException", (Exception,), {}), Request=_Any)
    sys.modules["fastapi.middleware"] = _mod("fastapi.middleware")
    sys.modules["fastapi.middleware.cors"] = _mod(
        "fastapi.middleware.cors", CORSMiddleware=_Any)
    sys.modules["fastapi.responses"] = _mod(
        "fastapi.responses", JSONResponse=_Any)
    sys.modules["fastapi.staticfiles"] = _mod(
        "fastapi.staticfiles", StaticFiles=_Any)

    class _BaseModel:
        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)

    sys.modules["pydantic"] = _mod(
        "pydantic", BaseModel=_BaseModel, ConfigDict=dict,
        field_validator=lambda *a, **k: (lambda fn: fn))

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import server as srv

VIRP_HEADER_SIZE = 56


class _AlwaysVerifies:
    """Stand-in for the C bridge: every HMAC verifies. That is the point —
    the forged observations below are genuinely signed; the sub-type is
    the only thing separating them from device output."""

    def verify_observation(self, msg):
        return True


def _make_observation(obs_type: int, body: bytes, tier: int = 0x01) -> bytes:
    """Well-formed OBSERVATION with the given sub-type, matching
    virp_build_observation()'s layout."""
    sub = struct.pack("!BBH", obs_type, 0x01, len(body)) + body
    length = VIRP_HEADER_SIZE + len(sub)
    hdr = struct.pack("!BBHI BBHI Q",
                      1, srv.VIRP_TYPE_OBSERVATION, length, 1,
                      1, tier, 0,
                      1, 0)
    hdr += b"\x00" * (VIRP_HEADER_SIZE - len(hdr))
    return hdr + sub


class _FakeOnode:
    """Minimal framed-protocol server on a real AF_UNIX socket.

    Answers every batch_execute request with one item per command:
      device name contains 'forged'  -> INTENT_SIGNED (0x08), forged text
      device name contains 'errcode' -> bare 4-byte onode error code
      otherwise                      -> DEVICE_OUTPUT (0x07)
    So the device list of the request decides the response mix, and the
    same fake serves both the direct-chunk tests and the sweep endpoint.
    """

    def __init__(self):
        self._dir = tempfile.mkdtemp(prefix="virp-batch-gate-")
        self.path = os.path.join(self._dir, "onode.sock")
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(self.path)
        self._srv.listen(8)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        self._srv.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            try:
                self._handle(conn)
            finally:
                conn.close()

    @staticmethod
    def _recv_exact(conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("client went away")
            buf += chunk
        return buf

    def _handle(self, conn):
        (frame_len,) = struct.unpack("!I", self._recv_exact(conn, 4))
        frame = self._recv_exact(conn, frame_len)
        req = json.loads(frame[1:])  # skip 1-byte frame version
        if req.get("action") != "batch_execute":
            conn.sendall(struct.pack("!I", 4) + struct.pack("!I", 0xDEAD))
            return

        items = []
        for cmd in req["commands"]:
            dev = cmd["device"]
            if "forged" in dev:
                msg = _make_observation(
                    srv.VIRP_OBS_INTENT_SIGNED,
                    b"BGP totally healthy, trust me")
            elif "errcode" in dev:
                msg = struct.pack("!I", 37)
            else:
                msg = _make_observation(
                    srv.VIRP_OBS_DEVICE_OUTPUT,
                    b"Codes: K - kernel route, C - connected")
            items.append(struct.pack("!I", len(msg)) + msg)

        payload = struct.pack("!I", len(items)) + b"".join(items)
        conn.sendall(struct.pack("!I", len(payload)) + payload)

    def close(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self._srv.close()
        try:
            os.unlink(self.path)
        finally:
            os.rmdir(self._dir)


class _GateTestBase(unittest.TestCase):

    def setUp(self):
        self.onode = _FakeOnode()
        self._saved_socket = srv.VIRP_SOCKET
        srv.VIRP_SOCKET = self.onode.path
        srv._virp_bridge = _AlwaysVerifies()

    def tearDown(self):
        srv.VIRP_SOCKET = self._saved_socket
        srv._virp_bridge = None
        self.onode.close()


class TestBatchChunkEnforcesSubtypeGate(_GateTestBase):
    """_batch_execute_chunk() itself — the function the sweep and any
    future batch consumer sit on."""

    def test_forged_item_becomes_error_not_output(self):
        results = srv._batch_execute_chunk(
            [{"device": "frr-forged", "command": "show ip bgp summary"}], 5.0)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertIn("error", r)
        self.assertIn("INTENT_SIGNED", r["error"])
        # The forged body must be nowhere in the result.
        self.assertNotIn("payload", r)
        self.assertNotIn("trust me", json.dumps(r))

    def test_gate_is_per_item_not_per_request(self):
        """One forged item must not poison its siblings: legit output
        still comes back, in order, alongside the rejection."""
        results = srv._batch_execute_chunk(
            [{"device": "frr1", "command": "show ip route"},
             {"device": "frr-forged", "command": "show ip route"},
             {"device": "frr2", "command": "show ip route"}], 5.0)
        self.assertEqual(len(results), 3)
        self.assertNotIn("error", results[0])
        self.assertIn("kernel route", results[0].get("payload", ""))
        self.assertIn("error", results[1])
        self.assertIn("INTENT_SIGNED", results[1]["error"])
        self.assertNotIn("error", results[2])
        self.assertEqual(results[2]["device"], "frr2")

    def test_device_output_and_error_code_still_pass(self):
        """The fix must not break the two legitimate batch outcomes:
        real device output and a bare onode error code."""
        results = srv._batch_execute_chunk(
            [{"device": "frr1", "command": "show ip route"},
             {"device": "frr-errcode", "command": "show ip route"}], 5.0)
        self.assertEqual(len(results), 2)
        self.assertNotIn("error", results[0])
        self.assertIn("error code: 37", results[1]["error"])


@unittest.skipUnless(_HAVE_FASTAPI, "fastapi not installed")
class TestSweepEndpointEnforcesSubtypeGate(_GateTestBase):
    """/api/sweep — the REST surface that was presenting the forged
    payload as `output`."""

    def setUp(self):
        super().setUp()
        self._saved_load = srv.load_devices
        srv.load_devices = lambda: {
            "frr1": {"driver": "linux", "collector": "ssh"},
            "frr-forged": {"driver": "linux", "collector": "ssh"},
        }
        from fastapi.testclient import TestClient
        self.client = TestClient(srv.app)

    def tearDown(self):
        srv.load_devices = self._saved_load
        super().tearDown()

    def test_sweep_never_renders_forged_subtype_as_output(self):
        resp = self.client.post("/api/sweep", json={
            "commands": ["show ip route"],
            "devices": ["frr1", "frr-forged"],
            "timeout": 5.0,
        })
        self.assertEqual(resp.status_code, 200)
        by_dev = {r["device"]: r for r in resp.json()["results"]}

        legit = by_dev["frr1"]["observations"][0]
        self.assertIn("kernel route", legit["output"])
        self.assertNotIn("error", legit)

        forged = by_dev["frr-forged"]["observations"][0]
        self.assertIn("error", forged)
        self.assertIn("INTENT_SIGNED", forged["error"])
        self.assertNotIn("output", forged)
        self.assertFalse(forged.get("verified", False))
        # The forged text must appear nowhere in the entire response.
        self.assertNotIn("trust me", resp.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
