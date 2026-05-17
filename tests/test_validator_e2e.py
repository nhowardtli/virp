#!/usr/bin/env python3
"""
End-to-end wire harness for the response validator.

Proves that api/validator and the C dispatcher (ONODE_ACTION_VALIDATE_TURN
in src/virp_onode.c) agree on byte layout over a real Unix socket. The
C unit tests and Python smoke tests pass independently; this harness
proves they pass together.

Opt-in — run with: make test-validator-e2e
(Requires prod-full: build/virp-onode-prod must exist.)

Scope is intentionally small: three round-trips (PASS, BLOCK on
prose_hash, WARN on null evidence). Matrix-level coverage stays in
tests/test_validator.c.
"""

import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_ROOT)

from api.validator import (  # noqa: E402
    Decision, Violation, Assertion, build_manifest, validate_turn,
)


ONODE_BIN = os.path.join(REPO_ROOT, "build", "virp-onode-prod")
VIRP_FRAME_VERSION = 0x02


def _send_framed(sock, obj):
    payload = json.dumps(obj).encode("utf-8")
    frame_len = 1 + len(payload)
    sock.sendall(struct.pack("!I", frame_len) + bytes([VIRP_FRAME_VERSION]) + payload)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed prematurely")
        buf += chunk
    return buf


def _recv_framed(sock):
    length = struct.unpack("!I", _recv_exact(sock, 4))[0]
    return b"" if length == 0 else _recv_exact(sock, length)


class ValidatorE2E(unittest.TestCase):
    """Round-trip tests against a real virp-onode-prod subprocess."""

    proc: "subprocess.Popen | None" = None
    tmp: str = ""

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(ONODE_BIN):
            raise unittest.SkipTest(
                f"missing {ONODE_BIN}; run: make prod-full"
            )

        cls.tmp = tempfile.mkdtemp(prefix="virp_test_e2e_")
        cls.okey_path   = os.path.join(cls.tmp, "okey.bin")
        cls.chain_key   = os.path.join(cls.tmp, "chain.key")
        cls.chain_db    = os.path.join(cls.tmp, "chain.db")
        cls.sock_path   = os.path.join(cls.tmp, "onode.sock")
        cls.devices     = os.path.join(cls.tmp, "devices.json")

        # O-Key and chain key: 32 raw bytes each, mode 0600, owned by
        # this UID. The prod binary refuses to generate an O-Key at
        # startup even though its usage help says it will; load-only.
        for path in (cls.okey_path, cls.chain_key):
            with open(path, "wb") as f:
                f.write(os.urandom(32))
            os.chmod(path, 0o600)

        # The prod binary refuses to start without at least one device.
        # A mock device satisfies that; no connection is made until a
        # execute request targets it, and this harness never sends one.
        with open(cls.devices, "w") as f:
            json.dump({"devices": [{
                "hostname": "mock-1",
                "host": "127.0.0.1",
                "port": 22,
                "vendor": "mock",
                "username": "u",
                "password": "p",
                "node_id": "01010101",
            }]}, f)

        cls.proc = subprocess.Popen(
            [ONODE_BIN,
             "-k", cls.okey_path,
             "-s", cls.sock_path,
             "-d", cls.devices,
             "-c", cls.chain_db,
             "-C", cls.chain_key,
             "-n", "00000001"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        # Poll until the socket is connectable. 5s is generous for a
        # local run — prod startup is normally <100ms.
        deadline = time.monotonic() + 5.0
        ready = False
        while time.monotonic() < deadline:
            if cls.proc.poll() is not None:
                err = cls.proc.stderr.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"virp-onode died during startup:\n{err}")
            if os.path.exists(cls.sock_path):
                try:
                    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    probe.settimeout(0.5)
                    probe.connect(cls.sock_path)
                    probe.close()
                    ready = True
                    break
                except OSError:
                    pass
            time.sleep(0.05)
        if not ready:
            cls.proc.terminate()
            raise RuntimeError("virp-onode socket never became connectable")

        # Seed the chain with one observation so the PASS case has a
        # real artifact_hash to cite. Use chain_append — the same
        # dispatcher path a live tool result would take.
        cls.seed_hash = hashlib.sha256(b"seed-tool-output").hexdigest()
        cls.seed_session = "s-e2e"
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5.0)
        try:
            s.connect(cls.sock_path)
            _send_framed(s, {
                "action":        "chain_append",
                "session_id":    cls.seed_session,
                "artifact_type": "observation",
                "artifact_id":   "obs-seed",
                "artifact_hash": cls.seed_hash,
            })
            resp = _recv_framed(s)
        finally:
            s.close()

        if len(resp) == 4:
            code = struct.unpack("!I", resp)[0]
            raise RuntimeError(f"chain_append seed failed, onode error {code}")
        if len(resp) < 56:
            raise RuntimeError(f"chain_append seed: short response ({len(resp)}B)")

    @classmethod
    def tearDownClass(cls):
        if cls.proc is not None and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
                cls.proc.wait(timeout=2)
        if cls.tmp:
            shutil.rmtree(cls.tmp, ignore_errors=True)

    # -- Round trips --------------------------------------------------

    def test_pass_roundtrip(self):
        """Evidence seeded in chain + cited in manifest → PASS."""
        prose = "BGP session on r1 is established."
        manifest = build_manifest(
            session_id=self.seed_session,
            prose=prose,
            tool_call_refs=[self.seed_hash],
            assertions=[
                Assertion(device="r1",
                          claim_type="state_observation",
                          evidence_ref=self.seed_hash),
            ],
        )
        r = validate_turn(self.seed_session, prose, manifest,
                          socket_path=self.sock_path)
        self.assertEqual(r.decision, Decision.PASS,
                         f"expected PASS, got {r.decision.name} "
                         f"({r.turn_violation.name})")
        self.assertEqual(r.turn_violation, Violation.NONE)
        self.assertEqual(len(r.per_assertion), 1)
        self.assertEqual(r.per_assertion[0][0], Decision.PASS)
        self.assertGreaterEqual(r.chain_sequence, 1)
        self.assertEqual(len(r.chain_entry_hash), 64)

    def test_block_prose_hash_mismatch(self):
        """Declared prose_hash does not match SHA-256(prose) → BLOCK."""
        prose = "the real bytes"
        manifest = {
            "session_id":     self.seed_session,
            "prose_hash":     "0" * 64,  # deliberately wrong
            "tool_call_refs": [],
            "assertions":     [],
        }
        r = validate_turn(self.seed_session, prose, manifest,
                          socket_path=self.sock_path)
        self.assertEqual(r.decision, Decision.BLOCK)
        self.assertEqual(r.turn_violation, Violation.PROSE_HASH_MISMATCH)

    def test_warn_state_read_no_evidence(self):
        """state_read + explicit null evidence → WARN."""
        prose = "r1 looks healthy, broadly speaking."
        manifest = build_manifest(
            session_id=self.seed_session,
            prose=prose,
            tool_call_refs=[],
            assertions=[
                Assertion(device="r1",
                          claim_type="state_observation",
                          evidence_ref=None),
            ],
        )
        r = validate_turn(self.seed_session, prose, manifest,
                          socket_path=self.sock_path)
        self.assertEqual(r.decision, Decision.WARN)
        self.assertEqual(r.turn_violation, Violation.NONE)
        self.assertEqual(r.per_assertion[0][0], Decision.WARN)
        self.assertEqual(r.per_assertion[0][1],
                         Violation.NO_EVIDENCE_STATE_READ)


if __name__ == "__main__":
    unittest.main(verbosity=2)
