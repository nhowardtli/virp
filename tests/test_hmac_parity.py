#!/usr/bin/env python3
"""
Test: C and Python HMAC verification produce identical results (audit item 3).

Uses the C library to build a signed observation, then verifies it via:
  1. The C bridge (virp_verify)
  2. Pure Python (hmac.new + hmac.compare_digest)
Both must agree on valid messages, tampered messages, and wrong keys.
"""

import ctypes
import hashlib
import hmac as hmac_mod
import os
import sys
import unittest

VIRP_KEY_SIZE = 32
VIRP_HMAC_SIZE = 32
VIRP_HEADER_SIZE = 56
VIRP_MAX_MESSAGE_SIZE = 65536


class VIRPKey(ctypes.Structure):
    _fields_ = [("key", ctypes.c_uint8 * VIRP_KEY_SIZE), ("loaded", ctypes.c_bool)]


class VIRPSigningKey(ctypes.Structure):
    _fields_ = [
        ("key", VIRPKey),
        ("type", ctypes.c_int),
        ("fingerprint", ctypes.c_uint8 * VIRP_HMAC_SIZE),
    ]


def _load_lib():
    path = os.environ.get("VIRP_LIB_PATH", "build/libvirp.so")
    lib = ctypes.CDLL(path)
    lib.virp_key_init.argtypes = [
        ctypes.POINTER(VIRPSigningKey), ctypes.c_int, ctypes.POINTER(ctypes.c_uint8)]
    lib.virp_key_init.restype = ctypes.c_int
    lib.virp_build_observation.argtypes = [
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t), ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_uint8, ctypes.c_uint8, ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_uint16, ctypes.POINTER(VIRPSigningKey)]
    lib.virp_build_observation.restype = ctypes.c_int
    lib.virp_verify.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t, ctypes.POINTER(VIRPSigningKey)]
    lib.virp_verify.restype = ctypes.c_int
    return lib


def _make_key(lib, key_bytes: bytes):
    sk = VIRPSigningKey()
    kb = (ctypes.c_uint8 * VIRP_KEY_SIZE)(*key_bytes)
    assert lib.virp_key_init(ctypes.byref(sk), 1, kb) == 0
    return sk


def _sign(lib, sk, payload: bytes):
    buf = (ctypes.c_uint8 * VIRP_MAX_MESSAGE_SIZE)()
    out_len = ctypes.c_size_t(0)
    dbuf = (ctypes.c_uint8 * len(payload))(*payload)
    err = lib.virp_build_observation(
        buf, ctypes.c_size_t(VIRP_MAX_MESSAGE_SIZE), ctypes.byref(out_len),
        ctypes.c_uint32(1), ctypes.c_uint32(1),
        ctypes.c_uint8(0x07), ctypes.c_uint8(0x01),
        dbuf, ctypes.c_uint16(len(payload)), ctypes.byref(sk))
    assert err == 0
    return bytes(buf[:out_len.value])


def _c_verify(lib, sk, msg: bytes) -> bool:
    mbuf = (ctypes.c_uint8 * len(msg))(*msg)
    return lib.virp_verify(None, mbuf, ctypes.c_size_t(len(msg)), ctypes.byref(sk)) == 0


def _py_verify(key_bytes: bytes, msg: bytes) -> bool:
    """Python HMAC verification — same logic as server.py's fallback."""
    if len(msg) < VIRP_HEADER_SIZE:
        return False
    import struct
    length = struct.unpack_from("!H", msg, 2)[0]
    payload_len = length - VIRP_HEADER_SIZE
    received_hmac = msg[24:56]
    sign_buf = msg[0:24] + msg[56:56 + payload_len]
    computed = hmac_mod.new(key_bytes, sign_buf, hashlib.sha256).digest()
    return hmac_mod.compare_digest(computed, received_hmac)


class TestHMACParity(unittest.TestCase):
    """C and Python HMAC verification must agree on all inputs."""

    @classmethod
    def setUpClass(cls):
        cls.lib = _load_lib()
        cls.key_bytes = bytes([0xAA] * VIRP_KEY_SIZE)
        cls.sk = _make_key(cls.lib, cls.key_bytes)
        cls.other_key_bytes = bytes([0xBB] * VIRP_KEY_SIZE)
        cls.other_sk = _make_key(cls.lib, cls.other_key_bytes)

    def test_valid_message_both_agree(self):
        msg = _sign(self.lib, self.sk, b"show ip bgp summary")
        self.assertTrue(_c_verify(self.lib, self.sk, msg))
        self.assertTrue(_py_verify(self.key_bytes, msg))

    def test_tampered_message_both_reject(self):
        msg = bytearray(_sign(self.lib, self.sk, b"show version"))
        msg[-1] ^= 0xFF
        msg = bytes(msg)
        self.assertFalse(_c_verify(self.lib, self.sk, msg))
        self.assertFalse(_py_verify(self.key_bytes, msg))

    def test_wrong_key_both_reject(self):
        msg = _sign(self.lib, self.sk, b"get system status")
        self.assertFalse(_c_verify(self.lib, self.other_sk, msg))
        self.assertFalse(_py_verify(self.other_key_bytes, msg))

    def test_multiple_payloads_agree(self):
        """Several different payloads all agree between C and Python."""
        payloads = [b"", b"a", b"x" * 1000, b"\x00\xff" * 50]
        for payload in payloads:
            msg = _sign(self.lib, self.sk, payload)
            c_ok = _c_verify(self.lib, self.sk, msg)
            py_ok = _py_verify(self.key_bytes, msg)
            self.assertEqual(c_ok, py_ok,
                             f"Disagreement on payload len={len(payload)}: C={c_ok} Py={py_ok}")
            self.assertTrue(c_ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)
