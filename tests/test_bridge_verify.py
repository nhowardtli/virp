#!/usr/bin/env python3
"""
Test: virp_verify ctypes signature fix (audit item 1).

Round-trips sign -> verify through ctypes against the C library.
Loads libvirp.so directly to isolate the virp_verify fix from other
bridge issues (fg_route_command missing — audit item 2).

Confirms that:
  1. A freshly signed observation verifies successfully with 4-arg virp_verify.
  2. A tampered message fails verification.
  3. Verification with a different key fails.
"""

import ctypes
import os
import sys
import tempfile
import unittest

VIRP_KEY_SIZE = 32
VIRP_HMAC_SIZE = 32
VIRP_MAX_MESSAGE_SIZE = 65536


class VIRPKey(ctypes.Structure):
    _fields_ = [
        ("key", ctypes.c_uint8 * VIRP_KEY_SIZE),
        ("loaded", ctypes.c_bool),
    ]


class VIRPSigningKey(ctypes.Structure):
    _fields_ = [
        ("key", VIRPKey),
        ("type", ctypes.c_int),
        ("fingerprint", ctypes.c_uint8 * VIRP_HMAC_SIZE),
    ]


def load_lib():
    path = os.environ.get("VIRP_LIB_PATH", "build/libvirp.so")
    return ctypes.CDLL(path)


def setup_verify(lib):
    """Set up virp_verify with the CORRECT 4-arg signature."""
    lib.virp_verify.argtypes = [
        ctypes.c_void_p,                    # ctx (unused, NULL)
        ctypes.POINTER(ctypes.c_uint8),     # msg
        ctypes.c_size_t,                    # msg_len
        ctypes.POINTER(VIRPSigningKey),     # sk
    ]
    lib.virp_verify.restype = ctypes.c_int


def setup_build_observation(lib):
    lib.virp_build_observation.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),     # buf
        ctypes.c_size_t,                    # buf_len
        ctypes.POINTER(ctypes.c_size_t),    # out_len
        ctypes.c_uint32,                    # node_id
        ctypes.c_uint32,                    # seq_num
        ctypes.c_uint8,                     # obs_type
        ctypes.c_uint8,                     # obs_scope
        ctypes.POINTER(ctypes.c_uint8),     # data
        ctypes.c_uint16,                    # data_len
        ctypes.POINTER(VIRPSigningKey),     # sk
    ]
    lib.virp_build_observation.restype = ctypes.c_int


def setup_key_init(lib):
    lib.virp_key_init.argtypes = [
        ctypes.POINTER(VIRPSigningKey),
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint8),
    ]
    lib.virp_key_init.restype = ctypes.c_int


def make_key(lib, fill_byte=0xAA):
    sk = VIRPSigningKey()
    key_bytes = (ctypes.c_uint8 * VIRP_KEY_SIZE)(*([fill_byte] * VIRP_KEY_SIZE))
    err = lib.virp_key_init(ctypes.byref(sk), 1, key_bytes)  # OKEY=1
    assert err == 0, f"virp_key_init failed: {err}"
    return sk


def sign_observation(lib, sk, payload: bytes, node_id=1, seq_num=1):
    buf = (ctypes.c_uint8 * VIRP_MAX_MESSAGE_SIZE)()
    out_len = ctypes.c_size_t(0)
    data_buf = (ctypes.c_uint8 * len(payload))(*payload)
    err = lib.virp_build_observation(
        buf,
        ctypes.c_size_t(VIRP_MAX_MESSAGE_SIZE),
        ctypes.byref(out_len),
        ctypes.c_uint32(node_id),
        ctypes.c_uint32(seq_num),
        ctypes.c_uint8(0x07),  # VIRP_OBS_DEVICE_OUTPUT
        ctypes.c_uint8(0x01),  # VIRP_SCOPE_LOCAL
        data_buf,
        ctypes.c_uint16(len(payload)),
        ctypes.byref(sk),
    )
    assert err == 0, f"virp_build_observation failed: {err}"
    return bytes(buf[:out_len.value])


class TestVerifyFourArgSignature(unittest.TestCase):
    """virp_verify requires 4 args: (ctx, msg, msg_len, sk)."""

    @classmethod
    def setUpClass(cls):
        cls.lib = load_lib()
        setup_key_init(cls.lib)
        setup_build_observation(cls.lib)
        setup_verify(cls.lib)
        cls.sk = make_key(cls.lib, 0xAA)

    def _verify(self, msg: bytes, sk) -> int:
        """Call virp_verify with the correct 4-arg signature."""
        msg_buf = (ctypes.c_uint8 * len(msg))(*msg)
        return self.lib.virp_verify(
            None,  # ctx — NULL, unused
            msg_buf,
            ctypes.c_size_t(len(msg)),
            ctypes.byref(sk),
        )

    def test_sign_then_verify_succeeds(self):
        """build_observation -> verify must return 0 (VIRP_OK)."""
        payload = b"show ip bgp summary\nBGP router identifier 10.0.0.1"
        signed_msg = sign_observation(self.lib, self.sk, payload)
        err = self._verify(signed_msg, self.sk)
        self.assertEqual(err, 0, f"virp_verify should return VIRP_OK(0), got {err}")

    def test_tampered_payload_fails(self):
        """Flipping a payload byte must cause verification to fail."""
        payload = b"show version\nCisco IOS Software"
        signed_msg = bytearray(sign_observation(self.lib, self.sk, payload))
        signed_msg[-1] ^= 0xFF  # flip last byte
        err = self._verify(bytes(signed_msg), self.sk)
        self.assertNotEqual(err, 0, "virp_verify should fail on tampered message")

    def test_wrong_key_fails(self):
        """Verification with a different key must fail."""
        payload = b"get system status"
        signed_msg = sign_observation(self.lib, self.sk, payload)
        other_sk = make_key(self.lib, 0xBB)
        err = self._verify(signed_msg, other_sk)
        self.assertNotEqual(err, 0, "virp_verify should fail with wrong key")


if __name__ == "__main__":
    unittest.main(verbosity=2)
