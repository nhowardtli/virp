#!/usr/bin/env python3
"""
Test: parse_virp_message() bounds checks on header length field (audit item 9).

Verifies that:
  1. A truncated message (declared length > actual) raises ValueError.
  2. An oversized declared length raises ValueError.
  3. A length smaller than VIRP_HEADER_SIZE raises ValueError.
  4. A valid message parses successfully.
"""

import ctypes
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

# We need to set up server.py's globals before importing parse_virp_message.
# Import the module and configure minimal state.
import server as srv
srv.key_material = None
srv.key_fingerprint = None
srv._virp_bridge = None
srv.VIRP_ALLOW_PY_FALLBACK = False

VIRP_HEADER_SIZE = 56


def _make_header(length: int, version=1, msg_type=1, node_id=1,
                 channel=1, tier=1, seq_num=1, timestamp_ns=0) -> bytes:
    """Build a 56-byte VIRP header with the given length field."""
    hdr = struct.pack("!BBHI BBHI Q",
                      version, msg_type, length, node_id,
                      channel, tier, 0,
                      seq_num, timestamp_ns)
    # Pad to 56 bytes (hdr is 24 bytes, need 32 bytes of fake HMAC)
    return hdr + b'\x00' * (VIRP_HEADER_SIZE - len(hdr))


class TestParseMessageBounds(unittest.TestCase):

    def test_truncated_message_raises(self):
        """Declared length > actual message size → ValueError."""
        payload = b"hello"
        actual_len = VIRP_HEADER_SIZE + len(payload)
        # Declare length larger than actual
        hdr = _make_header(length=actual_len + 100)
        msg = hdr + payload
        with self.assertRaises(ValueError) as ctx:
            srv.parse_virp_message(msg)
        self.assertIn("actual message size", str(ctx.exception))

    def test_oversized_declared_length(self):
        """Declared length = 65535, actual = 60 → ValueError."""
        hdr = _make_header(length=65535)
        msg = hdr + b"tiny"
        with self.assertRaises(ValueError) as ctx:
            srv.parse_virp_message(msg)
        self.assertIn("actual message size", str(ctx.exception))

    def test_length_too_small(self):
        """Declared length < VIRP_HEADER_SIZE → ValueError."""
        hdr = _make_header(length=10)
        msg = hdr
        with self.assertRaises(ValueError) as ctx:
            srv.parse_virp_message(msg)
        self.assertIn("header size", str(ctx.exception))

    def test_too_short_message(self):
        """Message shorter than VIRP_HEADER_SIZE → ValueError."""
        with self.assertRaises(ValueError) as ctx:
            srv.parse_virp_message(b"\x01\x01\x00\x38")
        self.assertIn("too short", str(ctx.exception))

    def test_valid_message_parses(self):
        """A correctly formed message parses without error."""
        payload = b"show ip route output here"
        length = VIRP_HEADER_SIZE + len(payload)
        hdr = _make_header(length=length)
        msg = hdr + payload
        result = srv.parse_virp_message(msg)
        self.assertEqual(result["payload_length"], len(payload))
        self.assertFalse(result["verified"])  # No key loaded


if __name__ == "__main__":
    unittest.main(verbosity=2)
