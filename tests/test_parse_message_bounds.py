#!/usr/bin/env python3
"""
Test: parse_virp_message() bounds checks on header length field.

Size validation now returns a dict with `parse_error` set rather than
raising, so callers handle parse failures uniformly with HMAC failures.
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import server as srv
srv.key_material = None
srv.key_fingerprint = None
srv._virp_bridge = None
srv.VIRP_ALLOW_PY_FALLBACK = False

VIRP_HEADER_SIZE = 56


def _make_header(length: int, version=1, msg_type=1, node_id=1,
                 channel=1, tier=1, seq_num=1, timestamp_ns=0) -> bytes:
    hdr = struct.pack("!BBHI BBHI Q",
                      version, msg_type, length, node_id,
                      channel, tier, 0,
                      seq_num, timestamp_ns)
    return hdr + b'\x00' * (VIRP_HEADER_SIZE - len(hdr))


class TestParseMessageBounds(unittest.TestCase):

    def test_truncated_message(self):
        """Declared length > actual buffer → parse_error."""
        payload = b"hello"
        actual_len = VIRP_HEADER_SIZE + len(payload)
        hdr = _make_header(length=actual_len + 100)
        msg = hdr + payload
        result = srv.parse_virp_message(msg)
        self.assertIn("parse_error", result)
        self.assertIn("declared length", result["parse_error"])
        self.assertFalse(result["verified"])

    def test_length_too_small(self):
        """Declared length < VIRP_HEADER_SIZE → parse_error."""
        hdr = _make_header(length=10)
        result = srv.parse_virp_message(hdr)
        self.assertIn("parse_error", result)
        self.assertIn("header size", result["parse_error"])

    def test_too_short_message(self):
        """Message shorter than VIRP_HEADER_SIZE → parse_error."""
        result = srv.parse_virp_message(b"\x01\x01\x00\x38")
        self.assertIn("parse_error", result)
        self.assertIn("too short", result["parse_error"])

    def test_length_over_max_frame(self):
        """Declared length > VIRP_MAX_FRAME → parse_error (new check).

        We pad the buffer so this can't trip the buffer-vs-length check
        first — the MAX_FRAME cap must be what rejects it."""
        too_big = srv.VIRP_MAX_FRAME + 1
        hdr = _make_header(length=too_big)
        msg = hdr + b'\x00' * (too_big - VIRP_HEADER_SIZE)
        result = srv.parse_virp_message(msg)
        self.assertIn("parse_error", result)
        self.assertIn("VIRP_MAX_FRAME", result["parse_error"])

    def test_length_at_max_frame_still_validates_buffer(self):
        """Declared length == VIRP_MAX_FRAME with a short buffer still
        rejects (via the buffer-length check, not the MAX_FRAME cap)."""
        hdr = _make_header(length=srv.VIRP_MAX_FRAME)
        msg = hdr + b"tiny"
        result = srv.parse_virp_message(msg)
        self.assertIn("parse_error", result)

    def test_valid_message_parses(self):
        """A correctly formed message parses without error."""
        payload = b"show ip route output here"
        length = VIRP_HEADER_SIZE + len(payload)
        hdr = _make_header(length=length)
        msg = hdr + payload
        result = srv.parse_virp_message(msg)
        self.assertNotIn("parse_error", result)
        self.assertEqual(result["payload_length"], len(payload))
        self.assertFalse(result["verified"])  # no key loaded


if __name__ == "__main__":
    unittest.main(verbosity=2)
