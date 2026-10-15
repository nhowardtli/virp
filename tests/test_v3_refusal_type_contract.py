#!/usr/bin/env python3
"""Characterize the unresolved v3 refusal-type contract; not execute acceptance.

Both ordinary device bytes and refusal bytes can be cryptographically valid
v3 observations, but the existing schema/parser exposes no error discriminator.
This test records that gap without inventing a payload envelope or using text
prefixes as a security decision.
"""
import hashlib
import hmac
from pathlib import Path
import struct
import sys
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'report'))
import verify

class RefusalTypeContract(unittest.TestCase):
    def frame(self, body):
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        header = struct.pack(verify.OBS_V2_HEADER_FMT,
                             3, 1, 1, 0, 17, 1, 1, bytes(16), 23,
                             hashlib.sha256(b'show version').digest(), len(body))
        span = header + body
        span += hmac.new(bytes(32), span, hashlib.sha256).digest()
        return span + key.sign(span), pub

    def check_body(self, body):
        raw, pub = self.frame(body)
        verdict, detail = verify.classify_observation_v3(raw, pub)
        self.assertEqual(verdict, verify.PASS, detail)
        parsed = verify.parse_observation_v2_payload(raw)  # current v3 payload layout
        self.assertIsNone(parsed['obs_type'])
        self.assertEqual(parsed['text'], body.decode())
        return raw, pub

    def test_gate_rejection_has_no_error_discriminator(self):
        self.check_body(b'ERROR: tier gate blocked; proposal_id=fixture')

    def test_replay_rejection_has_no_error_discriminator(self):
        self.check_body(b'ERROR: apply rejected (approval_reused, err=-37)')

    def test_device_can_print_identical_error_text(self):
        # An appliance printing this line cannot become a gate refusal merely
        # because a consumer looks for "ERROR:". Both bodies have the same type.
        raw, pub = self.check_body(b'ERROR: apply rejected (approval_reused, err=-37)')
        bad = bytearray(raw);bad[88] ^= 1
        self.assertEqual(verify.classify_observation_v3(bytes(bad), pub)[0], verify.FAIL)

    def test_typed_error_preserves_refusal(self):
        body = b"ERROR: approval_reused"
        raw, pub = self.frame(b"VIRP-XO1" + struct.pack("!BBH", 15, 1, len(body)) + body)
        self.assertEqual(verify.classify_observation_v3(raw, pub)[0], verify.PASS)
        self.assertEqual(verify.parse_execute_v3_payload(raw)["obs_type"], 15)

    def test_device_error_text_remains_device_output(self):
        body = b"ERROR: approval_reused"
        raw, _ = self.frame(b"VIRP-XO1" + struct.pack("!BBH", 7, 1, len(body)) + body)
        self.assertEqual(verify.parse_execute_v3_payload(raw)["obs_type"], 7)

    def test_malformed_typed_envelopes_refuse(self):
        for body in [b"VIRP-XO1", b"VIRP-XO1" + struct.pack("!BBH", 8, 1, 0),
                     b"VIRP-XO1" + struct.pack("!BBH", 15, 1, 10)]:
            raw, _ = self.frame(body)
            self.assertIsNone(verify.parse_execute_v3_payload(raw))

if __name__ == '__main__':
    unittest.main(verbosity=2)
