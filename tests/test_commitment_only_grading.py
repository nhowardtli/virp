#!/usr/bin/env python3
"""Q1(c)(i) evidence: a commitment-only observation is UNVERIFIABLE.

chain_append GATE 3 (src/virp_onode.c:2484) does not run when no body is
submitted — there are no bytes to check a signature over — so a caller
CAN register an entry that commits to a hash alone. This test pins the
reason that is not a signature bypass: what such a caller obtains is an
entry every reader grades UNVERIFIABLE, never one that reports as a
verified observation.

If this ever starts returning PASS for a body-less observation, the
commitment-only decision documented in SECURITY.md has silently become
a real bypass and GATE 3 must start requiring a body.
"""
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "report"))

import verify  # noqa: E402


class TestCommitmentOnlyGrading(unittest.TestCase):

    def _entry(self, artifact_id="obs:librenms:1"):
        return {
            "session_id": "autopilot:librenms",
            "sequence": 1,
            "artifact_type": "observation",
            "artifact_id": artifact_id,
            "artifact_hash": "a" * 64,
            "artifact_hash_alg": "sha256",
            "artifact_schema_version": "1",
            "chain_entry_hash": "b" * 64,
            "previous_entry_hash": "0" * 64,
            "timestamp_ns": 1754582400000000000,
            "monotonic_ns": 1,
            "signer_node_id": 0x42,
            "signer_org_id": "local",
            "chain_hmac": "c" * 64,
        }

    def test_body_less_observation_is_unverifiable_not_pass(self):
        """The oversized-LibreNMS shape: entry present, no body stored."""
        okey = bytes(range(32))
        v = verify.verify_entry(self._entry(), None, okey, None, None)

        self.assertEqual(v.obs_hmac, verify.UNVERIFIABLE)
        self.assertNotEqual(v.obs_hmac, verify.PASS)
        self.assertIn("no signed message body", v.obs_hmac_detail)

    def test_attacker_hash_only_entry_cannot_read_as_verified(self):
        """An invented commitment gets the same grade as a legitimate
        one: UNVERIFIABLE. Registering a hash buys an unverifiable row,
        not a forged observation."""
        okey = bytes(range(32))
        v = verify.verify_entry(self._entry("obs:invented:999"), None,
                                okey, None, None)
        self.assertEqual(v.obs_hmac, verify.UNVERIFIABLE)
        self.assertNotEqual(v.obs_hmac, verify.PASS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
