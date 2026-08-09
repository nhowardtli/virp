#!/usr/bin/env python3
"""Q1(c)(i) evidence: commitment-only observations, FIELD vs ROLL-UP.

chain_append GATE 3 (src/virp_onode.c:2548, inside the body-present
branch at :2548) does not run when no body is submitted — there are no
bytes to check a signature over — so a caller CAN register an entry
that commits to a hash alone.

The two levels answer differently, and the tests below are split to
match:

  FIELD    — v.obs_hmac is UNVERIFIABLE, never PASS. Correct, and what
             the SECURITY.md rationale for accepting commitment-only
             appends rests on.
  ROLL-UP  — v.ok is TRUE anyway, because it is `FAIL not in (...)` and
             UNVERIFIABLE is not FAIL. So the entry is excluded from
             summarize()'s failed_entries and rendered as the literal
             string PASS by virp_report.py. That is a real gap, pinned
             here as an expected failure rather than argued away.

If the FIELD assertions ever start returning PASS for a body-less
observation, the commitment-only decision has silently become a real
bypass and GATE 3 must start requiring a body.
"""
import hashlib
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

    # -----------------------------------------------------------------
    # The scope line of everything above: they bind the per-entry FIELD.
    # The roll-up is a different question, and it currently answers it
    # the other way.
    # -----------------------------------------------------------------

    def _well_formed_bodyless_entry(self):
        """A commitment-only observation whose OTHER checks all pass, so
        nothing else masks what the roll-up does. Self-contained: the
        entry hash is computed with verify's own canonical_json, so this
        needs no chain database."""
        e = self._entry("obs:librenms:oversized")
        e["previous_entry_hash"] = "d" * 64
        e["chain_entry_hash"] = hashlib.sha256(
            verify.canonical_json(e).encode()).hexdigest()
        return e

    @unittest.expectedFailure
    def test_KNOWN_GAP_bodyless_entry_still_rolls_up_as_ok(self):
        """DOCUMENTS A KNOWN GAP. Expected to FAIL until the roll-up
        gains a tri-state.

        `EntryVerification.ok` is `FAIL not in (...)`, so UNVERIFIABLE
        and UNCHECKED both pass through as "not a failure". A
        commitment-only observation therefore reports ok=True, is left
        out of summarize()'s failed_entries, and is rendered as the
        literal string PASS in the generated PDF — for an observation
        whose signature was never checked, because there were no bytes
        to check.

        Reproduced against a real production entry
        (obs:librenms-lab:1786029902471700439) on 2026-08-09, not only
        this synthetic one.

        This is the PASS/UNCHECKED tri-state item from the 2026-08-07
        review. Fixing it changes operator-facing verdicts on tens of
        thousands of existing entries and is deliberately NOT bundled
        into an unrelated deploy payload.

        WHEN THAT IS FIXED this test will report an unexpected success,
        which unittest treats as a failing run — that is the point. Drop
        the decorator then, and tighten the SECURITY.md rationale, which
        currently has to say the report renders PASS.
        """
        okey = bytes(range(32))
        e = self._well_formed_bodyless_entry()
        v = verify.verify_entry(e, None, okey, None, e["previous_entry_hash"])

        # Preconditions: nothing but the body-less checks is unresolved,
        # so ok() is answering about exactly this situation.
        self.assertEqual(v.entry_hash, verify.PASS)
        self.assertEqual(v.link, verify.PASS)
        self.assertEqual(v.obs_hmac, verify.UNVERIFIABLE)

        # THE GAP: an unverified observation must not roll up as ok.
        self.assertFalse(
            v.ok,
            "commitment-only entry rolled up as ok=True — an observation "
            "whose signature was never checked reads as PASS in the report")


if __name__ == "__main__":
    unittest.main(verbosity=2)
