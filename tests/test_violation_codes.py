"""Guards against drift between Python violation codes and the C enum.

Ground truth is /root/virp/include/virp_validator.h on CT 211,
lines 79-88. This test does not read that header at runtime (wrong
box). It asserts local invariants: the dict has exactly codes 0-9,
every entry is a non-empty string, and specific high-traffic codes
have the expected label format.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from server import VALIDATOR_VIOLATION_CODES

import unittest


class TestViolationCodes(unittest.TestCase):

    def test_exact_key_set(self):
        self.assertEqual(set(VALIDATOR_VIOLATION_CODES.keys()),
                         set(range(0, 10)))

    def test_all_values_non_empty_strings(self):
        for code, label in VALIDATOR_VIOLATION_CODES.items():
            self.assertIsInstance(label, str, f"code {code} not str")
            self.assertTrue(label.strip(),   f"code {code} empty")

    def test_code_4_is_chain_check(self):
        """Regression: afternoon of 2026-04-23 showed code 4 labeled
        as a semantic substantiation check, which hid a session_id
        bug. Code 4 is EVIDENCE_NOT_IN_CHAIN — a structural chain
        lookup miss, not a semantic judgement."""
        self.assertIn("chain", VALIDATOR_VIOLATION_CODES[4].lower())

    def test_code_9_is_manifest_missing(self):
        self.assertIn("missing", VALIDATOR_VIOLATION_CODES[9].lower())

    def test_code_7_is_manifest_malformed(self):
        self.assertIn("malformed", VALIDATOR_VIOLATION_CODES[7].lower())

    def test_no_fabrication_language(self):
        """Regression: the prior dict used the phrase 'not
        substantiated by the tool output' for code 4, which reads
        as a fabrication claim. The validator makes structural
        checks, not semantic ones. Banner text must not imply
        semantic judgement."""
        forbidden = ["fabricat", "substantiat", "hallucinat", "lied"]
        for code, label in VALIDATOR_VIOLATION_CODES.items():
            for word in forbidden:
                self.assertNotIn(
                    word, label.lower(),
                    f"code {code} uses forbidden semantic term "
                    f"'{word}' in '{label}'")


if __name__ == "__main__":
    unittest.main()
