"""Unit tests for evidence_map translation and violation code stringification."""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from server import _stringify_violation, VALIDATOR_VIOLATION_CODES

import unittest


class TestStringifyViolation(unittest.TestCase):

    def test_int_zero_is_none(self):
        self.assertEqual(_stringify_violation(0), "none")

    def test_known_int_codes(self):
        for code, expected in VALIDATOR_VIOLATION_CODES.items():
            self.assertEqual(_stringify_violation(code), expected)

    def test_unknown_int_code(self):
        result = _stringify_violation(999)
        self.assertIn("999", result)
        self.assertIn("unknown", result)

    def test_string_none_passthrough(self):
        self.assertEqual(_stringify_violation("none"), "none")

    def test_string_message_passthrough(self):
        self.assertEqual(
            _stringify_violation("custom validator message"),
            "custom validator message",
        )

    def test_evidence_ref_invalid_code(self):
        result = _stringify_violation(1)
        self.assertIn("tool_use_id", result)

    def test_prose_hash_mismatch_code(self):
        result = _stringify_violation(5)
        self.assertIn("prose_hash", result)


class TestEvidenceMapTranslation(unittest.TestCase):
    """Test that validate_turn_with_211 translates evidence_refs correctly.

    These tests exercise the translation logic by building a manifest
    and evidence_map, then checking the wire_assertions output.  Since
    calling the real validator requires CT 211 connectivity, we test the
    translation code path in isolation.
    """

    def _translate_assertions(self, assertions, evidence_map):
        """Replicate the evidence_ref translation from validate_turn_with_211."""
        wire_assertions = []
        for a in assertions:
            wa = dict(a)
            ref = wa.get("evidence_ref")
            if ref and ref in evidence_map:
                wa["evidence_ref"] = evidence_map[ref]
            wire_assertions.append(wa)
        return wire_assertions

    def test_translates_known_sequential_index(self):
        assertions = [
            {"id": "a_01", "evidence_ref": "tool_result[0]"},
        ]
        emap = {"tool_result[0]": "deadbeef" * 8}
        result = self._translate_assertions(assertions, emap)
        self.assertEqual(result[0]["evidence_ref"], "deadbeef" * 8)

    def test_preserves_null_evidence_ref(self):
        assertions = [
            {"id": "a_01", "evidence_ref": None},
        ]
        emap = {"tool_result[0]": "deadbeef" * 8}
        result = self._translate_assertions(assertions, emap)
        self.assertIsNone(result[0]["evidence_ref"])

    def test_preserves_unknown_evidence_ref(self):
        """Unknown refs pass through untranslated (fail-closed)."""
        assertions = [
            {"id": "a_01", "evidence_ref": "tool_result[99]"},
        ]
        emap = {"tool_result[0]": "deadbeef" * 8}
        result = self._translate_assertions(assertions, emap)
        self.assertEqual(result[0]["evidence_ref"], "tool_result[99]")

    def test_multiple_assertions_mixed(self):
        assertions = [
            {"id": "a_01", "evidence_ref": "tool_result[0]"},
            {"id": "a_02", "evidence_ref": None},
            {"id": "a_03", "evidence_ref": "tool_result[1]"},
        ]
        emap = {
            "tool_result[0]": "aaaa" * 16,
            "tool_result[1]": "bbbb" * 16,
        }
        result = self._translate_assertions(assertions, emap)
        self.assertEqual(result[0]["evidence_ref"], "aaaa" * 16)
        self.assertIsNone(result[1]["evidence_ref"])
        self.assertEqual(result[2]["evidence_ref"], "bbbb" * 16)

    def test_does_not_mutate_original(self):
        assertions = [{"id": "a_01", "evidence_ref": "tool_result[0]"}]
        emap = {"tool_result[0]": "hash123"}
        self._translate_assertions(assertions, emap)
        self.assertEqual(assertions[0]["evidence_ref"], "tool_result[0]")

    def test_empty_evidence_map_passthrough(self):
        assertions = [{"id": "a_01", "evidence_ref": "tool_result[0]"}]
        result = self._translate_assertions(assertions, {})
        self.assertEqual(result[0]["evidence_ref"], "tool_result[0]")

    def test_evidence_ref_synthetic_descriptive_name_falls_through(self):
        """A model emitting 'result_R1_show_interfaces' (synthetic
        descriptive name) must NOT accidentally translate. Translation
        must fall through, leaving the non-hex name in place, so the
        validator rejects the manifest.
        """
        evidence_map = {"tool_result[0]": "abc123de" * 8}
        assertions = [{"id": "a_01", "device": "R1",
                       "claim_type": "state_read",
                       "evidence_ref": "result_R1_show_interfaces"}]
        result = self._translate_assertions(assertions, evidence_map)
        # Must remain unchanged — NOT translated to the hash
        self.assertEqual(result[0]["evidence_ref"], "result_R1_show_interfaces")


if __name__ == "__main__":
    unittest.main()
