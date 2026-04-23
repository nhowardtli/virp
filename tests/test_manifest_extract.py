"""Unit tests for extract_validator_manifest."""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from server import extract_validator_manifest

import json
import unittest


class TestExtractValidatorManifest(unittest.TestCase):

    def test_well_formed(self):
        manifest_obj = {"assertions": [{"id": "a_01", "device": "R1",
                        "claim_type": "state_read",
                        "claim_text": "Gi0/1 is up",
                        "evidence_ref": "toolu_abc123"}]}
        text = (
            "R1 Gi0/1 is up.\n"
            "<<<VALIDATOR_MANIFEST>>>\n"
            + json.dumps(manifest_obj) + "\n"
            "<<<END_VALIDATOR_MANIFEST>>>"
        )
        stripped, manifest, err = extract_validator_manifest(text)
        self.assertIsNone(err)
        self.assertNotIn("<<<", stripped)
        self.assertEqual(stripped, "R1 Gi0/1 is up.")
        self.assertEqual(manifest["assertions"][0]["id"], "a_01")

    def test_missing_delimiters(self):
        text = "No manifest here. Just plain text."
        stripped, manifest, err = extract_validator_manifest(text)
        self.assertEqual(stripped, text)
        self.assertIsNone(manifest)
        self.assertIsNone(err)

    def test_missing_close_delimiter(self):
        text = "Some text\n<<<VALIDATOR_MANIFEST>>>\n{\"assertions\": []}"
        stripped, manifest, err = extract_validator_manifest(text)
        self.assertIsNone(manifest)
        self.assertEqual(err, "manifest opening delimiter without close")

    def test_bad_json(self):
        text = (
            "Text\n"
            "<<<VALIDATOR_MANIFEST>>>\n"
            "{bad json!!!}\n"
            "<<<END_VALIDATOR_MANIFEST>>>"
        )
        stripped, manifest, err = extract_validator_manifest(text)
        self.assertEqual(stripped, "Text")
        self.assertIsNone(manifest)
        self.assertIn("JSON parse failed", err)

    def test_missing_assertions_key(self):
        text = (
            "Text\n"
            "<<<VALIDATOR_MANIFEST>>>\n"
            '{"other": 123}\n'
            "<<<END_VALIDATOR_MANIFEST>>>"
        )
        stripped, manifest, err = extract_validator_manifest(text)
        self.assertIsNone(manifest)
        self.assertEqual(err, "manifest missing 'assertions' key")

    def test_assertions_not_a_list(self):
        text = (
            "Text\n"
            "<<<VALIDATOR_MANIFEST>>>\n"
            '{"assertions": "not a list"}\n'
            "<<<END_VALIDATOR_MANIFEST>>>"
        )
        stripped, manifest, err = extract_validator_manifest(text)
        self.assertIsNone(manifest)
        self.assertEqual(err, "manifest 'assertions' not a list")

    def test_empty_assertions_valid(self):
        text = (
            "No claims.\n"
            "<<<VALIDATOR_MANIFEST>>>\n"
            '{"assertions": []}\n'
            "<<<END_VALIDATOR_MANIFEST>>>"
        )
        stripped, manifest, err = extract_validator_manifest(text)
        self.assertIsNone(err)
        self.assertEqual(stripped, "No claims.")
        self.assertEqual(manifest["assertions"], [])

    def test_delimiters_present_zero_length_content(self):
        text = (
            "Text\n"
            "<<<VALIDATOR_MANIFEST>>>\n"
            "<<<END_VALIDATOR_MANIFEST>>>"
        )
        stripped, manifest, err = extract_validator_manifest(text)
        self.assertIsNone(manifest)
        self.assertIn("JSON parse failed", err)

    def test_text_after_manifest_preserved(self):
        text = (
            "Before.\n"
            "<<<VALIDATOR_MANIFEST>>>\n"
            '{"assertions": []}\n'
            "<<<END_VALIDATOR_MANIFEST>>>\n"
            "After."
        )
        stripped, manifest, err = extract_validator_manifest(text)
        self.assertIsNone(err)
        self.assertIn("Before.", stripped)
        self.assertIn("After.", stripped)
        self.assertNotIn("<<<", stripped)


if __name__ == "__main__":
    unittest.main()
