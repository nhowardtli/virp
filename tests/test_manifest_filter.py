"""Unit tests for _filter_manifest_for_stream and _flush_manifest_buffer."""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from server import _filter_manifest_for_stream, _flush_manifest_buffer

import unittest


def _new_block_state():
    return {"in_manifest": False, "manifest_buffer": ""}


def _simulate_stream(chunks):
    """Feed chunks through the filter, return concatenated visible output."""
    bs = _new_block_state()
    parts = []
    for chunk in chunks:
        visible = _filter_manifest_for_stream(bs, chunk)
        if visible:
            parts.append(visible)
    # Flush at the end (simulates content_block_stop)
    flushed = _flush_manifest_buffer(bs)
    if flushed:
        parts.append(flushed)
    return "".join(parts)


class TestManifestFilter(unittest.TestCase):

    def test_no_manifest(self):
        """All input emitted unchanged when no manifest is present."""
        chunks = ["Hello ", "world. ", "All good."]
        result = _simulate_stream(chunks)
        self.assertEqual(result, "Hello world. All good.")

    def test_manifest_single_chunk(self):
        """Manifest in one chunk — before/after emitted, manifest hidden."""
        text = (
            "R1 is up."
            "<<<VALIDATOR_MANIFEST>>>"
            '{"assertions":[]}'
            "<<<END_VALIDATOR_MANIFEST>>>"
            " Done."
        )
        result = _simulate_stream([text])
        self.assertEqual(result, "R1 is up. Done.")
        self.assertNotIn("<<<", result)
        self.assertNotIn("assertions", result)

    def test_opening_delimiter_split(self):
        """Opening delimiter split across two chunks."""
        chunks = [
            "Some text<<<VALIDATOR_",
            'MANIFEST>>>{"assertions":[]}<<<END_VALIDATOR_MANIFEST>>>after',
        ]
        result = _simulate_stream(chunks)
        self.assertNotIn("<<<", result)
        self.assertNotIn("VALIDATOR", result)
        self.assertIn("Some text", result)
        self.assertIn("after", result)

    def test_closing_delimiter_split(self):
        """Closing delimiter split across two chunks."""
        chunks = [
            'before<<<VALIDATOR_MANIFEST>>>{"assertions":[]}<<<END_VALIDAT',
            "OR_MANIFEST>>>after",
        ]
        result = _simulate_stream(chunks)
        self.assertNotIn("<<<", result)
        self.assertIn("before", result)
        self.assertIn("after", result)

    def test_text_ends_mid_manifest(self):
        """LLM truncated — flush does NOT emit content inside open manifest."""
        chunks = [
            "visible text",
            '<<<VALIDATOR_MANIFEST>>>{"assertions": [',
        ]
        result = _simulate_stream(chunks)
        self.assertEqual(result, "visible text")
        self.assertNotIn("assertions", result)

    def test_multiple_small_deltas(self):
        """Manifest delimiters arrive one character at a time."""
        full = (
            "pre"
            "<<<VALIDATOR_MANIFEST>>>"
            '{"assertions":[]}'
            "<<<END_VALIDATOR_MANIFEST>>>"
            "post"
        )
        # Feed one character at a time
        chunks = list(full)
        result = _simulate_stream(chunks)
        self.assertNotIn("<<<", result)
        self.assertNotIn("assertions", result)
        self.assertIn("pre", result)
        self.assertIn("post", result)

    def test_partial_start_delimiter_not_completed(self):
        """A partial start delimiter that is NOT completed is flushed."""
        chunks = ["hello<<<VALIDAT", "no manifest here"]
        result = _simulate_stream(chunks)
        # The partial "<<<VALIDAT" is not a real delimiter since
        # the next chunk doesn't continue it. It should eventually
        # be emitted.
        self.assertIn("hello", result)
        self.assertIn("no manifest here", result)

    def test_empty_manifest_body(self):
        """Empty body between delimiters."""
        text = "a<<<VALIDATOR_MANIFEST>>><<<END_VALIDATOR_MANIFEST>>>b"
        result = _simulate_stream([text])
        self.assertEqual(result, "ab")

    def test_flush_when_not_in_manifest(self):
        """Flush emits buffered content when not inside manifest."""
        bs = _new_block_state()
        # Feed text ending with a partial delimiter prefix
        _filter_manifest_for_stream(bs, "hello<<<")
        self.assertTrue(len(bs["manifest_buffer"]) > 0)
        flushed = _flush_manifest_buffer(bs)
        self.assertEqual(flushed, "<<<")

    def test_flush_inside_manifest_discards(self):
        """Flush inside a manifest discards the buffer."""
        bs = _new_block_state()
        _filter_manifest_for_stream(bs, "text<<<VALIDATOR_MANIFEST>>>partial")
        self.assertTrue(bs["in_manifest"])
        flushed = _flush_manifest_buffer(bs)
        self.assertEqual(flushed, "")


if __name__ == "__main__":
    unittest.main()
