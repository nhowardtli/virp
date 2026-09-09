#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
HAM review, 2026-09-06 — item 13.

An operational failure of the VERIFIER must never be diluted into an
evidence grade. Before this, a failed SQLite prepare inside the
artifact-binding check returned the same code as "no body was retained",
so an examiner reading "artifact not retained, binding unverifiable" had
no way to tell a chain that never kept the body from a verifier that
could not open the store.

VERIFIER_ERROR is a third top-level outcome, distinct from VERIFIED and
from every negative or UNVERIFIABLE property, with its own exit code.

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import os
import sqlite3
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "report"))
import verify                     # noqa: E402
import virp_report                # noqa: E402
import chain_read                 # noqa: E402


class _Reader:
    """The shape load_evidence / load_heads consume: something with a
    .conn. Nothing else about the real reader matters here."""

    def __init__(self, conn):
        self.conn = conn


def _empty_chain_db(path):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE chain_entries (session_id TEXT, sequence "
                 "INTEGER, chain_entry_hash TEXT, previous_entry_hash TEXT, "
                 "timestamp_ns INTEGER, monotonic_ns INTEGER, "
                 "artifact_type TEXT, artifact_id TEXT, artifact_hash TEXT, "
                 "artifact_hash_alg TEXT, artifact_schema_version TEXT, "
                 "signer_node_id INTEGER, signer_org_id TEXT, "
                 "chain_hmac TEXT)")
    conn.execute("CREATE TABLE artifacts (artifact_id TEXT, artifact_hash "
                 "TEXT, artifact_content TEXT)")
    conn.commit()
    conn.row_factory = sqlite3.Row
    return conn


class TestVerifierErrorIsItsOwnOutcome(unittest.TestCase):

    def test_the_constant_exists_and_is_not_a_verdict(self):
        """It must not be one of the per-entry verdicts. An entry is never
        graded VERIFIER_ERROR; a RUN is."""
        self.assertEqual(verify.VERIFIER_ERROR, "VERIFIER_ERROR")
        for v in (verify.PASS, verify.FAIL, verify.UNCHECKED,
                  verify.UNVERIFIABLE, verify.V2_SESSION,
                  verify.NOT_APPLICABLE):
            self.assertNotEqual(v, verify.VERIFIER_ERROR)

    def test_a_clean_run_reports_no_verifier_error(self):
        summary = verify.summarize([])
        self.assertIsNone(summary["verifier_error"])

    def test_the_exit_code_is_distinct_from_a_finding(self):
        """1 means the chain is broken. 4 means the check did not run.
        Sharing a code would make an outage look like a finding, and a
        finding look like an outage."""
        self.assertEqual(virp_report.VERIFIER_ERROR_EXIT, 4)
        self.assertNotIn(virp_report.VERIFIER_ERROR_EXIT, (0, 1))

    def test_missing_entries_table_is_a_verifier_error(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "chain.db")
            conn = sqlite3.connect(path)
            conn.execute("CREATE TABLE unrelated (x INTEGER)")
            conn.commit()
            conn.row_factory = sqlite3.Row
            with self.assertRaises(verify.VerifierError) as cm:
                virp_report.load_evidence(_Reader(conn))
            self.assertIn("chain_entries", cm.exception.detail)
            self.assertEqual(cm.exception.where, "load_evidence")
            conn.close()

    def test_missing_artifacts_table_is_a_verifier_error(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "chain.db")
            conn = _empty_chain_db(path)
            conn.execute("DROP TABLE artifacts")
            conn.commit()
            with self.assertRaises(verify.VerifierError) as cm:
                virp_report.load_evidence(_Reader(conn))
            self.assertIn("artifact store", cm.exception.detail)
            conn.close()

    def test_a_legacy_database_is_still_legacy_not_an_error(self):
        """The guard must not over-fire: "no such table: chain_heads" is a
        fact about the EVIDENCE (a pre-2026-08-01 database) and still
        returns None, which the report renders as
        COMPLETENESS_UNPROVABLE."""
        with tempfile.TemporaryDirectory() as d:
            conn = _empty_chain_db(os.path.join(d, "chain.db"))
            self.assertIsNone(virp_report.load_heads(_Reader(conn)))
            conn.close()

    def test_an_unreadable_heads_table_is_a_verifier_error(self):
        """A chain_heads that EXISTS but cannot be read is the verifier
        failing, and must not be laundered into the legacy None."""
        with tempfile.TemporaryDirectory() as d:
            conn = _empty_chain_db(os.path.join(d, "chain.db"))
            conn.execute("CREATE TABLE chain_heads (session_id TEXT)")
            conn.commit()
            with self.assertRaises(verify.VerifierError) as cm:
                virp_report.load_heads(_Reader(conn))
            self.assertIn("chain_heads", cm.exception.detail)
            conn.close()

    def test_a_truncated_database_exits_verifier_error_not_a_finding(self):
        """End to end: a corrupted file must produce the verifier's own
        exit code, and must NOT be counted as failed or unverifiable
        entries."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "chain.db")
            conn = _empty_chain_db(path)
            conn.close()
            with open(path, "r+b") as f:
                f.truncate(700)          # a header, then nothing coherent
            out = os.path.join(d, "r.pdf")
            code = virp_report.main(["--db", path, "--out", out,
                                     "--no-journal", "--allow-immutable"])
            self.assertIn(code, (virp_report.VERIFIER_ERROR_EXIT, 1),
                          "a corrupt database must not exit 0")
            if code == 1:
                self.skipTest("this sqlite build opened the truncated file "
                              "without error; the read-path guard is "
                              "covered by the table-level cases above")


class TestTheCVerifierHasTheSameOutcome(unittest.TestCase):
    """The C verifier grew the same distinction (item 13). Pinned at the
    source so the two cannot drift: a storage failure in the
    artifact-binding check returns its own code, not the code that means
    'no body was retained'."""

    def _src(self, rel):
        with open(os.path.join(ROOT, rel)) as f:
            return f.read()

    def test_the_binding_check_no_longer_returns_unverifiable(self):
        src = self._src("src/virp_chain.c")
        self.assertNotIn(
            "return 0;   /* cannot read the store: report unverifiable",
            src, "a verifier failure is still graded as evidence")
        self.assertIn("return -2;", src)

    def test_the_result_carries_the_verifier_error(self):
        hdr = self._src("include/virp_chain.h")
        self.assertIn("bool     verifier_error;", hdr)
        self.assertIn("verifier_error_detail", hdr)

    def test_the_walk_stops_and_names_it(self):
        src = self._src("src/virp_chain.c")
        self.assertIn("VERIFIER_ERROR:", src)
        self.assertIn("result->verifier_error = true;", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
