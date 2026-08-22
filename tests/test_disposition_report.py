#!/usr/bin/env python3
"""Execution disposition grading in the report layer.

The vocabulary lives in include/virp_disposition.h (mirrored into
report/virp_disposition.py). These tests pin the READER side of it:

  - each of the four states in an outcome/2 or gate_execution/2 body grades
    as itself, and EXECUTED_UNKNOWN is tallied in its own column, never as
    PASS or FAIL, and surfaces as unknown_dispositions in the summary;
  - a legacy body (success only, no "disposition") grades LEGACY_* and is
    NEVER mapped onto an EXECUTED_* state;
  - a gate_execution/1 body, which carried the raw DRIVER classification
    under the key name "disposition", is treated as legacy by schema;
  - a commitment-only outcome (no body retained) grades UNVERIFIABLE, not
    PASS and not FAIL;
  - none of this touches the integrity roll-up: an EXECUTED_UNKNOWN on an
    intact chain is not a chain failure and does not change the exit code.

The chains are built with the same ChainBuilder the report suite uses, and
graded through verify_chain, i.e. the path the PDF takes, not by calling
the grader on a hand-made dict.
"""
import json
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "report"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tests"))

import verify                                   # noqa: E402
import virp_disposition as disp                 # noqa: E402
from test_virp_report import ChainBuilder, analyse   # noqa: E402


def outcome_body(pid, disposition):
    """Exactly what src/virp_onode.c approval_emit_outcome writes."""
    return {"schema": disp.OUTCOME_SCHEMA_V2, "proposal_id": pid,
            "proposal_entry_hash": "d" * 64, "approval_entry_hash": "e" * 64,
            "device": "dev0", "command_hash": "b" * 64,
            "disposition": disposition,
            "success": disp.success_of(disposition)}


def gate_exec_body(disposition, schema=disp.GATE_EXECUTION_SCHEMA_V2):
    return {"schema": schema, "device": "dev0", "driver": "mock",
            "command": "show version", "classified_tier": "GREEN",
            "decision": "auto-execute", "disposition": disposition,
            "executed": disposition != disp.NAME_NOT_DISPATCHED,
            "success": disp.success_of(disposition),
            "response_sha256": "0" * 64, "response_len": 0}


class DispositionGradingBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="virp-disposition-")
        self.db = os.path.join(self.tmp, "chain.db")
        self.b = ChainBuilder(self.db)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def graded(self):
        self.b.close()
        vs, summary = analyse(self.db)
        by_id = {v.entry["artifact_id"]: v for v in vs}
        return by_id, summary


class TestFourStates(DispositionGradingBase):
    def test_each_state_grades_as_itself_in_outcome_bodies(self):
        for i, state in enumerate(disp.PERSISTABLE):
            pid = ("%02x" % i) * 16
            self.b.add_json("approval:dev0", "outcome", "outcome:" + pid,
                            outcome_body(pid, state))
        by_id, summary = self.graded()
        for i, state in enumerate(disp.PERSISTABLE):
            pid = ("%02x" % i) * 16
            v = by_id["outcome:" + pid]
            self.assertEqual(v.disposition, state)
            self.assertFalse(v.disposition_legacy)
            self.assertEqual(summary["dispositions"][state], 1)

    def test_each_state_grades_as_itself_in_gate_execution_bodies(self):
        for i, state in enumerate(disp.PERSISTABLE):
            self.b.add_json("gate-enforce:dev0", "gate_execution",
                            "gateexec-%016x" % i, gate_exec_body(state))
        by_id, summary = self.graded()
        for i, state in enumerate(disp.PERSISTABLE):
            self.assertEqual(by_id["gateexec-%016x" % i].disposition, state)

    def test_unknown_is_its_own_column_and_is_flagged(self):
        pid = "1" * 32
        self.b.add_json("approval:dev0", "outcome", "outcome:" + pid,
                        outcome_body(pid, disp.NAME_EXECUTED_UNKNOWN))
        by_id, summary = self.graded()
        v = by_id["outcome:" + pid]
        t = summary["dispositions"]
        self.assertEqual(t[disp.NAME_EXECUTED_UNKNOWN], 1)
        self.assertEqual(t[disp.NAME_EXECUTED_CONFIRMED], 0)
        self.assertEqual(t[disp.NAME_EXECUTED_FAILED], 0)
        # Surfaced for the summary to flag, never folded into a total.
        self.assertEqual(summary["unknown_dispositions"], [v])
        # And NOT an integrity failure: the chain itself is intact.
        self.assertEqual(v.rollup, verify.PASS)
        self.assertNotIn(v, summary["failed_entries"])
        self.assertNotIn(v, summary["unverifiable_entries"])

    def test_derived_success_is_null_for_unknown_and_not_dispatched(self):
        """The convenience boolean must not reintroduce the defect: a body
        the C side writes for UNKNOWN or NOT_DISPATCHED carries null, and the
        reader grades by disposition regardless of what success says."""
        self.assertIsNone(disp.success_of(disp.NAME_EXECUTED_UNKNOWN))
        self.assertIsNone(disp.success_of(disp.NAME_NOT_DISPATCHED))
        self.assertIs(disp.success_of(disp.NAME_EXECUTED_CONFIRMED), True)
        self.assertIs(disp.success_of(disp.NAME_EXECUTED_FAILED), False)
        # A hostile body that says success:false next to EXECUTED_UNKNOWN
        # still grades UNKNOWN: the disposition is the truth.
        pid = "2" * 32
        body = outcome_body(pid, disp.NAME_EXECUTED_UNKNOWN)
        body["success"] = False
        self.b.add_json("approval:dev0", "outcome", "outcome:" + pid, body)
        by_id, _ = self.graded()
        self.assertEqual(by_id["outcome:" + pid].disposition,
                         disp.NAME_EXECUTED_UNKNOWN)


class TestLegacyRecords(DispositionGradingBase):
    def test_legacy_outcome_is_rendered_legacy_never_mapped(self):
        pid_ok, pid_bad = "a" * 32, "b" * 32
        self.b.add_json("approval:dev0", "outcome", "outcome:" + pid_ok,
                        {"proposal_id": pid_ok, "device": "dev0",
                         "success": True, "proposal_entry_hash": "d" * 64,
                         "approval_entry_hash": "e" * 64})
        self.b.add_json("approval:dev0", "outcome", "outcome:" + pid_bad,
                        {"proposal_id": pid_bad, "device": "dev0",
                         "success": False, "proposal_entry_hash": "d" * 64,
                         "approval_entry_hash": "e" * 64})
        by_id, summary = self.graded()
        ok, bad = by_id["outcome:" + pid_ok], by_id["outcome:" + pid_bad]
        self.assertEqual(ok.disposition, disp.LEGACY_CONFIRMED)
        self.assertEqual(bad.disposition, disp.LEGACY_FAILED)
        self.assertTrue(ok.disposition_legacy and bad.disposition_legacy)
        for v in (ok, bad):
            self.assertNotIn(v.disposition, disp.PERSISTABLE,
                             "legacy record silently mapped onto a new state")
        self.assertEqual(summary["legacy_dispositions"], 2)
        self.assertEqual(summary["dispositions"][disp.LEGACY_FAILED], 1)
        self.assertEqual(summary["dispositions"][disp.NAME_EXECUTED_FAILED], 0)

    def test_gate_execution_v1_is_legacy_by_schema(self):
        """Under gate_execution/1 the key named 'disposition' held the raw
        driver classification — 'UNSET', 'DRIVER_ERROR', or even a real-
        looking 'EXECUTED_UNKNOWN' from the linux driver. The schema tag,
        not the key, decides; a /1 body is legacy whatever the key says."""
        self.b.add_json("gate-enforce:dev0", "gate_execution", "gateexec-1",
                        gate_exec_body("UNSET",
                                       schema=disp.GATE_EXECUTION_SCHEMA_V1)
                        | {"success": True})
        self.b.add_json("gate-enforce:dev0", "gate_execution", "gateexec-2",
                        gate_exec_body(disp.NAME_EXECUTED_UNKNOWN,
                                       schema=disp.GATE_EXECUTION_SCHEMA_V1)
                        | {"success": False})
        by_id, _ = self.graded()
        self.assertEqual(by_id["gateexec-1"].disposition, disp.LEGACY_CONFIRMED)
        self.assertEqual(by_id["gateexec-2"].disposition, disp.LEGACY_FAILED)
        self.assertTrue(by_id["gateexec-2"].disposition_legacy)

    def test_unrecognised_disposition_is_unverifiable_not_guessed(self):
        pid = "c" * 32
        self.b.add_json("approval:dev0", "outcome", "outcome:" + pid,
                        outcome_body(pid, "MAYBE"))
        by_id, _ = self.graded()
        self.assertEqual(by_id["outcome:" + pid].disposition,
                         verify.UNVERIFIABLE)


class TestCommitmentOnlyOutcome(DispositionGradingBase):
    def test_bodyless_outcome_is_unverifiable_not_pass_not_fail(self):
        """An outcome entry that commits to a hash and retains no body used
        to render as FAILURE (b.get('success') on an empty dict). Silence
        is not failure and it is not success: it is UNVERIFIABLE, the
        existing verdict for evidence that was never retained."""
        import hashlib
        pid = "d" * 32
        self.b.append("approval:dev0", "outcome", "outcome:" + pid,
                      hashlib.sha256(b"whatever").hexdigest(), None)
        by_id, summary = self.graded()
        v = by_id["outcome:" + pid]
        self.assertEqual(v.disposition, verify.UNVERIFIABLE)
        self.assertIn("no outcome body retained", v.disposition_detail)
        self.assertEqual(summary["dispositions"][verify.UNVERIFIABLE], 1)
        for state in disp.PERSISTABLE + (disp.LEGACY_CONFIRMED,
                                         disp.LEGACY_FAILED):
            self.assertEqual(summary["dispositions"][state], 0)


class TestVocabularyInSync(unittest.TestCase):
    def test_python_mirror_matches_header(self):
        """Belt and braces with `make check-disposition`: the generated
        module must say exactly what the header says."""
        import subprocess
        gen = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "scripts",
                                          "gen_disposition.py")],
            capture_output=True, text=True, check=True).stdout
        with open(os.path.join(REPO_ROOT, "report",
                               "virp_disposition.py")) as fh:
            self.assertEqual(gen, fh.read(),
                             "report/virp_disposition.py is stale; run "
                             "make gen-disposition")
        self.assertEqual(len(disp.PERSISTABLE), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
