#!/usr/bin/env python3
"""Evidence-required execution (Sep 1 review, Task 5) — Python parity.

The daemon commits a gate_intent chain entry BEFORE it dispatches a
command and a closer (gate_execution, or outcome for an approved apply)
AFTER, the closer naming the intent's chain_entry_hash as
intent_entry_hash in its stored body. tests/test_onode.c pins what the C
verifier (virp_chain_verify_session) says about the three shapes; this
file pins the same verdicts from report/verify.py, the independent
pure-Python verifier:

  intent + linked closer      -> executions_closed 1, open_executions []
  intent alone (daemon died)  -> open_executions [that intent]  AND the
                                 chain is NOT failed: every entry passes,
                                 no first_broken_link, failed_entries []
  closer citing nothing       -> nothing closed, nothing open
  cross-session closer        -> an outcome in approval:<device> closes an
                                 intent in gate-enforce:<device>

Entries are built with real canonical hashes (verify.canonical_json,
verify.genesis_hash) so the per-entry checks PASS on their own merits and
the "not a broken chain" claim is exercised, not assumed. Pure stdlib.
"""
import hashlib
import json
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "report"))

import verify  # noqa: E402

GATE_SESSION = "gate-enforce:PVE-LAB"
APPROVAL_SESSION = "approval:PVE-LAB"


def _sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


class ChainBuilder:
    """Append entries the way the daemon does: sequence per session,
    previous_entry_hash = predecessor's hash (genesis at seq 0),
    chain_entry_hash = sha256(canonical)."""

    def __init__(self):
        self.entries = []
        self.artifacts = {}
        self._last = {}

    def append(self, session, atype, artifact_id, body):
        prev = self._last.get(session)
        seq = 0 if prev is None else prev["sequence"] + 1
        e = {
            "session_id": session,
            "sequence": seq,
            "artifact_type": atype,
            "artifact_id": artifact_id,
            "artifact_hash": _sha(body),
            "artifact_hash_alg": "sha256",
            "artifact_schema_version": "1",
            "previous_entry_hash": (verify.genesis_hash(session)
                                    if prev is None
                                    else prev["chain_entry_hash"]),
            "timestamp_ns": 1756684800000000000 + len(self.entries),
            "monotonic_ns": 1000 + len(self.entries),
            "signer_node_id": 0xDEAD0008,
            "signer_org_id": "local",
            "chain_hmac": "0" * 64,        # UNCHECKED: no key supplied
        }
        e["chain_entry_hash"] = _sha(verify.canonical_json(e))
        self.entries.append(e)
        self.artifacts[(artifact_id, e["artifact_hash"])] = body
        self._last[session] = e
        return e

    def intent(self, session=GATE_SESSION, decision="auto-execute",
               proposal_id=None):
        body = json.dumps({
            "schema": "gate_intent/1", "device": "PVE-LAB",
            "driver": "mock", "command": "show version",
            "classified_tier": "GREEN", "gate_max_tier": "GREEN",
            "effective_max_tier": "GREEN", "ceiling_source": "node-wide",
            "gate_mode": "ENFORCE", "decision": decision, "uid": None,
            "session": None, "proposal_id": proposal_id, "obs_version": 1,
            "intent_ns": 1756684800000000000 + len(self.entries),
        }, separators=(",", ":"))
        return self.append(session, "gate_intent",
                           "gateintent-" + _sha(body)[:16], body)

    def execution(self, intent, session=GATE_SESSION):
        body = json.dumps({
            "schema": "gate_execution/1", "device": "PVE-LAB",
            "driver": "mock", "command": "show version",
            "classified_tier": "GREEN", "decision": "auto-execute",
            "uid": None,
            "intent_entry_hash": (intent["chain_entry_hash"]
                                  if intent else None),
            "intent_sequence": intent["sequence"] if intent else None,
            "intent_artifact_id": intent["artifact_id"] if intent else None,
            "executed": True, "executed_reported": True, "success": True,
            "response_sha256": "e" * 64, "response_len": 12, "error": None,
        }, separators=(",", ":"))
        return self.append(session, "gate_execution",
                           "gateexec-" + _sha(body)[:16], body)

    def outcome(self, intent, proposal_id="prop-1"):
        # The daemon's outcome body is hand-formatted snprintf JSON with
        # intent_entry_hash LAST; the verifier must not care about order.
        body = ('{"proposal_id":"%s","proposal_entry_hash":"%s",'
                '"approval_entry_hash":"%s","device":"PVE-LAB",'
                '"command_hash":"%s","success":true,'
                '"intent_entry_hash":%s}'
                % (proposal_id, "a" * 64, "b" * 64, "c" * 64,
                   '"%s"' % intent["chain_entry_hash"] if intent
                   else "null"))
        return self.append(APPROVAL_SESSION, "outcome",
                           "outcome:" + proposal_id, body)

    def verify(self):
        return verify.verify_chain(self.entries, self.artifacts,
                                   okey=None, chain_key=None, heads=None)


class TestOpenExecutionGrading(unittest.TestCase):

    def _assert_chain_clean(self, verifications, summary):
        """Every entry PASSes what it can; nothing is graded as tampering."""
        for v in verifications:
            self.assertEqual(v.entry_hash, verify.PASS, v.entry)
            self.assertEqual(v.link, verify.PASS, v.entry)
            self.assertEqual(v.artifact_bind, verify.PASS, v.entry)
            self.assertTrue(v.ok, v.entry)
        self.assertEqual(summary["failed_entries"], [])
        self.assertIsNone(summary["first_broken_link"])

    def test_intent_with_linked_execution_is_closed(self):
        b = ChainBuilder()
        i = b.intent()
        b.execution(i)
        verifications, summary = b.verify()
        self._assert_chain_clean(verifications, summary)
        self.assertEqual(summary["executions_closed"], 1)
        self.assertEqual(summary["open_executions"], [])

    def test_intent_with_no_closer_is_open_not_broken(self):
        """The crash shape: the daemon committed the intent, was killed
        inside the driver, and never wrote the outcome. The chain is
        VALID and says so; the execution is OPEN and says so."""
        b = ChainBuilder()
        i = b.intent()
        verifications, summary = b.verify()
        self._assert_chain_clean(verifications, summary)
        self.assertEqual(summary["executions_closed"], 0)
        self.assertEqual(len(summary["open_executions"]), 1)
        v = summary["open_executions"][0]
        self.assertEqual(v.entry["chain_entry_hash"], i["chain_entry_hash"])
        self.assertEqual(v.entry["artifact_type"], "gate_intent")
        # Not folded into the failure plumbing: an open execution is a
        # reconciliation task, never a non-zero exit for tampering.
        self.assertNotIn(v, summary["failed_entries"])

    def test_second_dispatch_after_a_crash_does_not_close_the_first(self):
        """Two intents, one closer: the closer names the SECOND intent.
        The first stays open — a later, unrelated execution must not
        paper over an earlier one whose outcome was lost."""
        b = ChainBuilder()
        i1 = b.intent()
        i2 = b.intent()
        b.execution(i2)
        verifications, summary = b.verify()
        self._assert_chain_clean(verifications, summary)
        self.assertEqual(summary["executions_closed"], 1)
        opened = [v.entry["chain_entry_hash"]
                  for v in summary["open_executions"]]
        self.assertEqual(opened, [i1["chain_entry_hash"]])

    def test_execution_without_intent_link_closes_nothing(self):
        """evidence_required=false shape: gate_execution with
        intent_entry_hash null. Nothing to close, nothing open, and the
        entry itself still verifies."""
        b = ChainBuilder()
        b.execution(None)
        verifications, summary = b.verify()
        self._assert_chain_clean(verifications, summary)
        self.assertEqual(summary["executions_closed"], 0)
        self.assertEqual(summary["open_executions"], [])

    def test_outcome_in_approval_session_closes_gate_intent(self):
        """An approved apply's intent lives in gate-enforce:<device>, its
        outcome in approval:<device>. The link crosses sessions and the
        grader must follow it."""
        b = ChainBuilder()
        i = b.intent(decision="approved-apply", proposal_id="prop-1")
        b.outcome(i, "prop-1")
        verifications, summary = b.verify()
        self._assert_chain_clean(verifications, summary)
        self.assertEqual(summary["executions_closed"], 1)
        self.assertEqual(summary["open_executions"], [])

    def test_closer_with_undecodable_body_closes_nothing(self):
        """A closer whose stored body is not JSON cannot vouch for an
        intent. The intent stays open rather than being closed by
        garbage."""
        b = ChainBuilder()
        i = b.intent()
        b.append(GATE_SESSION, "gate_execution", "gateexec-junk",
                 "not json at all " + i["chain_entry_hash"])
        verifications, summary = b.verify()
        self._assert_chain_clean(verifications, summary)
        self.assertEqual(summary["executions_closed"], 0)
        self.assertEqual(len(summary["open_executions"]), 1)

    def test_gate_intent_is_not_an_external_type(self):
        """A socket client must not be able to mint an intent (and so an
        open execution against an untouched device). verify.py has no
        append path, so this pins the constant the C policy lists the
        type under; src/virp_chain.c's RESERVED table is asserted in
        tests/test_chain.c."""
        self.assertEqual(verify.INTENT_TYPE, "gate_intent")
        self.assertEqual(verify.INTENT_CLOSER_TYPES,
                         frozenset(("gate_execution", "outcome")))
        self.assertNotIn(verify.INTENT_TYPE, verify.OBSERVATION_TYPES)
        self.assertNotIn(verify.INTENT_TYPE, verify.NO_BODY_TYPES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
