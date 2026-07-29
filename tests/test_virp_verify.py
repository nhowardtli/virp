#!/usr/bin/env python3
"""
Tests for virp-verify claim verification.

Creates a fixture observation corpus with signed observations from the
C library, then verifies claims against it.

Exercises:
  - Case A: VERIFIED — BGP neighbor state matches
  - Case B: UNVERIFIABLE — no observation covers the subject
  - CONTRADICTED — extracted value doesn't match assertion
  - STALE — observation is outside freshness window
  - INCOMPLETE — collection_status is not COMPLETE
  - SCHEMA_ERROR — missing required fields
"""

import hashlib
import hmac as hmac_mod
import json
import os
import struct
import sys
import tempfile
import time
import unittest

# Ensure we can import from the same directory and from api/
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "api")))

from virp_bridge import VIRPBridge, VIRP_HEADER_SIZE
from virp_verify import (
    Verdict, verify_claim, validate_schema, extract_value,
    evaluate_assertion, load_corpus,
)

KEY_PATH = "/opt/virp/keys/onode.key"


def resign_with_timestamp(signed_msg: bytes, ts_ns: int) -> bytes:
    """Patch timestamp_ns (offset 16) in a signed v1 message and re-sign.

    The HMAC covers bytes [0:24) and [56:end) — everything except the
    HMAC field itself (see virp_sign in src/virp_crypto.c). Python
    HMAC-SHA256 parity with the C library is proven by
    tests/test_hmac_parity.py, so re-signing here with the same O-Key
    produces a genuinely signed message with a back-dated timestamp —
    something virp_build_observation cannot do (it always stamps now).
    """
    with open(KEY_PATH, "rb") as f:
        key = f.read()
    m = bytearray(signed_msg)
    struct.pack_into("!Q", m, 16, ts_ns)
    digest = hmac_mod.new(key, bytes(m[:24]) + bytes(m[56:]),
                          hashlib.sha256).digest()
    m[24:56] = digest
    return bytes(m)


def make_corpus_entry(bridge, obs_id, node_id, raw_output,
                      collection_status="COMPLETE", timestamp=None,
                      signed_timestamp=None):
    """Build a signed observation and return a corpus entry dict.

    timestamp sets only the unsigned convenience field; signed_timestamp
    (seconds) back-dates the timestamp inside the signed bytes via
    resign_with_timestamp(). The verifier evaluates freshness from the
    signed bytes, so stale fixtures must set signed_timestamp.
    """
    output_bytes = raw_output.encode("utf-8") if isinstance(raw_output, str) else raw_output
    signed_msg = bridge.build_signed_observation(
        output_bytes,
        node_id=node_id,
        seq_num=obs_id,
    )
    if signed_timestamp is not None:
        signed_msg = resign_with_timestamp(signed_msg, int(signed_timestamp * 1e9))
        assert bridge.verify_observation(signed_msg), "re-signed fixture must verify"

    # Extract timestamp from the signed message header (offset 16, uint64 BE, nanoseconds)
    ts_ns = struct.unpack_from("!Q", signed_msg, 16)[0]
    ts_sec = ts_ns / 1_000_000_000

    if timestamp is None:
        timestamp = ts_sec

    return {
        "obs_id": obs_id,
        "node_id": f"R{node_id}",
        "raw_message": signed_msg.hex(),
        "raw_output": raw_output,
        "verified": True,
        "timestamp": timestamp,
        "collection_status": collection_status,
    }


class TestVIRPVerify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bridge = VIRPBridge(key_path=KEY_PATH)
        cls.now = time.time()

        # Build fixture corpus
        cls.bgp_output = (
            "BGP router identifier 10.0.0.1, local AS number 65001\n"
            "Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n"
            "10.0.0.2        4 65002     142     145        5    0    0 01:23:45 Established\n"
            "10.0.0.3        4 65003      98     101        5    0    0 00:45:12 Active\n"
        )

        cls.obs_bgp = make_corpus_entry(
            cls.bridge, obs_id=37807, node_id=1,
            raw_output=cls.bgp_output,
            timestamp=cls.now - 10,  # 10 seconds ago — fresh
        )

        cls.obs_stale = make_corpus_entry(
            cls.bridge, obs_id=37808, node_id=2,
            raw_output="interface GigabitEthernet0/0 is up",
            timestamp=cls.now - 600,          # unsigned convenience field
            signed_timestamp=cls.now - 600,   # stale inside the signed bytes
        )

        cls.obs_incomplete = make_corpus_entry(
            cls.bridge, obs_id=37809, node_id=3,
            raw_output="partial output...",
            collection_status="PARTIAL",
            timestamp=cls.now - 5,
        )

        cls.corpus = {
            37807: cls.obs_bgp,
            37808: cls.obs_stale,
            37809: cls.obs_incomplete,
        }

    # ── Case A: VERIFIED ──────────────────────────────────────────

    def test_case_a_verified(self):
        """BGP neighbor 10.0.0.2 state == Established → VERIFIED"""
        claim = {
            "claim_id": "bgp-001",
            "claim_type": "bgp.neighbor.state",
            "assertion": {
                "subject": "bgp",
                "predicate": "neighbor[10.0.0.2].state",
                "operator": "==",
                "value": "Established",
            },
            "evidence": [
                {
                    "obs_id": 37807,
                    "node_id": "R1",
                    "extracted_path": "bgp.neighbor[10.0.0.2].state",
                    "extracted_value": "Established",
                }
            ],
        }

        result = verify_claim(claim, self.corpus, self.bridge, freshness_window=300)
        self.assertEqual(result["verdict"], Verdict.VERIFIED)

        er = result["evidence_results"][0]
        self.assertEqual(er["details"]["signature"], "VALID")
        self.assertEqual(er["details"]["freshness"], "WITHIN WINDOW")
        self.assertEqual(er["details"]["complete"], "YES")
        self.assertEqual(er["details"]["extracted"], "Established")

        print("\n=== Case A: VERIFIED ===")
        from virp_verify import print_result
        print_result(result)

    # ── Case B: UNVERIFIABLE (no evidence) ─────────────────────────

    def test_case_b_unverifiable_no_observation(self):
        """Firewall policy not in corpus → UNVERIFIABLE"""
        claim = {
            "claim_id": "fw-001",
            "claim_type": "firewall.policy.exists",
            "assertion": {
                "subject": "firewall",
                "predicate": "policy[873a].exists",
                "operator": "==",
                "value": "true",
            },
            "evidence": [
                {
                    "obs_id": 99999,
                    "node_id": "FG1",
                    "extracted_path": "firewall.policy[873a].exists",
                    "extracted_value": "true",
                }
            ],
        }

        result = verify_claim(claim, self.corpus, self.bridge, freshness_window=300)
        self.assertEqual(result["verdict"], Verdict.UNVERIFIABLE)

        print("\n=== Case B: UNVERIFIABLE ===")
        from virp_verify import print_result
        print_result(result)

    # ── CONTRADICTED ──────────────────────────────────────────────

    def test_contradicted_wrong_value(self):
        """BGP neighbor 10.0.0.3 state == Established but actual is Active → CONTRADICTED"""
        claim = {
            "claim_id": "bgp-002",
            "claim_type": "bgp.neighbor.state",
            "assertion": {
                "subject": "bgp",
                "predicate": "neighbor[10.0.0.3].state",
                "operator": "==",
                "value": "Established",
            },
            "evidence": [
                {
                    "obs_id": 37807,
                    "node_id": "R1",
                    "extracted_path": "bgp.neighbor[10.0.0.3].state",
                    "extracted_value": "Active",
                }
            ],
        }

        result = verify_claim(claim, self.corpus, self.bridge, freshness_window=300)
        self.assertEqual(result["verdict"], Verdict.CONTRADICTED)

    # ── STALE ─────────────────────────────────────────────────────

    def test_stale_observation(self):
        """Observation older than freshness window → STALE"""
        claim = {
            "claim_id": "if-001",
            "claim_type": "interface.state",
            "assertion": {
                "subject": "interface",
                "predicate": "GigabitEthernet0/0.state",
                "operator": "==",
                "value": "up",
            },
            "evidence": [
                {
                    "obs_id": 37808,
                    "node_id": "R2",
                    "extracted_path": "regex:is (\\w+)",
                    "extracted_value": "up",
                }
            ],
        }

        result = verify_claim(claim, self.corpus, self.bridge, freshness_window=300)
        self.assertEqual(result["verdict"], Verdict.STALE)

    # ── INCOMPLETE ────────────────────────────────────────────────

    def test_incomplete_collection(self):
        """collection_status != COMPLETE → INCOMPLETE"""
        claim = {
            "claim_id": "partial-001",
            "claim_type": "test",
            "assertion": {
                "subject": "test",
                "predicate": "value",
                "operator": "==",
                "value": "something",
            },
            "evidence": [
                {
                    "obs_id": 37809,
                    "node_id": "R3",
                    "extracted_path": "regex:(partial)",
                    "extracted_value": "partial",
                }
            ],
        }

        result = verify_claim(claim, self.corpus, self.bridge, freshness_window=300)
        self.assertEqual(result["verdict"], Verdict.INCOMPLETE)

    # ── SCHEMA_ERROR ──────────────────────────────────────────────

    def test_schema_error_missing_assertion(self):
        """Missing assertion field → SCHEMA_ERROR"""
        claim = {
            "claim_id": "bad-001",
            "claim_type": "test",
            "evidence": [],
        }

        result = verify_claim(claim, self.corpus, self.bridge)
        self.assertEqual(result["verdict"], Verdict.SCHEMA_ERROR)

    # ── Precedence ────────────────────────────────────────────────

    def test_precedence_contradicted_wins(self):
        """Multiple evidence: one VERIFIED + one CONTRADICTED → CONTRADICTED wins"""
        claim = {
            "claim_id": "multi-001",
            "claim_type": "bgp.neighbor.state",
            "assertion": {
                "subject": "bgp",
                "predicate": "neighbor.state",
                "operator": "==",
                "value": "Established",
            },
            "evidence": [
                {
                    "obs_id": 37807,
                    "node_id": "R1",
                    "extracted_path": "bgp.neighbor[10.0.0.2].state",
                    "extracted_value": "Established",
                },
                {
                    "obs_id": 37807,
                    "node_id": "R1",
                    "extracted_path": "bgp.neighbor[10.0.0.3].state",
                    "extracted_value": "Active",
                },
            ],
        }

        result = verify_claim(claim, self.corpus, self.bridge, freshness_window=300)
        self.assertEqual(result["verdict"], Verdict.CONTRADICTED)

    # ── Extraction logic ──────────────────────────────────────────

    def test_extract_bgp_state(self):
        val = extract_value(self.bgp_output, "bgp.neighbor[10.0.0.2].state")
        self.assertEqual(val, "Established")

    def test_extract_regex(self):
        val = extract_value("interface Gi0/0 is up", "regex:is (\\w+)")
        self.assertEqual(val, "up")

    def test_extract_exists(self):
        val = extract_value("policy 873a action accept", "firewall.policy[873a].exists")
        self.assertEqual(val, "true")

    def test_extract_not_exists(self):
        val = extract_value("policy 100 action deny", "firewall.policy[873a].exists")
        self.assertEqual(val, "false")

    # ── Assertion evaluation ──────────────────────────────────────

    def test_evaluate_eq(self):
        self.assertTrue(evaluate_assertion("Established", "==", "Established"))
        self.assertFalse(evaluate_assertion("Active", "==", "Established"))

    def test_evaluate_neq(self):
        self.assertTrue(evaluate_assertion("Active", "!=", "Established"))

    def test_evaluate_numeric(self):
        self.assertTrue(evaluate_assertion("100", ">", "50"))
        self.assertFalse(evaluate_assertion("30", ">", "50"))

    # ── Signature tamper detection ────────────────────────────────

    def test_tampered_signature_unverifiable(self):
        """Tampered observation signature → UNVERIFIABLE"""
        tampered_obs = dict(self.obs_bgp)
        raw_hex = tampered_obs["raw_message"]
        raw_bytes = bytearray(bytes.fromhex(raw_hex))
        raw_bytes[30] ^= 0xFF  # Flip a byte in the HMAC field
        tampered_obs["raw_message"] = raw_bytes.hex()

        corpus = {37807: tampered_obs}

        claim = {
            "claim_id": "tamper-001",
            "claim_type": "bgp.neighbor.state",
            "assertion": {
                "subject": "bgp",
                "predicate": "neighbor[10.0.0.2].state",
                "operator": "==",
                "value": "Established",
            },
            "evidence": [
                {
                    "obs_id": 37807,
                    "node_id": "R1",
                    "extracted_path": "bgp.neighbor[10.0.0.2].state",
                    "extracted_value": "Established",
                }
            ],
        }

        result = verify_claim(claim, corpus, self.bridge, freshness_window=300)
        self.assertEqual(result["verdict"], Verdict.UNVERIFIABLE)

    # ── Finding N1: verifier must judge the signed bytes it verified ──

    @staticmethod
    def _bgp_claim(obs_id=37807, node_id="R1"):
        return {
            "claim_id": "n1-001",
            "claim_type": "bgp.neighbor.state",
            "assertion": {
                "subject": "bgp",
                "predicate": "neighbor[10.0.0.2].state",
                "operator": "==",
                "value": "Established",
            },
            "evidence": [
                {
                    "obs_id": obs_id,
                    "node_id": node_id,
                    "extracted_path": "bgp.neighbor[10.0.0.2].state",
                    "extracted_value": "Established",
                }
            ],
        }

    def test_forged_raw_output_with_genuine_signature_fails(self):
        """Genuinely signed payload says Idle; unsigned raw_output says
        Established. The claim asserts Established. Must NOT verify —
        and the failure must name the raw_output mismatch."""
        idle_output = self.bgp_output.replace("Established", "Idle")
        entry = make_corpus_entry(
            self.bridge, obs_id=37807, node_id=1,
            raw_output=idle_output, timestamp=self.now - 5,
        )
        entry["raw_output"] = self.bgp_output  # attacker's convenience copy

        result = verify_claim(self._bgp_claim(), {37807: entry},
                              self.bridge, freshness_window=300)
        self.assertNotEqual(result["verdict"], Verdict.VERIFIED)
        details = result["evidence_results"][0]["details"]
        self.assertEqual(details.get("mismatch"), "raw_output")

    def test_plaintext_verified_flag_without_raw_message_fails(self):
        """{"verified": true} with no raw_message must be UNVERIFIABLE."""
        entry = {
            "obs_id": 37807,
            "node_id": "R1",
            "verified": True,
            "raw_output": self.bgp_output,
            "timestamp": self.now - 5,
            "collection_status": "COMPLETE",
        }
        result = verify_claim(self._bgp_claim(), {37807: entry},
                              self.bridge, freshness_window=300)
        self.assertEqual(result["verdict"], Verdict.UNVERIFIABLE)

    def test_obs_id_disagrees_with_signed_seq_num_fails(self):
        """Corpus entry claims obs_id 37807 but the signed header carries
        seq_num 55555. Must fail with an obs_id mismatch, not verify."""
        entry = make_corpus_entry(
            self.bridge, obs_id=55555, node_id=1,
            raw_output=self.bgp_output, timestamp=self.now - 5,
        )
        entry["obs_id"] = 37807  # relabeled without re-signing

        result = verify_claim(self._bgp_claim(), {37807: entry},
                              self.bridge, freshness_window=300)
        self.assertNotEqual(result["verdict"], Verdict.VERIFIED)
        details = result["evidence_results"][0]["details"]
        self.assertEqual(details.get("mismatch"), "obs_id")

    def test_node_id_disagrees_with_signed_node_id_fails(self):
        """Signed header carries node_id 1; entry and evidence say R9.
        Must fail with a node_id mismatch, not verify."""
        entry = make_corpus_entry(
            self.bridge, obs_id=37807, node_id=1,
            raw_output=self.bgp_output, timestamp=self.now - 5,
        )
        entry["node_id"] = "R9"

        result = verify_claim(self._bgp_claim(node_id="R9"), {37807: entry},
                              self.bridge, freshness_window=300)
        self.assertNotEqual(result["verdict"], Verdict.VERIFIED)
        details = result["evidence_results"][0]["details"]
        self.assertEqual(details.get("mismatch"), "node_id")

    def test_stale_signed_timestamp_fails_freshness(self):
        """Timestamp inside the verified bytes is 600s old while the
        unsigned timestamp field claims fresh. Must be STALE."""
        entry = make_corpus_entry(
            self.bridge, obs_id=37807, node_id=1,
            raw_output=self.bgp_output,
            timestamp=self.now - 5,           # unsigned field lies: fresh
            signed_timestamp=self.now - 600,  # signed bytes: stale
        )
        result = verify_claim(self._bgp_claim(), {37807: entry},
                              self.bridge, freshness_window=300)
        self.assertEqual(result["verdict"], Verdict.STALE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
