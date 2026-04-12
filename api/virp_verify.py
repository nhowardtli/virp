#!/usr/bin/env python3
"""
virp-verify — CLI tool for verifying claims against signed VIRP observations.

Takes a claim file (JSON) and verifies it against the signed observation corpus.

Verification pipeline:
  1. Schema validation
  2. Observation lookup
  3. Signature verification (HMAC-SHA256 via C library)
  4. Freshness check
  5. Completeness check
  6. Extraction verification
  7. Assertion check

Usage:
    python3 virp_verify.py claim.json --corpus corpus.json --key /opt/virp/keys/onode.key
    python3 virp_verify.py claim.json --corpus corpus.json --key /opt/virp/keys/onode.key --freshness 600

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import argparse
import json
import re
import struct
import sys
import time
from enum import Enum
from typing import Optional

from virp_bridge import VIRPBridge, VIRP_HEADER_SIZE


# ── Verdict enum ───────────────────────────────────────────────────

class Verdict(Enum):
    VERIFIED = "VERIFIED"
    CONTRADICTED = "CONTRADICTED"
    UNVERIFIABLE = "UNVERIFIABLE"
    INCOMPLETE = "INCOMPLETE"
    STALE = "STALE"
    SCHEMA_ERROR = "SCHEMA_ERROR"


# Precedence: CONTRADICTED > INCOMPLETE > STALE > UNVERIFIABLE > VERIFIED
VERDICT_PRECEDENCE = {
    Verdict.CONTRADICTED: 5,
    Verdict.INCOMPLETE: 4,
    Verdict.STALE: 3,
    Verdict.UNVERIFIABLE: 2,
    Verdict.VERIFIED: 1,
    Verdict.SCHEMA_ERROR: 6,
}

VERDICT_COLORS = {
    Verdict.VERIFIED: "\033[32m",      # GREEN
    Verdict.CONTRADICTED: "\033[31m",  # RED
    Verdict.UNVERIFIABLE: "\033[33m",  # YELLOW
    Verdict.INCOMPLETE: "\033[33m",    # YELLOW
    Verdict.STALE: "\033[33m",         # YELLOW
    Verdict.SCHEMA_ERROR: "\033[31m",  # RED
}
COLOR_RESET = "\033[0m"


# ── Schema validation ─────────────────────────────────────────────

REQUIRED_CLAIM_FIELDS = {"claim_id", "claim_type", "assertion", "evidence"}
REQUIRED_ASSERTION_FIELDS = {"subject", "predicate", "operator", "value"}
REQUIRED_EVIDENCE_FIELDS = {"obs_id", "node_id", "extracted_path", "extracted_value"}


def validate_schema(claim: dict) -> Optional[str]:
    """Validate claim schema. Returns error message or None."""
    missing = REQUIRED_CLAIM_FIELDS - set(claim.keys())
    if missing:
        return f"Missing required fields: {', '.join(sorted(missing))}"

    assertion = claim.get("assertion")
    if not isinstance(assertion, dict):
        return "assertion must be an object"
    missing_a = REQUIRED_ASSERTION_FIELDS - set(assertion.keys())
    if missing_a:
        return f"assertion missing fields: {', '.join(sorted(missing_a))}"

    evidence = claim.get("evidence")
    if not isinstance(evidence, list):
        return "evidence must be an array"
    for i, ev in enumerate(evidence):
        if not isinstance(ev, dict):
            return f"evidence[{i}] must be an object"
        missing_e = REQUIRED_EVIDENCE_FIELDS - set(ev.keys())
        if missing_e:
            return f"evidence[{i}] missing fields: {', '.join(sorted(missing_e))}"

    return None


# ── Observation corpus ─────────────────────────────────────────────

def load_corpus(path: str) -> dict:
    """Load observation corpus. Returns dict keyed by obs_id."""
    with open(path) as f:
        raw = json.load(f)

    if isinstance(raw, list):
        return {obs["obs_id"]: obs for obs in raw if "obs_id" in obs}
    elif isinstance(raw, dict) and "observations" in raw:
        return {obs["obs_id"]: obs for obs in raw["observations"] if "obs_id" in obs}
    elif isinstance(raw, dict):
        return raw
    raise ValueError("Unrecognized corpus format")


# ── Extraction logic ──────────────────────────────────────────────

def extract_value(raw_output: str, path: str) -> Optional[str]:
    """
    Apply an extraction path to raw device output and return the value.

    Supports patterns like:
      - "bgp.neighbor[10.0.0.2].state" → looks for "10.0.0.2" line, extracts state field
      - "firewall.policy[873a].exists" → checks if policy ID appears
      - Simple regex: if path starts with "regex:" use it directly
    """
    if path.startswith("regex:"):
        pattern = path[6:]
        match = re.search(pattern, raw_output)
        return match.group(1) if match and match.groups() else (match.group(0) if match else None)

    # Parse structured path: category.subcategory[key].field
    m = re.match(r'^(\w+)\.(\w+)\[([^\]]+)\]\.(\w+)$', path)
    if m:
        category, subcategory, key, field = m.groups()

        # Special case: .exists field
        if field == "exists":
            return "true" if key in raw_output else "false"

        # Look for lines containing the key, then extract field-like value
        for line in raw_output.splitlines():
            if key in line:
                # Try to find the field value in common formats:
                # "field: value" or tabular where field is a column
                # For BGP: "10.0.0.2  4  65002  ...  Established"
                # Generic: split by whitespace and return last significant token
                parts = line.split()
                if field.lower() == "state" and parts:
                    return parts[-1]
                # Try "field = value" or "field: value"
                field_match = re.search(rf'{field}\s*[=:]\s*(\S+)', line, re.IGNORECASE)
                if field_match:
                    return field_match.group(1)
        return None

    # Fallback: treat path as a simple key to search for
    for line in raw_output.splitlines():
        if path in line:
            parts = line.split(":")
            if len(parts) >= 2:
                return parts[-1].strip()
    return None


# ── Assertion evaluation ──────────────────────────────────────────

def evaluate_assertion(extracted: str, operator: str, expected: str) -> bool:
    """Evaluate an assertion operator against extracted and expected values."""
    if operator == "==":
        return extracted == expected
    elif operator == "!=":
        return extracted != expected
    elif operator == "contains":
        return expected in extracted
    elif operator == "not_contains":
        return expected not in extracted
    elif operator in (">", "<", ">=", "<="):
        try:
            ev = float(extracted)
            xv = float(expected)
            if operator == ">":
                return ev > xv
            elif operator == "<":
                return ev < xv
            elif operator == ">=":
                return ev >= xv
            elif operator == "<=":
                return ev <= xv
        except ValueError:
            return False
    return False


# ── Core verification ─────────────────────────────────────────────

def verify_evidence(evidence: dict, corpus: dict, bridge: VIRPBridge,
                    freshness_window: float, now: float) -> tuple:
    """
    Verify a single evidence reference.
    Returns (verdict, details_dict).
    """
    obs_id = evidence["obs_id"]
    node_id = evidence["node_id"]
    extracted_path = evidence["extracted_path"]
    expected_value = evidence["extracted_value"]

    # Step 2: Observation lookup
    obs = corpus.get(obs_id)
    if obs is None:
        return Verdict.UNVERIFIABLE, {
            "obs_id": obs_id,
            "reason": "Observation not found in corpus",
        }

    # Step 3: Signature verification
    raw_msg = obs.get("raw_message")
    if raw_msg:
        if isinstance(raw_msg, str):
            raw_msg = bytes.fromhex(raw_msg)
        sig_valid = bridge.verify_observation(raw_msg)
    else:
        sig_valid = obs.get("verified", False)

    if not sig_valid:
        return Verdict.UNVERIFIABLE, {
            "obs_id": obs_id,
            "reason": "Signature verification failed",
            "signature": "INVALID",
        }

    # Step 4: Freshness check
    obs_timestamp = obs.get("timestamp", 0)
    if isinstance(obs_timestamp, str):
        # ISO format
        import datetime
        dt = datetime.datetime.fromisoformat(obs_timestamp.replace("Z", "+00:00"))
        obs_timestamp = dt.timestamp()
    age = now - obs_timestamp
    if age > freshness_window:
        return Verdict.STALE, {
            "obs_id": obs_id,
            "reason": f"Observation age {age:.0f}s exceeds window {freshness_window:.0f}s",
            "signature": "VALID",
            "freshness": "EXPIRED",
        }

    # Step 5: Completeness check
    collection_status = obs.get("collection_status", "COMPLETE")
    if collection_status != "COMPLETE":
        return Verdict.INCOMPLETE, {
            "obs_id": obs_id,
            "reason": f"Collection status: {collection_status}",
            "signature": "VALID",
            "freshness": "WITHIN WINDOW",
            "complete": "NO",
        }

    # Step 6: Extraction verification
    raw_output = obs.get("raw_output", obs.get("payload", ""))
    extracted = extract_value(raw_output, extracted_path)
    if extracted is None:
        return Verdict.UNVERIFIABLE, {
            "obs_id": obs_id,
            "reason": f"Could not extract value at path: {extracted_path}",
            "signature": "VALID",
            "freshness": "WITHIN WINDOW",
            "complete": "YES",
        }

    if extracted != expected_value:
        return Verdict.CONTRADICTED, {
            "obs_id": obs_id,
            "reason": f"Extracted '{extracted}' != expected '{expected_value}'",
            "signature": "VALID",
            "freshness": "WITHIN WINDOW",
            "complete": "YES",
            "extracted": extracted,
        }

    return Verdict.VERIFIED, {
        "obs_id": obs_id,
        "signature": "VALID",
        "freshness": "WITHIN WINDOW",
        "complete": "YES",
        "extracted": extracted,
    }


def verify_claim(claim: dict, corpus: dict, bridge: VIRPBridge,
                 freshness_window: float = 300.0) -> dict:
    """
    Verify a complete claim against the observation corpus.
    Returns verification result dict.
    """
    # Step 1: Schema validation
    schema_err = validate_schema(claim)
    if schema_err:
        return {
            "verdict": Verdict.SCHEMA_ERROR,
            "reason": schema_err,
            "claim": claim,
        }

    assertion = claim["assertion"]
    evidence_list = claim["evidence"]
    now = time.time()

    if not evidence_list:
        return {
            "verdict": Verdict.UNVERIFIABLE,
            "reason": "No evidence references provided",
            "claim": claim,
        }

    # Verify each evidence reference
    results = []
    for ev in evidence_list:
        verdict, details = verify_evidence(ev, corpus, bridge, freshness_window, now)
        results.append({"verdict": verdict, "details": details, "evidence": ev})

    # Step 7: Assertion check — apply operator if all evidence passed extraction
    for r in results:
        if r["verdict"] == Verdict.VERIFIED:
            extracted = r["details"]["extracted"]
            if not evaluate_assertion(extracted, assertion["operator"], assertion["value"]):
                r["verdict"] = Verdict.CONTRADICTED
                r["details"]["reason"] = (
                    f"Assertion failed: {extracted} {assertion['operator']} "
                    f"{assertion['value']} is false"
                )

    # Determine aggregate verdict by precedence
    final_verdict = max(
        (r["verdict"] for r in results),
        key=lambda v: VERDICT_PRECEDENCE[v]
    )

    return {
        "verdict": final_verdict,
        "claim": claim,
        "evidence_results": results,
    }


# ── Terminal output formatting ─────────────────────────────────────

def format_claim_string(assertion: dict) -> str:
    """Format assertion as human-readable claim string."""
    return (
        f"{assertion['subject']}.{assertion['predicate']} "
        f"{assertion['operator']} {assertion['value']}"
    )


def print_result(result: dict, use_color: bool = True):
    """Print verification result to terminal."""
    verdict = result["verdict"]
    claim = result["claim"]
    assertion = claim.get("assertion", {})

    color = VERDICT_COLORS.get(verdict, "") if use_color else ""
    reset = COLOR_RESET if use_color else ""

    claim_str = format_claim_string(assertion) if assertion else "???"

    evidence_results = result.get("evidence_results", [])

    if verdict == Verdict.SCHEMA_ERROR:
        print(f"  Claim:     {claim.get('claim_id', '???')}")
        print(f"  Verdict:   {color}{verdict.value}{reset}")
        print(f"  Reason:    {result.get('reason', '')}")
        return

    if not evidence_results:
        print(f"  Claim:     {claim_str}")
        print(f"  Evidence:  NONE")
        print(f"  Verdict:   {color}{verdict.value}{reset}")
        print(f"  Reason:    {result.get('reason', 'No signed observation covers this subject.')}")
        return

    for er in evidence_results:
        ev = er["evidence"]
        details = er["details"]
        ev_verdict = er["verdict"]

        obs_id = ev.get("obs_id", "???")
        node_id = ev.get("node_id", "???")
        timestamp = details.get("timestamp", "")

        print(f"  Claim:     {claim_str}")
        print(f"  Evidence:  obs_id {obs_id} ({node_id}, {timestamp})" if timestamp
              else f"  Evidence:  obs_id {obs_id} ({node_id})")
        print(f"  Signature: {details.get('signature', 'N/A')}")
        if "freshness" in details:
            print(f"  Freshness: {details['freshness']}")
        if "complete" in details:
            print(f"  Complete:  {details['complete']}")
        if "extracted" in details:
            print(f"  Extracted: {details['extracted']}")
        print(f"  Verdict:   {color}{ev_verdict.value}{reset}")
        if "reason" in details:
            print(f"  Reason:    {details['reason']}")
        print()

    if len(evidence_results) > 1:
        print(f"  Aggregate: {color}{verdict.value}{reset}")


# ── CLI entry point ────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Verify claims against signed VIRP observations"
    )
    parser.add_argument("claim", help="Path to claim JSON file")
    parser.add_argument("--corpus", required=True, help="Path to observation corpus JSON")
    parser.add_argument("--key", required=True, help="Path to O-Key file (32 bytes)")
    parser.add_argument("--freshness", type=float, default=300.0,
                        help="Freshness window in seconds (default: 300)")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")

    args = parser.parse_args()

    with open(args.claim) as f:
        claim = json.load(f)

    corpus = load_corpus(args.corpus)
    bridge = VIRPBridge(key_path=args.key)

    result = verify_claim(claim, corpus, bridge, freshness_window=args.freshness)
    print_result(result, use_color=not args.no_color)

    # Exit code: 0 for VERIFIED, 1 for anything else
    sys.exit(0 if result["verdict"] == Verdict.VERIFIED else 1)


if __name__ == "__main__":
    main()
