#!/usr/bin/env python3
"""
Python-side parity test for the canonical device-id resolver.

Phase 4 commit 2 binds api.validator.validation_resolve_device to the
C-side validator_resolve_device() in libvirp.so via ctypes. This test
file confirms the binding marshals correctly and the wrapper returns
the same RESOLVED/AMBIGUOUS/UNRESOLVED + canonical/candidates results
the C unit tests in tests/test_validator.c verified for the same
inputs.

Run with: make test-validator-resolver-py
(or directly: python3 tests/test_validator_resolver_py.py)

Requires libvirp.so to be built: make build/libvirp.so
"""

import json
import os
import sys
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_ROOT)

from api.validator import (  # noqa: E402
    validation_resolve_device,
    ResolveStatus,
)


class ResolverParity(unittest.TestCase):
    """Mirrors the 7 resolver test cases in tests/test_validator.c (tests 22–28).
    Each case here calls the Python wrapper; the C unit tests cover the
    same inputs through the C API. Parity = same status, same canonical,
    same candidate list on AMBIGUOUS."""

    def test_exact_match_case_insensitive(self):
        # Mirrors test_resolver_exact_match
        fleet = ["SW-3850", "fortigate-200g", "R1", "Wazuh"]
        r = validation_resolve_device("SW-3850", fleet)
        self.assertEqual(r.status, ResolveStatus.RESOLVED)
        self.assertEqual(r.canonical, "SW-3850")

        r = validation_resolve_device("sw-3850", fleet)
        self.assertEqual(r.status, ResolveStatus.RESOLVED)
        self.assertEqual(r.canonical, "SW-3850",
                         "canonical should preserve registry case")

        r = validation_resolve_device("WAZUH", fleet)
        self.assertEqual(r.status, ResolveStatus.RESOLVED)
        self.assertEqual(r.canonical, "Wazuh")

    def test_token_prefix(self):
        # Mirrors test_resolver_token_prefix
        fleet = ["fortigate-200g", "SW-3850", "pa-850", "R1"]
        r = validation_resolve_device("fortigate", fleet)
        self.assertEqual(r.status, ResolveStatus.RESOLVED)
        self.assertEqual(r.canonical, "fortigate-200g")

        r = validation_resolve_device("FORTIGATE", fleet)
        self.assertEqual(r.status, ResolveStatus.RESOLVED)
        self.assertEqual(r.canonical, "fortigate-200g")

    def test_prefix_rejects_too_short_and_midtoken(self):
        # Mirrors test_resolver_prefix_rejects_too_short_and_midtoken
        fleet = ["fortigate-200g"]
        for short in ("for", "fort", "fortigate-20"):
            r = validation_resolve_device(short, fleet)
            self.assertEqual(r.status, ResolveStatus.UNRESOLVED,
                             f"{short!r} should NOT resolve")

    def test_no_hyphen_exact_only(self):
        # Mirrors test_resolver_no_hyphen_exact_only
        fleet = ["R1", "R12", "Wazuh"]
        r = validation_resolve_device("R1", fleet)
        self.assertEqual(r.status, ResolveStatus.RESOLVED)
        self.assertEqual(r.canonical, "R1")

        for noisy in ("R", "router", "router1"):
            r = validation_resolve_device(noisy, fleet)
            self.assertEqual(r.status, ResolveStatus.UNRESOLVED,
                             f"{noisy!r} should not resolve in no-hyphen fleet")

        r = validation_resolve_device("wazuh", fleet)
        self.assertEqual(r.status, ResolveStatus.RESOLVED)
        self.assertEqual(r.canonical, "Wazuh")

    def test_ambiguous(self):
        # Mirrors test_resolver_ambiguous
        fleet = ["fortigate-200g", "fortigate-100f", "fortiwifi-60f"]
        r = validation_resolve_device("fortigate", fleet)
        self.assertEqual(r.status, ResolveStatus.AMBIGUOUS)
        self.assertEqual(r.candidates, ["fortigate-200g", "fortigate-100f"],
                         "candidate order matches input order")

        # "forti" doesn't end at a hyphen boundary in any of these — UNRESOLVED
        r = validation_resolve_device("forti", fleet)
        self.assertEqual(r.status, ResolveStatus.UNRESOLVED)

    def test_exact_priority_over_prefix(self):
        # Mirrors test_resolver_exact_priority_over_prefix
        fleet = ["fortigate", "fortigate-200g"]
        r = validation_resolve_device("fortigate", fleet)
        self.assertEqual(r.status, ResolveStatus.RESOLVED)
        self.assertEqual(r.canonical, "fortigate",
                         "exact wins over prefix")

    def test_no_match(self):
        # Mirrors test_resolver_no_match
        fleet = ["fortigate-200g", "SW-3850"]
        for unrelated in ("the firewall", "", "nonexistent-device-99"):
            r = validation_resolve_device(unrelated, fleet)
            self.assertEqual(r.status, ResolveStatus.UNRESOLVED,
                             f"{unrelated!r} should not resolve")

    def test_empty_candidate_list(self):
        """Defensive: empty candidate list → UNRESOLVED."""
        r = validation_resolve_device("fortigate-200g", [])
        self.assertEqual(r.status, ResolveStatus.UNRESOLVED)


class ResolverIntegrationWithRegistry(unittest.TestCase):
    """One integration test against the real /run/virp/devices.json fleet
    (43 devices when this test was written). Skipped if the runtime file
    is not present (e.g. running in a CI environment without the
    deployed onode)."""

    @classmethod
    def setUpClass(cls):
        path = "/run/virp/devices.json"
        if not os.path.exists(path):
            raise unittest.SkipTest(f"{path} not present (lab-only test)")
        with open(path) as f:
            data = json.load(f)
        cls.hostnames = [d.get("hostname", "") for d in data.get("devices", [])]
        if not cls.hostnames:
            raise unittest.SkipTest("registry has no devices")

    def test_fortigate_resolves_to_fortigate_200g(self):
        """The case the brief described:
        'fortigate' → RESOLVED canonical 'fortigate-200g'."""
        r = validation_resolve_device("fortigate", self.hostnames)
        self.assertEqual(r.status, ResolveStatus.RESOLVED,
                         f"got {r.status.name} candidates={r.candidates}")
        self.assertEqual(r.canonical, "fortigate-200g")

    def test_sw3850_case_insensitive(self):
        """'sw-3850' (lowercase) resolves to 'SW-3850' (registry case)."""
        r = validation_resolve_device("sw-3850", self.hostnames)
        self.assertEqual(r.status, ResolveStatus.RESOLVED)
        self.assertEqual(r.canonical, "SW-3850")

    def test_R1_no_fuzzy_match(self):
        """No-hyphen device: 'R' alone must NOT resolve to R1 (or any R*).
        Determinism over leniency."""
        r = validation_resolve_device("R", self.hostnames)
        self.assertEqual(r.status, ResolveStatus.UNRESOLVED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
