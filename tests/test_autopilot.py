#!/usr/bin/env python3
"""
Unit tests for the autopilot client — pure logic only: evaluators,
baseline math, corpus/battery policy invariants, and the exclusion
guarantee on the deployed device template. No daemon, no devices, no
network.

Run: make test-autopilot   (or python3 tests/test_autopilot.py)
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "autopilot"))

import virp_autopilot as ap  # noqa: E402

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
TEMPLATE = os.path.join(REPO_ROOT, "deploy", "devices.template.json")


def frr_neighbor_payload(n_full):
    lines = ["clab-frr-ospf-frr1$ vtysh -c \"show ip ospf neighbor\"", "",
             "Neighbor ID     Pri State           Up Time  ..."]
    for i in range(n_full):
        lines.append("%d.%d.%d.%d          1 Full/-          1h0%dm  ..."
                     % (i + 2, i + 2, i + 2, i + 2, i))
    return "\n".join(lines)


def wazuh_summary_payload(active=5, total=6):
    doc = {"data": {"connection": {"active": active,
                                   "disconnected": total - active,
                                   "never_connected": 0, "pending": 0,
                                   "total": total}},
           "error": 0}
    return "wazuh-lab>/agents/summary/status [HTTP 200]\n" + json.dumps(doc)


def wazuh_rbac_denied_payload():
    # The Wazuh RBAC subtlety: denial is HTTP 200 with EMPTY data,
    # not a 403 — must be asserted as empty-result.
    return ("wazuh-lab>/agents/summary/status [HTTP 200]\n" +
            json.dumps({"data": {}, "error": 0}))


def wazuh_items_payload(n):
    doc = {"data": {"affected_items": [{"i": i} for i in range(n)],
                    "total_affected_items": n}, "error": 0}
    return "wazuh-lab>/manager/stats/analysisd [HTTP 200]\n" + json.dumps(doc)


def librenms_payload(key, count):
    doc = {"status": "ok", key: [{}] * count, "count": count}
    return "librenms-lab>/api/v0/%s [HTTP 200]\n%s" % (key, json.dumps(doc))


def healthy_results():
    return {
        "frr_neighbors": [frr_neighbor_payload(2)] * 4,   # 8 Full total
        "frr_routes":    ["frr$ vtysh -c \"show ip route ospf\"\n"
                          "O>* 10.10.23.0/30 [110/20] via ..."] * 4,
        "wazuh_summary": [wazuh_summary_payload(5, 6)],
        "wazuh_alerts":  [wazuh_items_payload(1)],
        "librenms_devices": [librenms_payload("devices", 5)],
        "librenms_alerts":  [librenms_payload("alerts", 1)],
    }


class TestEvaluators(unittest.TestCase):
    def test_count_full_adjacencies(self):
        self.assertEqual(ap.count_full_adjacencies(frr_neighbor_payload(2)), 2)
        self.assertEqual(ap.count_full_adjacencies(frr_neighbor_payload(0)), 0)
        # 2-Way / Init states never count as Full
        p = frr_neighbor_payload(1) + "\n9.9.9.9  1 2-Way/DROther  ..."
        self.assertEqual(ap.count_full_adjacencies(p), 1)

    def test_wazuh_summary_parses(self):
        self.assertEqual(ap.eval_wazuh_summary(wazuh_summary_payload(5, 6)),
                         (5, 6))

    def test_wazuh_rbac_denial_is_empty_result_not_403(self):
        status, why = ap.eval_wazuh_summary(wazuh_rbac_denied_payload())
        self.assertEqual(status, "denied")
        self.assertIn("empty", why)

    def test_wazuh_affected_items_denial(self):
        status, why = ap.eval_wazuh_affected_items(wazuh_items_payload(0))
        self.assertEqual(status, "denied")
        status, n = ap.eval_wazuh_affected_items(wazuh_items_payload(3))
        self.assertEqual((status, n), ("ok", 3))

    def test_librenms_count(self):
        self.assertEqual(
            ap.eval_librenms_count(librenms_payload("devices", 5), "devices"), 5)
        bad = "librenms-lab>/api/v0/devices [HTTP 200]\n{\"status\":\"error\"}"
        self.assertIsNone(ap.eval_librenms_count(bad, "devices"))


class TestBaselines(unittest.TestCase):
    def test_healthy_cycle_no_deviations(self):
        self.assertEqual(ap.evaluate_baselines(healthy_results()), [])

    def test_lost_adjacency_flags(self):
        r = healthy_results()
        r["frr_neighbors"] = [frr_neighbor_payload(2)] * 3 + \
                             [frr_neighbor_payload(1)]
        devs = ap.evaluate_baselines(r)
        self.assertTrue(any(d["check"] == "frr_full_adjacencies" and
                            d["observed"] == 7 for d in devs))

    def test_wazuh_active_flags_in_both_directions(self):
        # The disconnected agent is unexplained: a drop AND a recovery
        # both deviate from the agreed baseline of 5.
        for active in (4, 6):
            r = healthy_results()
            r["wazuh_summary"] = [wazuh_summary_payload(active, 6)]
            devs = ap.evaluate_baselines(r)
            self.assertTrue(any(d["check"] == "wazuh_active_agents" and
                                d["observed"] == active for d in devs),
                            "active=%d must deviate" % active)

    def test_wazuh_rbac_denial_flags_not_zero_agents(self):
        r = healthy_results()
        r["wazuh_summary"] = [wazuh_rbac_denied_payload()]
        devs = ap.evaluate_baselines(r)
        self.assertTrue(any(d["check"] == "wazuh_summary_denied"
                            for d in devs))
        # and it must NOT read as an agent-count change
        self.assertFalse(any(d["check"] == "wazuh_active_agents"
                             for d in devs))

    def test_librenms_device_count_flags(self):
        r = healthy_results()
        r["librenms_devices"] = [librenms_payload("devices", 6)]
        devs = ap.evaluate_baselines(r)
        self.assertTrue(any(d["check"] == "librenms_devices" and
                            d["observed"] == 6 for d in devs))


class TestPolicyInvariants(unittest.TestCase):
    def test_corpus_has_no_yellow_live_replays(self):
        # Replaying YELLOW rows nightly would EXECUTE them (clears,
        # pings) on real devices. They are covered by the offline unit
        # suite instead. This test locks the policy in.
        yellow_markers = ["clear ip ospf neighbor", "clear ip ospf interface",
                          '"ping', '"traceroute']
        for _, command, _, _ in ap.CORPUS:
            for m in yellow_markers:
                self.assertNotIn(m, command,
                                 "YELLOW-executing command in live corpus: %s"
                                 % command)

    def test_corpus_expectation_kinds_are_known(self):
        kinds = {e for _, _, e, _ in ap.CORPUS}
        self.assertEqual(kinds, {"separator", "rejected", "green"})

    def test_separator_cases_assert_the_outer_layer(self):
        # A separator-carrying command is refused at the request
        # boundary (UNCLASSIFIED + "illegal separator"), before
        # classification. The corpus must assert that specific layer so
        # a regression demoting it to a weaker one is caught.
        seps = [(c, m) for _, c, e, m in ap.CORPUS if e == "separator"]
        self.assertTrue(seps)
        for command, must_contain in seps:
            self.assertTrue(any(ch in command for ch in ";|&`"),
                            "separator case must carry a separator: %s"
                            % command)
            self.assertEqual(must_contain, "illegal separator")

    def test_battery_rest_commands_are_in_green_sets(self):
        wazuh_green = {"/agents", "/agents/summary/status",
                       "/manager/stats/analysisd"}
        librenms_green = {"/api/v0/devices", "/api/v0/alerts"}
        for device, command, _ in ap.BATTERY:
            if device == ap.WAZUH_DEV:
                path = command.replace("GET ", "").split("?")[0]
                self.assertIn(path, wazuh_green, command)
            elif device == ap.LIBRENMS_DEV:
                path = command.replace("GET ", "").split("?")[0]
                self.assertIn(path, librenms_green, command)
            else:
                self.assertTrue(command.startswith('vtysh -c "show '),
                                "FRR battery must be vtysh show reads: %s"
                                % command)

    def test_no_green_ingestion_endpoint_means_log_only(self):
        # Policy lock: alerts are log-only until an ingestion endpoint is
        # EXPLICITLY classified GREEN. Whoever flips this must also build
        # the posting path deliberately.
        self.assertIsNone(ap.WAZUH_GREEN_INGESTION_ENDPOINT)

    def test_baselines_match_agreement(self):
        self.assertEqual(ap.BASELINES["frr_full_adjacencies"], 8)
        self.assertEqual(ap.BASELINES["wazuh_active"], 5)
        self.assertEqual(ap.BASELINES["wazuh_total"], 6)
        self.assertEqual(ap.BASELINES["librenms_devices"], 5)


class TestTemplateExclusions(unittest.TestCase):
    """Mirror of the C-side boundary scan (virp_config_blocked_address):
    the shipped device template must never carry 10.0.10.1 / 10.0.10.10,
    while the legitimate LibreNMS host 10.0.10.12 stays present."""

    BLOCKED = ["10.0.10.1", "10.0.10.10"]

    @staticmethod
    def blocked_hit(text, addr):
        start = 0
        while True:
            i = text.find(addr, start)
            if i < 0:
                return False
            prev = text[i - 1] if i > 0 else ""
            nxt = text[i + len(addr):i + len(addr) + 1]
            if not (prev.isdigit() or prev == ".") and not nxt.isdigit():
                return True
            start = i + 1

    def test_template_carries_no_blocked_address(self):
        text = open(TEMPLATE).read()
        for addr in self.BLOCKED:
            self.assertFalse(self.blocked_hit(text, addr),
                             "%s present in devices template" % addr)

    def test_template_still_has_librenms_and_placeholders_only(self):
        text = open(TEMPLATE).read()
        self.assertIn("10.0.10.12", text)
        self.assertIn("10.0.20.10", text)
        # Secrets are placeholders, rendered at daemon start — the
        # template itself must never contain a literal credential.
        for ph in ("${WAZUH_USER}", "${WAZUH_PASS}", "${LIBRENMS_TOKEN}"):
            self.assertIn(ph, text)

    def test_scan_boundary_semantics(self):
        self.assertTrue(self.blocked_hit('"host": "10.0.10.1"', "10.0.10.1"))
        self.assertTrue(self.blocked_hit('"host": "10.0.10.10"', "10.0.10.10"))
        self.assertFalse(self.blocked_hit('"host": "10.0.10.12"', "10.0.10.1"))
        self.assertFalse(self.blocked_hit('"host": "10.0.10.100"', "10.0.10.10"))


if __name__ == "__main__":
    r = unittest.main(exit=False, verbosity=1)
    sys.exit(0 if r.result.wasSuccessful() else 1)
