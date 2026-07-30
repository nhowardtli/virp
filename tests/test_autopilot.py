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
import shutil
import sqlite3
import subprocess
import sys
import tempfile
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
        "librenms_devices": [librenms_payload("devices", 6)],
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
        self.assertTrue(any(d["check"] == "wazuh_unobservable"
                            for d in devs))
        # and it must NOT read as an agent-count change
        self.assertFalse(any(d["check"] == "wazuh_active_agents"
                             for d in devs))

    def test_all_zero_connection_block_is_unobservable_not_zero_agents(self):
        # virp-node2's real behaviour: HTTP 200, connection block present
        # but every counter 0 — resource-level RBAC filtering. Must read
        # as unobservable, never as "0 active of 0 total".
        r = healthy_results()
        r["wazuh_summary"] = [wazuh_summary_payload(0, 0)]
        devs = ap.evaluate_baselines(r)
        self.assertTrue(any(d["check"] == "wazuh_unobservable"
                            for d in devs))
        self.assertFalse(any(d["check"] in ("wazuh_active_agents",
                                            "wazuh_total_agents")
                             for d in devs))
        status, why = ap.eval_wazuh_summary(wazuh_summary_payload(0, 0))
        self.assertEqual(status, "denied")
        self.assertIn("RBAC", why)

    def test_agentless_node_not_told_it_lost_adjacencies(self):
        # An agentless node observes no FRR ring; it must not be alerted
        # for 8 adjacencies it was never asked to watch.
        r = healthy_results()
        del r["frr_neighbors"]
        del r["frr_routes"]
        devs = ap.evaluate_baselines(r)
        self.assertFalse(any(d["check"] == "frr_full_adjacencies"
                             for d in devs),
                         "agentless node must not get an FRR deviation")
        self.assertEqual(devs, [])

    def test_librenms_device_count_flags(self):
        # Either direction deviates from the 6-device inventory baseline:
        # 5 would be the old availability-filtered figure (proxmox01
        # down), 7 would be a genuinely new device.
        for observed in (5, 7):
            r = healthy_results()
            r["librenms_devices"] = [librenms_payload("devices", observed)]
            devs = ap.evaluate_baselines(r)
            self.assertTrue(any(d["check"] == "librenms_devices" and
                                d["observed"] == observed for d in devs),
                            "count=%d must deviate" % observed)


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
        # Built from EXPLICIT configs, never from the ambient module-level
        # BATTERY: on a deployed node /etc/virp/autopilot-node.json exists
        # and adds peer rows, which made this assertion pass on a build
        # host and fail on the real nodes. A unit test must not depend on
        # deployed state.
        wazuh_green = {"/agents", "/agents/summary/status",
                       "/manager/stats/analysisd"}
        librenms_green = {"/api/v0/devices", "/api/v0/alerts"}
        peer_green = {ap.PEER_CMD_LIVENESS, ap.PEER_CMD_CHAIN_HEAD,
                      ap.PEER_CMD_PUBLISHED}
        shapes = [
            {"node": "virp-lab", "frr_nodes": list(ap.FRR_NODES),
             "peer_device": "virp-node2-peer"},
            {"node": "virp-node2", "frr_nodes": [],
             "peer_device": "virp-lab-peer"},
            {"node": "solo", "frr_nodes": [], "peer_device": None},
        ]
        for cfg in shapes:
            for device, command, kind in ap.build_battery(cfg):
                if device == ap.WAZUH_DEV:
                    path = command.replace("GET ", "").split("?")[0]
                    self.assertIn(path, wazuh_green, command)
                elif device == ap.LIBRENMS_DEV:
                    path = command.replace("GET ", "").split("?")[0]
                    self.assertIn(path, librenms_green, command)
                elif device == cfg["peer_device"]:
                    self.assertIn(command, peer_green,
                                  "peer probes must be exact GREEN rows: %s"
                                  % command)
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
        self.assertEqual(ap.BASELINES["librenms_devices"], 6)

    def test_device_baseline_is_measured_by_the_query_the_loop_issues(self):
        # The rule the librenms 5-vs-6 incident bought us: the device
        # baseline describes UNFILTERED inventory, so the battery must
        # issue exactly that query. A filtered variant (?type=up etc.)
        # answers a different question and would silently split the
        # baseline from the measurement again.
        device_cmds = [c for d, c, kind in ap.BATTERY
                       if kind == "librenms_devices"]
        self.assertEqual(device_cmds, ["GET /api/v0/devices"])
        for cmd in device_cmds:
            self.assertNotIn("?", cmd,
                             "inventory baseline must not use a filtered "
                             "query: %s" % cmd)


def peer_liveness_payload(state="active"):
    return "virp-lab-peer$ systemctl is-active virp-onode\n%s" % state


def peer_chain_head_payload(session="autopilot:2026-07-29", seq=239,
                            entry_hash="7626023f1ab8829a"):
    return ("virp-lab-peer$ /opt/virp/build/virp-tool chain tail -n 1 "
            "--db /var/lib/virp/chain.db\n"
            "SESSION SEQ TYPE ARTIFACT_ID ENTRY_HASH PREV_HASH\n"
            "%s %d observation obs:x:1 %s prevhash" % (session, seq, entry_hash))


def summary(node="virp-lab", at=1785360000, devices=6, active=5, total=6):
    return {"node": node, "published_at": at,
            "chain_head": {"session": "s", "seq": 1, "entry_hash": "h"},
            "alerts": 0,
            "observed": {"librenms_devices": devices, "librenms_alerts": 1,
                         "wazuh_active": active, "wazuh_total": total,
                         "frr_full_adjacencies": 8}}


class TestPeerEvaluators(unittest.TestCase):
    def test_liveness(self):
        self.assertTrue(ap.eval_peer_liveness(peer_liveness_payload("active")))
        for bad in ("inactive", "failed", "unknown", ""):
            self.assertFalse(ap.eval_peer_liveness(peer_liveness_payload(bad)),
                             "%r must not read as live" % bad)

    def test_chain_head_parse(self):
        head = ap.eval_peer_chain_head(peer_chain_head_payload())
        self.assertEqual(head, {"session": "autopilot:2026-07-29", "seq": 239,
                                "entry_hash": "7626023f1ab8829a"})

    def test_chain_head_header_only_is_none(self):
        p = ("peer$ cmd\nSESSION SEQ TYPE ARTIFACT_ID ENTRY_HASH PREV_HASH\n"
             "(no chain entries)")
        self.assertIsNone(ap.eval_peer_chain_head(p))

    def test_peer_deviations_flow_into_baselines(self):
        r = healthy_results()
        r["peer_liveness"] = [peer_liveness_payload("inactive")]
        devs = ap.evaluate_baselines(r)
        self.assertTrue(any(d["check"] == "peer_daemon_liveness" and
                            d["observed"] == "inactive" for d in devs))

    def test_peer_rows_match_the_classifier_exact_rows(self):
        # These strings must be byte-identical to LINUX_PEER_GREEN_EXACT
        # in src/drivers/driver_linux.c; drift classifies RED and alerts.
        with open(os.path.join(REPO_ROOT, "src", "drivers",
                               "driver_linux.c")) as f:
            src = f.read()
        for cmd in (ap.PEER_CMD_LIVENESS, ap.PEER_CMD_CHAIN_HEAD,
                    ap.PEER_CMD_PUBLISHED):
            self.assertIn('"%s"' % cmd, src.replace('"\n                       "', ''),
                          "peer command not an exact GREEN row: %s" % cmd)


class TestComparator(unittest.TestCase):
    NOW = 1785360000

    def test_agreement_is_silent(self):
        self.assertEqual(
            ap.compare_views(summary(), summary(node="virp-node2"), self.NOW),
            [])

    def test_librenms_disagreement_flagged(self):
        f = ap.compare_views(summary(devices=6),
                             summary(node="virp-node2", devices=5), self.NOW)
        self.assertTrue(any(x["check"] == "observer_disagreement" and
                            x["target"] == "librenms_devices" and
                            x["local"] == 6 and x["peer"] == 5 for x in f))

    def test_wazuh_active_disagreement_flagged(self):
        f = ap.compare_views(summary(active=5),
                             summary(node="virp-node2", active=4), self.NOW)
        self.assertTrue(any(x["check"] == "observer_disagreement" and
                            x["target"] == "wazuh_active" for x in f))

    def test_missing_value_is_a_disagreement_not_equality(self):
        theirs = summary(node="virp-node2")
        theirs["observed"]["wazuh_active"] = None
        f = ap.compare_views(summary(), theirs, self.NOW)
        self.assertTrue(any(x["check"] ==
                            "observer_disagreement_missing_value" and
                            x["target"] == "wazuh_active" for x in f))

    def test_both_missing_still_disagreement(self):
        # Two observers that both failed to observe must NOT be reported
        # as agreeing — silence is not consensus.
        mine, theirs = summary(), summary(node="virp-node2")
        mine["observed"]["librenms_devices"] = None
        theirs["observed"]["librenms_devices"] = None
        f = ap.compare_views(mine, theirs, self.NOW)
        self.assertTrue(any(x["target"] == "librenms_devices" for x in f))

    def test_stale_peer_summary_flagged(self):
        old = summary(node="virp-node2", at=self.NOW - 1000)
        f = ap.compare_views(summary(), old, self.NOW)
        self.assertTrue(any(x["check"] == "peer_summary_stale" and
                            x["peer_age_sec"] == 1000 for x in f))

    def test_fresh_peer_within_limit_not_stale(self):
        recent = summary(node="virp-node2", at=self.NOW - 60)
        f = ap.compare_views(summary(), recent, self.NOW)
        self.assertFalse(any(x["check"] == "peer_summary_stale" for x in f))

    def test_unreadable_peer_summary_flagged(self):
        f = ap.compare_views(summary(), None, self.NOW)
        self.assertEqual([x["check"] for x in f], ["peer_summary_unreadable"])

    def test_missing_local_summary_flagged(self):
        f = ap.compare_views(None, summary(node="virp-node2"), self.NOW)
        self.assertTrue(any(x["check"] == "local_summary_missing" for x in f))

    def test_compared_keys_are_the_shared_targets(self):
        self.assertEqual(set(ap.COMPARED_KEYS),
                         {"librenms_devices", "wazuh_active", "wazuh_total"})


class TestNodeConfig(unittest.TestCase):
    def test_default_config_is_virp_lab_shape(self):
        cfg = ap.load_node_config("/nonexistent/autopilot-node.json")
        self.assertEqual(cfg["node"], "virp-lab")
        self.assertEqual(len(cfg["frr_nodes"]), 4)
        self.assertIsNone(cfg["peer_device"])

    def test_peerless_battery_has_no_peer_rows(self):
        b = ap.build_battery({"node": "x", "frr_nodes": [],
                              "peer_device": None})
        kinds = {k for _, _, k in b}
        self.assertNotIn("peer_liveness", kinds)
        self.assertNotIn("frr_neighbors", kinds)
        self.assertIn("wazuh_summary", kinds)

    def test_node2_shape_battery(self):
        b = ap.build_battery({"node": "virp-node2", "frr_nodes": [],
                              "peer_device": "virp-lab-peer"})
        kinds = [k for _, _, k in b]
        self.assertEqual(kinds, ["wazuh_summary", "wazuh_alerts",
                                 "librenms_devices", "librenms_alerts",
                                 "peer_liveness", "peer_chain_head"])
        # Peer probes must be the exact GREEN rows, never improvised.
        peer_cmds = [c for d, c, k in b if k.startswith("peer_")]
        self.assertEqual(peer_cmds, [ap.PEER_CMD_LIVENESS,
                                     ap.PEER_CMD_CHAIN_HEAD])


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
        with open(TEMPLATE) as f:
            text = f.read()
        for addr in self.BLOCKED:
            self.assertFalse(self.blocked_hit(text, addr),
                             "%s present in devices template" % addr)

    def test_template_still_has_librenms_and_placeholders_only(self):
        with open(TEMPLATE) as f:
            text = f.read()
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
