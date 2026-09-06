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
        pbs_green_ops = {"backup.version.read", "backup.datastore.usage",
                         "backup.snapshots.list", "backup.verify.tasks"}
        shapes = [
            {"node": "virp-lab", "frr_nodes": list(ap.FRR_NODES),
             "peer_device": "virp-node2-peer",
             "pbs_device": ap.PBS_DEV, "pbs_datastore": "colo-backups"},
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
                elif device == cfg.get("pbs_device"):
                    # PBS commands are canonical typed operations, not
                    # paths: `pbs op=<id> [k=v ...]`. Assert the op id is
                    # one of the four v1 rows rather than pattern-matching
                    # a URL, which is the whole point of the encoding.
                    self.assertTrue(command.startswith("pbs op="), command)
                    op = command.split("op=", 1)[1].split(" ")[0]
                    self.assertIn(op, pbs_green_ops, command)
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
        # Built from an EXPLICIT config, never the ambient module-level
        # BATTERY. ap.BATTERY is assembled at import time from
        # /etc/virp/autopilot-node.json, so on a node whose identity names
        # no LibreNMS this read an empty list and the assertion failed on
        # the real node while passing on a build host.
        #
        # That is the SAME defect test_battery_rest_commands_are_in_green_sets
        # above records having fixed. This one survived because until
        # 2026-09-06 no deployed node had a LibreNMS-less identity: virp-lab
        # has LibreNMS and virp-onode-home had no identity file at all, so
        # both nodes happened to build a battery containing the rows. The
        # first correct home identity broke it immediately.
        battery = ap.build_battery({"node": "virp-lab",
                                    "frr_nodes": list(ap.FRR_NODES),
                                    "peer_device": None})
        device_cmds = [c for d, c, kind in battery
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

    def test_pbs_rows_are_config_gated(self):
        """A node without a PBS device must not probe one.

        node2's devices template has no PBS entry, so an ungated row
        would alert every cycle. Same gating as peer_device.
        """
        no_pbs = ap.build_battery({"node": "virp-node2", "frr_nodes": [],
                                   "peer_device": None})
        self.assertEqual([k for _, _, k in no_pbs if k.startswith("pbs_")], [])

        with_pbs = ap.build_battery({"node": "virp-lab", "frr_nodes": [],
                                     "peer_device": None,
                                     "pbs_device": ap.PBS_DEV,
                                     "pbs_datastore": "colo-backups"})
        self.assertEqual([k for _, _, k in with_pbs if k.startswith("pbs_")],
                         ["pbs_version", "pbs_datastore_usage",
                          "pbs_verify_tasks", "pbs_snapshots"])

        # No datastore configured -> the snapshots row is omitted rather
        # than improvised with a guessed store name.
        no_store = ap.build_battery({"node": "virp-lab", "frr_nodes": [],
                                     "peer_device": None,
                                     "pbs_device": ap.PBS_DEV})
        self.assertNotIn("pbs_snapshots", [k for _, _, k in no_store])

    def test_pbs_corpus_covers_every_refusal_class(self):
        """Each PBS refusal class must be replayed against the LIVE gate."""
        pbs_rows = [r for r in ap.CORPUS if r[0] == ap.PBS_DEV]
        cmds = [c for _, c, _, _ in pbs_rows]
        # unknown op / no write op at any tier
        self.assertIn("pbs op=backup.verify.run", cmds)
        # separator policy (refused at the daemon boundary)
        self.assertTrue(any(e == "separator" for _, _, e, _ in pbs_rows))
        # value charset: traversal, query smuggling, fragment
        self.assertTrue(any("../.." in c for c in cmds))
        self.assertTrue(any("?" in c for c in cmds))
        self.assertTrue(any("#" in c for c in cmds))
        # canonical form: duplicate, unsorted, undeclared, missing, case
        self.assertTrue(any("store=a store=b" in c for c in cmds))
        self.assertTrue(any("abc=1 store=" in c for c in cmds))
        self.assertIn("pbs op=backup.version.read store=colo-backups", cmds)
        self.assertIn("pbs op=backup.snapshots.list", cmds)
        self.assertIn("pbs op=BACKUP.VERSION.READ", cmds)
        # and exactly one GREEN control
        self.assertEqual(sum(1 for _, _, e, _ in pbs_rows if e == "green"), 1)

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


class TestHomeNodeShape(unittest.TestCase):
    """virp-onode-home ran for 14 days emitting the colo battery, because
    /etc/virp/autopilot-node.json did not exist there and load_node_config
    silently fell back to virp-lab. Every probe named a colo device the
    home daemon has never heard of, so all 12 returned a signed
    `device not found` ERROR, and the node published under virp-lab's
    identity. These pin the shape that fix cannot regress: the battery is
    built ONLY from config, and a target the node does not observe is
    omitted rather than probed and alerted on.
    """

    HOME = {"node": "virp-onode-home", "frr_nodes": [],
            "peer_device": None, "peer_node": None,
            "wazuh_device": "wazuh-home", "librenms_device": None,
            "pbs_device": None, "baselines": {}}

    def test_home_battery_is_wazuh_home_only(self):
        b = ap.build_battery(self.HOME)
        self.assertEqual(b, [
            ("wazuh-home", "GET /agents/summary/status",   "wazuh_summary"),
            ("wazuh-home", "GET /manager/stats/analysisd", "wazuh_alerts"),
        ])

    def test_home_battery_names_no_colo_device(self):
        colo = set(ap.FRR_NODES) | {ap.WAZUH_DEV, ap.LIBRENMS_DEV,
                                    ap.PBS_DEV}
        for device, command, kind in ap.build_battery(self.HOME):
            self.assertNotIn(device, colo,
                             "home battery must not name colo device %s"
                             % device)

    def test_librenms_rows_are_config_gated(self):
        """LibreNMS gets the treatment PBS and peer already have: a node
        with no LibreNMS must not probe one. Before this, LIBRENMS_DEV was
        a module constant used unconditionally, so config alone could not
        remove the rows."""
        kinds = {k for _, _, k in ap.build_battery(self.HOME)}
        self.assertNotIn("librenms_devices", kinds)
        self.assertNotIn("librenms_alerts", kinds)

    def test_wazuh_device_is_config_overridable(self):
        b = ap.build_battery(dict(self.HOME, wazuh_device="wazuh-elsewhere"))
        self.assertTrue(all(d == "wazuh-elsewhere" for d, _, _ in b))

    def test_wazuh_rows_absent_when_no_wazuh_device(self):
        kinds = {k for _, _, k in
                 ap.build_battery(dict(self.HOME, wazuh_device=None))}
        self.assertNotIn("wazuh_summary", kinds)
        self.assertNotIn("wazuh_alerts", kinds)


class TestScopedBaselines(unittest.TestCase):
    """A baseline the node has not agreed to is not a baseline. Home ships
    `baselines: {}` deliberately: its Wazuh agent count is not yet known,
    and inheriting the colo figures (5 active / 6 total) would alert every
    cycle on a number nobody chose. Absent key -> no check, which is the
    rule the FRR guard already followed."""

    def test_absent_wazuh_baseline_emits_no_count_deviation(self):
        r = {"wazuh_summary": [wazuh_summary_payload(3, 4)]}
        devs = ap.evaluate_baselines(r, baselines={})
        self.assertEqual(devs, [])

    def test_absent_librenms_baseline_emits_no_count_deviation(self):
        r = {"librenms_devices": [librenms_payload("devices", 99)]}
        self.assertEqual(ap.evaluate_baselines(r, baselines={}), [])

    def test_present_baseline_still_flags(self):
        r = {"wazuh_summary": [wazuh_summary_payload(3, 6)]}
        devs = ap.evaluate_baselines(r, baselines={"wazuh_active": 5,
                                                   "wazuh_total": 6})
        self.assertTrue(any(d["check"] == "wazuh_active_agents" and
                            d["observed"] == 3 for d in devs))

    def test_unobservable_still_reported_without_a_baseline(self):
        """An unreadable credential is a finding about THIS node, not a
        comparison against a number — it must survive an empty baseline
        set or home loses the only Wazuh signal it has."""
        r = {"wazuh_summary": [wazuh_rbac_denied_payload()]}
        devs = ap.evaluate_baselines(r, baselines={})
        self.assertTrue(any(d["check"] == "wazuh_unobservable"
                            for d in devs))

    def test_default_baselines_unchanged_when_omitted(self):
        """One-argument calls keep the module BASELINES: virp-lab must be
        bit-for-bit unaffected by this change."""
        self.assertEqual(ap.evaluate_baselines(healthy_results()), [])
        r = healthy_results()
        r["librenms_devices"] = [librenms_payload("devices", 5)]
        self.assertTrue(any(d["check"] == "librenms_devices"
                            for d in ap.evaluate_baselines(r)))


class TestShippedNodeTemplates(unittest.TestCase):
    """The node identity file is the artifact class that had no install
    path: referenced by the client, virp_report and DEPLOYED.md, present
    on virp-lab only because someone wrote it by hand, and absent on
    virp-onode-home. Both shapes are tracked now, so a node identity is
    something a commit names."""

    def load(self, name):
        path = os.path.join(REPO_ROOT, "deploy", name)
        self.assertTrue(os.path.exists(path), "%s missing" % name)
        with open(path) as f:
            return json.load(f)

    def test_home_template_builds_the_home_battery(self):
        cfg = ap.merge_node_config(self.load(
            "autopilot-node.home.template.json"))
        self.assertEqual(cfg["node"], "virp-onode-home")
        b = ap.build_battery(cfg)
        self.assertEqual([k for _, _, k in b],
                         ["wazuh_summary", "wazuh_alerts"])
        self.assertTrue(all(d == "wazuh-home" for d, _, _ in b))

    def test_home_template_ships_no_baselines(self):
        self.assertEqual(self.load(
            "autopilot-node.home.template.json").get("baselines"), {})

    def test_virp_lab_template_reproduces_the_live_colo_battery(self):
        cfg = ap.merge_node_config(self.load(
            "autopilot-node.virp-lab.template.json"))
        kinds = [k for _, _, k in ap.build_battery(cfg)]
        self.assertEqual(kinds,
                         ["frr_neighbors"] * 4 + ["frr_routes"] * 4 +
                         ["wazuh_summary", "wazuh_alerts",
                          "librenms_devices", "librenms_alerts",
                          "pbs_version", "pbs_datastore_usage",
                          "pbs_verify_tasks", "pbs_snapshots",
                          "peer_liveness", "peer_chain_head"])

    def test_templates_carry_no_credentials(self):
        for name in ("autopilot-node.home.template.json",
                     "autopilot-node.virp-lab.template.json"):
            text = json.dumps(self.load(name)).lower()
            for bad in ("password", "passwd", "secret", "token", "${"):
                self.assertNotIn(bad, text,
                                 "%s must carry no credential material"
                                 % name)


class TestCameraRuntimeCoversWhatTheTimersCall(unittest.TestCase):
    """virp-spool-retention.service execs

        virp_camera.py retention --tier spool --days 14 ...

    every night at 02:30 UTC, and virp-camera-submit.service execs
    `submit-spool` continuously.

    On 2026-09-06 the checkout on 313 was three commits behind and its
    camera/virp_camera.py defined no run_retention at all. Installing
    that tracked file over the running one would have broken retention
    silently — the timer would have exited non-zero into a log nobody
    reads, and the 14-day declare-then-delete would simply stop, which
    looks identical to "nothing was old enough to delete".

    The tracked runtime must not fall below what an installed unit
    invokes. Checked against the SOURCE TEXT rather than by importing:
    the module is 200 KB and pulls in camera dependencies that need not
    exist on a build host, and the question here is only what the file
    defines and dispatches.

    Assertions deliberately use assertTrue with a short message — an
    assertIn against this file embeds 200 KB of source in the failure.
    """

    CAMERA_PY = os.path.join(REPO_ROOT, "camera", "virp_camera.py")

    # Subcommand exactly as spelled in the unit's ExecStart.
    TIMER_SUBCOMMANDS = ("retention", "submit-spool")

    def source(self):
        self.assertTrue(os.path.exists(self.CAMERA_PY),
                        "camera/virp_camera.py must be tracked")
        with open(self.CAMERA_PY) as f:
            return f.read()

    def test_run_retention_is_defined(self):
        """The specific regression: the tracked copy had no run_retention
        while the timer called it."""
        self.assertTrue("def run_retention(" in self.source(),
                        "camera/virp_camera.py defines no run_retention(), "
                        "but virp-spool-retention.service execs "
                        "`virp_camera.py retention`")

    def test_every_timer_subcommand_is_registered_and_dispatched(self):
        text = self.source()
        for sub in self.TIMER_SUBCOMMANDS:
            self.assertTrue('add_parser("%s"' % sub in text,
                            "subcommand %r is execed by a unit but is not "
                            "registered with add_parser in the tracked "
                            "runtime" % sub)
            self.assertTrue('args.cmd == "%s"' % sub in text,
                            "subcommand %r is execed by a unit but nothing "
                            "dispatches it in the tracked runtime" % sub)

    def test_units_exec_the_camera_runtime_at_its_installed_path(self):
        """The units name an absolute path. If camera/virp_camera.py ever
        stops installing there, this is what notices."""
        deploy = os.path.join(REPO_ROOT, "deploy")
        for unit in ("virp-camera-submit.service",
                     "virp-spool-retention.service"):
            p = os.path.join(deploy, unit)
            self.assertTrue(os.path.exists(p), "%s must be tracked" % unit)
            with open(p) as f:
                body = f.read()
            self.assertTrue(
                "/usr/local/lib/virp-camera/virp_camera.py" in body,
                "%s must exec the camera runtime at its installed path"
                % unit)

    def test_each_unit_uses_the_subcommand_this_test_pins(self):
        """Keeps TIMER_SUBCOMMANDS honest: if a unit's ExecStart changes
        to a subcommand this test does not know about, say so here rather
        than quietly checking the wrong two."""
        deploy = os.path.join(REPO_ROOT, "deploy")
        for unit, sub in (("virp-camera-submit.service", "submit-spool"),
                          ("virp-spool-retention.service", "retention")):
            with open(os.path.join(deploy, unit)) as f:
                body = f.read()
            self.assertTrue(sub in body,
                            "%s no longer execs %r — update "
                            "TIMER_SUBCOMMANDS" % (unit, sub))
            self.assertIn(sub, self.TIMER_SUBCOMMANDS)


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

    def test_socket_allowlist_excludes_root(self):
        """Deliberate policy (2026-07-30): the daemon socket allowlist
        EXCLUDES uid 0 on every node. CT 211 always did; the colo nodes
        included it because the autopilot ran as root. The allowlist is now
        the daemon's own uid (rendered from ${VIRP_UID}) plus 1000, the
        interactive operator. Pinned here because the drift was silent —
        two nodes disagreed on a security policy and nothing failed."""
        for name in ("devices.template.json", "devices.node2.template.json"):
            path = os.path.join(REPO_ROOT, "deploy", name)
            with open(path) as f:
                cfg = json.load(f)
            uids = cfg.get("socket_allowed_uids")
            self.assertIsNotNone(uids, "%s: allowlist must be explicit" % name)
            self.assertNotIn(0, uids, "%s: uid 0 must not be allowed" % name)
            self.assertNotIn("0", uids, "%s: uid 0 must not be allowed" % name)
            self.assertIn("${VIRP_UID}", uids,
                          "%s: allowlist should resolve the daemon uid, not "
                          "hardcode a per-host number" % name)
            self.assertIn("_socket_allowlist_policy", cfg,
                          "%s: the policy must be documented in place" % name)

    def test_autopilot_units_do_not_run_as_root(self):
        """The units must name a User. Running as the daemon's own account
        is deliberate: verification needs the O-Key, VIRP signs with
        symmetric HMAC, and virp_key_load_file refuses a group-readable key
        — so a separate uid could only verify by weakening key hygiene or
        duplicating the signing key. Documented in the units themselves."""
        deploy = os.path.join(REPO_ROOT, "deploy")
        units = [u for u in os.listdir(deploy)
                 if u.startswith("virp-autopilot") and u.endswith(".service")]
        self.assertTrue(units, "no autopilot units found")
        for u in units:
            with open(os.path.join(deploy, u)) as f:
                text = f.read()
            self.assertIn("User=virp\n", text,
                          "%s must run as virp, not root" % u)
            self.assertNotIn("User=root", text, "%s must not run as root" % u)
            self.assertIn("insecure mode", text,
                          "%s must record WHY a separate uid was rejected" % u)

    def test_scan_boundary_semantics(self):
        self.assertTrue(self.blocked_hit('"host": "10.0.10.1"', "10.0.10.1"))
        self.assertTrue(self.blocked_hit('"host": "10.0.10.10"', "10.0.10.10"))
        self.assertFalse(self.blocked_hit('"host": "10.0.10.12"', "10.0.10.1"))
        self.assertFalse(self.blocked_hit('"host": "10.0.10.100"', "10.0.10.10"))


if __name__ == "__main__":
    r = unittest.main(exit=False, verbosity=1)
    sys.exit(0 if r.result.wasSuccessful() else 1)
