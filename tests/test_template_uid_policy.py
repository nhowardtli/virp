#!/usr/bin/env python3
"""
test_template_uid_policy.py — the SHIPPED deployment templates must give
every allowed uid an explicit per-uid action policy, and none of the
four service identities may be able to invoke shutdown.

Sep 1 review, Task 2. The daemon treats a uid that is on
socket_allowed_uids but absent from socket_uid_action_allow as
unrestricted (shutdown included), and the tracked template shipped
virp-backup, virp-evidence, virp-netclaw and virp-broker exactly that
way. onode_start() now refuses to run in that state; this test makes
the same mistake a CI failure before it can become a boot failure on a
host.

Renders the REAL templates with the REAL deploy/render-devices.sh
(paths redirected into a sandbox via the VIRP_RENDER_* overrides, with
throwaway values for every placeholder), then checks the rendered
policy against the daemon's own action table and limits, parsed from
src/ and include/ so the test cannot drift from the code it guards.
Reads no production path and writes none.

Copyright (c) 2026 Third Level IT LLC. All rights reserved.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RENDER = os.path.join(ROOT, "deploy", "render-devices.sh")
CANONICAL = os.path.join(ROOT, "deploy", "devices.template.json")
NODE2 = os.path.join(ROOT, "deploy", "devices.node2.template.json")

# Distinct, recognisable sandbox uids for the identities the canonical
# template names — what the policy assertions below key on.
UIDS = {
    "VIRP_UID": "999",
    "VIRP_BACKUP_UID": "997",
    "VIRP_EVIDENCE_UID": "995",
    "VIRP_NETCLAW_UID": "993",
    "VIRP_BROKER_UID": "994",
}
OPERATOR_UID = "1000"
SERVICE_IDENTITIES = ("VIRP_BACKUP_UID", "VIRP_EVIDENCE_UID",
                      "VIRP_NETCLAW_UID", "VIRP_BROKER_UID")

# Every non-uid placeholder the render script knows about, with a
# throwaway value. The script only demands the ones a template names.
SECRETS = {k: "sandbox-" + k.lower() for k in (
    "WAZUH_USER", "WAZUH_PASS", "LIBRENMS_TOKEN", "PEER_USER", "PEER_PASS",
    "ZAMMAD_RO_TOKEN", "ZAMMAD_RW_TOKEN", "PBS_HOST", "PBS_TOKENID",
    "PBS_TOKEN", "PBS_FINGERPRINT", "PBS_DATASTORES", "PBS_SERVERNAME",
    "SWITCH_PASS", "LAB_PASSWORD", "LAB_ENABLE")}
SECRETS["LAB_ENABLE"] = "sandbox-enable-distinct"   # must differ from LAB_PASSWORD


def daemon_action_names():
    """The wire-name table from src/virp_onode.c (ONODE_ACTION_NAMES)."""
    src = open(os.path.join(ROOT, "src", "virp_onode.c")).read()
    m = re.search(r"ONODE_ACTION_NAMES\[\] = \{(.*?)\};", src, re.S)
    assert m, "ONODE_ACTION_NAMES table not found in src/virp_onode.c"
    names = re.findall(r'\{\s*"([a-z_]+)",\s*ONODE_ACTION_', m.group(1))
    assert "shutdown" in names and "execute" in names, names
    return set(names)


def daemon_max_uid_actions():
    hdr = open(os.path.join(ROOT, "include", "virp_onode.h")).read()
    m = re.search(r"#define ONODE_MAX_UID_ACTIONS\s+(\d+)", hdr)
    assert m, "ONODE_MAX_UID_ACTIONS not found in include/virp_onode.h"
    return int(m.group(1))


def render(template_path):
    tmp = tempfile.mkdtemp()
    env_file = os.path.join(tmp, "env")
    out = os.path.join(tmp, "out.json")
    with open(env_file, "w") as f:
        for k, v in list(UIDS.items()) + list(SECRETS.items()):
            f.write("%s=%s\n" % (k, v))
    env = dict(os.environ, VIRP_RENDER_ENV_FILE=env_file,
               VIRP_RENDER_TEMPLATE=template_path, VIRP_RENDER_OUT=out)
    p = subprocess.run(["bash", RENDER], env=env, capture_output=True,
                       text=True)
    if p.returncode != 0:
        raise AssertionError("render of %s failed (rc=%d):\n%s"
                             % (os.path.basename(template_path),
                                p.returncode, p.stderr))
    with open(out) as f:
        return json.load(f)


class _PolicyChecks:
    """Assertions shared by both templates."""

    template = None

    @classmethod
    def setUpClass(cls):
        cls.doc = render(cls.template)
        cls.allowed = [str(u) for u in cls.doc["socket_allowed_uids"]]
        cls.policy = cls.doc.get("socket_uid_action_allow")
        cls.names = daemon_action_names()
        cls.max_actions = daemon_max_uid_actions()

    def test_policy_object_present(self):
        self.assertIsInstance(self.policy, dict,
                              "template ships no socket_uid_action_allow — "
                              "every allowed uid would be unrestricted and "
                              "the daemon now refuses to start")

    def test_every_allowed_uid_has_an_action_policy(self):
        missing = [u for u in self.allowed if u not in self.policy]
        self.assertEqual(missing, [],
                         "allowed uids with NO action policy (would be "
                         "unrestricted; daemon refuses to boot): %s"
                         % missing)

    def test_no_policy_for_a_uid_that_cannot_connect(self):
        # an entry for a uid the accept path refuses is inert and misleads
        # an auditor reading the template
        inert = [u for u in self.policy if u not in self.allowed]
        self.assertEqual(inert, [], "action policy for non-allowed uid: %s"
                         % inert)

    def test_every_action_set_is_well_formed(self):
        for uid, actions in self.policy.items():
            with self.subTest(uid=uid):
                self.assertIsInstance(actions, list)
                self.assertLessEqual(len(actions), self.max_actions,
                                     "loader would treat this as malformed "
                                     "(DENY-ALL)")
                self.assertEqual(len(actions), len(set(actions)),
                                 "duplicate action names")
                unknown = sorted(set(actions) - self.names)
                self.assertEqual(unknown, [], "not daemon action names "
                                              "(loader → DENY-ALL): %s"
                                 % unknown)

    def test_no_placeholder_survives_in_the_policy(self):
        for uid in self.policy:
            self.assertNotIn("${", uid)
            self.assertTrue(uid.isdigit(), uid)


class CanonicalTemplateTests(_PolicyChecks, unittest.TestCase):
    template = CANONICAL

    def test_the_four_service_identities_cannot_shut_the_daemon_down(self):
        for name in SERVICE_IDENTITIES:
            uid = UIDS[name]
            with self.subTest(identity=name, uid=uid):
                self.assertIn(uid, self.policy)
                self.assertNotIn("shutdown", self.policy[uid],
                                 "%s can invoke shutdown" % name)

    def test_backup_and_evidence_are_collect_only(self):
        # what autopilot/virp_config_backup.py and autopilot/virp_evidence.py
        # send, and nothing more: a gated read (execute) and the append
        # that stores its signed result
        for name in ("VIRP_BACKUP_UID", "VIRP_EVIDENCE_UID"):
            with self.subTest(identity=name):
                self.assertEqual(set(self.policy[UIDS[name]]),
                                 {"execute", "chain_append"})

    def test_netclaw_gets_only_what_the_bridge_sends(self):
        # the installed netclaw bridge (virp-bridge-mcp.py) sends exactly
        # session_hello, session_bind, execute, chain_append
        self.assertEqual(set(self.policy[UIDS["VIRP_NETCLAW_UID"]]),
                         {"session_hello", "session_bind", "execute",
                          "chain_append"})

    def test_broker_matches_its_own_relay_allowlist(self):
        src = open(os.path.join(ROOT, "broker", "virp_broker.py")).read()
        m = re.search(r"ALLOWED_ACTIONS = frozenset\(\{(.*?)\}\)", src, re.S)
        self.assertTrue(m, "broker ALLOWED_ACTIONS not found")
        relay = set(re.findall(r'"([a-z_]+)"', m.group(1)))
        self.assertEqual(set(self.policy[UIDS["VIRP_BROKER_UID"]]), relay)

    def test_daemon_service_account_has_no_shutdown(self):
        # no client running as the daemon's own uid sends shutdown; the
        # unit stops on SIGTERM. Everything else stays as before.
        acts = set(self.policy[UIDS["VIRP_UID"]])
        self.assertNotIn("shutdown", acts)
        self.assertEqual(acts, self.names - {"shutdown"})

    def test_operator_keeps_the_full_vocabulary(self):
        self.assertEqual(set(self.policy[OPERATOR_UID]), self.names)


class Node2TemplateTests(_PolicyChecks, unittest.TestCase):
    template = NODE2

    def test_daemon_service_account_has_no_shutdown(self):
        self.assertNotIn("shutdown", self.policy[UIDS["VIRP_UID"]])

    def test_operator_keeps_the_full_vocabulary(self):
        self.assertEqual(set(self.policy[OPERATOR_UID]), self.names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
