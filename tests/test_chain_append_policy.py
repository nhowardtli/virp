#!/usr/bin/env python3
"""Per-uid chain_append TYPE policy (v0.2.1) — fixture replay + invariants.

Two things are pinned here:

1. REPLAY the real 30-day (uid, chain_append, artifact_type) traffic exported
   from the production reference node (tests/fixtures/chain_append_triples_211_30d.json) against
   the canonical template's socket_uid_chain_append_types policy, and assert:
     - v0.2.1 (the explicit per-uid type policy) ADMITS every observed row;
     - v0.2.0 (any action-mapped uid narrowed to fed_* only) REFUSES at
       least the autopilot's observation appends — i.e. the regression this
       release fixes is reproduced from real traffic, not asserted in prose.

2. The STATIC boot invariant the daemon enforces (onode_start): every uid
   whose socket_uid_action_allow set includes chain_append must have a
   socket_uid_chain_append_types entry. A template that maps a chain_append
   uid without a type list is a boot failure; this test fails the same way.

Pure stdlib; no daemon. The template placeholders are substituted with the
uids the fixture uses so the two line up.
"""
import json
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CANON = os.path.join(ROOT, "deploy", "devices.template.json")
FIXTURE = os.path.join(HERE, "fixtures", "chain_append_triples_211_30d.json")

# Placeholder -> uid, matching the fixture's numeric uids (service accounts).
SUBST = {
    "${VIRP_UID}": "999",
    "${VIRP_BACKUP_UID}": "997",
    "${VIRP_EVIDENCE_UID}": "995",
    "${VIRP_NETCLAW_UID}": "993",
    "${VIRP_BROKER_UID}": "994",
}
FED_TYPES = {"fed_request", "fed_observation", "fed_outcome"}


def _subst_keys(obj):
    """Substitute the uid placeholders in a {uid_key: value} object."""
    return {SUBST.get(k, k): v for k, v in obj.items()}


def load_template():
    d = json.load(open(CANON))
    return {
        "allowed": [str(SUBST.get(u, u)) for u in d.get("socket_allowed_uids", [])],
        "action_allow": _subst_keys(d.get("socket_uid_action_allow", {})),
        "capp": _subst_keys(d.get("socket_uid_chain_append_types", {})),
    }


def load_fixture():
    """Only the chain_append rows are replayed against the type policy;
    the execute rows are carried in the fixture for the action-allowlist
    side and have no artifact_type."""
    return [t for t in json.load(open(FIXTURE))["triples"]
            if t["action"] == "chain_append" and t["artifact_type"]]


def load_fixture_execute():
    return [t for t in json.load(open(FIXTURE))["triples"]
            if t["action"] == "execute"]


def v021_allows(tmpl, uid, atype):
    """v0.2.1 semantics: a uid with a chain_append type policy may append
    only those types; a uid with no policy is unrestricted here."""
    pol = tmpl["capp"].get(str(uid))
    return atype in pol if pol is not None else True


def v020_allows(tmpl, uid, atype):
    """v0.2.0 semantics reproduced: any uid present in the action map is a
    'restricted federated principal' whose chain_append is narrowed to the
    fed_* triple; unmapped uids are unrestricted."""
    mapped = str(uid) in tmpl["action_allow"]
    return atype in FED_TYPES if mapped else True


class TestChainAppendPolicy(unittest.TestCase):
    def setUp(self):
        self.tmpl = load_template()
        self.fixture = load_fixture()

    def test_v021_admits_all_observed_traffic(self):
        """Every real 30-day chain_append row is admitted by the v0.2.1
        per-uid type policy."""
        refused = [(t["uid"], t["artifact_type"]) for t in self.fixture
                   if not v021_allows(self.tmpl, t["uid"], t["artifact_type"])]
        self.assertEqual(refused, [],
                         "v0.2.1 policy refuses real traffic: %s" % refused)

    def test_v020_refuses_the_real_traffic(self):
        """The v0.2.0 blanket fed-narrowing refuses the observed local-service
        appends — the regression, reproduced from real traffic. In
        particular the autopilot (999) observation append is refused."""
        refused = [(t["uid"], t["artifact_type"]) for t in self.fixture
                   if not v020_allows(self.tmpl, t["uid"], t["artifact_type"])]
        self.assertIn((999, "observation"), refused)
        # every non-fed observed type is refused by v0.2.0
        for t in self.fixture:
            if t["artifact_type"] not in FED_TYPES:
                self.assertIn((t["uid"], t["artifact_type"]), refused)

    def test_boot_invariant_every_chain_append_uid_has_a_type_policy(self):
        """The daemon's onode_start invariant, at the template level: any
        allowlisted uid whose action set includes chain_append must have a
        socket_uid_chain_append_types entry."""
        missing = []
        for uid, actions in self.tmpl["action_allow"].items():
            if "chain_append" in actions and uid not in self.tmpl["capp"]:
                missing.append(uid)
        self.assertEqual(missing, [],
                         "uids with chain_append but no type policy "
                         "(daemon would refuse to boot): %s" % missing)

    def test_broker_has_no_chain_append_and_no_type_policy(self):
        """The broker (994) relays no chain_append, so it correctly has no
        type policy — the invariant does not force one."""
        broker = self.tmpl["action_allow"].get("994", [])
        self.assertNotIn("chain_append", broker)
        self.assertNotIn("994", self.tmpl["capp"])

    def test_execute_rows_are_covered_by_the_action_allowlist(self):
        """Every uid observed issuing execute is allowlisted and has execute
        in its action set — the verb-level half of the same policy."""
        for t in load_fixture_execute():
            uid = str(t["uid"])
            self.assertIn(uid, self.tmpl["action_allow"],
                          "uid %s issues execute but has no action set" % uid)
            self.assertIn("execute", self.tmpl["action_allow"][uid],
                          "uid %s issues execute but its action set omits it" % uid)

    def test_uid_1000_covers_every_type_virp_tool_can_emit(self):
        """LINT: uid 1000 is the interactive operator, who appends through
        virp-tool. Derive the artifact types the tool can emit straight from
        its source and assert 1000's policy covers every one, so adding a
        new type to the tool cannot silently make it unappendable."""
        tool = os.path.join(ROOT, "src", "virp_tool.c")
        src = open(tool).read()
        # the tool builds requests as  \"artifact_type\":\"<type>\"
        emitted = set(re.findall(r'\\"artifact_type\\":\\"([a-z_]+)\\"', src))
        self.assertTrue(emitted, "found no artifact_type literals in virp_tool.c "
                                 "— the lint would pass vacuously")
        # The regex above only sees STRING LITERALS. If the tool ever builds
        # artifact_type through a format specifier, this lint would silently
        # stop covering it, so fail loudly instead of passing weakly.
        self.assertNotRegex(
            src, r'\\"artifact_type\\":\\"%',
            "virp_tool.c builds artifact_type with a format specifier; this "
            "lint only reads literals and can no longer prove coverage")
        policy = set(self.tmpl["capp"].get("1000", []))
        missing = sorted(emitted - policy)
        self.assertEqual(missing, [],
                         "virp-tool can emit %s which uid 1000's "
                         "chain_append policy does not cover" % missing)

    def test_netclaw_fed_narrowing_is_now_a_policy_row(self):
        """993's fed_* reach — the whole point of the old code path — is now
        exactly one row of the type policy."""
        self.assertEqual(set(self.tmpl["capp"]["993"]), FED_TYPES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
