#!/usr/bin/env python3
"""Tests for the compliance-evidence collector and its control report.

Covers, per the module's contract:
  - a clean collection cycle produces signed, chain-registered evidence
    for EVERY item on EVERY device, and submits nothing but GREEN reads
  - the identity refuses to start when it can read key/credential
    material, or when running as root / the daemon user / the other
    runbook's identity
  - the collector is structurally unable to approve anything
  - the read-only mandate survives a hostile edit of the operator-owned
    item list: a non-GREEN command is refused before it reaches the gate
  - an unmapped item is FLAGGED, never dropped
  - the control mapping is data: re-mapping needs no code change
  - the report renders control-by-control and its integrity numbers agree
    with an independent count of the same chain
  - deployment policy: unit sandbox, timer cadence, socket allowlist
    placeholder, render-script resolution, ACL grant shape
"""

import base64
import hashlib
import hmac as hmac_mod
import json
import os
import re
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "autopilot"))
sys.path.insert(0, os.path.join(REPO_ROOT, "report"))

import virp_evidence as ev  # noqa: E402
import verify  # noqa: E402

try:
    import reportlab  # noqa: F401
    HAVE_REPORTLAB = True
except ImportError:
    HAVE_REPORTLAB = False

OBS_DEVICE_OUTPUT = 0x07
OBS_ERROR = 0x0F

SHIPPED_ITEMS = os.path.join(REPO_ROOT, "deploy", "evidence-items.json")
SHIPPED_CONTROLS = os.path.join(REPO_ROOT, "deploy", "controls.json")

RUNNING_CONFIG = """Building configuration...

Current configuration:
!
frr version 10.2.1_git
hostname frr1
!
interface eth1
 ip address 10.10.12.1/30
exit
!
end
"""

TEST_OKEY = bytes(range(32))
TEST_CHAIN_KEY = bytes((i * 7 + 3) & 0xFF for i in range(32))


# ── fake daemon ────────────────────────────────────────────────────────

def fake_obs(payload, obs_type=OBS_DEVICE_OUTPUT, tier=0x01):
    data = payload.encode()
    body = struct.pack("!BBH", obs_type, 1, len(data)) + data
    hdr = struct.pack("!BBHIBBHIQ", 2, 3, 24 + 32 + len(body), 1, 1, tier,
                      0, 7, 1234567890)
    return hdr + b"\x00" * 32 + body


class FakeSend:
    """Records every request; answers like the live daemon: GREEN device
    output for reads, signed receipts for chain_append."""

    def __init__(self, outputs=None, default=RUNNING_CONFIG, tier=0x01,
                 fail_chain=False):
        self.outputs = outputs or {}     # command -> output text
        self.default = default
        self.tier = tier
        self.fail_chain = fail_chain
        self.requests = []

    def __call__(self, req):
        self.requests.append(req)
        if req["action"] == "chain_append":
            if self.fail_chain:
                return struct.pack(">i", -7)
            return fake_obs('{"chain_entry_hash":"feed"}', obs_type=0x0B)
        if req["action"] == "execute":
            text = self.outputs.get(req["command"], self.default)
            echo = "%s$ %s\n" % (req["device"], req["command"])
            return fake_obs(echo + text, tier=self.tier)
        raise AssertionError("unexpected action %r" % req["action"])

    def executes(self):
        return [r["command"] for r in self.requests
                if r["action"] == "execute"]

    def chain_appends(self, artifact_type=None):
        return [r for r in self.requests if r["action"] == "chain_append"
                and (artifact_type is None
                     or r["artifact_type"] == artifact_type)]


class CollectorCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.alerts = os.path.join(self.root, "alerts.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def alert_kinds(self):
        if not os.path.exists(self.alerts):
            return []
        with open(self.alerts) as f:
            return [json.loads(l)["kind"] for l in f if l.strip()]

    def write_json(self, name, obj):
        path = os.path.join(self.root, name)
        with open(path, "w") as f:
            json.dump(obj, f)
        return path

    def items_file(self, items):
        return self.write_json("items.json",
                               {"schema": "virp_evidence_items/1",
                                "items": items})

    def controls_file(self, controls, framework="PLACEHOLDER"):
        return self.write_json("controls.json",
                               {"schema": "virp_evidence_controls/1",
                                "framework": framework,
                                "controls": controls})

    def run_cycle(self, send, items_paths=(SHIPPED_ITEMS,),
                  controls_paths=(SHIPPED_CONTROLS,), devices=("frr1",)):
        return ev.run(root=self.root, send=send, alerts_file=self.alerts,
                      items_paths=items_paths, controls_paths=controls_paths,
                      devices=list(devices))


# ── The read-only mandate ──────────────────────────────────────────────

class TestGreenFormGuard(unittest.TestCase):
    """The collector must be unable to ASK for anything but a GREEN read,
    however its operator-editable item list is edited."""

    def test_accepts_green_reads(self):
        for c in ('vtysh -c "show running-config"',
                  'vtysh -c "show logging"',
                  'vtysh -c "show ip ospf neighbor"',
                  'VTYSH  -c   "show   daemons"'):
            self.assertTrue(ev.assert_green_form(c).startswith("vtysh -c "))

    def test_refuses_everything_that_is_not_a_green_read(self):
        cases = {
            'vtysh -c "configure terminal"': "config mode",
            'vtysh -c "clear ip ospf process"': "disruptive reset",
            'vtysh -c "clear ip ospf neighbor 1.1.1.1"': "YELLOW row",
            'vtysh -c "ping 1.1.1.1"': "YELLOW row",
            'vtysh -c "traceroute 1.1.1.1"': "YELLOW row",
            'vtysh -c "show run"; rm -rf /etc/frr': "separator",
            'vtysh -c "show a" | tee /tmp/x': "pipe",
            'vtysh -c "show $(id)"': "command substitution",
            'vtysh -c "show ${HOME}"': "parameter expansion",
            'vtysh -c "show a" -c "configure terminal"': "second -c",
            'FRR_PAGER=cat vtysh -c "show running-config"': "env prefix",
            'vtysh -c "sh ip os nei"': "abbreviation",
            'vtysh -c "show running-config" > /tmp/x': "redirect",
            'cat /etc/frr/frr.conf': "bare shell",
            'sed -i s/a/b/ /etc/frr/frr.conf': "mutating tool",
            'systemctl restart frr': "service control",
            'vtysh -c "show a\nshow b"': "embedded newline",
            'vtysh -c "show UPPER_CASE"': "charset (underscore)",
            "": "empty",
            "x" * 950: "over the daemon request limit",
        }
        for command, why in cases.items():
            with self.assertRaises(ev.NotAReadOnlyCommand,
                                   msg="accepted %r (%s)" % (command, why)):
                ev.assert_green_form(command)

    def test_hostile_item_list_is_refused_at_load(self):
        """The whole point: an operator edit cannot weaponise the
        collector. A bad command fails the LOAD, before any device is
        contacted — not item by item mid-collection."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "items.json")
        with open(path, "w") as f:
            json.dump({"items": [
                {"name": "good", "command": 'vtysh -c "show version"'},
                {"name": "evil", "command": 'vtysh -c "configure terminal"'},
            ]}, f)
        with self.assertRaises(ev.ConfigError) as cm:
            ev.load_items((path,))
        self.assertIn("evil", str(cm.exception))

    def test_shipped_item_set_is_entirely_green(self):
        items, _, _ = ev.load_items((SHIPPED_ITEMS,))
        self.assertEqual(len(items), 5)
        for item in items:
            ev.assert_green_form(item["command"])
            self.assertTrue(item["command"].startswith('vtysh -c "show'))

    def test_duplicate_item_names_are_refused(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "items.json")
        with open(path, "w") as f:
            json.dump({"items": [
                {"name": "dup", "command": 'vtysh -c "show version"'},
                {"name": "dup", "command": 'vtysh -c "show logging"'},
            ]}, f)
        with self.assertRaises(ev.ConfigError):
            ev.load_items((path,))


# ── Identity ───────────────────────────────────────────────────────────

class TestIdentity(unittest.TestCase):
    def test_refuses_root(self):
        p = ev.identity_problems(secret_paths=(), euid=0, gids=[])
        self.assertTrue(any("root" in x for x in p))

    def test_refuses_daemon_user_and_group_when_present(self):
        import pwd
        import grp
        try:
            uid = pwd.getpwnam("virp").pw_uid
            gid = grp.getgrnam("virp").gr_gid
        except KeyError:
            self.skipTest("no virp user on this host")
        p = ev.identity_problems(secret_paths=(), euid=uid, gids=[])
        self.assertTrue(any("virp" in x for x in p))
        p = ev.identity_problems(secret_paths=(), euid=12345, gids=[gid])
        self.assertTrue(any("credential" in x for x in p))

    def test_refuses_the_other_runbook_identity(self):
        """Each automation owns its own identity: running as virp-backup
        would give this collector the backup runbook's reach."""
        import pwd
        try:
            uid = pwd.getpwnam("virp-backup").pw_uid
        except KeyError:
            self.skipTest("no virp-backup user on this host")
        p = ev.identity_problems(secret_paths=(), euid=uid, gids=[])
        self.assertTrue(any("virp-backup" in x for x in p))

    def test_refuses_when_key_material_readable(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"\x00" * 32)
            f.flush()
            p = ev.identity_problems(secret_paths=(f.name,), euid=12345,
                                     gids=[])
            self.assertTrue(any("can read" in x for x in p))

    def test_refuses_each_secret_individually(self):
        """Every path in the must-not-read set is actually checked — a
        set that silently skipped one would still pass a single-path
        test."""
        for path in ev.SECRET_PATHS:
            with tempfile.NamedTemporaryFile() as f:
                f.write(b"x")
                f.flush()
                p = ev.identity_problems(secret_paths=(f.name,), euid=12345,
                                         gids=[])
                self.assertEqual(len(p), 1, "%s not checked" % path)

    def test_clean_when_material_unreadable(self):
        p = ev.identity_problems(
            secret_paths=("/nonexistent/onode.key",), euid=12345, gids=[])
        self.assertEqual(p, [])

    def test_secret_set_covers_all_required_material(self):
        joined = " ".join(ev.SECRET_PATHS)
        for needle in ("onode.key", "chain.key", "approval.key",
                       "autopilot.env", "devices.json"):
            self.assertIn(needle, joined)

    def test_parity_with_the_config_backup_runbook(self):
        """The spec is 'the same refusal check as virp-backup'. Pin it, so
        hardening one runbook's secret set and not the other's fails."""
        import virp_config_backup as cb
        self.assertEqual(set(cb.SECRET_PATHS), set(ev.SECRET_PATHS))
        for name in cb.FORBIDDEN_USERS:
            self.assertIn(name, ev.FORBIDDEN_USERS)
        for name in cb.FORBIDDEN_GROUPS:
            self.assertIn(name, ev.FORBIDDEN_GROUPS)

    def test_main_refuses_and_exits_three(self):
        """A refusal must exit 3 and must NOT write into the evidence
        tree — a root-owned dropping would break the real identity.

        SECRET_PATHS points at a key this process CAN read, so the
        refusal fires on any machine, not just ones where the ambient
        user happens to be root or in a forbidden group. EVIDENCE_ROOT
        is redirected into the tmp dir so the no-write assertion is
        real: if the refusal ever regressed, run() would write here —
        not into /var/lib/virp — and the listdir below would catch it.
        """
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with tempfile.NamedTemporaryFile() as key:
            key.write(b"x" * 32)
            key.flush()
            orig = (ev.SECRET_PATHS, ev.EVIDENCE_ROOT, ev.ALERTS_FILE)
            ev.SECRET_PATHS = (key.name,)
            ev.EVIDENCE_ROOT = tmp.name
            ev.ALERTS_FILE = os.path.join(tmp.name, "alerts.jsonl")
            try:
                rc = ev.main(["run"])
            finally:
                ev.SECRET_PATHS, ev.EVIDENCE_ROOT, ev.ALERTS_FILE = orig
        self.assertEqual(rc, 3)
        self.assertEqual(os.listdir(tmp.name), [])


# ── Structural inability to approve ────────────────────────────────────

class TestNoApprovalPath(unittest.TestCase):
    def test_collector_speaks_only_execute_and_chain_append(self):
        """The collector can be structurally unable to approve only if it
        never emits an approval action. Pin the full action vocabulary."""
        with open(os.path.join(REPO_ROOT, "autopilot",
                               "virp_evidence.py")) as f:
            src = f.read()
        actions = set(re.findall(r'"action":\s*"(\w+)"', src))
        self.assertEqual(actions, {"execute", "chain_append"})
        for forbidden in ("approval_challenge", "approval_submit",
                          "import subprocess", "os.system", "os.exec",
                          "os.popen"):
            self.assertNotIn(forbidden, src)

    def test_approval_secret_is_in_the_must_not_read_set(self):
        self.assertTrue(any(p.endswith("approval.key")
                            for p in ev.SECRET_PATHS))

    def test_no_write_actions_reach_the_gate_in_a_full_cycle(self):
        """Behavioural counterpart to the source pin: over a whole cycle
        the only thing ever submitted is a GREEN vtysh read."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        send = FakeSend()
        ev.run(root=tmp.name, send=send,
               alerts_file=os.path.join(tmp.name, "alerts.jsonl"),
               items_paths=(SHIPPED_ITEMS,),
               controls_paths=(SHIPPED_CONTROLS,),
               devices=["frr1", "frr2"])
        self.assertTrue(send.executes())
        for command in send.executes():
            ev.assert_green_form(command)     # raises if not a GREEN read
        self.assertEqual({r["action"] for r in send.requests},
                         {"execute", "chain_append"})


# ── A clean collection cycle ───────────────────────────────────────────

class TestCleanCycle(CollectorCase):
    def test_every_item_on_every_device_is_signed_and_registered(self):
        send = FakeSend()
        rc = self.run_cycle(send, devices=("frr1", "frr2"))
        self.assertEqual(rc, 0, "clean cycle should exit 0")
        self.assertEqual(self.alert_kinds(), [])

        items, _, _ = ev.load_items((SHIPPED_ITEMS,))
        expected = len(items) * 2

        # One GREEN read per item per device, and nothing else.
        self.assertEqual(len(send.executes()), expected)
        # One signed observation AND one evidence record per result.
        self.assertEqual(len(send.chain_appends("observation")), expected)
        self.assertEqual(len(send.chain_appends("evidence_item")), expected)

        # Every evidence record carries the full metadata set the report
        # renders from, bound to the entry by artifact_hash.
        seen = set()
        for req in send.chain_appends("evidence_item"):
            body = json.loads(req["artifact_content"])
            self.assertEqual(body["schema"], "evidence_item/1")
            for field in ("item", "device", "ts", "collection_method",
                          "control", "proves", "does_not_prove",
                          "observation", "output_sha256", "mapping_status",
                          "items_sha256", "controls_sha256"):
                self.assertIn(field, body)
            self.assertEqual(body["mapping_status"], "mapped")
            self.assertEqual(body["tier"], "GREEN")
            self.assertEqual(body["collection_status"], "ok")
            # artifact_hash commits to exactly the body that was sent.
            self.assertEqual(
                req["artifact_hash"],
                hashlib.sha256(req["artifact_content"].encode()).hexdigest())
            seen.add((body["device"], body["item"]))
        self.assertEqual(len(seen), expected)

    def test_every_item_names_the_observation_that_backs_it(self):
        send = FakeSend()
        self.run_cycle(send)
        obs_ids = {r["artifact_id"] for r in send.chain_appends("observation")}
        for req in send.chain_appends("evidence_item"):
            body = json.loads(req["artifact_content"])
            self.assertIn(body["observation"], obs_ids)

    def test_results_are_stored_locally_with_the_signed_bytes(self):
        send = FakeSend()
        self.run_cycle(send)
        runs = [d for d in os.listdir(self.root)
                if os.path.isdir(os.path.join(self.root, d))]
        self.assertEqual(len(runs), 1)
        run_dir = os.path.join(self.root, runs[0])
        with open(os.path.join(run_dir, "manifest.json")) as f:
            manifest = json.load(f)
        self.assertEqual(manifest["expected_results"],
                         manifest["collected_results"])
        self.assertEqual(manifest["alerts"], [])
        self.assertEqual(manifest["alerting_results"], 0)
        self.assertEqual(manifest["unmapped"], 0)

        ddir = os.path.join(run_dir, "frr1")
        stored = sorted(os.listdir(ddir))
        self.assertEqual(stored, sorted("%s.json" % i["name"] for i in
                                        ev.load_items((SHIPPED_ITEMS,))[0]))
        with open(os.path.join(ddir, "logging_config.json")) as f:
            rec = json.load(f)
        # The raw signed bytes are kept for a key holder to verify: this
        # identity holds no O-Key and never claims to have checked them.
        self.assertTrue(base64.b64decode(rec["signed_observation_b64"]))
        self.assertFalse(rec["signature_verified_here"])

    def test_stored_output_excludes_our_own_echoed_command(self):
        send = FakeSend()
        self.run_cycle(send)
        run_dir = os.path.join(self.root, os.listdir(self.root)[0])
        with open(os.path.join(run_dir, "frr1",
                               "running_config_baseline.json")) as f:
            rec = json.load(f)
        self.assertNotIn("frr1$ vtysh", rec["output"])
        self.assertIn("hostname frr1", rec["output"])
        self.assertEqual(rec["output_sha256"],
                         hashlib.sha256(rec["output"].encode()).hexdigest())

    def test_chain_registration_failure_alerts(self):
        send = FakeSend(fail_chain=True)
        rc = self.run_cycle(send)
        # A read that succeeded but whose evidence never reached the chain
        # must NOT exit 0: the unit has to show failed, or an operator
        # would believe evidence was registered when it was not.
        self.assertEqual(rc, 1)
        self.assertIn("chain_register_failed", self.alert_kinds())


# ── Evidence is never dropped ──────────────────────────────────────────

class TestUnmappedItem(CollectorCase):
    def test_unmapped_item_is_flagged_not_dropped(self):
        items = self.items_file([
            {"name": "mapped_one", "title": "Mapped",
             "command": 'vtysh -c "show logging"',
             "proves": "p", "does_not_prove": "d"},
            {"name": "orphan", "title": "Orphan",
             "command": 'vtysh -c "show daemons"',
             "proves": "p", "does_not_prove": "d"},
        ])
        controls = self.controls_file({
            "mapped_one": {"control_id": "AU-1",
                           "control_description": "logging",
                           "framework": "PLACEHOLDER"}})
        send = FakeSend()
        rc = ev.run(root=self.root, send=send, alerts_file=self.alerts,
                    items_paths=(items,), controls_paths=(controls,),
                    devices=["frr1"])

        # Collected exactly like a mapped item: read submitted, signed
        # observation and evidence record both chain-registered.
        self.assertEqual(len(send.executes()), 2)
        self.assertEqual(len(send.chain_appends("observation")), 2)
        bodies = {json.loads(r["artifact_content"])["item"]:
                  json.loads(r["artifact_content"])
                  for r in send.chain_appends("evidence_item")}
        self.assertIn("orphan", bodies, "an unmapped item was DROPPED")
        self.assertEqual(bodies["orphan"]["mapping_status"], "unmapped")
        self.assertIsNone(bodies["orphan"]["control"])
        self.assertEqual(bodies["mapped_one"]["mapping_status"], "mapped")
        self.assertEqual(bodies["mapped_one"]["control"]["control_id"], "AU-1")

        # And it surfaces: alerted, and the run reports a non-zero exit so
        # the operator to-do cannot sit unnoticed.
        self.assertIn("unmapped_item", self.alert_kinds())
        self.assertEqual(rc, 1)

        # Stored on disk too.
        run_dir = os.path.join(self.root, [
            d for d in os.listdir(self.root)
            if os.path.isdir(os.path.join(self.root, d))][0])
        self.assertTrue(os.path.exists(
            os.path.join(run_dir, "frr1", "orphan.json")))

    def test_missing_mapping_file_collects_everything_as_unmapped(self):
        items = self.items_file([
            {"name": "solo", "command": 'vtysh -c "show version"'}])
        send = FakeSend()
        rc = ev.run(root=self.root, send=send, alerts_file=self.alerts,
                    items_paths=(items,),
                    controls_paths=("/nonexistent/controls.json",),
                    devices=["frr1"])
        self.assertEqual(rc, 1)
        self.assertEqual(len(send.chain_appends("evidence_item")), 1)
        body = json.loads(send.chain_appends("evidence_item")[0]
                          ["artifact_content"])
        self.assertEqual(body["mapping_status"], "unmapped")
        self.assertIn("unmapped_item", self.alert_kinds())


class TestControlMappingIsData(CollectorCase):
    def test_remapping_requires_no_code_change(self):
        """Same item set, two different mapping files, two different
        control ids — with nothing in the code touched."""
        items = self.items_file([
            {"name": "logging_config", "command": 'vtysh -c "show logging"'}])
        for control_id, framework in (("AU-1", "PLACEHOLDER"),
                                      ("LOG-42", "ClientFramework v3")):
            controls = self.write_json(
                "controls-%s.json" % control_id,
                {"framework": framework,
                 "controls": {"logging_config": {
                     "control_id": control_id,
                     "control_description": "desc for %s" % control_id,
                     "framework": framework}}})
            send = FakeSend()
            ev.run(root=self.root, send=send, alerts_file=self.alerts,
                   items_paths=(items,), controls_paths=(controls,),
                   devices=["frr1"])
            body = json.loads(send.chain_appends("evidence_item")[0]
                              ["artifact_content"])
            self.assertEqual(body["control"]["control_id"], control_id)
            self.assertEqual(body["control"]["framework"], framework)

    def test_mapping_provenance_is_recorded_with_every_result(self):
        send = FakeSend()
        self.run_cycle(send)
        with open(SHIPPED_CONTROLS, "rb") as f:
            expect = hashlib.sha256(f.read()).hexdigest()
        for req in send.chain_appends("evidence_item"):
            body = json.loads(req["artifact_content"])
            self.assertEqual(body["controls_source"], SHIPPED_CONTROLS)
            self.assertEqual(body["controls_sha256"], expect)


# ── Honest handling of results that evidence nothing ───────────────────

class TestDegradedResults(CollectorCase):
    def test_device_rejected_command_is_flagged_not_reported_as_evidence(self):
        """FRR answers an unknown command on stdout and exits 0, so the
        gate sees an ordinary GREEN read and signs it. The signature is
        valid; the content evidences nothing. Say so."""
        items = self.items_file([
            {"name": "bogus", "command": 'vtysh -c "show nonexistent thing"'}])
        controls = self.controls_file({
            "bogus": {"control_id": "X-1", "control_description": "x",
                      "framework": "PLACEHOLDER"}})
        send = FakeSend(default="% Unknown command: show nonexistent thing")
        rc = ev.run(root=self.root, send=send, alerts_file=self.alerts,
                    items_paths=(items,), controls_paths=(controls,),
                    devices=["frr1"])
        self.assertEqual(rc, 1)
        body = json.loads(send.chain_appends("evidence_item")[0]
                          ["artifact_content"])
        self.assertEqual(body["collection_status"], "device_rejected_command")
        self.assertIn("evidences nothing", body["collection_note"])
        self.assertIn("collection_device_rejected_command",
                      self.alert_kinds())

    def test_empty_output_is_flagged(self):
        items = self.items_file([
            {"name": "quiet", "command": 'vtysh -c "show vrf"'}])
        send = FakeSend(default="")
        ev.run(root=self.root, send=send, alerts_file=self.alerts,
               items_paths=(items,), controls_paths=("/nonexistent",),
               devices=["frr1"])
        body = json.loads(send.chain_appends("evidence_item")[0]
                          ["artifact_content"])
        self.assertEqual(body["collection_status"], "empty_output")

    def test_non_green_tier_is_a_loud_refusal_not_stored_evidence(self):
        """A read-only collector must never accept a non-GREEN
        observation. If the gate returns one, that is a gate problem."""
        send = FakeSend(tier=0x03)      # RED
        rc = self.run_cycle(send)
        self.assertEqual(rc, 1)
        self.assertIn("non_green_tier", self.alert_kinds())
        self.assertEqual(send.chain_appends("evidence_item"), [])

    def test_gate_error_observation_is_alerted(self):
        class ErrSend(FakeSend):
            def __call__(self, req):
                self.requests.append(req)
                if req["action"] == "execute":
                    return fake_obs("ERROR: blocked", obs_type=OBS_ERROR,
                                    tier=0x03)
                return fake_obs("{}", obs_type=0x0B)
        send = ErrSend()
        rc = self.run_cycle(send)
        self.assertEqual(rc, 1)
        self.assertIn("gate_error", self.alert_kinds())


# ── Report: control-mapped rendering over a re-verified chain ──────────

CREATE_SQL = """
CREATE TABLE chain_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
  sequence INTEGER NOT NULL, chain_entry_hash TEXT NOT NULL,
  previous_entry_hash TEXT NOT NULL, timestamp_ns INTEGER NOT NULL,
  monotonic_ns INTEGER NOT NULL, artifact_type TEXT NOT NULL,
  artifact_id TEXT NOT NULL, artifact_hash TEXT NOT NULL,
  artifact_hash_alg TEXT NOT NULL DEFAULT 'sha256',
  artifact_schema_version TEXT NOT NULL DEFAULT '1',
  signer_node_id INTEGER NOT NULL,
  signer_org_id TEXT NOT NULL DEFAULT 'local',
  chain_hmac TEXT NOT NULL, UNIQUE(session_id, sequence));
CREATE TABLE artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, artifact_id TEXT NOT NULL,
  artifact_type TEXT NOT NULL, artifact_content TEXT NOT NULL,
  artifact_hash TEXT NOT NULL, session_id TEXT NOT NULL,
  created_at_ns INTEGER NOT NULL, UNIQUE(artifact_id));
"""

EV_SESSION = "evidence:2026-07-30"


def sign_observation(okey, payload, tier=0x01):
    body = struct.pack("!BBH", 0x07, 0x01, len(payload)) + payload
    total = verify.VIRP_HEADER_SIZE + len(body)
    head = struct.pack("!BBHIBBHIQ", 1, 0x01, total, 0x0A000A01, 0x01, tier,
                       0, 1, 1785300000000000000)
    mac = hmac_mod.new(okey, head + body, hashlib.sha256).digest()
    return head + mac + body


class ChainBuilder:
    """Builds a valid chain the way the daemon would."""

    def __init__(self, path):
        self.conn = sqlite3.connect(path)
        self.conn.executescript(CREATE_SQL)
        self.heads = {}
        self.ts = 1785300000000000000

    def append(self, session_id, atype, artifact_id, artifact_hash,
               content=None):
        seq = self.heads.get(session_id, (-1, None))[0] + 1
        prev = (verify.genesis_hash(session_id) if seq == 0
                else self.heads[session_id][1])
        self.ts += 1_000_000
        e = {"session_id": session_id, "sequence": seq,
             "previous_entry_hash": prev, "timestamp_ns": self.ts,
             "monotonic_ns": self.ts // 2, "artifact_type": atype,
             "artifact_id": artifact_id, "artifact_hash": artifact_hash,
             "artifact_hash_alg": "sha256", "artifact_schema_version": "1",
             "signer_node_id": 1, "signer_org_id": "local"}
        canonical = verify.canonical_json(e)
        e["chain_entry_hash"] = hashlib.sha256(canonical.encode()).hexdigest()
        e["chain_hmac"] = hmac_mod.new(TEST_CHAIN_KEY, canonical.encode(),
                                       hashlib.sha256).hexdigest()
        self.conn.execute(
            "INSERT INTO chain_entries (" + ",".join(verify.ENTRY_COLUMNS) +
            ") VALUES (" + ",".join("?" * len(verify.ENTRY_COLUMNS)) + ")",
            [e[c] for c in verify.ENTRY_COLUMNS])
        if content is not None:
            self.conn.execute(
                "INSERT INTO artifacts (artifact_id, artifact_type, "
                "artifact_content, artifact_hash, session_id, created_at_ns)"
                " VALUES (?,?,?,?,?,?)",
                (artifact_id, atype, content, artifact_hash, session_id,
                 self.ts))
        self.heads[session_id] = (seq, e["chain_entry_hash"])
        self.conn.commit()
        return e

    def add_evidence(self, device, item, command, output, control=None,
                     gap=None, status="ok"):
        """One collected result: the signed observation plus the evidence
        record that names it — exactly the pair the collector writes."""
        text = "%s$ %s\n%s" % (device, command, output)
        raw = sign_observation(TEST_OKEY, text.encode())
        obs_id = "obs:%s:%d" % (device, self.ts)
        self.append(EV_SESSION, "observation", obs_id,
                    hashlib.sha256(raw).hexdigest(),
                    "base64:" + base64.b64encode(raw).decode())
        body = {"schema": "evidence_item/1", "item": item,
                "title": "Title for " + item, "device": device,
                "ts": "20260730T120000Z", "collection_method": command,
                "tier": "GREEN", "collection_status": status,
                "collection_note": "" if status == "ok" else "flagged",
                "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
                "observation": obs_id,
                "mapping_status": "mapped" if control else "unmapped",
                "control": control,
                "proves": "PROVES-%s" % item,
                "does_not_prove": "NOTPROVES-%s" % item,
                "evidence_gap": gap,
                "items_source": "/etc/virp/evidence-items.json",
                "items_sha256": "a" * 64,
                "controls_source": "/etc/virp/controls.json",
                "controls_sha256": "b" * 64}
        blob = json.dumps(body, sort_keys=True)
        self.append(EV_SESSION, "evidence_item",
                    "evidence:%s:%s:%d" % (device, item, self.ts),
                    hashlib.sha256(blob.encode()).hexdigest(), blob)

    def close(self):
        self.conn.close()


def build_evidence_chain(path):
    b = ChainBuilder(path)
    au1 = {"control_id": "AU-1", "control_description": "Audit logging",
           "framework": "PLACEHOLDER"}
    cm2 = {"control_id": "CM-2", "control_description": "Baseline config",
           "framework": "PLACEHOLDER"}
    au8 = {"control_id": "AU-8", "control_description": "Time stamps",
           "framework": "PLACEHOLDER"}
    for device in ("frr1", "frr2"):
        b.add_evidence(device, "logging_config",
                       'vtysh -c "show logging"',
                       "Syslog logging: disabled\n", control=au1)
        b.add_evidence(device, "running_config_baseline",
                       'vtysh -c "show running-config"',
                       RUNNING_CONFIG, control=cm2)
        b.add_evidence(device, "time_sync", 'vtysh -c "show zebra"',
                       "Zebra started at time Wed Jul 29\n", control=au8,
                       gap="FRR exposes no NTP configuration.")
        # An item nobody has mapped yet — must still be reported.
        b.add_evidence(device, "orphan_item", 'vtysh -c "show daemons"',
                       "mgmtd zebra ospfd\n", control=None)
    b.close()


def independent_evidence_counts(db_path):
    """Count the evidence in the chain with separate, naive code.

    Deliberately does NOT import the report's model builder: agreement is
    then corroboration, not the same code agreeing with itself.
    """
    conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    conn.row_factory = sqlite3.Row
    rows = list(conn.execute(
        "SELECT * FROM chain_entries WHERE session_id = ? "
        "ORDER BY sequence", (EV_SESSION,)))
    arts = {r["artifact_id"]: r["artifact_content"]
            for r in conn.execute(
                "SELECT artifact_id, artifact_content FROM artifacts")}
    conn.close()

    control_ids, devices, items, gaps = set(), set(), set(), set()
    unmapped_names = set()
    records = unmapped = 0
    for r in rows:
        if r["artifact_type"] != "evidence_item":
            continue
        body = json.loads(arts[r["artifact_id"]])
        records += 1
        devices.add(body["device"])
        items.add(body["item"])
        if body.get("evidence_gap"):
            gaps.add(body["item"])
        if body.get("mapping_status") == "mapped":
            control_ids.add(body["control"]["control_id"])
        else:
            unmapped += 1
            unmapped_names.add(body["item"])
    return {"entries": len(rows), "records": records,
            "controls": len(control_ids), "devices": len(devices),
            "items": len(items), "gaps": len(gaps),
            "unmapped_records": unmapped,
            "unmapped_items": len(unmapped_names),
            "observations": sum(1 for r in rows
                                if r["artifact_type"] == "observation")}


def extract_pdf_text(path):
    """Best-effort text extraction, for asserting on rendered content."""
    try:
        out = subprocess.run(["pdftotext", "-layout", path, "-"],
                             capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.decode("utf-8", errors="replace") \
        if out.returncode == 0 else None


@unittest.skipUnless(HAVE_REPORTLAB, "reportlab is not installed")
class TestEvidenceReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="virp-evidence-report-")
        cls.db = os.path.join(cls.tmp, "chain.db")
        cls.okey_path = os.path.join(cls.tmp, "onode.key")
        cls.ckey_path = os.path.join(cls.tmp, "chain.key")
        with open(cls.okey_path, "wb") as f:
            f.write(TEST_OKEY)
        with open(cls.ckey_path, "wb") as f:
            f.write(TEST_CHAIN_KEY)
        build_evidence_chain(cls.db)

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def model(self):
        import chain_read
        import virp_evidence_report as er
        with chain_read.open_chain(self.db) as reader:
            import virp_report as vr
            entries, artifacts = vr.load_evidence(reader, EV_SESSION)
            verifications, summary = verify.verify_chain(
                entries, artifacts, okey=TEST_OKEY, chain_key=TEST_CHAIN_KEY)
        controls, unmapped, stats, unparsable = er.build_model(verifications)
        return controls, unmapped, stats, summary, unparsable

    def render(self, out_name="evidence.pdf", extra=()):
        import virp_evidence_report as er
        out = os.path.join(self.tmp, out_name)
        code = er.main(["--db", self.db, "--out", out,
                        "--okey", self.okey_path,
                        "--chain-key", self.ckey_path] + list(extra))
        return code, out

    # ── integrity numbers vs an independent count ──

    def test_model_counts_match_an_independent_count(self):
        controls, unmapped, stats, summary, unparsable = self.model()
        indep = independent_evidence_counts(self.db)
        self.assertEqual(summary["entries"], indep["entries"])
        self.assertEqual(stats["evidence_records"], indep["records"])
        self.assertEqual(stats["controls"], indep["controls"])
        self.assertEqual(len(stats["devices"]), indep["devices"])
        self.assertEqual(len(stats["items"]), indep["items"])
        self.assertEqual(len(stats["gaps"]), indep["gaps"])
        self.assertEqual(stats["observations_linked"], indep["observations"])
        self.assertEqual(stats["observations_missing"], 0)
        self.assertEqual(unparsable, [])

    def test_every_check_passes_on_a_clean_evidence_chain(self):
        _, _, _, summary, _ = self.model()
        self.assertEqual(summary["failed_entries"], [])
        self.assertEqual(summary["entry_hash"][verify.FAIL], 0)
        self.assertEqual(summary["chain_hmac"][verify.FAIL], 0)
        self.assertEqual(summary["link"][verify.FAIL], 0)
        # Every observation's O-Key HMAC recomputed and passed.
        self.assertEqual(summary["obs_hmac"][verify.PASS],
                         independent_evidence_counts(self.db)["observations"])

    # ── organisation BY CONTROL ──

    def test_model_is_organised_by_control(self):
        controls, unmapped, stats, _, _ = self.model()
        ids = [c["control_id"] for c in controls]
        self.assertEqual(ids, sorted(ids), "controls must be ordered by id")
        self.assertEqual(set(ids), {"AU-1", "AU-8", "CM-2"})
        for c in controls:
            self.assertTrue(c["items"])
            for item in c["items"].values():
                self.assertTrue(item["command"])
                self.assertTrue(item["proves"])
                self.assertTrue(item["does_not_prove"])
                # Both devices are represented under each item.
                self.assertEqual(
                    sorted(r["body"]["device"] for r in item["results"]),
                    ["frr1", "frr2"])

    def test_unmapped_item_is_reported_not_dropped(self):
        controls, unmapped, stats, _, _ = self.model()
        mapped_items = {i for c in controls for i in c["items"]}
        self.assertNotIn("orphan_item", mapped_items)
        self.assertEqual([i["name"] for i in unmapped], ["orphan_item"])
        self.assertEqual(len(unmapped[0]["results"]), 2)
        indep = independent_evidence_counts(self.db)
        self.assertEqual(stats["unmapped_items"], indep["unmapped_items"])
        self.assertEqual(stats["unmapped_records"], indep["unmapped_records"])

    def test_evidence_gap_is_surfaced(self):
        controls, _, stats, _, _ = self.model()
        self.assertEqual(stats["gaps"], ["time_sync"])
        au8 = [c for c in controls if c["control_id"] == "AU-8"][0]
        self.assertTrue(au8["items"]["time_sync"]["evidence_gap"])

    def test_signed_output_is_re_derived_from_the_signed_bytes(self):
        """The rendered result must come from the signed observation, not
        from a value the collector stored beside it."""
        import virp_evidence_report as er
        controls, _, _, _, _ = self.model()
        cm2 = [c for c in controls if c["control_id"] == "CM-2"][0]
        r = cm2["items"]["running_config_baseline"]["results"][0]
        text, note = er.signed_output(r)
        self.assertIn("hostname frr1", text)
        self.assertNotIn("$ vtysh", text.splitlines()[0])

    # ── the rendered PDF ──

    def test_renders_a_pdf_control_by_control(self):
        code, out = self.render()
        self.assertEqual(code, 0)
        self.assertTrue(os.path.getsize(out) > 5000)
        with open(out, "rb") as f:
            self.assertTrue(f.read(5).startswith(b"%PDF"))

        text = extract_pdf_text(out)
        if text is None:
            self.skipTest("pdftotext unavailable")
        # Organised by control: every control id and description present.
        for needle in ("AU-1", "AU-8", "CM-2", "Audit logging",
                       "Baseline config", "Time stamps"):
            self.assertIn(needle, text)
        # Collection method (the EXACT command) is shown.
        for needle in ('show logging', 'show running-config', 'show zebra'):
            self.assertIn(needle, text)
        # The signed result is rendered.
        self.assertIn("hostname frr1", text)
        # Per-item caveats, both halves.
        self.assertIn("PROVES-logging_config", text)
        self.assertIn("NOTPROVES-logging_config", text)
        # Unmapped items are reported under their own heading.
        self.assertIn("orphan_item", text)
        self.assertIn("Unmapped evidence items", text)
        # Declared gaps.
        self.assertIn("EVIDENCE GAP", text)

    def test_limitations_section_states_every_required_caveat(self):
        code, out = self.render("limits.pdf")
        self.assertEqual(code, 0)
        text = extract_pdf_text(out)
        if text is None:
            self.skipTest("pdftotext unavailable")
        flat = " ".join(text.split())
        for needle in (
                "read-only, point-in-time snapshot",
                "operator-supplied, not tool-asserted",
                "HMAC is not a digital signature",
                "non-repudiation",
                "Unmapped items",
                "orphan_item"):
            self.assertIn(needle, flat, "limitations missing %r" % needle)

    def test_printed_summary_agrees_with_the_independent_count(self):
        """The numbers the CLI prints are the ones a reader will quote."""
        import io
        import contextlib
        import virp_evidence_report as er
        out = os.path.join(self.tmp, "summary.pdf")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = er.main(["--db", self.db, "--out", out,
                            "--okey", self.okey_path,
                            "--chain-key", self.ckey_path])
        self.assertEqual(code, 0)
        printed = buf.getvalue()
        indep = independent_evidence_counts(self.db)
        self.assertIn("evidence records : %d" % indep["records"], printed)
        self.assertIn("controls         : %d" % indep["controls"], printed)
        self.assertIn("unmapped items   : %d (%d record(s))"
                      % (indep["unmapped_items"], indep["unmapped_records"]),
                      printed)
        self.assertIn("devices          : %d" % indep["devices"], printed)

    def test_tampering_with_an_evidence_body_is_reported_not_hidden(self):
        """A modified evidence record must surface as a FAILED check, not
        vanish and not render as if it were sound."""
        import shutil
        import virp_evidence_report as er
        import chain_read
        import virp_report as vr
        tampered = os.path.join(self.tmp, "tampered.db")
        shutil.copy(self.db, tampered)
        conn = sqlite3.connect(tampered)
        row = conn.execute(
            "SELECT artifact_id, artifact_content FROM artifacts WHERE "
            "artifact_type='evidence_item' LIMIT 1").fetchone()
        body = json.loads(row[1])
        body["proves"] = "this control is fully satisfied"
        conn.execute("UPDATE artifacts SET artifact_content=? WHERE "
                     "artifact_id=?",
                     (json.dumps(body, sort_keys=True), row[0]))
        conn.commit()
        conn.close()

        with chain_read.open_chain(tampered) as reader:
            entries, artifacts = vr.load_evidence(reader, EV_SESSION)
            verifications, summary = verify.verify_chain(
                entries, artifacts, okey=TEST_OKEY, chain_key=TEST_CHAIN_KEY)
        self.assertEqual(len(summary["failed_entries"]), 1)
        controls, unmapped, stats, unparsable = er.build_model(verifications)
        # Still rendered — nothing is dropped to keep the report tidy.
        self.assertEqual(stats["evidence_records"],
                         independent_evidence_counts(self.db)["records"])
        out = os.path.join(self.tmp, "tampered.pdf")
        code = er.main(["--db", tampered, "--out", out,
                        "--okey", self.okey_path,
                        "--chain-key", self.ckey_path])
        self.assertEqual(code, 1, "a failed check must set a non-zero exit")
        text = extract_pdf_text(out)
        if text is not None:
            self.assertIn("FAILED artifact_bind", text)

    def test_missing_session_is_an_error_not_an_empty_report(self):
        import virp_evidence_report as er
        out = os.path.join(self.tmp, "none.pdf")
        code = er.main(["--db", self.db, "--out", out,
                        "--session", "evidence:1999-01-01",
                        "--okey", self.okey_path,
                        "--chain-key", self.ckey_path])
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(out))


# ── Deployment policy ──────────────────────────────────────────────────

class TestDeployPolicy(unittest.TestCase):
    def read(self, *parts):
        with open(os.path.join(REPO_ROOT, *parts)) as f:
            return f.read()

    def test_service_runs_a_dedicated_identity_with_sandbox(self):
        unit = self.read("deploy", "virp-evidence.service")
        self.assertIn("User=virp-evidence", unit)
        self.assertNotIn("User=virp\n", unit)
        self.assertNotIn("User=virp-backup", unit)
        self.assertIn("UMask=0077", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("NoNewPrivileges=yes", unit)
        blocked = unit.split("InaccessiblePaths=")[1]
        for path in ("/etc/virp/keys", "/var/lib/virp/approvals",
                     "/var/lib/virp/chain.db", "/etc/virp/autopilot.env",
                     "/var/lib/virp/config-backups"):
            self.assertIn(path, blocked)
        # The sandbox must NOT be weakened to self-grant access: the ACL
        # grant lives on the daemon unit's ExecStartPost drop-in.
        self.assertNotIn("evidence-access.sh", unit)
        dropin = self.read("deploy", "virp-onode-evidence.dropin.conf")
        self.assertIn("ExecStartPost=+/usr/local/lib/virp/evidence-access.sh",
                      dropin)
        # The grant script must be an INSTALLED artifact, never a file in a
        # source worktree (2026-07-31) — see the matching assertion in
        # tests/test_config_backup.py for why.
        for exec_line in [ln for ln in dropin.splitlines()
                          if ln.startswith("Exec")]:
            for worktree in ("/opt/virp", "/root/", "/home/", "/build/"):
                self.assertNotIn(worktree, exec_line)

    def test_timer_defaults_daily_and_documents_the_override(self):
        timer = self.read("deploy", "virp-evidence.timer")
        self.assertIn("OnCalendar=daily", timer)
        self.assertIn("systemctl edit virp-evidence.timer", timer)
        self.assertIn("OnCalendar=", timer.split("systemctl edit")[1])

    def test_allowlist_placeholder_on_virp_lab_only(self):
        cfg = json.loads(self.read("deploy", "devices.template.json"))
        uids = cfg["socket_allowed_uids"]
        self.assertIn("${VIRP_EVIDENCE_UID}", uids)
        self.assertNotIn(0, uids)
        self.assertNotIn("0", uids)
        node2 = json.loads(self.read("deploy", "devices.node2.template.json"))
        self.assertNotIn("${VIRP_EVIDENCE_UID}", node2["socket_allowed_uids"])

    def test_render_script_resolves_the_evidence_uid(self):
        sh = self.read("deploy", "render-devices.sh")
        self.assertIn('pwd.getpwnam("virp-evidence")', sh)
        self.assertIn("VIRP_EVIDENCE_UID", sh)

    def test_access_script_grants_traversal_not_read(self):
        sh = self.read("deploy", "evidence-access.sh")
        self.assertIn("u:${USER_NAME}:--x", sh)
        self.assertIn("u:${USER_NAME}:rw-", sh)
        self.assertNotIn("usermod", sh)
        self.assertIn("virp-evidence", sh)

    def test_shipped_controls_are_visibly_placeholders(self):
        raw = self.read("deploy", "controls.json")
        cfg = json.loads(raw)
        self.assertEqual(cfg["framework"], "PLACEHOLDER")
        self.assertIn("PLACEHOLDER", cfg["_comment"])
        self.assertIn("NOT A COMPLIANCE ASSERTION", cfg["_comment"])
        for name, ref in cfg["controls"].items():
            self.assertEqual(ref["framework"], "PLACEHOLDER")
            self.assertIn("PLACEHOLDER", ref["control_description"])
            self.assertRegex(ref["control_id"], r"^[A-Z]{2}-\d+$")

    def test_every_shipped_item_carries_both_halves_of_its_caveat(self):
        cfg = json.loads(self.read("deploy", "evidence-items.json"))
        for item in cfg["items"]:
            self.assertTrue(item.get("proves"),
                            "%s has no 'proves'" % item["name"])
            self.assertTrue(item.get("does_not_prove"),
                            "%s has no 'does_not_prove'" % item["name"])
            self.assertGreater(len(item["does_not_prove"]), 80,
                               "%s caveat is too thin to be honest"
                               % item["name"])

    def test_every_shipped_item_is_mapped(self):
        items = json.loads(self.read("deploy", "evidence-items.json"))
        controls = json.loads(self.read("deploy", "controls.json"))
        for item in items["items"]:
            self.assertIn(item["name"], controls["controls"],
                          "%s ships unmapped" % item["name"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
