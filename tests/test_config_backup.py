#!/usr/bin/env python3
"""Tests for the config-backup-and-drift runbook.

Covers, per the runbook's contract:
  - a clean run records a signed no-drift chain entry and submits
    nothing but the GREEN read
  - an induced config change produces a drift artifact + a restore
    PROPOSAL (via the gate's refuse-and-propose path) and never a
    device mutation
  - the runbook is structurally unable to approve its own proposals
    (no approval code path, no approval key in its readable set)
  - the identity check refuses to start when key/credential material is
    readable, or when running as root / the daemon user
  - baselines are only ever written by the explicit set-baseline
    command, never adopted from a run
  - deployment policy: unit sandbox, timer cadence, socket allowlist
    placeholder, render-script resolution
"""

import base64
import json
import os
import re
import struct
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "autopilot"))

import virp_config_backup as cb  # noqa: E402

OBS_DEVICE_OUTPUT = 0x07
OBS_ERROR = 0x0F

BASELINE_CFG = """Building configuration...

Current configuration:
!
frr version 10.0
frr defaults traditional
hostname frr1
!
interface eth1
 ip address 10.0.0.1/30
 ip ospf cost 10
exit
!
router ospf
 ospf router-id 1.1.1.1
 network 10.0.0.0/30 area 0
exit
!
end
"""

DRIFTED_CFG = BASELINE_CFG.replace(
    " ip ospf cost 10", " ip ospf cost 10\n description DRIFT-TEST")

PROPOSAL_ID = "ab" * 16


def fake_obs(payload, obs_type=OBS_DEVICE_OUTPUT, tier=0x01):
    data = payload.encode()
    body = struct.pack("!BBH", obs_type, 1, len(data)) + data
    hdr = struct.pack("!BBHIBBHIQ", 2, 3, 24 + 32 + len(body), 1, 1, tier,
                      0, 7, 1234567890)
    return hdr + b"\x00" * 32 + body


class FakeSend:
    """Records every request; answers like the live daemon: GREEN for
    the show, refuse-and-propose for anything else, signed receipts for
    chain_append."""

    def __init__(self, device_config, propose=True, execute_mutations=False):
        self.device_config = device_config
        self.propose = propose
        self.execute_mutations = execute_mutations
        self.requests = []

    def __call__(self, req):
        self.requests.append(req)
        if req["action"] == "chain_append":
            return fake_obs('{"chain_entry_hash":"feed"}', obs_type=0x0B)
        if req["action"] == "execute":
            if req["command"] == cb.SHOW_RUNNING:
                return fake_obs(self.device_config)
            if self.execute_mutations:
                return fake_obs("OK")  # a gate failure, never legitimate
            payload = ("ERROR: tier gate blocked ... reason: use "
                       "propose/approve/apply")
            if self.propose:
                payload += " proposal_id=%s" % PROPOSAL_ID
            return fake_obs(payload, obs_type=OBS_ERROR, tier=0x03)
        raise AssertionError("unexpected action %r" % req["action"])

    def executes(self):
        return [r["command"] for r in self.requests
                if r["action"] == "execute"]

    def chain_appends(self, artifact_type=None):
        return [r for r in self.requests if r["action"] == "chain_append"
                and (artifact_type is None
                     or r["artifact_type"] == artifact_type)]


class RunbookCase(unittest.TestCase):
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

    def run_device(self, send):
        return cb.run_device("frr1", "config-backup:test", root=self.root,
                             send=send, alerts_file=self.alerts)

    def write_baseline(self, content):
        d = os.path.join(self.root, "frr1")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "baseline.conf"), "w") as f:
            f.write(content)


# ── Normalization / parsing / revert generation ────────────────────────

class TestParsing(unittest.TestCase):
    def test_normalize_strips_presentation_noise(self):
        n = cb.normalize_config(BASELINE_CFG)
        self.assertNotIn("Building configuration", n)
        self.assertNotIn("Current configuration", n)
        self.assertIn("hostname frr1", n)

    def test_parse_blocks_and_toplevel(self):
        p = cb.parse_frr(BASELINE_CFG)
        self.assertEqual(p["hostname frr1"], [])
        self.assertEqual(p["interface eth1"],
                         ["ip address 10.0.0.1/30", "ip ospf cost 10"])
        self.assertIn("router ospf", p)

    def test_nested_blocks_are_unrevertable(self):
        cfg = "router bgp 65000\n address-family ipv4 unicast\n exit-address-family\nexit\n"
        with self.assertRaises(cb.UnrevertableDrift):
            cb.parse_frr(cfg)

    def test_flip(self):
        self.assertEqual(cb._flip("description X"), "no description X")
        self.assertEqual(cb._flip("no ip forwarding"), "ip forwarding")


class TestRevert(unittest.TestCase):
    def test_identical_yields_no_args(self):
        self.assertEqual(cb.revert_args(BASELINE_CFG, BASELINE_CFG), [])

    def test_added_child_line(self):
        args = cb.revert_args(BASELINE_CFG, DRIFTED_CFG)
        self.assertEqual(args,
                         ["interface eth1", "no description DRIFT-TEST",
                          "exit"])

    def test_removed_child_line_is_readded(self):
        cur = BASELINE_CFG.replace(" ip ospf cost 10\n", "")
        args = cb.revert_args(BASELINE_CFG, cur)
        self.assertEqual(args, ["interface eth1", "ip ospf cost 10", "exit"])

    def test_added_toplevel_statement_negated(self):
        cur = BASELINE_CFG.replace("hostname frr1",
                                   "hostname frr1\nip forwarding")
        self.assertEqual(cb.revert_args(BASELINE_CFG, cur),
                         ["no ip forwarding"])

    def test_removed_block_readded_with_children(self):
        cur = BASELINE_CFG.replace(
            "router ospf\n ospf router-id 1.1.1.1\n"
            " network 10.0.0.0/30 area 0\nexit\n!\n", "")
        args = cb.revert_args(BASELINE_CFG, cur)
        self.assertEqual(args, ["router ospf", "ospf router-id 1.1.1.1",
                                "network 10.0.0.0/30 area 0", "exit"])

    def test_added_no_form_is_unnegated(self):
        cur = BASELINE_CFG.replace("hostname frr1",
                                   "hostname frr1\nno ip forwarding")
        self.assertEqual(cb.revert_args(BASELINE_CFG, cur), ["ip forwarding"])

    def test_command_assembly(self):
        cmd = cb.build_revert_command(
            ["interface eth1", "no description DRIFT-TEST", "exit"])
        self.assertEqual(cmd,
                         'vtysh -c "configure terminal" -c "interface eth1" '
                         '-c "no description DRIFT-TEST" -c "exit"')

    def test_command_refuses_separator_chars(self):
        for bad in ["desc a;b", "desc a|b", "desc `x`", "desc $(x)",
                    'desc "q"', "desc 'q'", "desc a&b"]:
            with self.assertRaises(cb.UnrevertableDrift):
                cb.build_revert_command([bad])

    def test_command_refuses_overlong(self):
        with self.assertRaises(cb.UnrevertableDrift):
            cb.build_revert_command(["x" * 1000])


# ── Identity check ─────────────────────────────────────────────────────

class TestIdentity(unittest.TestCase):
    def test_refuses_root(self):
        p = cb.identity_problems(secret_paths=(), euid=0, gids=[])
        self.assertTrue(any("root" in x for x in p))

    def test_refuses_daemon_user_and_group_when_present(self):
        import pwd, grp
        try:
            uid = pwd.getpwnam("virp").pw_uid
            gid = grp.getgrnam("virp").gr_gid
        except KeyError:
            self.skipTest("no virp user on this host")
        p = cb.identity_problems(secret_paths=(), euid=uid, gids=[])
        self.assertTrue(any("daemon user" in x for x in p))
        p = cb.identity_problems(secret_paths=(), euid=12345, gids=[gid])
        self.assertTrue(any("credential" in x for x in p))

    def test_refuses_when_key_material_readable(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"\x00" * 32)
            f.flush()
            p = cb.identity_problems(secret_paths=(f.name,), euid=12345,
                                     gids=[])
            self.assertTrue(any("can read" in x for x in p))

    def test_clean_when_material_unreadable(self):
        p = cb.identity_problems(
            secret_paths=("/nonexistent/onode.key",), euid=12345, gids=[])
        self.assertEqual(p, [])

    def test_secret_set_covers_all_required_material(self):
        joined = " ".join(cb.SECRET_PATHS)
        for needle in ("onode.key", "chain.key", "approval.key",
                       "autopilot.env", "devices.json"):
            self.assertIn(needle, joined)


# ── Behavior: no baseline / clean / drift ──────────────────────────────

class TestNoBaseline(RunbookCase):
    def test_first_run_alerts_and_never_adopts(self):
        send = FakeSend(BASELINE_CFG)
        rec = self.run_device(send)
        self.assertEqual(rec["status"], "no_baseline")
        self.assertIn("no_baseline", self.alert_kinds())
        ddir = os.path.join(self.root, "frr1")
        # The observed config was recorded ...
        self.assertTrue(any(f.endswith(".conf") for f in os.listdir(ddir)))
        # ... but NOT adopted as baseline.
        self.assertFalse(os.path.exists(os.path.join(ddir, "baseline.conf")))
        # Only the GREEN read was submitted; observation chain-registered.
        self.assertEqual(send.executes(), [cb.SHOW_RUNNING])
        self.assertEqual(len(send.chain_appends("observation")), 1)


class TestCleanRun(RunbookCase):
    def test_no_drift_recorded_and_signed(self):
        self.write_baseline(BASELINE_CFG)
        send = FakeSend(BASELINE_CFG)
        rec = self.run_device(send)
        self.assertEqual(rec["status"], "no_drift")
        self.assertEqual(send.executes(), [cb.SHOW_RUNNING])
        nodrift = send.chain_appends("no_drift")
        self.assertEqual(len(nodrift), 1)
        body = json.loads(nodrift[0]["artifact_content"])
        self.assertEqual(body["schema"], "config_nodrift/1")
        self.assertEqual(body["baseline_sha256"], body["observed_sha256"])
        self.assertEqual(self.alert_kinds(), [])

    def test_presentation_noise_is_not_drift(self):
        self.write_baseline(BASELINE_CFG)
        send = FakeSend("Building configuration...\n\n" +
                        cb.normalize_config(BASELINE_CFG))
        rec = self.run_device(send)
        self.assertEqual(rec["status"], "no_drift")


class TestDrift(RunbookCase):
    def setUp(self):
        super().setUp()
        self.write_baseline(BASELINE_CFG)

    def test_drift_files_proposal_and_artifact_and_never_mutates(self):
        send = FakeSend(DRIFTED_CFG)
        rec = self.run_device(send)
        self.assertEqual(rec["status"], "drift")
        self.assertEqual(rec["restore_proposal_id"], PROPOSAL_ID)
        # Diff artifact exists and shows the induced line.
        with open(rec["diff"]) as f:
            self.assertIn("+ description DRIFT-TEST", f.read())
        # Exactly two submissions: the GREEN read and the revert (which
        # the gate refuses-and-proposes). Nothing else ever reaches the
        # gate, and the revert response was a signed rejection — the
        # device was not changed.
        self.assertEqual(len(send.executes()), 2)
        self.assertEqual(send.executes()[0], cb.SHOW_RUNNING)
        self.assertIn('-c "configure terminal"', send.executes()[1])
        self.assertIn("no description DRIFT-TEST", send.executes()[1])
        # Drift chain record registered, carrying the proposal id.
        drifts = send.chain_appends("drift_alert")
        self.assertEqual(len(drifts), 1)
        body = json.loads(drifts[0]["artifact_content"])
        self.assertEqual(body["restore_proposal_id"], PROPOSAL_ID)
        self.assertIn("config_drift", self.alert_kinds())
        # Baseline untouched.
        with open(os.path.join(self.root, "frr1", "baseline.conf")) as f:
            self.assertEqual(f.read(), BASELINE_CFG)

    def test_missing_proposal_id_is_flagged_not_silent(self):
        send = FakeSend(DRIFTED_CFG, propose=False)
        rec = self.run_device(send)
        self.assertEqual(rec["status"], "drift")
        self.assertIsNone(rec["restore_proposal_id"])
        self.assertIn("config_drift", self.alert_kinds())

    def test_gate_executing_a_mutation_is_a_loud_policy_violation(self):
        send = FakeSend(DRIFTED_CFG, execute_mutations=True)
        self.run_device(send)
        self.assertIn("gate_policy_violation", self.alert_kinds())

    def test_unrevertable_drift_still_alerts_with_artifact(self):
        send = FakeSend(BASELINE_CFG.replace(
            "hostname frr1", 'hostname frr1\nbanner motd "pwned"'))
        rec = self.run_device(send)
        self.assertEqual(rec["status"], "drift")
        self.assertIsNone(rec["restore_proposal_id"])
        # No second execute: the unquotable line never reaches the gate.
        self.assertEqual(send.executes(), [cb.SHOW_RUNNING])
        self.assertTrue(os.path.exists(rec["diff"]))
        self.assertIn("config_drift", self.alert_kinds())


class TestSetBaseline(RunbookCase):
    def test_explicit_adoption_of_recorded_backup(self):
        send = FakeSend(BASELINE_CFG)
        self.run_device(send)   # records a backup, no baseline
        rc = cb.set_baseline("frr1", "latest", root=self.root, send=send)
        self.assertEqual(rc, 0)
        ddir = os.path.join(self.root, "frr1")
        with open(os.path.join(ddir, "baseline.conf")) as f:
            self.assertEqual(cb.normalize_config(f.read()),
                             cb.normalize_config(BASELINE_CFG))
        with open(os.path.join(ddir, "baseline.meta.json")) as f:
            prov = json.load(f)
        self.assertEqual(prov["schema"], "config_baseline_set/1")
        self.assertEqual(len(send.chain_appends("baseline_set")), 1)

    def test_refuses_when_nothing_recorded(self):
        rc = cb.set_baseline("frr9", "latest", root=self.root,
                             send=FakeSend(""))
        self.assertEqual(rc, 1)


# ── Structural inability to approve ────────────────────────────────────

class TestNoApprovalPath(unittest.TestCase):
    def test_runbook_speaks_only_execute_and_chain_append(self):
        """The runbook can be structurally unable to approve only if it
        never emits an approval action. Pin the full action vocabulary."""
        src = open(os.path.join(REPO_ROOT, "autopilot",
                                "virp_config_backup.py")).read()
        actions = set(re.findall(r'"action":\s*"(\w+)"', src))
        self.assertEqual(actions, {"execute", "chain_append"})
        # No approval socket messages, and no shelling out (so it cannot
        # invoke the virp CLI's approve/apply either). Prose mentions of
        # `virp approve` in docstrings/alerts are fine — code paths are
        # what grant ability.
        for forbidden in ("approval_challenge", "approval_submit",
                          "import subprocess", "os.system", "os.exec"):
            self.assertNotIn(forbidden, src)

    def test_approval_secret_is_in_the_must_not_read_set(self):
        self.assertTrue(any(p.endswith("approval.key")
                            for p in cb.SECRET_PATHS))


# ── Deployment policy ──────────────────────────────────────────────────

class TestDeployPolicy(unittest.TestCase):
    def read(self, *parts):
        with open(os.path.join(REPO_ROOT, *parts)) as f:
            return f.read()

    def test_service_runs_dedicated_identity_with_sandbox(self):
        unit = self.read("deploy", "virp-config-backup.service")
        self.assertIn("User=virp-backup", unit)
        self.assertNotIn("User=virp\n", unit)
        self.assertIn("UMask=0077", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("NoNewPrivileges=yes", unit)
        for path in ("/etc/virp/keys", "/var/lib/virp/approvals",
                     "/var/lib/virp/chain.db", "/etc/virp/autopilot.env"):
            self.assertIn(path, unit.split("InaccessiblePaths=")[1])
        # The sandbox must NOT be weakened to self-grant access: the ACL
        # grant lives on the daemon unit's ExecStartPost drop-in.
        self.assertNotIn("config-backup-access.sh", unit)
        dropin = self.read("deploy", "virp-onode-runbook.dropin.conf")
        self.assertIn(
            "ExecStartPost=+/usr/local/lib/virp/config-backup-access.sh",
            dropin)
        # The grant script must be an INSTALLED artifact, never a file in a
        # source worktree (2026-07-31). This drop-in previously executed
        # /opt/virp/deploy/config-backup-access.sh — a path inside a live
        # git checkout — so editing the tree changed what ran on the next
        # daemon restart. Asserted as an invariant rather than as a second
        # literal so it keeps holding if the install prefix ever moves.
        for exec_line in [ln for ln in dropin.splitlines()
                          if ln.startswith("Exec")]:
            for worktree in ("/opt/virp", "/root/", "/home/", "/build/"):
                self.assertNotIn(worktree, exec_line)

    def test_timer_is_hourly(self):
        self.assertIn("OnCalendar=hourly",
                      self.read("deploy", "virp-config-backup.timer"))

    def test_allowlist_placeholder_on_virp_lab_only(self):
        cfg = json.loads(self.read("deploy", "devices.template.json"))
        uids = cfg["socket_allowed_uids"]
        self.assertIn("${VIRP_BACKUP_UID}", uids)
        self.assertNotIn(0, uids)
        self.assertNotIn("0", uids)
        node2 = json.loads(self.read("deploy", "devices.node2.template.json"))
        self.assertNotIn("${VIRP_BACKUP_UID}",
                         node2["socket_allowed_uids"])

    def test_render_script_resolves_backup_uid(self):
        sh = self.read("deploy", "render-devices.sh")
        self.assertIn('pwd.getpwnam("virp-backup")', sh)
        self.assertIn("VIRP_BACKUP_UID", sh)

    def test_pbs_device_pins_its_certificate(self):
        """The PBS entry must carry tls_fingerprint and no verify_tls knob.

        The PBS driver has no insecure mode; a template entry that omitted
        the pin would be refused at load, so catching it here turns a
        failed daemon start into a failed test.
        """
        cfg = json.loads(self.read("deploy", "devices.template.json"))
        pbs = [d for d in cfg["devices"] if d.get("vendor") == "pbs"]
        self.assertEqual(len(pbs), 1, "expected exactly one PBS device")
        entry = pbs[0]
        self.assertEqual(entry["tls_fingerprint"], "${PBS_FINGERPRINT}")
        self.assertEqual(entry["api_token"], "${PBS_TOKEN}")
        self.assertEqual(entry["username"], "${PBS_TOKENID}")
        self.assertIn("datastore_allow", entry)
        # A boolean has a value meaning "do not check"; a fingerprint does
        # not. verify_tls must never appear on a PBS device.
        self.assertNotIn("verify_tls", entry)
        # No secret may be baked into the tracked template.
        for key in ("api_token", "tls_fingerprint", "username"):
            self.assertTrue(entry[key].startswith("${"),
                            f"{key} must be a render placeholder")

    def test_render_script_requires_every_pbs_placeholder(self):
        """A missing PBS value must fail the render, not the connect.

        render-devices.sh treats an unsubstituted placeholder as fatal, so
        every PBS placeholder used by the template has to be in its
        required-variable list — otherwise a missing fingerprint would
        surface as a puzzling auth failure hours later.
        """
        sh = self.read("deploy", "render-devices.sh")
        tmpl = self.read("deploy", "devices.template.json")
        for var in ("PBS_HOST", "PBS_TOKENID", "PBS_TOKEN",
                    "PBS_FINGERPRINT", "PBS_DATASTORES", "PBS_SERVERNAME"):
            self.assertIn("${%s}" % var, tmpl)
            self.assertIn('"%s"' % var, sh)

    def test_pbs_device_carries_a_tls_servername(self):
        """Hostname verification must have something true to check.

        Pinning does NOT subsume hostname verification: libcurl performs
        the name check separately from the certificate-verify callback, so
        a correct pin still failed live with "no alternative certificate
        subject name matches target host name '<ip>'". The fix is
        tls_servername + CURLOPT_RESOLVE, NOT lowering VERIFYHOST — so the
        field has to stay present in the template.
        """
        cfg = json.loads(self.read("deploy", "devices.template.json"))
        pbs = [d for d in cfg["devices"] if d.get("vendor") == "pbs"][0]
        self.assertEqual(pbs["tls_servername"], "${PBS_SERVERNAME}")

    def test_pbs_driver_never_lowers_tls_verification(self):
        """The driver must not reach for the easy workaround.

        Guards the exact regression the live probe caught: setting
        VERIFYHOST/VERIFYPEER to 0 makes the pin "work" against an IP by
        turning off the check that was complaining.
        """
        src = self.read("src", "drivers", "driver_pbs.c")
        self.assertNotIn("CURLOPT_SSL_VERIFYHOST, 0", src)
        self.assertNotIn("CURLOPT_SSL_VERIFYPEER, 0", src)
        self.assertIn("CURLOPT_SSL_VERIFYHOST, 2L", src)
        self.assertIn("CURLOPT_SSL_VERIFYPEER, 1L", src)
        self.assertIn("CURLOPT_RESOLVE", src)

    def test_no_unit_executes_from_a_source_worktree(self):
        """Deployment must be an act, not a side effect of a restart.

        Every Exec* line in every shipped unit has to name an installed
        artifact. Until 2026-07-31 the daemon unit ran
        /opt/virp/build/virp-onode-prod and /opt/virp/deploy/*.sh, so any
        `make` in the checkout armed the next restart to ship it.
        """
        units = ("virp-onode.service",
                 "virp-onode-runbook.dropin.conf",
                 "virp-onode-evidence.dropin.conf",
                 "virp-config-backup.service",
                 "virp-evidence.service")
        for unit in units:
            text = self.read("deploy", unit)
            for line in text.splitlines():
                if not line.startswith("Exec"):
                    continue
                for worktree in ("/opt/virp", "/root/", "/home/", "/build/"):
                    self.assertNotIn(
                        worktree, line,
                        f"{unit}: {line!r} executes from a source worktree")

    def test_access_script_grants_traversal_not_read(self):
        sh = self.read("deploy", "config-backup-access.sh")
        self.assertIn("u:${USER_NAME}:--x", sh)
        self.assertIn("u:${USER_NAME}:rw-", sh)
        self.assertNotIn("usermod", sh)


if __name__ == "__main__":
    unittest.main(verbosity=2)
