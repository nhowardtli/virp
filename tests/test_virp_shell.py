#!/usr/bin/env python3
"""
tools/virp-shell.py — parser, abbreviation resolver, frame decoder, output
contract, and the build gate that ties the shell to uid 988's allowlist.

The allowlist test renders deploy/devices.template.json exactly as the
daemon would (tests/test_template_uid_policy.render) and asserts that the
set of gate actions the shell can emit is EXACTLY uid 988's
socket_uid_action_allow entry. A new shell command that the uid cannot run
— or a template edit that strips an action the shell uses — fails here.

Run:  python3 tests/test_virp_shell.py   (from the repo root; no daemon,
no devices, no chain database; the gate is a fake UNIX socket in a tmpdir).
"""

import importlib.util
import io
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHELL_PATH = os.path.join(ROOT, "tools", "virp-shell.py")
TEMPLATE = os.path.join(ROOT, "deploy", "devices.template.json")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_template_uid_policy as tpl  # noqa: E402  (render(), daemon_action_names())


def load_shell():
    spec = importlib.util.spec_from_file_location("virp_shell", SHELL_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vs = load_shell()
SHELL_UID = str(vs.SHELL_UID)


# ── fake gate: frames exactly as the daemon does (send_framed) ─────────

def frame_header(mtype, node_id, seq, tier, total_len, ts_ns=1_700_000_000_000_000_000):
    hdr = struct.pack(vs.HEADER_FMT, 1, mtype, total_len, node_id, 0x01,
                      tier, 0, seq, ts_ns)
    return hdr + b"\xab" * vs.HMAC_LEN


def observation(obs_type, text, node_id=0x0A0B0C0D, seq=7, tier=0x01, scope=0x01):
    data = text.encode()
    total = vs.FRAME_HDR + 4 + len(data)
    return frame_header(vs.MSG_OBSERVATION, node_id, seq, tier, total) + \
        struct.pack("!BBH", obs_type, scope, len(data)) + data


def heartbeat(uptime=90061, onode_ok=1, rnode_ok=1, obs=5, props=2,
              node_id=0x0A0B0C0D, seq=9):
    total = vs.FRAME_HDR + 12
    return frame_header(vs.MSG_HEARTBEAT, node_id, seq, 0x01, total) + \
        struct.pack("!IBBHI", uptime, onode_ok, rnode_ok, obs, props)


def error_frame(code):
    return struct.pack(">i", code)


FLEET_TEXT = (
    "VIRP Fleet (3 devices)\n"
    "%-24s %-12s %s\n" % ("Name", "Class", "Status") +
    "----------------------------------------------\n"
    "%-24s %-12s %s\n" % ("sw-3850", "cisco_ios", "connected") +
    "%-24s %-12s %s\n" % ("fortigate-200g", "fortinet", "unconnected") +
    "%-24s %-12s %s\n" % ("pbs-lab", "pbs", "disabled") +
    "%-24s %-12s refused: %s\n" % ("dup-host", "linux", "duplicate hostname")
)


class FakeGate:
    """One-shot UNIX socket server that records the request and answers
    with a canned reply. Framing mirrors the daemon: [4B len][payload]."""

    def __init__(self, reply_for):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "onode.sock")
        self.reply_for = reply_for          # callable(request dict) -> bytes
        self.requests = []
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.path)
        self.srv.listen(4)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            with c:
                hdr = c.recv(4)
                if len(hdr) < 4:
                    continue
                (n,) = struct.unpack(">I", hdr)
                body = b""
                while len(body) < n:
                    chunk = c.recv(n - len(body))
                    if not chunk:
                        break
                    body += chunk
                assert body[:1] == b"\x02", "client must send the v2 frame byte"
                req = json.loads(body[1:].decode())
                self.requests.append(req)
                reply = self.reply_for(req)
                c.sendall(struct.pack(">I", len(reply)) + reply)

    def close(self):
        try:
            self.srv.close()
        except OSError:
            pass


def run(shell_args, line, reply_for):
    g = FakeGate(reply_for)
    try:
        buf = io.StringIO()
        sh = vs.VirpShell(sock_path=g.path, stdout=buf, host="virp-lab")
        sh.default(line)
        return buf.getvalue(), g.requests
    finally:
        g.close()


# ── 1. the build gate: shell vocabulary == uid 988 allowlist ──────────

class TestShellMatchesAllowlist(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.doc = tpl.render(TEMPLATE)

    def test_uid_988_is_allowlisted_with_a_green_ceiling(self):
        allowed = [str(u) for u in self.doc["socket_allowed_uids"]]
        self.assertIn(SHELL_UID, allowed)
        self.assertEqual(self.doc["socket_uid_tier_ceilings"][SHELL_UID], "green")

    def test_every_shell_command_maps_to_an_action_uid_988_may_run(self):
        allow = set(self.doc["socket_uid_action_allow"][SHELL_UID])
        used = set(vs.COMMAND_ACTIONS.values())
        self.assertEqual(used - allow, set(),
                         "shell emits actions uid 988 cannot run: %s"
                         % sorted(used - allow))

    def test_uid_988_allowlist_is_exactly_what_the_shell_uses(self):
        # Rulings: 2026-09-14 exactly [list_fleet, health, heartbeat,
        # chain_verify]; 2026-09-15 phase 2a adds execute for config mode
        # with the ceiling kept GREEN. No spare verbs, no dead grants.
        allow = set(self.doc["socket_uid_action_allow"][SHELL_UID])
        self.assertEqual(allow, {"list_fleet", "health", "heartbeat", "chain_verify",
                                 "execute", "list_sessions"})
        self.assertEqual(allow, set(vs.COMMAND_ACTIONS.values()))

    def test_admin_seat_985_is_yellow_with_the_same_verbs_and_no_approval(self):
        # `enable` = a real uid change to 985 (deploy/virp-shell.wrapper +
        # deploy/sudoers-virp-shell). Same vocabulary, higher ceiling, and
        # still no way to approve: proposer and approver stay two people.
        doc = self.doc
        admin = str(vs.ADMIN_UID)
        self.assertIn(admin, [str(u) for u in doc["socket_allowed_uids"]])
        self.assertEqual(doc["socket_uid_tier_ceilings"][admin], "yellow")
        self.assertEqual(set(doc["socket_uid_action_allow"][admin]),
                         set(doc["socket_uid_action_allow"][SHELL_UID]))
        for verb in ("approval_submit", "approval_challenge", "chain_append", "shutdown"):
            self.assertNotIn(verb, doc["socket_uid_action_allow"][admin])
        self.assertNotIn(admin, doc.get("socket_uid_chain_append_types", {}))

    def test_wrapper_and_sudoers_agree_on_seats_and_exit_codes(self):
        wrapper = open(os.path.join(ROOT, "deploy", "virp-shell.wrapper")).read()
        sudoers = open(os.path.join(ROOT, "deploy", "sudoers-virp-shell")).read()
        self.assertIn("42) seat=virp-shell-admin", wrapper)
        self.assertIn("43) seat=virp-shell", wrapper)
        self.assertEqual((vs.EXIT_ENABLE, vs.EXIT_DISABLE), (42, 43))
        self.assertIn("sudo -k", wrapper)                       # ask every time
        self.assertIn("-u virp-shell-admin -- /usr/bin/python3", wrapper)
        self.assertIn("--privileged", wrapper)
        self.assertRegex(sudoers, r"\(virp-shell\)\s+NOPASSWD:")
        self.assertRegex(sudoers, r"\(virp-shell-admin\)\s+PASSWD:.*--privileged")
        self.assertNotIn("ALL=(ALL", sudoers)                   # never root
        self.assertNotIn("(root)", sudoers)

    def test_shell_actions_are_real_daemon_action_names(self):
        names = tpl.daemon_action_names()
        for a in vs.COMMAND_ACTIONS.values():
            self.assertIn(a, names)

    def test_uid_988_cannot_append_execute_or_shut_down(self):
        allow = set(self.doc["socket_uid_action_allow"][SHELL_UID])
        for verb in ("batch_execute", "chain_append", "shutdown",
                     "intent_execute", "approval_submit", "approval_challenge"):
            self.assertNotIn(verb, allow)
        self.assertNotIn(SHELL_UID, self.doc.get("socket_uid_chain_append_types", {}))

    def test_gate_refuses_an_action_outside_the_vocabulary(self):
        with self.assertRaises(vs.GateError):
            vs.gate({"action": "shutdown"}, "/nonexistent")
        with self.assertRaises(vs.GateError):
            vs.gate({"action": "batch_execute", "device": "x"}, "/nonexistent")


# ── 2. parser + abbreviation resolver ─────────────────────────────────

class TestResolver(unittest.TestCase):

    def r(self, s):
        return vs.resolve(s.split())

    def test_full_commands(self):
        self.assertEqual(self.r("show devices"), ("show devices", []))
        self.assertEqual(self.r("show device sw-3850"), ("show device", ["sw-3850"]))
        self.assertEqual(self.r("verify chain abc 1 9"), ("verify chain", ["abc", "1", "9"]))
        self.assertEqual(self.r("configure terminal"), ("configure terminal", []))

    def test_ios_abbreviations(self):
        self.assertEqual(self.r("sh dev")[0], "show devices")
        self.assertEqual(self.r("sh dev sw-3850"), ("show device", ["sw-3850"]))
        self.assertEqual(self.r("sh no")[0], "show node")
        self.assertEqual(self.r("sh ser")[0], "show services")
        self.assertEqual(self.r("sh ver")[0], "show version")
        self.assertEqual(self.r("sh log 5"), ("show log", ["5"]))
        self.assertEqual(self.r("ver ch deadbeef"), ("verify chain", ["deadbeef"]))
        self.assertEqual(self.r("en")[0], "enable")
        self.assertEqual(self.r("conf t")[0], "configure terminal")
        self.assertEqual(self.r("SH DEV")[0], "show devices")

    def test_exact_match_beats_prefix(self):
        # "device" is itself a prefix of "devices": exact wins.
        self.assertEqual(self.r("show device x")[0], "show device")

    def test_arity_disambiguates_device_vs_devices(self):
        # 'd' matches device AND devices; with no argument only 'devices'
        # fits, with one argument only 'device' fits.
        self.assertEqual(self.r("sh d"), ("show devices", []))
        self.assertEqual(self.r("sh d sw1"), ("show device", ["sw1"]))

    def test_ambiguous_when_arity_cannot_decide(self):
        # 'e' matches enable/end/exit — all take 0 args -> ambiguous.
        with self.assertRaises(vs.Ambiguous) as cm:
            self.r("e")
        self.assertEqual(cm.exception.choices, ["enable", "end", "exit"])

    def test_invalid_and_incomplete(self):
        with self.assertRaises(ValueError) as cm:
            self.r("reload")
        self.assertTrue(str(cm.exception).startswith("Invalid input"))
        with self.assertRaises(ValueError) as cm:
            self.r("show")
        self.assertEqual(str(cm.exception), "Incomplete command")
        with self.assertRaises(ValueError) as cm:
            self.r("show device")
        self.assertEqual(str(cm.exception), "Incomplete command")
        with self.assertRaises(ValueError) as cm:
            self.r("show devices extra")
        self.assertTrue(str(cm.exception).startswith("Invalid input"))

    def test_completions(self):
        self.assertEqual(vs.completions([], "s"), ["show"])
        self.assertIn("devices", vs.completions(["show"], "dev"))
        self.assertIn("device", vs.completions(["sh"], "dev"))
        self.assertEqual(vs.completions(["show", "node"], ""), ["<cr>"])
        self.assertEqual(vs.completions(["bogus"], ""), [])
        # leaves that take arguments: placeholder first, <cr> once enough typed
        self.assertEqual(vs.completions(["show", "device"], ""), ["<name>"])
        self.assertEqual(vs.completions(["show", "device", "R1"], ""), ["<cr>"])
        self.assertEqual(vs.completions(["verify", "chain"], ""), ["<session-id>"])
        self.assertEqual(vs.completions(["verify", "chain", "s"], ""),
                         ["[from-sequence]", "<cr>"])
        self.assertEqual(vs.completions(["verify", "chain", "s", "1", "9"], ""), ["<cr>"])
        self.assertEqual(vs.completions(["show", "log"], ""), ["[lines]", "<cr>"])

    def test_every_tree_word_has_help(self):
        for w in vs.COMMAND_TREE:
            self.assertIn(w, vs.COMMAND_HELP)

    def test_every_tree_leaf_has_help(self):
        def walk(node, path):
            for w, sub in node.items():
                p = path + [w]
                if isinstance(sub, dict):
                    walk(sub, p)
                else:
                    self.assertIn(" ".join(p), vs.COMMAND_HELP)
        walk(vs.COMMAND_TREE, [])

    def test_every_gate_command_is_in_the_tree(self):
        for path in vs.COMMAND_ACTIONS:
            if path == "config execute":
                continue            # pseudo-path: any line in (config-<dev>)#
            self.assertEqual(vs.resolve(path.split() + (["x"] if path == "show device"
                                                        else ["s"] if path == "verify chain"
                                                        else []))[0], path)


# ── 3. decoder ─────────────────────────────────────────────────────────

class TestDecode(unittest.TestCase):

    def test_error_frame(self):
        d = vs.decode_reply(error_frame(-50))
        self.assertEqual((d["kind"], d["name"]), ("error", "ACTION_FORBIDDEN"))

    def test_observation(self):
        d = vs.decode_reply(observation(0x05, FLEET_TEXT))
        self.assertEqual(d["kind"], "observation")
        self.assertEqual(d["obs_type_name"], "resource_state")
        self.assertEqual(d["tier_name"], "GREEN")
        self.assertEqual(d["node_id"], 0x0A0B0C0D)
        self.assertEqual(d["text"], FLEET_TEXT)

    def test_heartbeat(self):
        d = vs.decode_reply(heartbeat())
        self.assertEqual(d["kind"], "heartbeat")
        self.assertEqual(d["uptime_seconds"], 90061)
        self.assertEqual(d["active_proposals"], 2)
        self.assertTrue(d["onode_ok"] and d["rnode_ok"])

    def test_length_mismatch_is_rejected(self):
        raw = observation(0x07, "x")
        bad = raw[:2] + struct.pack("!H", len(raw) + 1) + raw[4:]
        with self.assertRaises(vs.GateError):
            vs.decode_reply(bad)

    def test_fleet_text_parser(self):
        count, rows, refused = vs.parse_fleet_text(FLEET_TEXT)
        self.assertEqual(count, 3)
        self.assertEqual(rows[0], ("sw-3850", "cisco_ios", "connected"))
        self.assertEqual(rows[2], ("pbs-lab", "pbs", "disabled"))
        self.assertEqual(refused, [("dup-host", "linux", "duplicate hostname")])


# ── 4. end-to-end through a fake gate: requests + output contract ─────

class TestCommands(unittest.TestCase):

    def test_show_devices_sends_list_fleet_and_renders_a_table(self):
        out, reqs = run(None, "sh dev",
                        lambda r: observation(0x05, FLEET_TEXT))
        self.assertEqual(reqs, [{"action": "list_fleet"}])
        self.assertIn("VIRP fleet: 3 devices", out)
        self.assertIn("name", out.splitlines()[3])          # header row
        self.assertIn("sw-3850", out)
        self.assertIn("cisco_ios", out)
        self.assertIn("dup-host", out)
        self.assertIn("node_id 0x0a0b0c0d  seq 7  tier GREEN", out)
        self.assertTrue(out.rstrip().endswith(vs.trailer()))
        self.assertNotIn("{", out)                           # no JSON dumps

    def test_show_device_sends_health_for_that_device(self):
        out, reqs = run(None, "show device sw-3850",
                        lambda r: observation(0x07, "Cisco IOS Software, ...\n"))
        self.assertEqual(reqs, [{"action": "health", "device": "sw-3850"}])
        self.assertIn("chained `show version`", out)
        self.assertIn("Cisco IOS Software", out)
        self.assertTrue(out.rstrip().endswith(vs.trailer()))

    def test_show_node_sends_heartbeat(self):
        out, reqs = run(None, "sh node", lambda r: heartbeat())
        self.assertEqual(reqs, [{"action": "heartbeat"}])
        self.assertIn("1d 01h 01m 01s", out)
        self.assertIn("active_proposals", out)
        self.assertTrue(out.rstrip().endswith(vs.trailer()))

    def test_verify_chain_sends_session_and_range(self):
        res = {"entries_checked": 12, "executions_open": 0, "first_broken": -1,
               "from_sequence": 1, "to_sequence": 12, "valid": True}
        out, reqs = run(None, "verify chain 0123abcd 1 12",
                        lambda r: observation(0x0B, json.dumps(res)))
        self.assertEqual(reqs, [{"action": "chain_verify", "session_id": "0123abcd",
                                 "from_sequence": 1, "to_sequence": 12}])
        self.assertIn("entries_checked", out)
        self.assertIn("12", out)
        self.assertTrue(out.rstrip().endswith(vs.trailer()))

    def test_gate_refusal_is_a_percent_line(self):
        out, _ = run(None, "show devices", lambda r: error_frame(-50))
        self.assertTrue(out.startswith("% gate refused: VIRP_ERR_ACTION_FORBIDDEN (-50)"))
        self.assertNotIn(vs.trailer(), out)

    def test_never_prints_valid(self):
        res = {"entries_checked": 1, "executions_open": 0, "first_broken": -1,
               "from_sequence": 1, "to_sequence": 1, "valid": True}
        out, _ = run(None, "verify chain s", lambda r: observation(0x0B, json.dumps(res)))
        self.assertNotIn("VALID", out)
        out2, _ = run(None, "show devices", lambda r: observation(0x05, FLEET_TEXT))
        self.assertNotIn("VALID", out2)

    def test_unreachable_socket(self):
        buf = io.StringIO()
        sh = vs.VirpShell(sock_path="/nonexistent/onode.sock", stdout=buf, host="h")
        sh.default("show devices")
        self.assertTrue(buf.getvalue().startswith("% gate unreachable"))

    def test_modes_ios_style(self):
        buf = io.StringIO()
        sh = vs.VirpShell(sock_path="/nonexistent", stdout=buf, host="virp-lab")
        self.assertEqual(sh.prompt, "virp-lab>")
        sh.default("conf t")
        self.assertIn("% configure terminal requires enable", buf.getvalue())
        sh.default("en")
        self.assertEqual(sh.prompt, "virp-lab#")
        sh.default("conf t")
        self.assertEqual(sh.prompt, "virp-lab(config)#")
        buf.truncate(0); buf.seek(0)
        sh.default("interface Gi1/0/1")
        self.assertIn("% no device selected", buf.getvalue())
        sh.default("device R1")
        self.assertEqual(sh.prompt, "virp-lab(config-R1)#")
        self.assertFalse(sh.default("exit"))          # leaves the device context
        self.assertEqual(sh.prompt, "virp-lab(config)#")
        self.assertFalse(sh.default("exit"))          # leaves config
        self.assertEqual(sh.prompt, "virp-lab#")
        sh.default("conf t"); sh.default("dev R1"); sh.default("end")
        self.assertEqual(sh.prompt, "virp-lab#")     # end -> privileged exec
        sh.default("disable")
        self.assertEqual(sh.prompt, "virp-lab>")
        self.assertTrue(sh.default("exit"))
        buf.truncate(0); buf.seek(0)
        sh.default("device R1")
        self.assertIn("% device is a config-mode command", buf.getvalue())

    def _config_session(self, reply_for, lines):
        g = FakeGate(reply_for)
        try:
            buf = io.StringIO()
            sh = vs.VirpShell(sock_path=g.path, stdout=buf, host="virp-lab")
            for l in ("enable", "configure terminal", "device R1") + tuple(lines):
                sh.default(l)
            # the vendor lookup for abbreviation expansion is a list_fleet;
            # these tests assert on the device-bound requests only
            reqs = [r for r in g.requests if r["action"] != "list_fleet"]
            return buf.getvalue(), reqs, sh
        finally:
            g.close()

    BLOCKED = ("ERROR: tier gate blocked '%s' on 'R1' (tier=%s max=GREEN)"
               " reason: configuration change proposal_id=%s")

    def test_config_line_is_sent_as_execute_to_the_selected_device(self):
        out, reqs, _ = self._config_session(
            lambda r: observation(0x07, "Gi1/0/1 is up\n"),
            ["show ip interface brief"])
        self.assertEqual(reqs, [{"action": "execute", "device": "R1",
                                 "command": "show ip interface brief"}])
        self.assertIn("R1: 'show ip interface brief' executed (GREEN)", out)
        self.assertIn("Gi1/0/1 is up", out)
        self.assertTrue(out.rstrip().endswith(vs.trailer()))

    def test_yellow_change_is_proposed_not_applied(self):
        pid = "0123456789abcdef0123456789abcdef"
        out, reqs, sh = self._config_session(
            lambda r: observation(0x0F, self.BLOCKED % (r.get("command", ""), "YELLOW", pid), tier=0x02),
            ["interface Gi1/0/1 description uplink"])
        self.assertEqual(reqs[0]["command"], "interface Gi1/0/1 description uplink")
        self.assertIn("PROPOSED, not applied", out)
        self.assertIn("proposal_id " + pid, out)
        self.assertIn("virp-tool approve " + pid, out)
        self.assertEqual(sh.proposals[0][4], pid)
        self.assertNotIn("VALID", out)
        buf = io.StringIO(); sh.stdout = buf
        sh.default("end"); sh.default("show proposals")
        self.assertIn(pid, buf.getvalue())
        self.assertIn("R1", buf.getvalue())

    def test_black_is_refused_without_a_proposal(self):
        out, _, sh = self._config_session(
            lambda r: observation(0x0F, "ERROR: tier gate blocked 'reload' on 'R1' (tier=BLACK max=GREEN)", tier=0xFF),
            ["reload"])
        self.assertIn("REFUSED: 'reload' on R1 is BLACK", out)
        self.assertIn("no proposal was filed", out)
        self.assertEqual(sh.proposals, [])

    def test_config_gate_refusal_is_a_percent_line(self):
        out, _, _ = self._config_session(lambda r: error_frame(-50), ["show clock"])
        self.assertIn("% gate refused: VIRP_ERR_ACTION_FORBIDDEN (-50)", out)

    def test_device_question_mark_lists_the_fleet_through_the_gate(self):
        g = FakeGate(lambda r: observation(0x05, FLEET_TEXT))
        try:
            buf = io.StringIO()
            sh = vs.VirpShell(sock_path=g.path, stdout=buf, host="virp-lab")
            sh.default("enable"); sh.default("configure terminal")
            buf.truncate(0); buf.seek(0)
            sh.default("device ?")
            out = buf.getvalue()
            self.assertIn("sw-3850", out)
            self.assertIn("cisco_ios", out)
            self.assertIn("connected", out)
            self.assertNotIn("<name>", out)
            self.assertEqual(g.requests, [{"action": "list_fleet"}])
            buf.truncate(0); buf.seek(0)
            sh.default("device sw?")                     # partial filters, cache reused
            self.assertIn("sw-3850", buf.getvalue())
            self.assertNotIn("pbs-lab", buf.getvalue())
            self.assertEqual(len(g.requests), 1)
            buf.truncate(0); buf.seek(0)
            sh.default("device zz?")
            self.assertIn("% no device matches 'zz'", buf.getvalue())
            sh.default("end")
            buf.truncate(0); buf.seek(0)
            sh.default("show device ?")                  # same listing in exec
            self.assertIn("fortigate-200g", buf.getvalue())
            self.assertEqual(sh.device_names("sw"), ["sw-3850"])
        finally:
            g.close()

    def test_device_question_mark_falls_back_when_gate_is_down(self):
        buf = io.StringIO()
        sh = vs.VirpShell(sock_path="/nonexistent", stdout=buf, host="virp-lab")
        sh.default("show device ?")
        self.assertIn("<name>", buf.getvalue())

    def test_ios_abbreviations_expand_to_canonical_spellings(self):
        x = vs.expand_ios
        self.assertEqual(x("sh ip int br"), "show ip interface brief")
        self.assertEqual(x("SH VER"), "show version")
        self.assertEqual(x("sh run"), "show running-config")
        self.assertEqual(x("int g1/0/48 des uplink"),
                         "interface GigabitEthernet1/0/48 description uplink")
        self.assertEqual(x("sh int te1/1/1 status"),
                         "show interface TenGigabitEthernet1/1/1 status")
        self.assertEqual(x("wr mem"), "write memory")
        self.assertEqual(x("relo"), "reload")
        self.assertEqual(x("show foo bar"), "show foo bar")      # unknown: untouched
        # unique 2+ char prefixes expand (IOS rule); ambiguous ones do not
        self.assertEqual(x("sh cdp ne"), "show cdp neighbors")
        self.assertEqual(x("sh inv"), "show inventory")
        self.assertEqual(x("sh in"), "show in")                   # interface? inventory? ambiguous
        self.assertEqual(x("s ver"), "s version")                 # one char: never expanded
        # free text after description/hostname is never rewritten
        self.assertEqual(x("int g1/0/1 des pro to core ver 2"),
                         "interface GigabitEthernet1/0/1 description pro to core ver 2")
        # Linux/FRR interface names are literal: never rewrite eth1 -> Ethernet1
        self.assertEqual(x("interface eth1 description x"), "interface eth1 description x")
        self.assertEqual(x("show ip interface brief"), "show ip interface brief")

    def test_expansions_land_on_the_cisco_classifier_table(self):
        # The expander must produce spellings the gate's classifier
        # literally knows (src/drivers/driver_cisco.c), or it is pointless.
        src = open(os.path.join(ROOT, "src", "drivers", "driver_cisco.c")).read()
        i = src.index("CISCO_GATE_TABLE[] = {"); j = src.index("};", i)
        import re
        table = dict(re.findall(r'\{\s*"([^"]+)",\s*VIRP_TIER_([A-Z]+)', src[i:j]))
        i = src.index("CISCO_BLACK_COMMANDS[] = {"); j = src.index("};", i)
        black = re.findall(r'"([^"]+)"', src[i:j])

        def tier_of(cmd):
            if any(cmd.lower().startswith(b) for b in black):
                return "BLACK"
            best = max((p for p in table if cmd.startswith(p)), key=len, default=None)
            return table.get(best, "RED(unmatched)")

        for abbr, want in (("sh ip int br", "GREEN"), ("sh ver", "GREEN"),
                           ("sh int status", "GREEN"), ("sh mac add", "GREEN"),
                           ("sh clo", "GREEN"), ("sh run", "YELLOW"),
                           ("int g1/0/48 des x", "RED"), ("conf t", "RED"),
                           ("relo", "BLACK"), ("wr era", "BLACK")):
            self.assertEqual(tier_of(vs.expand_ios(abbr)), want,
                             "%r -> %r" % (abbr, vs.expand_ios(abbr)))
        # and the unexpanded abbreviation really would have fallen through
        self.assertEqual(tier_of("sh ip int br"), "RED(unmatched)")
        self.assertEqual(tier_of("relo"), "RED(unmatched)")       # the gap the expander closes

    def test_config_line_is_expanded_for_ios_devices_and_shown(self):
        def reply(r):
            if r["action"] == "list_fleet":
                return observation(0x05, FLEET_TEXT)
            return observation(0x07, "Interface  IP-Address  Status\n")
        g = FakeGate(reply)
        try:
            buf = io.StringIO()
            sh = vs.VirpShell(sock_path=g.path, stdout=buf, host="virp-lab")
            for l in ("enable", "configure terminal", "device sw-3850", "sh ip int br"):
                sh.default(l)
            ex = [r for r in g.requests if r["action"] == "execute"]
            self.assertEqual(ex, [{"action": "execute", "device": "sw-3850",
                                   "command": "show ip interface brief"}])
            out = buf.getvalue()
            self.assertIn("sent as: show ip interface brief", out)
            self.assertIn("sw-3850: 'show ip interface brief' executed (GREEN)", out)
            # a non-IOS device is never rewritten
            sh.default("device pbs-lab"); sh.default("sh clo")
            self.assertEqual(g.requests[-1]["command"], "sh clo")
        finally:
            g.close()

    def test_output_filters_are_applied_locally_not_sent(self):
        sof = vs.split_output_filter
        self.assertEqual(sof("show run | include ntp"), ("show run", ("include", "ntp")))
        self.assertEqual(sof("show run | inc ntp"), ("show run", ("include", "ntp")))
        self.assertEqual(sof("show run | sec router bgp"), ("show run", ("section", "router bgp")))
        self.assertEqual(sof("show run | count"), ("show run", ("count", "")))
        self.assertEqual(sof("show run | bogus x"), ("show run | bogus x", None))
        self.assertEqual(sof("show run"), ("show run", None))
        lines = ["a ntp 1", " child", "b other", "c ntp 2"]
        self.assertEqual(vs.apply_output_filter(lines, ("include", "ntp")), ["a ntp 1", "c ntp 2"])
        self.assertEqual(vs.apply_output_filter(lines, ("exclude", "ntp")), [" child", "b other"])
        self.assertEqual(vs.apply_output_filter(lines, ("begin", "other")), ["b other", "c ntp 2"])
        self.assertEqual(vs.apply_output_filter(lines, ("section", "^a")), ["a ntp 1", " child"])
        self.assertEqual(vs.apply_output_filter(lines, ("count", "ntp")),
                         ["Number of lines which match regexp = 2"])

        out, reqs, _ = self._config_session(
            lambda r: observation(0x07, "R1#show ip interface brief\nVlan1 down\nVlan10 up\nGi1/0/1 up\n"),
            ["show ip interface brief | include Vlan"])
        self.assertEqual(reqs[0]["command"], "show ip interface brief")   # pipe never sent
        self.assertIn("filtered locally: | include Vlan (2 of 3 lines shown", out)
        self.assertIn("Vlan10 up", out)
        self.assertNotIn("Gi1/0/1 up", out)

    def test_yellow_read_says_needs_approval_to_run(self):
        pid = "abcdef0123456789abcdef0123456789"
        out, _, _ = self._config_session(
            lambda r: observation(0x0F, self.BLOCKED % (r.get("command", ""), "YELLOW", pid), tier=0x02),
            ["show users"])
        self.assertIn("PROPOSED (needs approval to run): 'show users'", out)
        out, _, _ = self._config_session(
            lambda r: observation(0x0F, self.BLOCKED % (r.get("command", ""), "RED", pid), tier=0x03),
            ["interface Gi1/0/1 shutdown"])
        self.assertIn("PROPOSED, not applied: 'interface Gi1/0/1 shutdown'", out)

    def test_scripted_stdin_echoes_the_command_after_the_prompt(self):
        import subprocess
        p = subprocess.run([sys.executable, SHELL_PATH, "--socket", "/nonexistent"],
                           input="enable\nshow chain\nexit\n", capture_output=True, text=True)
        self.assertIn(">enable\n", p.stdout)
        self.assertIn("#show chain\n", p.stdout)

    def test_device_error_frame_is_rendered_once(self):
        out, _, _ = self._config_session(
            lambda r: observation(0x0F, "ERROR: cannot connect to 'R1'"),
            ["show ip interface brief"])
        self.assertIn("device error (signed, GREEN): cannot connect to 'R1'", out)
        self.assertNotIn("GATE ERROR: ERROR", out)

    def test_shell_words_still_win_inside_a_device_context(self):
        out, reqs, sh = self._config_session(lambda r: heartbeat(), ["show node"])
        self.assertEqual(reqs, [{"action": "heartbeat"}])   # not execute
        self.assertEqual(sh.prompt, "virp-lab(config-R1)#")

    def test_question_mark_lists_completions(self):
        buf = io.StringIO()
        sh = vs.VirpShell(sock_path="/nonexistent", stdout=buf, host="h")
        sh.default("show ?")
        out = buf.getvalue()
        for w in ("devices", "device", "node", "services", "log", "version", "uid"):
            self.assertIn(w, out)
        buf.truncate(0); buf.seek(0)
        sh.default("sh dev?")
        self.assertIn("devices", buf.getvalue())
        buf.truncate(0); buf.seek(0)
        sh.default("show device ?")
        self.assertIn("<name>", buf.getvalue())
        self.assertNotIn("<cr>", buf.getvalue())
        buf.truncate(0); buf.seek(0)
        sh.default("show device R1 ?")
        self.assertIn("<cr>", buf.getvalue())

    def test_phase1_gaps_say_so(self):
        buf = io.StringIO()
        sh = vs.VirpShell(sock_path="/nonexistent", stdout=buf, host="h")
        sh.default("show proposals")
        out = buf.getvalue()
        self.assertIn("% no proposals filed by this session", out)

    def test_show_chain_lists_sessions_and_verifies_each(self):
        listing = {"sessions": [
            {"session_id": "sess-b", "first_sequence": 0, "last_sequence": 4,
             "entries": 5, "last_timestamp_ns": int(time.time() * 1e9) - 120_000_000_000},
            {"session_id": "sess-a", "first_sequence": 0, "last_sequence": 1,
             "entries": 2, "last_timestamp_ns": int(time.time() * 1e9) - 3_600_000_000_000},
        ], "count": 2, "limit": 3, "truncated": False}

        def reply(r):
            if r["action"] == "list_sessions":
                return observation(0x05, json.dumps(listing))
            ok = r["session_id"] == "sess-b"
            return observation(0x0B, json.dumps({
                "entries_checked": 5 if ok else 2, "executions_open": 0,
                "first_broken": -1 if ok else 1, "from_sequence": 0,
                "to_sequence": 4 if ok else 1, "valid": ok}))

        out, reqs = run(None, "show chain 3", reply)
        self.assertEqual(reqs[0], {"action": "list_sessions", "limit": 3})
        self.assertEqual([r["session_id"] for r in reqs[1:]], ["sess-b", "sess-a"])
        self.assertEqual((reqs[1]["from_sequence"], reqs[1]["to_sequence"]), (0, 4))
        self.assertTrue(all(r["action"] == "chain_verify" for r in reqs[1:]))
        self.assertIn("chain sessions: 2 listed of the most recent 3; 1 broken", out)
        self.assertIn("sess-b", out)
        self.assertIn("NO", out)                       # sess-a is broken at 1
        self.assertIn("120s", out)
        self.assertTrue(out.rstrip().endswith(vs.trailer()))
        self.assertNotIn("VALID", out)

    def test_show_chain_refusal_is_a_percent_line(self):
        out, _ = run(None, "show chain", lambda r: error_frame(-50))
        self.assertTrue(out.startswith("% gate refused: VIRP_ERR_ACTION_FORBIDDEN (-50)"))

    def test_show_uid_reads_the_rendered_policy(self):
        doc = tpl.render(TEMPLATE)
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "devices.json")
        with open(path, "w") as f:
            json.dump(doc, f)
        old = vs.RENDERED_DEVICES
        vs.RENDERED_DEVICES = path
        try:
            buf = io.StringIO()
            sh = vs.VirpShell(sock_path="/nonexistent", stdout=buf, host="h")
            sh.default("show uid 988")
            out = buf.getvalue()
            self.assertIn("988", out)
            self.assertIn("green", out)
            self.assertIn("list_fleet", out)
            row = [l for l in out.splitlines() if l.startswith("988")][0]
            for verb in ("chain_append", "shutdown", "batch_execute"):
                self.assertNotIn(verb, row)
        finally:
            vs.RENDERED_DEVICES = old

    def test_enable_and_disable_reseat_through_the_wrapper(self):
        real_uid, real_tty = os.geteuid, sys.stdin.isatty
        try:
            sys.stdin.isatty = lambda: True
            # read seat: enable hands back to the wrapper with EXIT_ENABLE
            os.geteuid = lambda: vs.SHELL_UID
            buf = io.StringIO()
            sh = vs.VirpShell(sock_path="/nonexistent", stdout=buf, host="h")
            self.assertTrue(sh.default("enable"))
            self.assertEqual(sh.exit_code, vs.EXIT_ENABLE)
            self.assertIn("sudo will ask for your password", buf.getvalue())
            # admin seat: starts privileged, disable hands back with EXIT_DISABLE
            os.geteuid = lambda: vs.ADMIN_UID
            buf = io.StringIO()
            sh = vs.VirpShell(sock_path="/nonexistent", stdout=buf, host="h", privileged=True)
            self.assertEqual(sh.prompt, "h#")
            self.assertFalse(sh.default("enable"))             # already there
            self.assertTrue(sh.default("disable"))
            self.assertEqual(sh.exit_code, vs.EXIT_DISABLE)
            # any other uid: mode only, with the honest note
            os.geteuid = lambda: 1000
            buf = io.StringIO()
            sh = vs.VirpShell(sock_path="/nonexistent", stdout=buf, host="h")
            self.assertFalse(sh.default("enable"))
            self.assertEqual(sh.prompt, "h#")
            self.assertIn("% mode only: uid 1000 keeps its own ceiling", buf.getvalue())
            self.assertFalse(sh.default("disable"))
            self.assertEqual(sh.prompt, "h>")
            # scripted stdin never re-seats (no terminal for sudo to ask on)
            sys.stdin.isatty = lambda: False
            os.geteuid = lambda: vs.SHELL_UID
            sh = vs.VirpShell(sock_path="/nonexistent", stdout=io.StringIO(), host="h")
            self.assertFalse(sh.default("enable"))
            self.assertEqual(sh.exit_code, 0)
        finally:
            os.geteuid, sys.stdin.isatty = real_uid, real_tty

    def test_show_whoami_reports_seat_and_ceiling(self):
        doc = tpl.render(TEMPLATE)
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "devices.json")
        with open(path, "w") as f:
            json.dump(doc, f)
        old, real_uid = vs.RENDERED_DEVICES, os.geteuid
        vs.RENDERED_DEVICES = path
        try:
            for uid, seat, ceiling in ((vs.SHELL_UID, "read seat", "green"),
                                       (vs.ADMIN_UID, "admin seat", "yellow")):
                os.geteuid = lambda uid=uid: uid
                buf = io.StringIO()
                sh = vs.VirpShell(sock_path="/nonexistent", stdout=buf, host="h")
                sh.default("show whoami")
                out = buf.getvalue()
                self.assertIn(seat, out)
                self.assertIn(ceiling, out)
                self.assertIn("allowlisted  yes", out)
                self.assertIn("execute", out)
        finally:
            vs.RENDERED_DEVICES, os.geteuid = old, real_uid

    def test_refuses_root_and_notes_wrong_uid(self):
        # main() must refuse euid 0 without touching anything.
        real = os.geteuid
        os.geteuid = lambda: 0
        try:
            self.assertEqual(vs.main([]), 2)
        finally:
            os.geteuid = real


if __name__ == "__main__":
    unittest.main(verbosity=1)
