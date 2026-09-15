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
        # The ruling (2026-09-14): exactly [list_fleet, health, heartbeat,
        # chain_verify]. No spare verbs on the seat, no dead grants.
        allow = set(self.doc["socket_uid_action_allow"][SHELL_UID])
        self.assertEqual(allow, {"list_fleet", "health", "heartbeat", "chain_verify"})
        self.assertEqual(allow, set(vs.COMMAND_ACTIONS.values()))

    def test_shell_actions_are_real_daemon_action_names(self):
        names = tpl.daemon_action_names()
        for a in vs.COMMAND_ACTIONS.values():
            self.assertIn(a, names)

    def test_uid_988_cannot_append_execute_or_shut_down(self):
        allow = set(self.doc["socket_uid_action_allow"][SHELL_UID])
        for verb in ("execute", "batch_execute", "chain_append", "shutdown",
                     "intent_execute", "approval_submit"):
            self.assertNotIn(verb, allow)
        self.assertNotIn(SHELL_UID, self.doc.get("socket_uid_chain_append_types", {}))

    def test_gate_refuses_an_action_outside_the_vocabulary(self):
        with self.assertRaises(vs.GateError):
            vs.gate({"action": "execute", "device": "x", "command": "reload"},
                    "/nonexistent")


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
        self.assertTrue(out.rstrip().endswith(vs.TRAILER))
        self.assertNotIn("{", out)                           # no JSON dumps

    def test_show_device_sends_health_for_that_device(self):
        out, reqs = run(None, "show device sw-3850",
                        lambda r: observation(0x07, "Cisco IOS Software, ...\n"))
        self.assertEqual(reqs, [{"action": "health", "device": "sw-3850"}])
        self.assertIn("chained `show version`", out)
        self.assertIn("Cisco IOS Software", out)
        self.assertTrue(out.rstrip().endswith(vs.TRAILER))

    def test_show_node_sends_heartbeat(self):
        out, reqs = run(None, "sh node", lambda r: heartbeat())
        self.assertEqual(reqs, [{"action": "heartbeat"}])
        self.assertIn("1d 01h 01m 01s", out)
        self.assertIn("active_proposals", out)
        self.assertTrue(out.rstrip().endswith(vs.TRAILER))

    def test_verify_chain_sends_session_and_range(self):
        res = {"entries_checked": 12, "executions_open": 0, "first_broken": -1,
               "from_sequence": 1, "to_sequence": 12, "valid": True}
        out, reqs = run(None, "verify chain 0123abcd 1 12",
                        lambda r: observation(0x0B, json.dumps(res)))
        self.assertEqual(reqs, [{"action": "chain_verify", "session_id": "0123abcd",
                                 "from_sequence": 1, "to_sequence": 12}])
        self.assertIn("entries_checked", out)
        self.assertIn("12", out)
        self.assertTrue(out.rstrip().endswith(vs.TRAILER))

    def test_gate_refusal_is_a_percent_line(self):
        out, _ = run(None, "show devices", lambda r: error_frame(-50))
        self.assertTrue(out.startswith("% gate refused: VIRP_ERR_ACTION_FORBIDDEN (-50)"))
        self.assertNotIn(vs.TRAILER, out)

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

    def test_config_mode_not_built_and_modes(self):
        buf = io.StringIO()
        sh = vs.VirpShell(sock_path="/nonexistent", stdout=buf, host="virp-lab")
        self.assertEqual(sh.prompt, "virp-lab>")
        sh.default("en")
        self.assertEqual(sh.prompt, "virp-lab#")
        sh.default("conf t")
        self.assertIn("% config mode not built", buf.getvalue())
        sh.default("end")
        self.assertEqual(sh.prompt, "virp-lab>")
        self.assertTrue(sh.default("exit"))

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
        sh.default("show chain")
        sh.default("show proposals")
        out = buf.getvalue()
        self.assertIn("% show chain is not built in phase 1", out)
        self.assertIn("% not available", out)

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
            self.assertNotIn("execute", out.split("\n", 3)[-1].replace("chain_verify", ""))
        finally:
            vs.RENDERED_DEVICES = old

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
