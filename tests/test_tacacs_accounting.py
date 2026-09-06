#!/usr/bin/env python3
"""
Tests for the TACACS+ accounting receiver and reconciler (lab only).

These prove the codec and the record discipline WITHOUT a lab: packets
are built with the same construction RFC 8907 specifies and decoded by
the receiver's own path. What they do NOT prove is interoperation with
a real IOS — only the lab run in docs/TACACS-ACCOUNTING.md §7 does that,
and the two are kept separate on purpose.

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import hashlib
import json
import os
import sqlite3
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tacacs"))

import virp_tacacs_codec as tp
import virp_tacacs_recv as rx
import virp_tacacs_reconcile as rc


SECRET = b"labsecret"
SID = 0x12345678
VERSION = 0xC0


def cisco_args(cmd, cmd_args, task_id="7"):
    out = ["task_id=%s" % task_id, "timezone=UTC", "service=shell",
           "priv-lvl=15", "cmd=%s" % cmd]
    out += ["cmd-arg=%s" % a for a in cmd_args]
    out.append("cmd-arg=<cr>")
    return out


def make_packet(acct_flags, args, seq=1, user="aiops-svc", port="tty2",
                rem="192.168.122.1", secret=SECRET, unencrypted=False,
                sid=SID):
    body = tp.build_acct_request(acct_flags, 0x06, 15, 0x01, 0x01,
                                 user, port, rem, args)
    flags = tp.TAC_PLUS_UNENCRYPTED_FLAG if unencrypted else 0
    wire = body if unencrypted else tp.xor_body(body, sid, secret,
                                                VERSION, seq)
    hdr = tp.parse_header(tp.build_header(VERSION, tp.TAC_PLUS_ACCT, seq,
                                          flags, sid, len(wire)))
    return hdr, wire


def cfg_for(addr="192.168.122.50", identity="R1", secret=SECRET):
    return {
        "receiver_node": "virp-tacacs-lab",
        "_by_addr": {addr: {"client_identity": identity, "secret": secret}},
    }


class TestPad(unittest.TestCase):

    def test_pad_is_md5_chained_per_rfc(self):
        """MD5_1 = MD5(session_id||key||version||seq_no); MD5_n chains on
        the previous digest. Recomputed here independently of the module."""
        import struct
        sid_b = struct.pack("!I", SID)
        base = sid_b + SECRET + bytes([VERSION, 3])
        d1 = hashlib.md5(base).digest()
        d2 = hashlib.md5(base + d1).digest()
        self.assertEqual(tp.pseudo_pad(SID, SECRET, VERSION, 3, 32),
                         d1 + d2)

    def test_pad_length_truncates_not_pads(self):
        self.assertEqual(len(tp.pseudo_pad(SID, SECRET, VERSION, 1, 5)), 5)
        self.assertEqual(len(tp.pseudo_pad(SID, SECRET, VERSION, 1, 33)), 33)

    def test_xor_is_its_own_inverse(self):
        body = b"the quick brown fox" * 5
        ob = tp.xor_body(body, SID, SECRET, VERSION, 1)
        self.assertNotEqual(ob, body)
        self.assertEqual(tp.xor_body(ob, SID, SECRET, VERSION, 1), body)

    def test_wrong_secret_does_not_recover_body(self):
        body = b"accounting body"
        ob = tp.xor_body(body, SID, SECRET, VERSION, 1)
        self.assertNotEqual(tp.xor_body(ob, SID, b"wrong", VERSION, 1), body)

    def test_pad_depends_on_seq_no(self):
        self.assertNotEqual(tp.pseudo_pad(SID, SECRET, VERSION, 1, 16),
                            tp.pseudo_pad(SID, SECRET, VERSION, 2, 16))


class TestHeader(unittest.TestCase):

    def test_header_round_trip(self):
        raw = tp.build_header(0xC0, tp.TAC_PLUS_ACCT, 1, 0x05, SID, 99)
        h = tp.parse_header(raw)
        self.assertEqual(h["version_major"], 12)
        self.assertEqual(h["version_minor"], 0)
        self.assertEqual(h["type"], tp.TAC_PLUS_ACCT)
        self.assertEqual(h["type_name"], "ACCT")
        self.assertEqual(h["session_id"], SID)
        self.assertEqual(h["length"], 99)
        self.assertTrue(h["unencrypted"])
        self.assertTrue(h["single_connect"])

    def test_short_header_raises(self):
        with self.assertRaises(tp.TacacsMalformed):
            tp.parse_header(b"\x00" * 11)


class TestAcctBody(unittest.TestCase):

    def test_round_trip_complete(self):
        args = cisco_args("show", ["version"])
        body = tp.build_acct_request(tp.TAC_PLUS_ACCT_FLAG_START, 0x06, 15,
                                     0x01, 0x01, "aiops-svc", "tty2",
                                     "192.168.122.1", args)
        f, state = tp.parse_acct_request(body)
        self.assertEqual(state, "COMPLETE")
        self.assertEqual(f["args"], args)
        self.assertEqual(f["user"], "aiops-svc")
        self.assertEqual(f["priv_lvl"], 15)
        self.assertEqual(f["acct_flags"], ["START"])
        self.assertEqual(f["authen_method"], "TACACSPLUS")

    def test_watchdog_and_start_reported_as_both(self):
        flags = tp.TAC_PLUS_ACCT_FLAG_WATCHDOG | tp.TAC_PLUS_ACCT_FLAG_START
        self.assertEqual(tp.acct_flag_names(flags), ["START", "WATCHDOG"])

    def test_truncated_body_is_malformed_but_returns_fields(self):
        args = cisco_args("show", ["running-config"])
        body = tp.build_acct_request(tp.TAC_PLUS_ACCT_FLAG_STOP, 0x06, 15,
                                     0x01, 0x01, "aiops-svc", "tty2",
                                     "10.0.0.1", args)
        f, state = tp.parse_acct_request(body[:20])
        self.assertEqual(state, "MALFORMED")
        # The fixed header fields still decoded, and are still reported.
        self.assertEqual(f["priv_lvl"], 15)
        self.assertEqual(f["acct_flags"], ["STOP"])

    def test_body_shorter_than_fixed_fields_is_malformed(self):
        f, state = tp.parse_acct_request(b"\x02\x06")
        self.assertEqual(state, "MALFORMED")
        self.assertIsNone(f["priv_lvl"])

    def test_non_utf8_argument_survives_byte_for_byte(self):
        raw = "cmd-arg=\xff\xfe"
        body = tp.build_acct_request(tp.TAC_PLUS_ACCT_FLAG_START, 0x06, 15,
                                     0x01, 0x01, "u", "t", "r", [raw])
        f, state = tp.parse_acct_request(body)
        self.assertEqual(state, "COMPLETE")
        self.assertEqual(f["args"], [raw])

    def test_reply_round_trip_status_follows_both_lengths(self):
        blob = tp.build_acct_reply(tp.TAC_PLUS_ACCT_STATUS_SUCCESS,
                                   b"ok", b"d")
        self.assertEqual(blob[:5], b"\x00\x02\x00\x01\x01")
        r = tp.parse_acct_reply(blob)
        self.assertEqual(r["status"], tp.TAC_PLUS_ACCT_STATUS_SUCCESS)
        self.assertEqual(r["server_msg"], "ok")
        self.assertEqual(r["data"], "d")


class TestArgsIndex(unittest.TestCase):

    def test_values_are_verbatim_and_first_occurrence(self):
        idx = tp.args_index(["task_id=7", "service=shell", "task_id=9"])
        self.assertEqual(idx["task_id"], "7")
        self.assertEqual(idx["duplicates"], ["task_id"])

    def test_star_separator_is_honoured(self):
        self.assertEqual(tp.args_index(["service*shell"])["service"], "shell")

    def test_no_case_folding(self):
        self.assertIsNone(tp.args_index(["TASK_ID=7"])["task_id"])

    def test_valueless_arg_is_none_not_empty(self):
        self.assertIsNone(tp.args_index(["task_id"])["task_id"])


class TestReceipt(unittest.TestCase):

    def _receipt(self, hdr, wire, cfg=None, peer=("192.168.122.50", 51314)):
        body, aid = rx.build_receipt(cfg or cfg_for(), peer,
                                     ("192.168.122.1", 49), hdr, wire,
                                     1757030400123456789, 884412339006112)
        return body, aid

    def test_obfuscated_packet_decodes_and_records(self):
        hdr, wire = make_packet(tp.TAC_PLUS_ACCT_FLAG_START,
                                cisco_args("show", ["version"]))
        b, aid = self._receipt(hdr, wire)
        self.assertEqual(b["schema"], "tacacs_accounting/1")
        self.assertEqual(b["decode"], "OBFUSCATED_MD5")
        self.assertEqual(b["parse"], "COMPLETE")
        self.assertEqual(b["client_identity"], "R1")
        self.assertEqual(b["client_identity_source"],
                         "configured_by_source_address")
        self.assertEqual(b["acct_flags"], ["START"])
        self.assertEqual(b["args_index"]["task_id"], "7")
        self.assertTrue(aid.startswith("tacacs:192.168.122.50:"))

    def test_raw_body_sha256_is_over_the_decrypted_body(self):
        args = cisco_args("show", ["version"])
        plain = tp.build_acct_request(tp.TAC_PLUS_ACCT_FLAG_START, 0x06, 15,
                                      0x01, 0x01, "aiops-svc", "tty2",
                                      "192.168.122.1", args)
        hdr, wire = make_packet(tp.TAC_PLUS_ACCT_FLAG_START, args)
        b, _ = self._receipt(hdr, wire)
        self.assertEqual(b["raw_body_sha256"],
                         hashlib.sha256(plain).hexdigest())
        self.assertEqual(b["raw_body_len"], len(plain))

    def test_cleartext_flag_is_recorded_not_swallowed(self):
        hdr, wire = make_packet(tp.TAC_PLUS_ACCT_FLAG_START,
                                cisco_args("show", ["clock"]),
                                unencrypted=True)
        b, _ = self._receipt(hdr, wire)
        self.assertEqual(b["decode"], "CLEARTEXT")
        self.assertTrue(b["tacacs_unencrypted"])
        self.assertEqual(b["parse"], "COMPLETE")

    def test_unconfigured_source_is_still_recorded(self):
        hdr, wire = make_packet(tp.TAC_PLUS_ACCT_FLAG_START,
                                cisco_args("show", ["version"]))
        b, _ = self._receipt(hdr, wire, peer=("10.9.9.9", 5000))
        self.assertIsNone(b["client_identity"])
        self.assertEqual(b["client_identity_source"], "unconfigured_source")
        self.assertEqual(b["decode"], "NO_SECRET_CONFIGURED")
        # NOT_ATTEMPTED, never MALFORMED: nothing was decoded, so the body
        # is not known to be broken.
        self.assertEqual(b["parse"], "NOT_ATTEMPTED")
        self.assertEqual(b["raw_body_sha256"],
                         hashlib.sha256(wire).hexdigest())

    def test_wrong_secret_yields_malformed_and_still_ships(self):
        hdr, wire = make_packet(tp.TAC_PLUS_ACCT_FLAG_START,
                                cisco_args("show", ["version"]),
                                secret=b"a-different-secret")
        b, _ = self._receipt(hdr, wire)
        self.assertEqual(b["decode"], "OBFUSCATED_MD5")
        # The record exists regardless of whether the garbage parsed.
        self.assertIn(b["parse"], ("MALFORMED", "COMPLETE"))
        self.assertEqual(len(b["raw_body_sha256"]), 64)

    def test_closed_vocabularies_are_never_omitted(self):
        hdr, wire = make_packet(tp.TAC_PLUS_ACCT_FLAG_STOP,
                                cisco_args("show", ["version"]))
        for peer in (("192.168.122.50", 1), ("10.9.9.9", 1)):
            b, _ = self._receipt(hdr, wire, peer=peer)
            self.assertIn("decode", b)
            self.assertIn("parse", b)
            self.assertIn(b["decode"], ("OBFUSCATED_MD5", "CLEARTEXT",
                                        "NO_SECRET_CONFIGURED"))
            self.assertIn(b["parse"], ("COMPLETE", "MALFORMED",
                                       "NOT_ATTEMPTED"))

    def test_device_clock_is_not_promoted_to_a_top_level_field(self):
        """start_time is the DEVICE's clock. It stays inside args."""
        args = cisco_args("show", ["version"]) + ["start_time=1600000000"]
        hdr, wire = make_packet(tp.TAC_PLUS_ACCT_FLAG_START, args)
        b, _ = self._receipt(hdr, wire)
        self.assertIn("start_time=1600000000", b["args"])
        self.assertNotIn("start_time", b)

    def test_body_is_canonical_and_signs_round_trip(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        sk = ed25519.Ed25519PrivateKey.generate()
        hdr, wire = make_packet(tp.TAC_PLUS_ACCT_FLAG_START,
                                cisco_args("show", ["version"]))
        b, _ = self._receipt(hdr, wire)
        body_bytes, body = rx.producer_sign(sk, b)
        self.assertEqual(body_bytes, rx.canonical_bytes(body))
        stripped = {k: v for k, v in body.items() if k != "producer_sig"}
        sk.public_key().verify(bytes.fromhex(body["producer_sig"]),
                               rx.canonical_bytes(stripped))

    def test_artifact_type_fits_the_wire_field(self):
        """Why these records ride as evidence_item: artifact_type is
        char[16], and the real type names do not fit."""
        self.assertLessEqual(len(rx.ARTIFACT_TYPE), 15)
        self.assertGreater(len("tacacs_accounting"), 15)
        self.assertGreater(len("tacacs_reconciliation"), 15)


class TestReassembly(unittest.TestCase):

    def test_cisco_join_drops_trailing_cr(self):
        cmd, rule = rc.reassemble_command(cisco_args("show", ["ip", "route"]))
        self.assertEqual(cmd, "show ip route")
        self.assertEqual(rule, rc.REASSEMBLY_CISCO)

    def test_no_cmd_is_unrecognized_not_guessed(self):
        cmd, rule = rc.reassemble_command(["task_id=1", "service=shell"])
        self.assertIsNone(cmd)
        self.assertEqual(rule, rc.REASSEMBLY_UNRECOGNIZED)

    def test_single_cmd_argument_form_drops_trailing_cr(self):
        """MEASURED on IOS 15.2(4)M7: the whole command arrives in ONE
        cmd= argument with a literal trailing " <cr>", and there are no
        cmd-arg= arguments. Missing this is what made every gated command
        reconcile UNGOVERNED on the first full run."""
        cmd, rule = rc.reassemble_command(
            ["task_id=3", "service=shell", "priv-lvl=15",
             "cmd=show ip route <cr>"])
        self.assertEqual(cmd, "show ip route")
        self.assertEqual(rule, rc.REASSEMBLY_CISCO_SINGLE)

    def test_two_wire_shapes_get_different_rule_names(self):
        """A reader comparing runs must see which shape the device sent."""
        _, split = rc.reassemble_command(cisco_args("show", ["version"]))
        _, single = rc.reassemble_command(["cmd=show version <cr>"])
        self.assertNotEqual(split, single)

    def test_bare_command_has_no_trailing_space(self):
        cmd, _ = rc.reassemble_command(["cmd=configure", "cmd-arg=<cr>"])
        self.assertEqual(cmd, "configure")


def build_db(path, receipts, gates):
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE chain_entries (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " session_id TEXT, sequence INTEGER, artifact_type TEXT,"
        " artifact_id TEXT, artifact_hash TEXT, timestamp_ns INTEGER);"
        "CREATE TABLE artifacts (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " artifact_id TEXT, artifact_type TEXT, artifact_content TEXT,"
        " artifact_hash TEXT, session_id TEXT, created_at_ns INTEGER);")
    seq = 0
    for sess, atype, body, ts in receipts + gates:
        content = json.dumps(body, sort_keys=True, separators=(",", ":"))
        h = hashlib.sha256(content.encode()).hexdigest()
        aid = "%s:%d" % (sess, seq)
        conn.execute("INSERT INTO chain_entries (session_id, sequence,"
                     " artifact_type, artifact_id, artifact_hash,"
                     " timestamp_ns) VALUES (?,?,?,?,?,?)",
                     (sess, seq, atype, aid, h, ts))
        conn.execute("INSERT INTO artifacts (artifact_id, artifact_type,"
                     " artifact_content, artifact_hash, session_id,"
                     " created_at_ns) VALUES (?,?,?,?,?,?)",
                     (aid, atype, content, h, sess, ts))
        seq += 1
    conn.commit()
    conn.close()


def receipt_body(device, task_id, flags, cmd, cmd_args, recv_ns):
    args = cisco_args(cmd, cmd_args, task_id=task_id)
    return {
        "schema": "tacacs_accounting/1",
        "client_identity": device,
        "source_addr": "192.168.122.50",
        "recv_utc_ns": recv_ns,
        "acct_flags": flags,
        "args": args,
        "args_index": tp.args_index(args),
        "raw_body_sha256": hashlib.sha256(
            ("%s%s%s" % (device, task_id, flags)).encode()).hexdigest(),
        "decode": "OBFUSCATED_MD5",
        "parse": "COMPLETE",
    }


def gate_body(device, command):
    return {"schema": "gate_execution/1", "device": device,
            "command": command, "decision": "auto-execute"}


class TestReconcile(unittest.TestCase):

    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "chain.db")

    def _run(self, receipts, gates, windows=(), window_ms=15000):
        build_db(self.db, receipts, gates)
        r, g = rc.read_chain(self.db)
        return rc.reconcile(r, g, list(windows), window_ms), r, g

    def test_gated_command_matches(self):
        t = 1_757_000_000_000_000_000
        receipts = [
            ("tacacs:lab", "evidence_item",
             receipt_body("R1", "1", ["START"], "show", ["version"], t), t),
            ("tacacs:lab", "evidence_item",
             receipt_body("R1", "1", ["STOP"], "show", ["version"],
                          t + 1_000_000), t + 1_000_000),
        ]
        gates = [("gate", "gate_execution",
                  gate_body("R1", "show version"), t + 500_000)]
        items, _, _ = self._run(receipts, gates)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["verdict"], "MATCHED")
        self.assertEqual(items[0]["command"], "show version")
        self.assertEqual(items[0]["command_reassembly"], rc.REASSEMBLY_CISCO)
        self.assertEqual(len(items[0]["receipt_cites"]), 2)


    # ── Defect E: IOS-XE drops the output modifier ─────────────────────
    #
    # MEASURED 2026-09-05 on SW-3850. The operator typed
    #   sh interfaces status | i 1/0/24
    # and the switch accounted
    #   cmd=show interfaces status <cr>
    # (chain tacacs:virp-lab seq 31, arg_cnt 6, ONE cmd= arg). The
    # abbreviation is expanded AND the `| ...` modifier is discarded
    # entirely - it is not moved into a second argument, it is gone.
    #
    # match_rule.command_comparison is exact_bytes, so a filtered command
    # the operator actually ran could never equal the switch's record of
    # it: the receipt graded UNGOVERNED and the gate execution UNREPORTED.
    # Two wrong verdicts from one correct command.
    #
    # ASSUMPTION, stated because the fix depends on it: the gate refuses
    # `|` from agents at the ingress separator check, so a filtered
    # command is HUMAN-issued. Stripping the modifier from the gate side
    # therefore cannot mask an agent's redirection attempt - an agent
    # cannot get one past the gate in the first place.

    def test_filtered_command_matches_stripped_accounting_record(self):
        t = 1_757_000_400_000_000_000
        receipts = [
            ("tacacs:lab", "evidence_item",
             receipt_body("R1", "31", ["START"], "show",
                          ["interfaces", "status"], t), t),
            ("tacacs:lab", "evidence_item",
             receipt_body("R1", "31", ["STOP"], "show",
                          ["interfaces", "status"], t + 1_000_000),
             t + 1_000_000),
        ]
        # The GATE saw the command the human typed, filter and all.
        gates = [("gate", "gate_execution",
                  gate_body("R1", "show interfaces status | include 1/0/24"),
                  t + 500_000)]
        items, _, _ = self._run(receipts, gates)
        self.assertEqual(items[0]["verdict"], "MATCHED",
                         "a filtered command must reconcile against the "
                         "switch's stripped record")

    def test_every_ios_output_modifier_is_stripped(self):
        t = 1_757_000_500_000_000_000
        for mod in ("include hostname", "exclude down", "begin Vlan",
                    "section router bgp", "count Gi"):
            with self.subTest(modifier=mod):
                # a fresh chain per iteration; build_db creates the table
                self.db = os.path.join(self.tmp, "chain-%d.db" % len(mod))
                receipts = [
                    ("tacacs:lab", "evidence_item",
                     receipt_body("R1", "41", ["START"], "show",
                                  ["running-config"], t), t),
                    ("tacacs:lab", "evidence_item",
                     receipt_body("R1", "41", ["STOP"], "show",
                                  ["running-config"], t + 1000), t + 1000),
                ]
                gates = [("gate", "gate_execution",
                          gate_body("R1", "show running-config | " + mod),
                          t + 500)]
                items, _, _ = self._run(receipts, gates)
                self.assertEqual(items[0]["verdict"], "MATCHED",
                                 "modifier %r must be stripped" % mod)

    def test_stripping_is_not_over_broad(self):
        """A genuinely DIFFERENT command must still not match. If the
        strip were greedy - cutting at the first space, say - every
        `show X` would collapse onto `show` and match anything."""
        t = 1_757_000_600_000_000_000
        receipts = [
            ("tacacs:lab", "evidence_item",
             receipt_body("R1", "51", ["START"], "show", ["version"], t), t),
            ("tacacs:lab", "evidence_item",
             receipt_body("R1", "51", ["STOP"], "show", ["version"],
                          t + 1000), t + 1000),
        ]
        gates = [("gate", "gate_execution",
                  gate_body("R1", "show running-config | include hostname"),
                  t + 500)]
        items, _, _ = self._run(receipts, gates)
        self.assertEqual(items[0]["verdict"], "UNGOVERNED",
                         "`show running-config | ...` must NOT match a "
                         "receipt for `show version`")

    def test_pipe_inside_a_value_is_not_treated_as_a_modifier(self):
        """Only ` | <known-modifier> ` is an output filter. A pipe that is
        part of the command text is not, and cutting there would silently
        shorten a command the device really ran."""
        t = 1_757_000_700_000_000_000
        cmd = "banner motd | not-a-modifier |"
        receipts = [
            ("tacacs:lab", "evidence_item",
             receipt_body("R1", "61", ["START"], "banner",
                          ["motd", "|", "not-a-modifier", "|"], t), t),
            ("tacacs:lab", "evidence_item",
             receipt_body("R1", "61", ["STOP"], "banner",
                          ["motd", "|", "not-a-modifier", "|"], t + 1000),
             t + 1000),
        ]
        gates = [("gate", "gate_execution", gate_body("R1", cmd), t + 500)]
        items, _, _ = self._run(receipts, gates)
        self.assertEqual(items[0]["verdict"], "MATCHED",
                         "an unknown word after `|` is not an output "
                         "modifier and must not be stripped")

    def test_match_rule_names_the_strip(self):
        """The reassembly/canonicalization that ran is an interpretation,
        and the record must say which one - same contract as the existing
        cisco_cmd_*_drop_cr rule names."""
        t = 1_757_000_800_000_000_000
        receipts = [("tacacs:lab", "evidence_item",
                     receipt_body("R1", "71", ["START"], "show",
                                  ["version"], t), t)]
        rec, _, _2 = None, None, None
        items, r, g = self._run(receipts, [])
        rec = rc.build_record(items, 15000, self.db, None, [])
        self.assertIn(rc.CANON_STRIP_OUTPUT_MODIFIER,
                      rec["match_rule"]["known_canonicalization_rules"],
                      "the record must name the gate-side strip")

    def test_console_command_is_ungoverned(self):
        t = 1_757_000_100_000_000_000
        receipts = [
            ("tacacs:lab", "evidence_item",
             receipt_body("R2", "5", ["START"], "show", ["clock"], t), t),
            ("tacacs:lab", "evidence_item",
             receipt_body("R2", "5", ["STOP"], "show", ["clock"],
                          t + 1000), t + 1000),
        ]
        items, _, _ = self._run(receipts, [])
        self.assertEqual(items[0]["verdict"], "UNGOVERNED")

    def test_start_without_stop_is_graded_not_hidden(self):
        t = 1_757_000_200_000_000_000
        receipts = [("tacacs:lab", "evidence_item",
                     receipt_body("R3", "9", ["START"], "show",
                                  ["interfaces"], t), t)]
        items, _, _ = self._run(receipts, [])
        self.assertEqual(items[0]["verdict"], "START_WITHOUT_STOP")

    def test_stop_without_start_applies_to_session_records_only(self):
        """STOP_WITHOUT_START is a SESSION-accounting defect. A session
        record carries no cmd= argument."""
        t = 1_757_000_300_000_000_000
        body = receipt_body("R3", "11", ["STOP"], "show", ["version"], t)
        body["args"] = ["task_id=11", "service=shell", "priv-lvl=15"]
        body["args_index"] = tp.args_index(body["args"])
        receipts = [("tacacs:lab", "evidence_item", body, t)]
        items, _, _ = self._run(receipts, [])
        self.assertEqual(items[0]["record_class"], "session")
        self.assertEqual(items[0]["verdict"], "STOP_WITHOUT_START")

    def test_command_accounting_lone_stop_is_complete(self):
        """MEASURED on IOS 15.2(4)M7: command accounting emits ONE STOP
        per command, no START. Grading that STOP_WITHOUT_START would mark
        every correctly-accounted command as a defect, and a real missing
        record would then be invisible in the noise."""
        t = 1_757_000_350_000_000_000
        receipts = [("tacacs:lab", "evidence_item",
                     receipt_body("R1", "30", ["STOP"], "show",
                                  ["version"], t), t)]
        gates = [("gate", "gate_execution", gate_body("R1", "show version"),
                  t + 100)]
        items, _, _ = self._run(receipts, gates)
        self.assertEqual(items[0]["record_class"], "command")
        self.assertEqual(items[0]["verdict"], "MATCHED")

    def test_command_record_with_no_stop_is_still_a_gap(self):
        t = 1_757_000_360_000_000_000
        body = receipt_body("R1", "31", ["START"], "show", ["version"], t)
        receipts = [("tacacs:lab", "evidence_item", body, t)]
        items, _, _ = self._run(receipts, [])
        self.assertEqual(items[0]["record_class"], "command")
        self.assertEqual(items[0]["verdict"], "START_WITHOUT_STOP")

    def test_restart_without_listen_stop_still_interrupts(self):
        """A listener killed by SIGKILL writes no LISTEN_STOP. Two
        consecutive LISTEN_STARTs must not read as continuous uptime."""
        import tempfile
        led = os.path.join(self.tmp, "led.jsonl")
        t = 1_757_000_370_000_000_000
        with open(led, "w") as f:
            f.write(json.dumps({"event": "LISTEN_START", "utc_ns": t}) + "\n")
            f.write(json.dumps({"event": "LISTEN_START",
                                "utc_ns": t + 10_000}) + "\n")
        w = rc.read_ledger(led)
        self.assertEqual(len(w), 2)
        cov, ev = rc.coverage_for_span(w, t + 1, t + 20_000)
        self.assertEqual(cov, "INTERRUPTED")
        self.assertTrue(ev)

    def test_two_identical_gate_records_are_ambiguous_not_guessed(self):
        t = 1_757_000_400_000_000_000
        receipts = [
            ("tacacs:lab", "evidence_item",
             receipt_body("R1", "2", ["START"], "show", ["version"], t), t),
            ("tacacs:lab", "evidence_item",
             receipt_body("R1", "2", ["STOP"], "show", ["version"],
                          t + 1000), t + 1000),
        ]
        gates = [("gate", "gate_execution", gate_body("R1", "show version"),
                  t + 100),
                 ("gate", "gate_execution", gate_body("R1", "show version"),
                  t + 200)]
        items, _, _ = self._run(receipts, gates)
        pair = [i for i in items if i["task_id"] == "2"][0]
        self.assertEqual(pair["verdict"], "AMBIGUOUS")
        self.assertEqual(len(pair["gate_cite"]), 2)

    def test_gate_without_accounting_is_unreported(self):
        t = 1_757_000_500_000_000_000
        receipts = [
            ("tacacs:lab", "evidence_item",
             receipt_body("R1", "3", ["START"], "show", ["version"], t), t),
            ("tacacs:lab", "evidence_item",
             receipt_body("R1", "3", ["STOP"], "show", ["version"],
                          t + 1000), t + 1000),
        ]
        gates = [("gate", "gate_execution", gate_body("R1", "show version"),
                  t + 100),
                 ("gate", "gate_execution", gate_body("R1", "show clock"),
                  t + 200)]
        items, _, _ = self._run(receipts, gates)
        verdicts = sorted(i["verdict"] for i in items)
        self.assertEqual(verdicts, ["MATCHED", "UNREPORTED"])

    def test_gate_far_outside_the_span_is_not_graded_unreported(self):
        """A gate record from before this receiver ever listened is not
        evidence a device failed to report."""
        t = 1_757_000_600_000_000_000
        receipts = [
            ("tacacs:lab", "evidence_item",
             receipt_body("R1", "4", ["START"], "show", ["version"], t), t),
            ("tacacs:lab", "evidence_item",
             receipt_body("R1", "4", ["STOP"], "show", ["version"],
                          t + 1000), t + 1000),
        ]
        gates = [("gate", "gate_execution", gate_body("R1", "show version"),
                  t + 100),
                 ("gate", "gate_execution", gate_body("R1", "reload"),
                  t - 999_000_000_000)]
        items, _, _ = self._run(receipts, gates)
        self.assertEqual([i["verdict"] for i in items], ["MATCHED"])

    def test_coverage_unknown_without_a_ledger(self):
        t = 1_757_000_700_000_000_000
        receipts = [("tacacs:lab", "evidence_item",
                     receipt_body("R1", "6", ["START"], "show",
                                  ["version"], t), t)]
        items, _, _ = self._run(receipts, [])
        self.assertEqual(items[0]["coverage"], "RECEIVER_UNKNOWN")

    def test_receiver_down_explains_but_does_not_excuse_the_gap(self):
        """The verdict stays START_WITHOUT_STOP. coverage is a separate
        axis and never upgrades the verdict."""
        t = 1_757_000_800_000_000_000
        receipts = [("tacacs:lab", "evidence_item",
                     receipt_body("R1", "8", ["START"], "show",
                                  ["version"], t), t)]
        windows = [(t - 10_000, t - 5_000)]      # listener stopped before t
        items, _, _ = self._run(receipts, [], windows=windows)
        self.assertEqual(items[0]["verdict"], "START_WITHOUT_STOP")
        self.assertEqual(items[0]["coverage"], "RECEIVER_DOWN")

    def test_receiver_up_when_a_window_covers_the_receipt(self):
        t = 1_757_000_900_000_000_000
        receipts = [
            ("tacacs:lab", "evidence_item",
             receipt_body("R1", "10", ["START"], "show", ["version"], t), t),
            ("tacacs:lab", "evidence_item",
             receipt_body("R1", "10", ["STOP"], "show", ["version"],
                          t + 1000), t + 1000),
        ]
        items, _, _ = self._run(receipts, [], windows=[(t - 1000, None)])
        self.assertEqual(items[0]["coverage"], "RECEIVER_UP")

    def test_reconciler_does_not_modify_any_receipt(self):
        """The invariant. Byte-compare every artifact row before and
        after a full reconcile."""
        t = 1_757_001_100_000_000_000
        receipts = [
            ("tacacs:lab", "evidence_item",
             receipt_body("R1", "12", ["START"], "show", ["version"], t), t),
            ("tacacs:lab", "evidence_item",
             receipt_body("R1", "12", ["STOP"], "show", ["version"],
                          t + 1000), t + 1000),
        ]
        gates = [("gate", "gate_execution", gate_body("R1", "show version"),
                  t + 100)]
        build_db(self.db, receipts, gates)
        before = hashlib.sha256(open(self.db, "rb").read()).hexdigest()
        r, g = rc.read_chain(self.db)
        items = rc.reconcile(r, g, [], 15000)
        rec = rc.build_record(items, 15000, self.db, None, [])
        after = hashlib.sha256(open(self.db, "rb").read()).hexdigest()
        self.assertEqual(before, after)
        self.assertEqual(rec["tally"]["MATCHED"], 1)

    def test_listener_killed_mid_session_grades_interrupted(self):
        """The scenario the field exists for: START received, listener
        killed, STOP never arrives. Verdict stays START_WITHOUT_STOP;
        coverage says INTERRUPTED and CITES the ledger boundary."""
        t = 1_757_001_200_000_000_000
        receipts = [("tacacs:lab", "evidence_item",
                     receipt_body("R1", "20", ["START"], "show",
                                  ["version"], t), t)]
        # Up from before the START, stopped 1s after it, back up later.
        windows = [(t - 5_000_000_000, t + 1_000_000_000),
                   (t + 9_000_000_000, None)]
        build_db(self.db, receipts, [])
        r, g = rc.read_chain(self.db)
        items = rc.reconcile(r, g, windows, 15000,
                             horizon_ns=t + 20_000_000_000)
        self.assertEqual(items[0]["verdict"], "START_WITHOUT_STOP")
        self.assertEqual(items[0]["coverage"], "INTERRUPTED")
        evs = [e["event"] for e in items[0]["coverage_evidence"]]
        self.assertIn("LISTEN_STOP", evs)
        self.assertIn("LISTEN_START", evs)

    def test_interrupted_is_not_receiver_down(self):
        """A whole-interval outage and a mid-interval one are different
        facts and must not collapse onto one another."""
        t = 1_757_001_300_000_000_000
        down = rc.coverage_for_span([(t - 9_000, t - 5_000)], t, t + 1_000)
        self.assertEqual(down[0], "RECEIVER_DOWN")
        self.assertEqual(down[1], [])
        interrupted = rc.coverage_for_span(
            [(t - 9_000, t + 500), (t + 900, None)], t, t + 1_000)
        self.assertEqual(interrupted[0], "INTERRUPTED")
        self.assertTrue(interrupted[1])

    def test_missing_stop_while_receiver_up_is_not_blamed_on_the_receiver(self):
        """A gap the receiver CANNOT explain must not borrow the
        receiver-outage cause -- that is where emulator or device loss
        would show, and it has to stay visible as such."""
        t = 1_757_001_400_000_000_000
        receipts = [("tacacs:lab", "evidence_item",
                     receipt_body("R1", "21", ["START"], "show",
                                  ["version"], t), t)]
        build_db(self.db, receipts, [])
        r, g = rc.read_chain(self.db)
        items = rc.reconcile(r, g, [(t - 1_000_000_000, None)], 15000,
                             horizon_ns=t + 5_000_000_000)
        self.assertEqual(items[0]["verdict"], "START_WITHOUT_STOP")
        self.assertEqual(items[0]["coverage"], "RECEIVER_UP")
        self.assertEqual(items[0]["coverage_evidence"], [])

    def test_no_ledger_never_reports_receiver_up(self):
        self.assertEqual(rc.coverage_for_span([], 1, 2)[0],
                         "RECEIVER_UNKNOWN")

    def test_session_and_first_command_sharing_a_task_id_stay_separate(self):
        """MEASURED on IOS 15.2(4)M7: the EXEC session record and the
        FIRST command inside that session carry the SAME task_id.
        Grouping on task_id alone merged them, classified the pair
        "session", and silently lost the first command of every session
        -- 6 of 32 records on the first full run."""
        t = 1_757_001_500_000_000_000
        sess = receipt_body("R1", "30", ["START"], "show", ["version"], t)
        sess["args"] = ["task_id=30", "service=shell", "priv-lvl=15"]
        sess["args_index"] = tp.args_index(sess["args"])
        sess["port"] = "tty2"
        cmd = receipt_body("R1", "30", ["STOP"], "show", ["version"], t + 500)
        cmd["args"] = ["task_id=30", "service=shell", "priv-lvl=15",
                       "cmd=show version <cr>"]
        cmd["args_index"] = tp.args_index(cmd["args"])
        cmd["port"] = "tty2"
        gates = [("gate", "gate_execution", gate_body("R1", "show version"),
                  t + 200)]
        items, _, _ = self._run(
            [("tacacs:lab", "evidence_item", sess, t),
             ("tacacs:lab", "evidence_item", cmd, t + 500)], gates)
        classes = sorted(i["record_class"] for i in items if i["record_class"])
        self.assertEqual(classes, ["command", "session"])
        matched = [i for i in items if i["verdict"] == "MATCHED"]
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["command"], "show version")

    def test_record_states_the_rule_it_ran_under(self):
        rec = rc.build_record([], 12345, self.db, None, [])
        self.assertEqual(rec["match_rule"]["match_window_ms"], 12345)
        self.assertEqual(rec["match_rule"]["command_comparison"],
                         "exact_bytes")
        self.assertIn("beside", rec["presentation"])

    def test_verdict_vocabulary_is_closed(self):
        t = 1_757_001_000_000_000_000
        receipts = [("tacacs:lab", "evidence_item",
                     receipt_body("R1", "13", ["START"], "show",
                                  ["version"], t), t)]
        items, _, _ = self._run(receipts, [])
        for it in items:
            self.assertIn(it["verdict"], rc.VERDICTS)
            self.assertIn(it["coverage"], rc.COVERAGE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
