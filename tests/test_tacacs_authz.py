#!/usr/bin/env python3
"""
Attack list A1-A9 for TACACS+ per-command authorization.

Written BEFORE the implementation. Each test names the attack it pins.
The unit-testable attacks live here against the decision engine, which
is a pure function of (policy, request, clock) so a denial can be proved
without a router in the loop. The live-router half is Phase 4.

The rule these tests exist to enforce: THE GATE DOES NOT DECIDE. A
request is authorized only if a grant compiled from a signed, unexpired,
unspent approval names this device and these exact command bytes.

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tacacs"))

import virp_tacacs_authz as az
import virp_tacacs_policy as pol

sys.path.insert(0, os.path.join(ROOT, "tacacs", "lab"))
import iossh

NOW = 1_757_002_000_000_000_000
SEC = 1_000_000_000


def grant(device="R1", command="interface Loopback99", uses=1,
          not_before=NOW - 10 * SEC, not_after=NOW + 300 * SEC,
          approval_id="appr-1"):
    return {
        "grant_id": "g-" + approval_id,
        "device": device,
        "user": "virp-rw",
        "command": command,
        "approval_id": approval_id,
        "approval_entry_hash": "a" * 64,
        "not_before_ns": not_before,
        "not_after_ns": not_after,
        "uses_remaining": uses,
    }


def policy(grants=None, device="R1"):
    return {
        "schema": "tacacs_authz_policy/1",
        "device": device,
        "rendered_utc_ns": NOW,
        "grants": list(grants or []),
    }


def req(command, user="virp-rw", device="R1", now=NOW):
    return {"device": device, "user": user, "command": command, "now_ns": now}


class TestA1NoApproval(unittest.TestCase):
    """A1: gate sends a command with no approval on chain. Deny."""

    def test_empty_policy_denies_everything_for_rw(self):
        st, reason, gid = az.authorize(policy([]), **req("interface Loopback99"))
        self.assertEqual(st, az.FAIL)
        self.assertIsNone(gid)
        self.assertIn("no grant", reason.lower())

    def test_rw_with_empty_policy_cannot_even_show_version(self):
        """virp-rw has nothing permitted by default except exit/quit."""
        st, _, _ = az.authorize(policy([]), **req("show version"))
        self.assertEqual(st, az.FAIL)

    def test_rw_may_always_exit_and_quit(self):
        for c in ("exit", "quit"):
            st, _, _ = az.authorize(policy([]), **req(c))
            self.assertEqual(st, az.PASS_ADD, "%s must be permitted" % c)


class TestSessionDisplayCommands(unittest.TestCase):
    """`terminal length 0` is the first thing the cisco_ios driver sends
    on every session. Under `aaa authorization commands 1` it needs a
    decision, and denying it breaks every gate session including
    read-only ones.

    It is permitted for BOTH identities as a deliberate, minimal
    exemption: it changes only the current session's pager and cannot
    alter device state or reveal anything. Stated and tested rather than
    discovered later as a mystery outage."""

    def test_terminal_length_permitted_for_ro(self):
        st, _, _ = az.authorize(policy([]), **req("terminal length 0",
                                                  user="virp-ro"))
        self.assertEqual(st, az.PASS_ADD)

    def test_terminal_length_permitted_for_rw_without_a_grant(self):
        st, _, _ = az.authorize(policy([]), **req("terminal length 0"))
        self.assertEqual(st, az.PASS_ADD)

    def test_exemption_does_not_extend_to_other_terminal_commands(self):
        """The exemption is the exact string, not a `terminal` prefix."""
        for c in ("terminal monitor", "terminal exec prompt timestamp"):
            st, _, _ = az.authorize(policy([]), **req(c))
            self.assertEqual(st, az.FAIL, c)


class TestA2Expiry(unittest.TestCase):
    """A2: approved command after TTL expiry. Deny."""

    def test_after_not_after_denies(self):
        p = policy([grant(not_after=NOW - 1)])
        st, reason, _ = az.authorize(p, **req("interface Loopback99"))
        self.assertEqual(st, az.FAIL)
        self.assertIn("expired", reason.lower())

    def test_before_not_before_denies(self):
        p = policy([grant(not_before=NOW + 60 * SEC)])
        st, reason, _ = az.authorize(p, **req("interface Loopback99"))
        self.assertEqual(st, az.FAIL)
        self.assertIn("not yet valid", reason.lower())

    def test_inside_window_passes(self):
        st, _, gid = az.authorize(policy([grant()]),
                                  **req("interface Loopback99"))
        self.assertEqual(st, az.PASS_ADD)
        self.assertEqual(gid, "g-appr-1")


class TestA3ArgumentChanged(unittest.TestCase):
    """A3: approved command with one argument changed. Deny."""

    def test_changed_argument_denies(self):
        p = policy([grant(command="interface Loopback99")])
        st, _, _ = az.authorize(p, **req("interface Loopback98"))
        self.assertEqual(st, az.FAIL)

    def test_extra_argument_denies(self):
        p = policy([grant(command="description OK")])
        st, _, _ = az.authorize(p, **req("description OK EXTRA"))
        self.assertEqual(st, az.FAIL)

    def test_prefix_of_grant_denies(self):
        """No regex, no prefix matching: a shorter command is not a match."""
        p = policy([grant(command="interface Loopback99")])
        st, _, _ = az.authorize(p, **req("interface"))
        self.assertEqual(st, az.FAIL)

    def test_grant_is_not_a_wildcard(self):
        p = policy([grant(command="show ip route")])
        st, _, _ = az.authorize(p, **req("show ip route 10.0.0.0"))
        self.assertEqual(st, az.FAIL)


class TestA4SingleUse(unittest.TestCase):
    """A4: approved command twice. Second denies."""

    def test_second_use_denies(self):
        p = policy([grant(uses=1)])
        st1, _, _ = az.authorize(p, **req("interface Loopback99"))
        self.assertEqual(st1, az.PASS_ADD)
        az.consume(p, "g-appr-1")
        st2, reason, _ = az.authorize(p, **req("interface Loopback99"))
        self.assertEqual(st2, az.FAIL)
        self.assertIn("spent", reason.lower())

    def test_repeat_count_three_allows_three(self):
        p = policy([grant(uses=3)])
        for i in range(3):
            st, _, _ = az.authorize(p, **req("interface Loopback99"))
            self.assertEqual(st, az.PASS_ADD, "use %d should pass" % (i + 1))
            az.consume(p, "g-appr-1")
        st, _, _ = az.authorize(p, **req("interface Loopback99"))
        self.assertEqual(st, az.FAIL)


class TestA5WrongDevice(unittest.TestCase):
    """A5: approved command sent to a device the approval does not name."""

    def test_other_device_denies(self):
        p = policy([grant(device="R1")], device="R2")
        st, reason, _ = az.authorize(p, **req("interface Loopback99",
                                              device="R2"))
        self.assertEqual(st, az.FAIL)
        self.assertIn("device", reason.lower())


class TestA6MultiLine(unittest.TestCase):
    """A6: multi-line config change; added lines deny."""

    LINES = ["interface Loopback99",
             "description APPROVED-CHANGE",
             "ip address 10.99.99.1 255.255.255.255",
             "exit"]

    def _multi(self):
        return policy([grant(command=c, approval_id="appr-multi-%d" % i,
                             uses=1)
                       for i, c in enumerate(self.LINES)])

    def test_each_approved_line_passes(self):
        p = self._multi()
        for i, line in enumerate(self.LINES):
            st, _, _ = az.authorize(p, **req(line))
            self.assertEqual(st, az.PASS_ADD, "line %r" % line)
            az.consume(p, "g-appr-multi-%d" % i)

    def test_inserted_line_denies(self):
        p = self._multi()
        st, _, _ = az.authorize(p, **req("shutdown"))
        self.assertEqual(st, az.FAIL)

    def test_out_of_order_still_authorizes_each_line(self):
        """Order is NOT enforced by per-command authorization: the router
        asks about one command at a time and has no notion of sequence.
        Recording that plainly matters more than pretending otherwise --
        ordering is the reconciler's problem, not the authorizer's."""
        p = self._multi()
        st, _, _ = az.authorize(p, **req(self.LINES[2]))
        self.assertEqual(st, az.PASS_ADD)


class TestA8BadSignature(unittest.TestCase):
    """A8: an approval whose signature does not verify must not render."""

    def test_compiler_refuses_unverified_approval(self):
        appr = {"approval_id": "appr-bad", "device": "R1",
                "command": "interface Loopback99",
                "ttl_ns": 300 * SEC, "issued_utc_ns": NOW,
                "signature_verified": False}
        grants, refusals = pol.compile_grants([appr], now_ns=NOW)
        self.assertEqual(grants, [])
        self.assertEqual(len(refusals), 1)
        self.assertIn("signature", refusals[0]["reason"].lower())

    def test_compiler_renders_verified_approval(self):
        appr = {"approval_id": "appr-ok", "device": "R1",
                "command": "interface Loopback99",
                "ttl_ns": 300 * SEC, "issued_utc_ns": NOW,
                "signature_verified": True}
        grants, refusals = pol.compile_grants([appr], now_ns=NOW)
        self.assertEqual(len(grants), 1)
        self.assertEqual(refusals, [])
        self.assertEqual(grants[0]["command"], "interface Loopback99")

    def test_missing_verification_flag_is_refused_not_assumed(self):
        """Absence of the flag is never treated as verified."""
        appr = {"approval_id": "appr-x", "device": "R1",
                "command": "interface Loopback99",
                "ttl_ns": 300 * SEC, "issued_utc_ns": NOW}
        grants, refusals = pol.compile_grants([appr], now_ns=NOW)
        self.assertEqual(grants, [])
        self.assertEqual(len(refusals), 1)


class TestA9ChainedCommands(unittest.TestCase):
    """A9: chained command against an approval for the first half only."""

    def test_semicolon_chain_denies(self):
        p = policy([grant(command="show clock")])
        st, _, _ = az.authorize(p, **req("show clock ; conf t"))
        self.assertEqual(st, az.FAIL)

    def test_pipe_chain_denies(self):
        p = policy([grant(command="show clock")])
        st, _, _ = az.authorize(p, **req("show clock | conf t"))
        self.assertEqual(st, az.FAIL)

    def test_chain_metacharacters_never_split_the_request(self):
        """The authorizer compares the WHOLE command string it was given.
        It must never split on ; or | and authorize a prefix -- that would
        be inventing a permission the approval never granted."""
        p = policy([grant(command="show clock")])
        for sep in (";", "|", "&&"):
            st, _, _ = az.authorize(p, **req("show clock %s reload" % sep))
            self.assertEqual(st, az.FAIL, "separator %r" % sep)


class TestCanonicalisationSharedWithReconciler(unittest.TestCase):
    """The policy and the accounting match must use one normal form. If
    they ever disagree, a command could be authorized under one spelling
    and reconciled under another."""

    def test_trailing_cr_is_stripped_the_same_way(self):
        import virp_tacacs_reconcile as rc
        from_acct, _ = rc.reassemble_command(["cmd=show ip route <cr>"])
        from_policy = az.canonical_command("show ip route <cr>")
        self.assertEqual(from_acct, from_policy)

    def test_authorizer_collapses_where_the_reconciler_preserves(self):
        """FINDING, pinned rather than papered over.

        VIRP's own `virp_canonicalize_command` (include/virp_crypto.h)
        trims, COLLAPSES repeated internal spaces, and strips \r. That is
        the form an approval's `command_hash` commits to. The accounting
        reconciler PRESERVES internal whitespace.

        Two normal forms exist in one system. The authorizer must use
        VIRP's, because the grant is derived from a proposal whose text is
        bound to the approval by a hash over the COLLAPSED form -- using
        the reconciler's form would mean granting a string the approver
        never actually signed for.

        Consequence, stated: a command differing only in whitespace runs
        authorizes (IOS treats them as identical anyway), while the
        accounting matcher may still see them as distinct strings. That
        asymmetry is reported in the design doc, not hidden here."""
        import virp_tacacs_reconcile as rc
        from_acct, _ = rc.reassemble_command(["cmd=show   ip  route <cr>"])
        self.assertEqual(from_acct, "show   ip  route")      # preserves
        self.assertEqual(az.canonical_command("show   ip  route"),
                         "show ip route")                     # collapses
        self.assertNotEqual(az.canonical_command("show   ip  route"),
                            from_acct)

    def test_virp_canonical_form_matches_the_c_contract(self):
        """trim, collapse internal runs, strip \r -- the three rules
        include/virp_crypto.h states for virp_canonicalize_command."""
        self.assertEqual(az.canonical_command("  show   ip  route  "),
                         "show ip route")
        self.assertEqual(az.canonical_command("show\rip route"),
                         "showip route")
        self.assertEqual(az.canonical_command("show ip route <cr>"),
                         "show ip route")


class TestReplyShape(unittest.TestCase):
    """MEASURED on IOS 15.2(4)M7: a PASS_ADD carrying arguments the
    router did not ask to have added is rejected, and the router prints
    "Command authorization failed." even though the server said PASS.

    PASS_ADD with arg_cnt 0 is "permit exactly as requested". That is the
    only correct reply for a command authorization we are not modifying.
    """

    def test_permit_replies_with_no_arguments(self):
        self.assertEqual(az.reply_args_for(az.PASS_ADD), [])

    def test_denial_replies_with_no_arguments(self):
        self.assertEqual(az.reply_args_for(az.FAIL), [])
        self.assertEqual(az.reply_args_for(az.ERROR), [])


class TestDenialMarker(unittest.TestCase):
    """The router prints the server_msg to the operator. Prefixing every
    denial makes it unambiguous who denied and greppable in a transcript
    -- otherwise a VIRP denial is indistinguishable from any other IOS
    message, in evidence and to the person at the keyboard."""

    def test_denial_reason_is_prefixed(self):
        st, reason, _ = az.authorize(policy([]), **req("configure terminal"))
        self.assertEqual(st, az.FAIL)
        self.assertTrue(reason.startswith(az.DENY_PREFIX), reason)

    def test_permit_reason_is_not_prefixed(self):
        st, reason, _ = az.authorize(policy([grant()]),
                                     **req("interface Loopback99"))
        self.assertEqual(st, az.PASS_ADD)
        self.assertFalse(reason.startswith(az.DENY_PREFIX))

    def test_every_denial_path_is_prefixed(self):
        cases = [
            (policy([]), "configure terminal"),
            (policy([grant(not_after=NOW - 1)]), "interface Loopback99"),
            (policy([grant(not_before=NOW + 60 * SEC)]), "interface Loopback99"),
            (policy([grant(uses=0)]), "interface Loopback99"),
            (policy([grant(device="R9")]), "interface Loopback99"),
        ]
        for p, cmd in cases:
            st, reason, _ = az.authorize(p, **req(cmd))
            self.assertEqual(st, az.FAIL, cmd)
            self.assertTrue(reason.startswith(az.DENY_PREFIX),
                            "%r -> %r" % (cmd, reason))

    def test_ro_denial_is_prefixed(self):
        st, reason, _ = az.authorize(policy([]),
                                     **req("show running-config",
                                           user="virp-ro"))
        self.assertTrue(reason.startswith(az.DENY_PREFIX), reason)


class TestNoLocalFallbackInRenderedConfig(unittest.TestCase):
    """A7's router half: the rw method list must never fall back to local
    or if-authenticated. A fallback is an authorization control that
    stops controlling exactly when it is needed."""

    def test_rendered_config_has_tacacs_only_for_rw(self):
        cfg = pol.render_router_config(device="R1")
        line = [l for l in cfg.splitlines()
                if l.startswith("aaa authorization commands 15 VIRPRW")]
        self.assertEqual(len(line), 1)
        self.assertIn("group GRP-VIRPAZ", line[0])
        self.assertNotIn("local", line[0])
        self.assertNotIn("if-authenticated", line[0])
        self.assertNotIn("none", line[0])

    def test_config_mode_commands_are_authorized(self):
        """MEASURED on IOS 15.2(4)M7: without `aaa authorization
        config-commands`, commands typed INSIDE config mode are not
        authorized at all. Authorizing `configure terminal` and then
        leaving the config session unpoliced would be the whole control
        defeated by one command -- an operator who gets into config mode
        could do anything."""
        cfg = pol.render_router_config(device="R1")
        self.assertIn("aaa authorization config-commands", cfg)

    def test_console_is_exempt_so_the_lab_cannot_be_locked_out(self):
        cfg = pol.render_router_config(device="R1")
        self.assertIn("authorization commands 15 CONSOLE", cfg)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestAuthorCodec(unittest.TestCase):
    """RFC 8907 §6.1/§6.2 authorization REQUEST and RESPONSE.

    The authorization REQUEST body is NOT the accounting body with a
    different type byte: accounting starts with a flags octet and
    authorization does not. Reusing the accounting parser here would
    misread every field by one byte.
    """

    def test_request_round_trip(self):
        import virp_tacacs_codec as tp
        args = ["service=shell", "cmd=show", "cmd-arg=version",
                "cmd-arg=<cr>"]
        body = tp.build_author_request(
            authen_method=0x06, priv_lvl=15, authen_type=0x01,
            authen_service=0x01, user="virp-rw", port="tty2",
            rem_addr="192.168.122.1", args=args)
        f, state = tp.parse_author_request(body)
        self.assertEqual(state, "COMPLETE")
        self.assertEqual(f["user"], "virp-rw")
        self.assertEqual(f["priv_lvl"], 15)
        self.assertEqual(f["args"], args)

    def test_request_body_has_no_flags_octet(self):
        """Pinning the one-byte difference from the accounting body."""
        import virp_tacacs_codec as tp
        body = tp.build_author_request(
            authen_method=0x06, priv_lvl=15, authen_type=0x01,
            authen_service=0x01, user="u", port="p", rem_addr="r",
            args=["service=shell"])
        # byte 0 is authen_method, not flags
        self.assertEqual(body[0], 0x06)
        self.assertEqual(body[1], 15)

    def test_response_round_trip(self):
        import virp_tacacs_codec as tp
        blob = tp.build_author_response(
            tp.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
            args=["service=shell"], server_msg=b"ok", data=b"")
        r = tp.parse_author_response(blob)
        self.assertEqual(r["status"], tp.TAC_PLUS_AUTHOR_STATUS_PASS_ADD)
        self.assertEqual(r["args"], ["service=shell"])
        self.assertEqual(r["server_msg"], "ok")

    def test_fail_status_carries_no_args(self):
        import virp_tacacs_codec as tp
        blob = tp.build_author_response(tp.TAC_PLUS_AUTHOR_STATUS_FAIL,
                                        args=[], server_msg=b"denied")
        r = tp.parse_author_response(blob)
        self.assertEqual(r["status"], tp.TAC_PLUS_AUTHOR_STATUS_FAIL)
        self.assertEqual(r["args"], [])
        self.assertEqual(r["server_msg"], "denied")

    def test_short_body_is_malformed_not_an_exception(self):
        import virp_tacacs_codec as tp
        f, state = tp.parse_author_request(b"\x06\x0f")
        self.assertEqual(state, "MALFORMED")

    def test_command_reassembly_from_author_args_matches_accounting(self):
        """The authorizer must reassemble a command from AUTHOR args the
        same way the reconciler does from accounting args, or the two
        will disagree about what was asked for."""
        import virp_tacacs_reconcile as rc
        cmd, rule = rc.reassemble_command(
            ["service=shell", "cmd=show", "cmd-arg=ip", "cmd-arg=route",
             "cmd-arg=<cr>"])
        self.assertEqual(cmd, "show ip route")


class TestOutcomeClassifier(unittest.TestCase):
    """Router output must be classified three ways, not two.

    DENIED and NOT_A_COMMAND are different facts: the first means the
    authorization server refused, the second means the command never
    reached authorization because IOS did not recognise it in the current
    mode. Collapsing them would let a typo be recorded as a successful
    denial -- evidence that a control worked when it was never asked.
    """

    def test_iOS_denial_is_denied(self):
        self.assertEqual(
            iossh.classify("show run\r\nCommand authorization failed.\r\nR1#"),
            iossh.DENIED)

    def test_virp_reason_is_denied(self):
        out = "conf t\r\n" + az.DENY_PREFIX + "no grant\r\nR1#"
        self.assertEqual(iossh.classify(out), iossh.DENIED)

    def test_invalid_input_is_not_a_command(self):
        out = "interface Loopback99\r\n     ^\r\n% Invalid input detected at '^' marker.\r\nR1#"
        self.assertEqual(iossh.classify(out), iossh.NOT_A_COMMAND)

    def test_incomplete_command_is_not_a_command(self):
        self.assertEqual(
            iossh.classify("interface\r\n% Incomplete command.\r\nR1#"),
            iossh.NOT_A_COMMAND)

    def test_plain_output_is_executed(self):
        self.assertEqual(
            iossh.classify("show clock\r\n*12:00:00.000 UTC Fri Sep 5 2026\r\nR1#"),
            iossh.EXECUTED)

    def test_denial_wins_over_invalid_when_both_appear(self):
        """A denial anywhere in the transcript is the stronger fact."""
        out = ("conf t\r\nCommand authorization failed.\r\n"
               "% Invalid input detected\r\nR1#")
        self.assertEqual(iossh.classify(out), iossh.DENIED)
