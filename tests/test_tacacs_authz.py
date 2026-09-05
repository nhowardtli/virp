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

    def test_internal_whitespace_is_preserved_identically(self):
        """Named for what it proves. Neither side COLLAPSES internal
        whitespace -- matching is byte-exact, so "show  ip route" and
        "show ip route" are different requests and the second is denied
        against a grant for the first. Failing closed on a spelling
        difference is the correct direction to fail; the earlier name for
        this test claimed a normalisation that does not happen."""
        import virp_tacacs_reconcile as rc
        from_acct, _ = rc.reassemble_command(["cmd=show   ip  route <cr>"])
        self.assertEqual(from_acct, "show   ip  route")
        self.assertEqual(az.canonical_command("show   ip  route"), from_acct)


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

    def test_console_is_exempt_so_the_lab_cannot_be_locked_out(self):
        cfg = pol.render_router_config(device="R1")
        self.assertIn("authorization commands 15 CONSOLE", cfg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
