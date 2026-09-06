"""Operator vs gate authorization, against a REAL tac_plus-ng.

Why this suite talks to a live server instead of evaluating the .conf
files in Python: guard.conf rule 3 is

    if (cmd =~ /\\|\\s*+(?!(?:include|exclude|begin|section|count)\\b)/) { deny }

`\\s*+` is a POSSESSIVE quantifier and Python's `re` cannot express it.
The possessiveness is load-bearing, not cosmetic -- with a backtracking
`\\s*`, the engine retries having consumed zero spaces, the negative
lookahead then sees " include" (which does not literally start with
`include`), the lookahead succeeds and the rule DENIES a command it is
meant to allow. A Python reimplementation would therefore not be testing
the deployed policy; it would be testing a different one that happens to
agree on the easy cases.

So: drive the actual daemon with the actual wire protocol, using
deploy/tacacs/tacacs_probe.py, which shapes per-command requests the way
IOS shapes them (cmd= plus one cmd-arg= per token, terminated <cr>).

Authorization needs no password, so this suite never handles the
operator's credential. It sets no policy and writes nothing.

Run:
    TACACS_PROBE_HOST=127.0.0.1 \\
    TACACS_PROBE_KEY="$(...)"   \\
    python3 tests/test_tacacs_operator_policy.py

Skips cleanly when those are unset, so it is safe in a checkout with no
lab attached.
"""

import importlib.util
import os
import socket
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "deploy" / "tacacs" / "tacacs_probe.py"

_spec = importlib.util.spec_from_file_location("tacacs_probe", PROBE)
tacacs_probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tacacs_probe)

HOST = os.environ.get("TACACS_PROBE_HOST")
PORT = int(os.environ.get("TACACS_PROBE_PORT", "49"))
KEY = os.environ.get("TACACS_PROBE_KEY")

# The two commands the operator account exists to cover, and which the
# gate must still be refused. The second is deliberately a guard.conf
# violation and not merely an ungranted command: it proves the operator
# profile omits the guard, rather than just carrying a wider allow-list.
CONFIGURE = "configure terminal"
REDIRECT = "show version | redirect flash:x"


def _reachable():
    if not (HOST and KEY):
        return False
    try:
        with socket.create_connection((HOST, PORT), 3):
            return True
    except OSError:
        return False


@unittest.skipUnless(
    _reachable(),
    "set TACACS_PROBE_HOST and TACACS_PROBE_KEY to a reachable tac_plus-ng")
class TestOperatorVsGateAuthorization(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.c = tacacs_probe.Client(HOST, PORT, KEY)

    def decide(self, user, command, priv_lvl):
        status, _ = self.c.authorize(user, command, priv_lvl=priv_lvl)
        self.assertIn(status, ("PASS_ADD", "PASS_REPL", "FAIL"),
                      "unexpected status %r for %s/%r -- an ERROR here is a "
                      "server fault, not a policy decision"
                      % (status, user, command))
        return status in ("PASS_ADD", "PASS_REPL")

    # ---- the operator is permitted both -------------------------------
    def test_nhoward_permitted_configure_terminal(self):
        self.assertTrue(
            self.decide("nhoward", CONFIGURE, 15),
            "operator_profile must permit %r; a human at priv 15 is "
            "decisioned for visibility, never refused (9.1)" % CONFIGURE)

    def test_nhoward_permitted_pipe_redirect(self):
        self.assertTrue(
            self.decide("nhoward", REDIRECT, 15),
            "operator_profile must permit %r. This is the guard.conf "
            "bypass working as designed: the guard is a floor under the "
            "GATE, not under a human." % REDIRECT)

    # ---- the gate is still denied both --------------------------------
    def test_virp_ro_denied_configure_terminal(self):
        self.assertFalse(
            self.decide("virp-ro", CONFIGURE, 1),
            "virp-ro must still be DENIED %r -- it is not in the GREEN "
            "table and the gate fence is unchanged by the operator "
            "account" % CONFIGURE)

    def test_virp_ro_denied_pipe_redirect(self):
        self.assertFalse(
            self.decide("virp-ro", REDIRECT, 1),
            "virp-ro must still be DENIED %r -- guard.conf rule 3 refuses "
            "any pipe modifier outside the display-only list" % REDIRECT)

    # ---- and the fence still PERMITS what it should -------------------
    def test_virp_ro_still_permitted_show_version(self):
        """Regression guard: adding operator_profile must not have
        disturbed the GREEN table. Without this, all three tests above
        would still pass if virp_ro_profile had been broken into
        deny-everything."""
        self.assertTrue(
            self.decide("virp-ro", "show version", 1),
            "virp-ro must still be PERMITTED 'show version'")


if __name__ == "__main__":
    unittest.main(verbosity=2)
