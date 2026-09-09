#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary
"""ONODE_ACTION_HEALTH must carry the client uid into the tier gate.

Found live on 2026-09-07, through the virp-sean seat (uid 987) minutes after
that seat was deployed to 10.0.10.211.

THE BUG. `health` is not a node-liveness ping on this daemon. Its handler
takes a CLIENT-CHOSEN device and runs "show version" against it:

    case ONODE_ACTION_HEALTH:
        err = onode_execute_obs(state, req.device, "show version", ...)

and the plain `onode_execute_obs()` wrapper hardcodes `(uid_t)-1` as
client_uid. `onode_effective_max_tier()` returns the node-wide
`gate_max_tier` immediately for `(uid_t)-1`, so a uid pinned to a TIGHTER
per-uid ceiling silently gets the node-wide one on this path. Only
`onode_execute_obs_ex()` carries the uid.

LIVE PROOF, uid 987 pinned GREEN on a node whose gate_max_tier is YELLOW,
replies read back through the seat's own socket:

    'show version' on 'pbs-lab'   (tier=RED max=YELLOW)
    'show version' on 'wazuh-lab' (tier=RED max=YELLOW) proposal_id=ab1c298f...

`max=YELLOW` is the node-wide ceiling, not the GREEN that uid carries.

WHY THE TEST IS SHAPED THIS WAY. The obvious test — "a YELLOW-capped uid,
health against a RED command, expect refusal" — does NOT discriminate: RED
already exceeds YELLOW, so it is refused with or without the fix and would
pass green against the broken code. A regression test that cannot fail
against the bug it names is worse than none. The discriminating case is a
uid whose per-uid ceiling is TIGHTER than the node-wide one, running a
command that falls BETWEEN the two: GREEN-capped uid, YELLOW node, YELLOW
command. Broken: effective ceiling YELLOW, command executes. Fixed:
effective ceiling GREEN, command does not.

Pure stdlib; no daemon. Part 1 models the ceiling helper and pins the
semantics. Part 2 reads the real source and pins the call site, because the
semantic model cannot see which wrapper the handler actually calls.
"""
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ONODE_C = os.path.join(ROOT, "src", "virp_onode.c")
ONODE_H = os.path.join(ROOT, "include", "virp_onode.h")

# Tier ordering as virp.h defines it: GREEN < YELLOW < RED < BLACK.
GREEN, YELLOW, RED = 0, 1, 2
NO_UID = -1


def effective_max_tier(gate_max_tier, uid_ceilings, client_uid):
    """Model of onode_effective_max_tier() (src/virp_onode.c).

    Mirrors it exactly, including the early return that is the bug's
    enabler: a caller passing (uid_t)-1 gets the node-wide ceiling and no
    per-uid entry is ever consulted.
    """
    eff = gate_max_tier
    if client_uid == NO_UID:
        return eff
    if client_uid in uid_ceilings and uid_ceilings[client_uid] < eff:
        eff = uid_ceilings[client_uid]
    return eff


class TestCeilingSemantics(unittest.TestCase):
    """Part 1 — what passing the uid is worth, in the discriminating case."""

    NODE = YELLOW                 # .211's gate_max_tier
    CEILINGS = {987: GREEN}       # the virp-sean seat, pinned GREEN
    COMMAND = YELLOW              # falls between the two ceilings

    def test_uid_minus_one_loses_the_per_uid_ceiling(self):
        """The bug, stated as a property rather than as prose."""
        eff = effective_max_tier(self.NODE, self.CEILINGS, NO_UID)
        self.assertEqual(eff, YELLOW)
        self.assertLessEqual(
            self.COMMAND, eff,
            "with (uid_t)-1 a YELLOW command is INSIDE the ceiling and executes")

    def test_real_uid_keeps_the_per_uid_ceiling(self):
        eff = effective_max_tier(self.NODE, self.CEILINGS, 987)
        self.assertEqual(eff, GREEN)
        self.assertGreater(
            self.COMMAND, eff,
            "with the real uid a YELLOW command EXCEEDS the ceiling and must not execute")

    def test_the_two_paths_disagree_which_is_the_whole_defect(self):
        self.assertNotEqual(
            effective_max_tier(self.NODE, self.CEILINGS, NO_UID),
            effective_max_tier(self.NODE, self.CEILINGS, 987),
            "if these agreed there would be nothing to fix")

    def test_a_red_command_does_not_discriminate(self):
        """Guards the test itself against being rewritten into a tautology."""
        broken = effective_max_tier(self.NODE, self.CEILINGS, NO_UID)
        fixed = effective_max_tier(self.NODE, self.CEILINGS, 987)
        self.assertGreater(RED, broken)
        self.assertGreater(RED, fixed)


def _strip_comments(src):
    """Remove C comments before scanning; keep string literals.

    Necessary, not cosmetic: the fix's own comment explains what the old
    call site did and therefore contains the literal text
    `onode_execute_obs(`. A scanner that reads prose would report the
    explanation as the defect. Tests that grep source must look at code.
    """
    out, i, n = [], 0, len(src)
    while i < n:
        two = src[i:i + 2]
        if two == "/*":
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif two == "//":
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src[i] == '"':
            # Copy string literals THROUGH. They are parsed only so that a
            # /* inside a string is not mistaken for a comment. Dropping
            # them would delete the "show version" this test looks for —
            # which it did, and the body assertion below caught it.
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
        else:
            out.append(src[i])
            i += 1
    return "".join(out)


def _health_case_body(src):
    """The ONODE_ACTION_HEALTH case, up to the NEXT case label.

    Deliberately not "up to the first break": the handler opens with a
    guard clause that breaks on a missing device, so a non-greedy match to
    the first `break;` captures only the guard and never sees the call the
    test exists to check. That version passed against the FIXED code for
    the wrong reason, which is the failure mode this docstring is here to
    stop someone reintroducing.
    """
    m = re.search(
        r"case\s+ONODE_ACTION_HEALTH\s*:(.*?)(?=\n\s*(?:case\s+ONODE_ACTION_|default\s*:))",
        src, re.S)
    assert m, "ONODE_ACTION_HEALTH case not found in src/virp_onode.c"
    body = m.group(1)
    assert "show version" in body, (
        "extracted health body does not contain the show-version call; "
        "the case-boundary regex is wrong, not the source")
    return body


class TestHealthCallSite(unittest.TestCase):
    """Part 2 — the call site itself. This is the assertion that fails
    against the unfixed source."""

    @classmethod
    def setUpClass(cls):
        with open(ONODE_C, encoding="utf-8") as fh:
            raw = fh.read()
        cls.src = _strip_comments(raw)
        with open(ONODE_H, encoding="utf-8") as fh:
            cls.hdr = _strip_comments(fh.read())
        cls.body = _health_case_body(cls.src)

    def test_health_uses_the_uid_carrying_variant(self):
        self.assertIn(
            "onode_execute_obs_ex(", self.body,
            "ONODE_ACTION_HEALTH must call onode_execute_obs_ex() so the "
            "per-uid tier ceiling is applied; the plain wrapper hardcodes "
            "(uid_t)-1 and silently falls back to the node-wide ceiling")

    def test_health_does_not_use_the_plain_wrapper(self):
        plain = re.findall(r"\bonode_execute_obs\s*\(", self.body)
        self.assertEqual(
            plain, [],
            "ONODE_ACTION_HEALTH still calls the plain onode_execute_obs(), "
            "which passes (uid_t)-1")

    def test_health_passes_a_real_client_uid(self):
        self.assertTrue(
            re.search(r"onode_execute_obs_ex\s*\((?:[^;]*?)client_uid",
                      self.body, re.S),
            "the health call must pass client_uid, not (uid_t)-1")

    def test_the_plain_wrappers_no_longer_exist(self):
        """Stronger than the original: the symbols are GONE.

        This started life as "no request handler calls the plain wrapper",
        which left the wrapper in place for someone to reach for again. Both
        onode_execute() and onode_execute_obs() were deleted 2026-09-08, so
        the property is now structural rather than a convention: there is no
        entry point that can omit the uid, because onode_execute_obs_ex()
        takes it as a required argument.

        Asserted against the DEFINITIONS, not call sites — a definition is
        what makes the hazard available at all.
        """
        for sym in ("onode_execute", "onode_execute_obs"):
            defn = re.search(
                r"^virp_error_t\s+" + sym + r"\s*\(", self.src, re.M)
            self.assertIsNone(
                defn,
                f"{sym}() is defined again in src/virp_onode.c. It forwarded "
                f"to onode_execute_obs_ex() with client_uid hardcoded to "
                f"(uid_t)-1, which onode_effective_max_tier() reads as "
                f"'use the node-wide ceiling' — the bypass this branch "
                f"removed. Call onode_execute_obs_ex() with a real uid.")
            decl = re.search(
                r"^virp_error_t\s+" + sym + r"\s*\(", self.hdr, re.M)
            self.assertIsNone(
                decl, f"{sym}() is declared again in include/virp_onode.h")

    def test_no_caller_passes_the_sentinel_as_a_client_uid(self):
        """(uid_t)-1 may still be COMPARED against, never PASSED as an
        argument to an execute path. The comparisons are legitimate: they
        render a null uid in a record and guard the unknown-identity refusal.
        Passing it is what re-creates the bypass."""
        for m in re.finditer(r"onode_execute_obs_ex\s*\(([^;]*?)\)\s*;",
                             self.src, re.S):
            self.assertNotIn(
                "(uid_t)-1", m.group(1),
                "a call to onode_execute_obs_ex() passes the (uid_t)-1 "
                "sentinel as client_uid; that is the bypass. Pass a real "
                "uid, or justify the absence of one at the call site.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
