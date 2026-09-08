#!/usr/bin/env python3
"""A seat uid may only chain_append under its own session_id namespace.

Requested 2026-09-07 for the virp-sean seat (uid 987), which may append
`evidence_item` and nothing else. Type narrowing alone does not stop it
writing into somebody else's session: `chain_append` takes a client-supplied
`session_id`, and until now any string was accepted. A seat could therefore
append into `autopilot:2026-09-07`, `camera:...`, `gate-enforce:pbs-lab` or
`approval:...` and its records would sit inside a session an operator reads
as the node's own.

THE RULE. A uid carrying a `socket_uid_session_prefix` entry may only append
when `session_id` STARTS WITH that prefix. Anything else is refused with
VIRP_ERR_ACTION_FORBIDDEN (-50). The daemon NEVER rewrites, prefixes or
normalises the caller's session_id — a silent rewrite would make the chain
disagree with what the client believes it wrote, which is worse than a
refusal. A uid with no entry is unrestricted, so nothing else on the node
changes.

Part 1 models the matching rule, including every prefix the operator named as
reserved. Part 2 pins the call site in the real source, because the model
cannot see whether the daemon actually consults the policy or whether it
mutates the caller's string. Part 3 pins the shipped template.

Pure stdlib; no daemon.
"""
import json
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ONODE_C = os.path.join(ROOT, "src", "virp_onode.c")
PROD_C = os.path.join(ROOT, "src", "virp_onode_prod.c")
TEMPLATE = os.path.join(ROOT, "deploy", "devices.template.json")

SEAT_UID = "987"
SEAT_PREFIX = "seat987:"

# Namespaces the operator owns. A seat must never be able to append into one.
RESERVED = ("autopilot:", "camera:", "gate-enforce:", "approval:")


def session_allowed(prefix, session_id):
    """Model of the rule. Byte prefix, case-sensitive, no normalisation."""
    if prefix is None:          # uid carries no policy -> unrestricted
        return True
    if not session_id:
        return False
    return session_id.startswith(prefix)


class TestRule(unittest.TestCase):

    def test_its_own_namespace_is_accepted(self):
        for sid in (SEAT_PREFIX + "a",
                    SEAT_PREFIX + "20260907T160000Z",
                    SEAT_PREFIX + "anything/with:colons"):
            self.assertTrue(session_allowed(SEAT_PREFIX, sid), sid)

    def test_operator_namespaces_are_refused(self):
        """The case this policy exists for."""
        for ns in RESERVED:
            for suffix in ("2026-09-07", "pbs-lab", "x"):
                sid = ns + suffix
                self.assertFalse(
                    session_allowed(SEAT_PREFIX, sid),
                    f"{sid} must be refused: {ns} is an operator namespace")

    def test_the_bare_prefix_without_its_colon_is_refused(self):
        # "seat987" is not in the namespace "seat987:" — the separator is
        # part of the prefix, or "seat987x:" would slip through.
        self.assertFalse(session_allowed(SEAT_PREFIX, "seat987"))
        self.assertFalse(session_allowed(SEAT_PREFIX, "seat987x:1"))

    def test_prefix_must_be_at_the_START(self):
        for sid in ("x" + SEAT_PREFIX + "1",
                    "autopilot:seat987:1",
                    " " + SEAT_PREFIX + "1"):
            self.assertFalse(session_allowed(SEAT_PREFIX, sid), sid)

    def test_case_sensitive(self):
        for sid in ("SEAT987:1", "Seat987:1"):
            self.assertFalse(session_allowed(SEAT_PREFIX, sid), sid)

    def test_empty_session_id_is_refused(self):
        self.assertFalse(session_allowed(SEAT_PREFIX, ""))

    def test_a_uid_with_no_policy_is_unrestricted(self):
        """Backward compatibility: this must change nothing for 999/1000/993."""
        for sid in ("autopilot:2026-09-07", "seat987:1", "anything"):
            self.assertTrue(session_allowed(None, sid), sid)


def _strip_comments(src):
    """Drop C comments, keep string literals (the literals are the evidence)."""
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
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
        else:
            out.append(src[i])
            i += 1
    return "".join(out)


def _chain_append_case(src):
    m = re.search(
        r"case\s+ONODE_ACTION_CHAIN_APPEND\s*:(.*?)(?=\n\s*case\s+ONODE_ACTION_|\n\s*default\s*:)",
        src, re.S)
    assert m, "ONODE_ACTION_CHAIN_APPEND case not found"
    body = m.group(1)
    assert "artifact_type" in body, "case-boundary regex is wrong, not the source"
    return body


class TestCallSite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = _strip_comments(open(ONODE_C, encoding="utf-8").read())
        cls.body = _chain_append_case(cls.src)
        cls.prod = _strip_comments(open(PROD_C, encoding="utf-8").read())

    def test_chain_append_consults_the_session_prefix_policy(self):
        self.assertTrue(
            re.search(r"onode_uid_session_prefix_allowed\s*\(", self.body),
            "ONODE_ACTION_CHAIN_APPEND must consult the per-uid session "
            "prefix policy before it appends")

    def test_refusal_is_action_forbidden(self):
        seg = self.body[:self.body.find("virp_chain_append")] or self.body
        self.assertIn(
            "VIRP_ERR_ACTION_FORBIDDEN", seg,
            "a session_id outside the uid's namespace must be refused with "
            "VIRP_ERR_ACTION_FORBIDDEN (-50)")

    def test_the_daemon_never_rewrites_the_callers_session_id(self):
        """No assignment into req.session_id anywhere in the handler."""
        writes = re.findall(r"\breq\.session_id\s*(?:\[[^\]]*\])?\s*=[^=]",
                            self.body)
        self.assertEqual(
            writes, [],
            "the handler assigns to req.session_id; the policy must REFUSE, "
            "never rewrite or namespace-prefix the caller's value")
        for fn in ("strcpy", "strncpy", "snprintf", "memcpy", "strcat"):
            self.assertNotIn(
                f"{fn}(req.session_id", self.body,
                f"{fn} writes into req.session_id; refuse, do not rewrite")

    def test_the_loader_reads_the_new_template_key(self):
        self.assertIn(
            "socket_uid_session_prefix", self.prod,
            "virp_onode_prod.c must load socket_uid_session_prefix from the "
            "device template")


class TestTemplate(unittest.TestCase):

    def test_seat_uid_carries_the_prefix(self):
        doc = json.load(open(TEMPLATE, encoding="utf-8"))
        pol = doc.get("socket_uid_session_prefix")
        self.assertIsInstance(
            pol, dict, "template must carry socket_uid_session_prefix")
        self.assertEqual(pol.get(SEAT_UID), SEAT_PREFIX)

    def test_no_operator_uid_is_accidentally_namespaced(self):
        """Only the seat is constrained; constraining 999 would break the node."""
        doc = json.load(open(TEMPLATE, encoding="utf-8"))
        pol = doc.get("socket_uid_session_prefix", {})
        self.assertEqual(
            set(pol.keys()), {SEAT_UID},
            "only the seat uid should carry a session prefix today")


if __name__ == "__main__":
    unittest.main(verbosity=2)
