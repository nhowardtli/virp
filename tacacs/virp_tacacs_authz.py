#!/usr/bin/env python3
"""
virp_tacacs_authz.py — TACACS+ per-command AUTHORIZATION decision engine.
LAB ONLY.

This is the piece that makes the router refuse what the gate was never
approved to run. It is a SEPARATE service from the accounting receiver,
deliberately:

  - `virp_tacacs_recv.py` serves ACCT and refuses AUTHOR at the type
    byte. That refusal is load-bearing and stays.
  - This module serves AUTHOR and refuses ACCT.

Keeping them apart keeps their failure modes apart. An authorization
outage must not lose evidence, and an accounting outage must not deny
commands. `docs/TACACS-ACCOUNTING.md` v1 scope spends a paragraph on
exactly that separation; this preserves it while extending scope.

THE ONE RULE: the gate does not decide. A request is authorized only if a
grant, compiled from a signature-verified, unexpired, unspent approval,
names this device and these exact command bytes. There is no wildcard, no
prefix match, no regex, and no "close enough".

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# TACACS+ authorization reply statuses (RFC 8907 §6.4). The full
# vocabulary is carried even though this engine returns only three,
# because a reconciler must be able to name what it saw.
PASS_ADD = "PASS_ADD"
PASS_REPL = "PASS_REPL"
FAIL = "FAIL"
ERROR = "ERROR"
STATUSES = (PASS_ADD, PASS_REPL, FAIL, ERROR)

# Every denial the operator sees is prefixed. The router prints
# server_msg straight to the terminal, and an unprefixed message is
# indistinguishable from any other IOS output -- both to the person at
# the keyboard and to anyone grepping a transcript later.
DENY_PREFIX = "VIRP-DENY: "


def reply_args_for(status):
    """Arguments to put in the AUTHOR reply.

    MEASURED on IOS 15.2(4)M7: a PASS_ADD carrying arguments the router
    did not ask to have added is REJECTED -- the router prints "Command
    authorization failed." even though the server said PASS. PASS_ADD
    with arg_cnt 0 means "permit exactly as requested", which is the only
    correct reply for a command we are not modifying.
    """
    return []

# The only things virp-rw may do with no grant. Not a convenience: a
# session that cannot leave config mode is a session that has to be
# killed, and killing it loses the accounting for what it did.
# `terminal length 0` is here for a concrete reason: the cisco_ios driver
# sends it on every session, and under `aaa authorization commands 1` it
# needs a decision. Denying it breaks every gate session, read-only ones
# included. It changes only the current session's pager -- it cannot
# alter device state and reveals nothing -- so it is permitted for both
# identities as a minimal, exact-string exemption. Not a `terminal`
# prefix: `terminal monitor` is still denied.
ALWAYS_PERMITTED = ("exit", "quit", "end", "terminal length 0")

# virp-ro is the gate's steady state: GREEN reads and nothing else. This
# list is deliberately short and explicit -- no "show *" -- because
# `show running-config` leaks credentials and `show tech-support` is a
# denial of service on an emulated router.
RO_PERMITTED = (
    "show version",
    "show ip interface brief",
    "show ip route",
    "show ip protocols",
    "show users",
    "show inventory",
    "show clock",
    "show sessions",
    "show cdp neighbors",
    "show processes cpu",
    "show memory statistics",
)


def canonical_command(text):
    """VIRP's canonical command form, matching virp_canonicalize_command
    (include/virp_crypto.h): trim, collapse repeated internal spaces to
    one, strip CR. Plus the TACACS-specific step of dropping the literal
    trailing " <cr>" IOS appends (measured, 15.2(4)M7).

    WHY THIS FORM AND NOT THE RECONCILER'S. An approval's `command_hash`
    is sha256 over virp_canonicalize_command(command). The grant is only
    legitimate if its text is the text that hash commits to, so the
    authorizer must speak the same form the approval was signed in. Using
    the accounting reconciler's form -- which PRESERVES internal
    whitespace -- would mean granting a string the approver never signed
    for.

    The two forms therefore differ, deliberately, and the difference is
    pinned by test and reported in the design doc rather than smoothed
    over. Practical effect: a command differing only in whitespace runs
    still authorizes, which is correct because IOS treats those as the
    same command; the accounting matcher may still see them as distinct
    strings, which is a reporting asymmetry, not an authorization hole.
    """
    if text is None:
        return None
    t = text.replace("\r", "")
    t = t.strip()
    if t.endswith("<cr>"):
        t = t[:-4]
    return " ".join(t.split())


def _grant_matches(g, device, command):
    return (g.get("device") == device
            and canonical_command(g.get("command")) == command)


def authorize(policy, device, user, command, now_ns):
    """(status, reason, grant_id).

    Pure function of the policy, the request and the clock -- no I/O, no
    chain read, no network. That is what makes a denial provable in a
    unit test rather than only observable on a router.

    NOTE ON CHAINED COMMANDS: `command` is compared WHOLE. This function
    never splits on ';', '|' or '&&' to authorize a prefix. Splitting
    would invent a permission the approval never granted -- and the shell
    metacharacter is the attacker's input, not ours.
    """
    cmd = canonical_command(command)

    if cmd in ALWAYS_PERMITTED:
        return PASS_ADD, "always permitted (%s)" % cmd, None

    if user == "virp-ro":
        if cmd in RO_PERMITTED:
            return PASS_ADD, "virp-ro read allowlist", None
        return (FAIL,
                DENY_PREFIX + "virp-ro may not run %r (read allowlist "
                              "only)" % cmd, None)

    # virp-rw: nothing is permitted without a grant.
    candidates = [g for g in policy.get("grants", [])
                  if _grant_matches(g, device, cmd)]
    if not candidates:
        # Say WHICH way it missed, because "denied" with no reason is the
        # thing operators disable controls over.
        by_cmd = [g for g in policy.get("grants", [])
                  if canonical_command(g.get("command")) == cmd]
        if by_cmd:
            return (FAIL,
                    DENY_PREFIX + "no grant for %r on device %r (approved "
                                  "for %s)"
                    % (cmd, device,
                       ", ".join(sorted({g.get("device") for g in by_cmd}))),
                    None)
        return (FAIL,
                DENY_PREFIX + "no grant for %r on device %r" % (cmd, device),
                None)

    # Among matching grants, report the most specific failure rather than
    # a generic one: an expired grant and a spent grant are different
    # operational problems.
    reasons = []
    for g in candidates:
        if now_ns < g.get("not_before_ns", 0):
            reasons.append("grant %s not yet valid" % g.get("grant_id"))
            continue
        if now_ns > g.get("not_after_ns", 0):
            reasons.append("grant %s expired" % g.get("grant_id"))
            continue
        if int(g.get("uses_remaining", 0)) <= 0:
            reasons.append("grant %s already spent" % g.get("grant_id"))
            continue
        return PASS_ADD, "grant %s" % g.get("grant_id"), g.get("grant_id")

    return FAIL, DENY_PREFIX + "; ".join(reasons), None


def consume(policy, grant_id):
    """Spend one use. Returns the remaining count, or None if unknown.

    Single use is the DEFAULT and the caller must call this explicitly:
    an authorizer that decremented inside authorize() would spend a use
    on a probe that never reached the device."""
    for g in policy.get("grants", []):
        if g.get("grant_id") == grant_id:
            g["uses_remaining"] = max(0, int(g.get("uses_remaining", 0)) - 1)
            return g["uses_remaining"]
    return None
