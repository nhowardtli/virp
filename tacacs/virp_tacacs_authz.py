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

# The only things virp-rw may do with no grant. Not a convenience: a
# session that cannot leave config mode is a session that has to be
# killed, and killing it loses the accounting for what it did.
ALWAYS_PERMITTED = ("exit", "quit", "end")

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
    """The ONE normal form shared with the accounting reconciler.

    IOS delivers a command as a single `cmd=` argument with a literal
    trailing " <cr>" (measured, IOS 15.2(4)M7). Both the authorizer and
    the accounting matcher must strip it the same way, or a command could
    be authorized under one spelling and reconciled under another.

    Internal whitespace is PRESERVED, not collapsed. Matching is
    byte-exact by design: "show  ip route" and "show ip route" are
    different requests, and a device that sends the first when the
    approval says the second gets a denial rather than a guess. Failing
    closed on a spelling difference is the correct direction to fail.
    """
    if text is None:
        return None
    t = text.strip()
    if t.endswith("<cr>"):
        t = t[:-4]
    return t.strip()


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
        return FAIL, "virp-ro may not run %r (read allowlist only)" % cmd, None

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
                    "no grant for %r on device %r (approved for %s)"
                    % (cmd, device,
                       ", ".join(sorted({g.get("device") for g in by_cmd}))),
                    None)
        return FAIL, "no grant for %r on device %r" % (cmd, device), None

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

    return FAIL, "; ".join(reasons), None


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
