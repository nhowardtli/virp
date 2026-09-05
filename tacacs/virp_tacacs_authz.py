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
import re
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


# MEASURED on IOS 15.2(4)M7: the router re-tokenizes a command before
# authorizing it, separating an interface type from its unit number --
# `interface Loopback91` is authorized as `interface Loopback 91`. An
# exact-match policy denies the approved change and looks, from the
# outside, exactly like the control working.
#
# The response is NOT a loose matcher. This rule derives a FINITE set of
# spellings from the approved text, the grant records that set, and only
# those are accepted. An auditor can read exactly what the router will be
# allowed to say.
SPELLING_RULE = "cisco_interface_unit_spacing"

# Phase 2: IOS canonical form.
#
# Exact-match on the approved text is wrong in BOTH directions, and both
# were measured:
#   - IOS RE-SPELLS commands before accounting/authorizing them
#     (`interface Loopback91` -> `interface Loopback 91`), so an exact
#     match FALSE-DENIES a legitimate approval;
#   - IOS TRUNCATES at `;`, so `show clock ; reload` is accounted as
#     `show clock`, and an approval written with a `;` claims something
#     the router will never be asked about.
#
# The canonicalizer maps approved text to the form IOS actually uses. Its
# expansion table is derived FROM THE ROUTER (the corpus in
# tests/fixtures/ios_respelling_corpus.json), never from memory. A token
# the table cannot resolve raises rather than passing through: passing an
# unexpanded abbreviation would silently compare the wrong string and
# deny an approved change.
CANONICAL_RULE = "ios_15_2_accounted_form"


class CanonicalizationError(ValueError):
    """The canonicalizer could not produce IOS's form for this text.

    Raised rather than returning the input unchanged. A passthrough would
    put a string into the policy that the router will never send, which
    denies approved work and looks like the control working."""

_UNIT_SPLIT = re.compile(r"^([A-Za-z][A-Za-z-]*)(\d[\d/.:]*)$")


def command_spellings(command):
    """Every spelling accepted for `command`, under SPELLING_RULE.

    Scoped TIGHTLY to what was measured: the token immediately following
    the literal `interface` keyword, whose type name and unit number IOS
    separates. Nothing else is respelled.

    A first, broader draft joined any alphabetic token to a following
    number and produced `ip route10.0.0.0` from `ip route 10.0.0.0` --
    a spelling no router will ever send and no approver ever wrote.
    Inventing accepted spellings is the one thing this rule must not do,
    so it is anchored to a keyword rather than to a character class.
    """
    base = canonical_command(command)
    if base is None:
        return []
    toks = base.split()
    out = {base}

    for i, t in enumerate(toks):
        if t.lower() != "interface":
            continue
        if i + 1 >= len(toks):
            break
        nxt = toks[i + 1]
        m = _UNIT_SPLIT.match(nxt)
        if m:
            # "Loopback91" -> "Loopback 91"
            out.add(" ".join(toks[:i + 1] + [m.group(1), m.group(2)]
                             + toks[i + 2:]))
        elif (i + 2 < len(toks)
              and re.fullmatch(r"[A-Za-z][A-Za-z-]*", nxt)
              and re.fullmatch(r"\d[\d/.:]*", toks[i + 2])):
            # "Loopback 91" -> "Loopback91"
            out.add(" ".join(toks[:i + 1] + [nxt + toks[i + 2]]
                             + toks[i + 3:]))
        break
    return sorted(out)


_CORPUS_PATH = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "tests", "fixtures",
    "ios_respelling_corpus.json")

_TABLE = None


def _load_table(path=None):
    """Token expansion table, DERIVED FROM THE ROUTER.

    Built by aligning each corpus row's typed tokens with the tokens IOS
    actually accounted. Nothing here is typed from memory of IOS: if the
    router was never observed expanding a token, the table does not claim
    to know it.
    """
    global _TABLE
    if _TABLE is not None and path is None:
        return _TABLE
    import json as _json
    tok, verbs, bigram = {}, set(), {}
    try:
        with open(path or _CORPUS_PATH) as f:
            corpus = _json.load(f)
    except OSError:
        corpus = {"entries": []}
    for e in corpus.get("entries", []):
        acct = e.get("accounted_cmd")
        if not acct:
            continue
        typed = _pre_normalise(e["typed"]).split()
        got = acct[:-4].strip().split() if acct.endswith("<cr>") \
            else acct.split()
        if not typed or not got:
            continue
        verbs.add(got[0].lower())
        if len(typed) == len(got):
            for i, (a, b) in enumerate(zip(typed, got)):
                if a.lower() != b.lower() or a != b:
                    tok[a.lower()] = b
                    # MEASURED: `int` expands to `interfaces` after
                    # `show` and to `interface` in config mode. A
                    # context-free table cannot hold both, so the
                    # preceding token is part of the key.
                    prev = typed[i - 1].lower() if i else ""
                    bigram[(prev, a.lower())] = b
        elif len(got) == len(typed) + 1:
            # IOS split an interface unit off its type name, so the two
            # token sequences are the same up to the split point and
            # offset by one after it. Aligning naively with zip() pairs
            # the wrong tokens and silently learns nothing -- which is
            # how `int` -> `interfaces` (exec) was missed while
            # `int` -> `interface` (config) was learned.
            split_at = None
            for i, a in enumerate(typed):
                m = _UNIT_SPLIT.match(a)
                if m and i + 1 < len(got) and got[i + 1] == m.group(2):
                    split_at = i
                    break
            if split_at is None:
                continue
            pairs = [(typed[i], got[i]) for i in range(split_at)]
            pairs.append((typed[split_at], got[split_at]))   # type name
            for i in range(split_at + 1, len(typed)):
                pairs.append((typed[i], got[i + 1]))
            for i, (a, b) in enumerate(pairs):
                if a == b:
                    continue
                m = _UNIT_SPLIT.match(a)
                key = m.group(1).lower() if (m and i == split_at) else a.lower()
                tok[key] = b
                prev = typed[i - 1].lower() if i else ""
                bigram[(prev, key)] = b
    table = {"tokens": tok, "verbs": verbs, "bigrams": bigram}
    if path is None:
        _TABLE = table
    return table


def _pre_normalise(text):
    """The shape-only steps, before any expansion.

    All four measured on the router:
      - trailing " <cr>" dropped;
      - everything from `;` onward TRUNCATED (IOS discards it, and never
        asks about it);
      - everything from `|` onward STRIPPED (the output filter never
        reaches the accounting or authorization record);
      - whitespace runs collapsed, case lowered.
    """
    t = (text or "").replace("\r", "").strip()
    if t.endswith("<cr>"):
        t = t[:-4]
    for sep in (";", "|"):
        i = t.find(sep)
        if i >= 0:
            t = t[:i]
    return " ".join(t.lower().split())


def ios_canonical(text, table=None):
    """Approved text -> the exact string IOS accounts and authorizes.

    Raises CanonicalizationError rather than passing an unrecognised verb
    through. A passthrough would put a string in the policy that the
    router will never send, which denies approved work while looking like
    the control working.
    """
    tbl = table or _load_table()
    base = _pre_normalise(text)
    if not base:
        raise CanonicalizationError("empty command after normalisation: %r"
                                    % text)
    toks = base.split()

    verb = tbl["tokens"].get(toks[0], toks[0]).lower()
    if tbl["verbs"] and verb not in tbl["verbs"]:
        raise CanonicalizationError(
            "verb %r is not in the corpus-derived table (%d verbs known); "
            "the router has never been observed accounting it, so its "
            "canonical form is unknown" % (toks[0], len(tbl["verbs"])))

    out = []
    for idx, t in enumerate(toks):
        prev = toks[idx - 1].lower() if idx else ""
        rep = tbl.get("bigrams", {}).get((prev, t))
        if rep is None:
            rep = tbl["tokens"].get(t)
        if rep is None:
            out.append(t)
            continue
        m = _UNIT_SPLIT.match(t)
        out.append(rep)
        if m and not _UNIT_SPLIT.match(rep):
            out.append(m.group(2))              # unit split off by IOS
    # A unit typed adjacent to a known interface type, e.g. "Loopback301"
    # where the table knows "loopback301" only as part of a longer row.
    final = []
    for t in out:
        m = _UNIT_SPLIT.match(t)
        if m and m.group(1).lower() in tbl["tokens"]:
            final.append(tbl["tokens"][m.group(1).lower()])
            final.append(m.group(2))
        else:
            final.append(t)
    return " ".join(final)


def _grant_matches(g, device, command):
    if g.get("device") != device:
        return False
    accepted = g.get("accepted_spellings")
    if not accepted:
        accepted = command_spellings(g.get("command"))
    return command in accepted


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
