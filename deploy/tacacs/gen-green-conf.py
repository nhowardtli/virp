#!/usr/bin/env python3
"""gen-green-conf.py -- generate the virp-ro permit rules for tac_plus-ng.

The GREEN table is NOT copied by hand. It is parsed out of
src/drivers/driver_cisco.c, the same bytes the gate classifies with, so
the authorization server and the gate cannot silently disagree about
what GREEN means. If the driver table changes, re-run this and the
generated file changes with it.

Two transformations happen here, and both are load-bearing:

1. The IOS <cr> terminator.
   IOS sends per-command authorization as cmd=show, cmd-arg=version,
   cmd-arg=<cr>.  tac_plus-ng reassembles that (author.c:eval_args) into
   the single string "show version <cr>".  The GREEN table holds
   "show version".  Every generated rule therefore accepts an OPTIONAL
   trailing " <cr>" so the wire form and the table form are the same
   command.  Without this, every GREEN command is denied.

2. The separator refusal.
   driver_cisco.c calls virp_command_check_separators() BEFORE it
   classifies, refusing ; | & ` > < $( ${ and control bytes
   (src/virp_message.c:992).  The <cr> terminator contains '<' and '>',
   so the separator test must run on the command with <cr> already
   stripped, never on the raw wire string.  The generated regexes are
   fully anchored and admit no character outside the literal command
   text plus the optional terminator, which enforces the same refusal
   structurally rather than as a second test that could be skipped.

MATCH STRICTNESS -- a deliberate divergence, documented for review:
   driver_cisco.c classifies by LONGEST PREFIX ending on a token
   boundary, so under the driver "show interfaces GigabitEthernet0/0"
   is GREEN by virtue of the "show interfaces" row.  The rules
   generated here are EXACT-MATCH: only the 38 canonical strings
   themselves are permitted, arguments are not.  This is strictly
   tighter than the driver, never looser, and it is the reading of
   "permitted commands are exactly the GREEN table, canonical form.
   Anything else denied."  Set --prefix to emit the driver's prefix
   semantics instead if that is the intent.
"""
import argparse
import hashlib
import re
import sys

ROW = re.compile(r'^\s*\{\s*"([^"]+)"\s*,\s*VIRP_TIER_(GREEN|YELLOW|RED)\s*\}')


def parse_table(path):
    """Return [(command, tier)] in source order from the driver gate table."""
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            m = ROW.match(line)
            if m:
                rows.append((m.group(1), m.group(2)))
    if not rows:
        sys.exit("no gate table rows parsed from %s -- refusing to emit an "
                 "empty policy" % path)
    return rows


def check_no_green_shadows_worse(rows):
    """Fail if a YELLOW/RED row is reachable by a string that also matches
    a GREEN row under the driver's longest-prefix rule.

    If that were ever true, permitting on a GREEN match alone would let a
    YELLOW or RED command through, and this generator would be building a
    policy looser than the gate.  Today it is not true; this asserts it
    rather than trusting it.
    """
    green = [c for c, t in rows if t == "GREEN"]
    bad = []
    for cmd, tier in rows:
        if tier == "GREEN":
            continue
        for g in green:
            if cmd == g or cmd.startswith(g + " "):
                bad.append((g, cmd, tier))
    return bad


def canonicalize(cmds, repo_root):
    """Round-trip every command through VIRP's own IOS canonicalizer.

    Not decorative: it is the check that the string written into the
    policy is the string IOS will actually send.  A command the
    canonicalizer cannot resolve is fatal here rather than a silent
    mismatch at 3am.
    """
    sys.path.insert(0, str(repo_root / "tacacs"))
    from virp_tacacs_authz import ios_canonical, CanonicalizationError
    out = []
    for c in cmds:
        try:
            canon = ios_canonical(c)
        except CanonicalizationError as e:
            sys.exit("FATAL: %r has no known IOS canonical form: %s" % (c, e))
        if canon != c:
            sys.exit("FATAL: %r canonicalizes to %r -- the driver table is "
                     "not in canonical form and the policy would compare "
                     "the wrong string" % (c, canon))
        out.append(canon)
    return out


# REGEX FLAVOUR -- this cost a parse failure to find, so it is written
# down. tac_plus-ng picks the engine from the DELIMITER:
#
#   cmd =~ "pattern"   -> POSIX ERE  (regcomp, REG_EXTENDED)
#   cmd =~ /pattern/   -> PCRE2      (pcre2_compile)
#
# (tac_plus-ng/config.c:5125-5150). POSIX ERE has no non-capturing
# group, so `(?: <cr>)?` inside quotes fails with "Invalid preceding
# regular expression". Slash-delimited PCRE2 is used throughout.
#
# The 38 GREEN commands are letters, spaces and hyphens only -- none is
# a PCRE2 metacharacter outside a character class, and none is the '/'
# that would need escaping inside slash delimiters, so the literal goes
# in as-is. Anything outside the safe set is refused rather than
# escaped, so a future table entry with a metacharacter fails loudly
# here instead of silently compiling to a different pattern.
SAFE_LITERAL = re.compile(r"^[A-Za-z0-9 -]+$")


# Allowed IOS display modifiers after a pipe. Everything else after a
# pipe is denied outright.
#
# This list is CLOSED and it is the security boundary of the pipe. IOS
# accepts modifiers that write ("| redirect flash:x", "| tee", "| append")
# alongside ones that only filter, and a read command with a writing
# modifier is a write performed by something that classifies as a read --
# exactly the reasoning driver_cisco.c uses when it refuses '>' outright
# (src/virp_message.c:1008). Filtering modifiers cannot move bytes, so
# they are safe to permit; nothing else is.
PIPE_MODIFIERS = ["include", "exclude", "begin", "section", "count"]


def guard_block():
    alt = "|".join(PIPE_MODIFIERS)
    L = []
    L.append("# GENERATED BY deploy/tacacs/gen-green-conf.py -- DO NOT EDIT.")
    L.append("#")
    L.append("# Hard denials, evaluated BEFORE any permit rule. Included by")
    L.append("# BOTH profiles: virp-ro ahead of green.conf, virp-rw ahead of")
    L.append("# approved.conf. A grant cannot opt out of these, which is the")
    L.append("# point -- the approved.conf writer is a machine, and this is")
    L.append("# the floor it cannot write below.")
    L.append("#")
    L.append("# \\A and \\z everywhere, never ^ and $: tac_plus-ng compiles")
    L.append("# PCRE2 with PCRE2_MULTILINE (config.c:5136), under which ^ and")
    L.append("# $ match at embedded newlines. Measured: /^show version$/ also")
    L.append("# permitted \"show version\\nconfigure terminal\".")
    L.append("")
    L.append("    # 1. Command separator. IOS truncates at ';' before it")
    L.append("    #    authorizes, so a ';' arriving here did not come from a")
    L.append("    #    router's own parser.")
    L.append("    if (cmd =~ /;/) { deny }")
    L.append("")
    L.append("    # 2. Control bytes, backtick, ampersand, and shell")
    L.append("    #    expansion. Same refusal set as")
    L.append("    #    virp_command_check_separators() (src/virp_message.c:992).")
    L.append("    if (cmd =~ /[\\x00-\\x1f\\x7f`&]/) { deny }")
    L.append("    if (cmd =~ /\\$[({]/) { deny }")
    L.append("")
    L.append("    # 3. Pipe modifiers: the closed allow-list, or nothing.")
    L.append("    #    The negative lookahead denies a pipe followed by")
    L.append("    #    anything not in the list -- 'redirect', 'tee',")
    L.append("    #    'append', or an empty/garbage modifier.")
    # \s*+ is POSSESSIVE, and that is the whole rule.
    #
    # With a plain \s*, the engine backtracks the whitespace to zero
    # width and evaluates the negative lookahead at the SPACE rather
    # than at the modifier. "include" does not match at a space, so the
    # negative lookahead succeeds and every legal modifier is DENIED.
    # Measured: all five of include/exclude/begin/section/count were
    # refused before this was made possessive.
    #
    # \s*+ consumes the whitespace and cannot give it back, so the
    # lookahead is evaluated exactly where the modifier starts.
    L.append("    if (cmd =~ /\\|\\s*+(?!(?:%s)\\b)/) { deny }" % alt)
    L.append("")
    L.append("    # 4. A pipe may appear at most once. '| include x | redirect y'")
    L.append("    #    would otherwise pass rule 3 on its first pipe.")
    L.append("    if (cmd =~ /\\|[^|]*\\|/) { deny }")
    L.append("")
    return "\n".join(L) + "\n"

def rule(cmd, prefix_mode):
    if not SAFE_LITERAL.match(cmd):
        sys.exit("FATAL: %r contains a character this generator will not "
                 "put in a quoted regex unescaped. Extend SAFE_LITERAL "
                 "deliberately, with the config-lexer escaping checked, "
                 "rather than reaching for re.escape()." % cmd)
    if prefix_mode:
        # Driver semantics: longest prefix ending on a TOKEN BOUNDARY
        # (driver_cisco.c:cisco_gate_tier). The tail must start with a
        # space, which is what keeps "show boot" from admitting
        # "show bootleg" -- the same boundary rule the C classifier
        # applies, expressed in the regex instead of in code.
        #
        # The tail character class excludes control bytes, ';' and the
        # shell metacharacters. '|' IS allowed through here and is
        # policed separately in guard.conf, because a pipe is legal on
        # IOS for a closed set of display modifiers and illegal for
        # everything else -- a distinction a character class cannot
        # make. '<' and '>' are allowed only because the IOS terminator
        # is literally "<cr>".
        body = cmd + r"(?:[ ][^\x00-\x1f;`&]*)?"
    else:
        body = cmd
    # \A and \z, NOT ^ and $. This is a security fix, not a style choice.
    #
    # tac_plus-ng compiles every PCRE2 pattern with PCRE2_MULTILINE
    # (tac_plus-ng/config.c:5136). Under MULTILINE, ^ and $ match at
    # EMBEDDED NEWLINES, so /^show version$/ matches the first line of
    #     "show version\nconfigure terminal <cr>"
    # and the command is PERMITTED. Measured against this server before
    # the fix: a forged cmd-arg carrying a newline was authorized.
    #
    # \A and \z anchor to the start and absolute end of the subject and
    # are unaffected by MULTILINE, so the whole command line must match
    # or nothing does. Any rule written into approved.conf MUST use them
    # for the same reason.
    return r"/\A" + body + r"(?: <cr>)?\z/"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--driver", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--guard-out",
                    help="also write the hard-deny guard block here")
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--prefix", action="store_true",
                    help="emit driver longest-prefix semantics instead of "
                         "exact match")
    args = ap.parse_args()

    from pathlib import Path
    repo_root = Path(args.repo_root)

    rows = parse_table(args.driver)
    shadows = check_no_green_shadows_worse(rows)
    if shadows:
        for g, cmd, tier in shadows:
            print("SHADOW: GREEN %r would admit %s %r" % (g, tier, cmd),
                  file=sys.stderr)
        sys.exit("refusing to emit: permitting on GREEN match alone would "
                 "admit a non-GREEN command")

    green = [c for c, t in rows if t == "GREEN"]
    green = canonicalize(green, repo_root)

    lines = []
    lines.append("# GENERATED BY deploy/tacacs/gen-green-conf.py -- DO NOT EDIT.")
    lines.append("#")
    lines.append("# Source of truth: src/drivers/driver_cisco.c, the GREEN rows of")
    lines.append("# CISCO_GATE_TABLE. Regenerate rather than edit; an edit here")
    lines.append("# makes the authorization server and the gate disagree about")
    lines.append("# what GREEN means, and nothing would detect that.")
    lines.append("#")
    lines.append("# Match mode: %s" % ("driver longest-prefix" if args.prefix
                                       else "EXACT canonical form"))
    lines.append("# GREEN commands: %d" % len(green))
    lines.append("#")
    lines.append("# Each rule accepts an optional trailing ' <cr>' because that")
    lines.append("# is how IOS terminates a per-command authorization request")
    lines.append("# (cmd-arg=<cr>, reassembled by tac_plus-ng author.c).")
    lines.append("#")
    lines.append("# Slash delimiters select PCRE2. Double quotes would select")
    lines.append("# POSIX ERE, which has no non-capturing group and rejects these.")
    lines.append("")
    for c in green:
        lines.append("    if (cmd =~ %s) { permit }" % rule(c, args.prefix))
    lines.append("")
    body = "\n".join(lines) + "\n"

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(body)

    if args.guard_out:
        gb = guard_block()
        with open(args.guard_out, "w", encoding="utf-8") as fh:
            fh.write(gb)
        print("wrote %s" % args.guard_out)
        print("guard_sha256=%s"
              % hashlib.sha256(gb.encode("utf-8")).hexdigest())

    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    print("wrote %s" % args.out)
    print("green_commands=%d" % len(green))
    print("sha256=%s" % digest)


if __name__ == "__main__":
    main()
