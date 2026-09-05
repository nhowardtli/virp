#!/bin/sh
# The deploy dirty-tree guard, in one place.
#
# What gets installed must be exactly what a commit hash names, so every
# install target refuses to run from a dirty worktree. Until 2026-09-04
# each of the four targets (install-prod, deploy-record, install-units,
# install-devices-template) carried its own copy of the check, and every
# copy had the same fail-OPEN shape:
#
#     st=$(git status --porcelain 2>/dev/null); \
#      if [ -n "$st" ]; then echo FAIL; exit 1; fi
#
# git's exit status was discarded and its stderr sent to /dev/null, so a
# failure to ANSWER the question produced empty output and was read as
# "clean". Three ordinary ways to reach that:
#
#   - dubious ownership. `sudo make install-prod` from a worktree owned
#     by the invoking user, with no safe.directory exception, makes git
#     exit 128 with nothing on stdout. This is the NORMAL way these
#     targets are run: every one of them needs root to write to
#     /usr/local/lib/virp, /etc/systemd/system or /etc/virp.
#   - not a repository. A tarball, an rsync'd copy, a deploy tree whose
#     .git was never shipped.
#   - git absent from PATH on the install host.
#
# In all three the guard passed, the install proceeded, and DEPLOYED.md
# was stamped with provenance nobody had verified -- the deploy claimed
# a commit hash while nothing had checked that the tree matched it. A
# provenance claim must fail CLOSED: if repository state cannot be
# established, that is a failure, not a clean tree.
#
# Usage:
#   require-clean-tree.sh [--tree DIR] "<what is being refused>"
#
# Exit 0 only when git ANSWERED (exit 0) and the worktree is clean.
#
# Writes nothing to stdout, ever. deploy-record's recipe pipes its own
# stdout into DEPLOYED.md as a markdown stanza; a chatty guard would
# corrupt the record it exists to protect. All diagnostics go to stderr.
#
# Regression test: tests/test_deploy_dirty_guard.sh (make test-deploy-dirty-guard).
set -u

tree="."
what="refusing to proceed"

while [ $# -gt 0 ]; do
    case "$1" in
        --tree) tree="$2"; shift 2 ;;
        --)     shift; break ;;
        -*)     echo "unknown argument: $1" >&2; exit 2 ;;
        *)      what="$1"; shift ;;
    esac
done

# Indent a captured block onto stderr without depending on sed: the
# git-missing case is exercised with a deliberately minimal PATH.
indent() {
    while IFS= read -r _line || [ -n "$_line" ]; do
        echo "        $_line" >&2
    done
}

err=$(mktemp) || { echo "FAIL: $what -- cannot create a temporary file" >&2; exit 1; }
trap 'rm -f "$err"' EXIT INT TERM HUP

# The whole point: keep the exit status. `st=$(cmd)` sets $? from the
# command substitution, so rc is git's own status.
st=$(git -C "$tree" status --porcelain 2>"$err")
rc=$?

if [ "$rc" -ne 0 ]; then
    echo "FAIL: unable to establish repository state -- $what" >&2
    echo "      \`git -C $tree status --porcelain\` exited $rc. Silence from a" >&2
    echo "      git that failed is not a clean tree, and a deploy names a" >&2
    echo "      commit, so this is a refusal rather than a warning." >&2
    if [ -s "$err" ]; then
        echo "      git said:" >&2
        indent < "$err"
    fi
    echo "      Likely causes, in the order they actually happen:" >&2
    echo "        - running under sudo against a worktree owned by another" >&2
    echo "          user (git calls this dubious ownership). Fix the OWNERSHIP" >&2
    echo "          or deploy from a tree root owns; adding a safe.directory" >&2
    echo "          exception silences the check without establishing" >&2
    echo "          anything, so it is not the fix here." >&2
    echo "        - $tree is not a git repository (a tarball or rsync'd copy)." >&2
    echo "        - git is not installed or not on PATH." >&2
    exit 1
fi

if [ -n "$st" ]; then
    echo "FAIL: $what -- the tree is dirty. What gets deployed must be" >&2
    echo "      exactly what a commit hash names:" >&2
    printf '%s\n' "$st" | indent
    exit 1
fi

exit 0
