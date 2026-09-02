#!/bin/sh
# Does the INSTALLED binary come from the deploy tree that is checked out?
#
# v0.2.0's node_config entry said build_id="unknown", so the chain could
# not answer "which source produced the daemon that wrote this?" at all.
# With Fix 2 the binary self-reports, which makes a second question
# answerable and worth asking: does the running binary match the source
# tree it was supposedly built from? A deploy that checks out a tag but
# fails to rebuild, or rebuilds from a dirty tree, is invisible to any
# check that reads only the repo -- the same blind spot check-unit-drift
# exists to close for unit files.
#
# Usage:
#   check-deploy-build-id.sh [--tree DIR] [--binary PATH]
#   check-deploy-build-id.sh --selftest
#
# Self-skips when the deploy tree or the binary is absent, so it is safe
# on a build host and inside all-tests.
set -eu

TREE="${VIRP_DEPLOY_TREE:-/opt/virp}"
BIN="${VIRP_DEPLOY_BIN:-/usr/local/bin/virp-onode-prod}"
selftest=0

while [ $# -gt 0 ]; do
    case "$1" in
        --tree)     TREE="$2"; shift 2 ;;
        --binary)   BIN="$2";  shift 2 ;;
        --selftest) selftest=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

check_one() {
    _tree="$1"; _bin="$2"

    if [ ! -d "$_tree/.git" ]; then
        echo "  SKIP: no deploy tree at $_tree (not a deploy host)"
        return 0
    fi
    if [ ! -x "$_bin" ]; then
        echo "  SKIP: no installed binary at $_bin"
        return 0
    fi

    _want=$(git -C "$_tree" describe --always --dirty 2>/dev/null || true)
    if [ -z "$_want" ]; then
        echo "FAIL: cannot 'git describe' the deploy tree at $_tree" >&2
        return 1
    fi

    # The binary must answer without config, keys or a socket.
    if ! _got=$("$_bin" --version 2>/dev/null); then
        echo "FAIL: $_bin does not support --version." >&2
        echo "  A binary that cannot state its own build id predates v0.2.1" >&2
        echo "  and cannot be checked against the deploy tree." >&2
        return 1
    fi

    if [ "$_want" != "$_got" ]; then
        echo "FAIL: installed binary does not match the deploy tree." >&2
        echo "  deploy tree ($_tree) describes: $_want" >&2
        echo "  installed binary   ($_bin) reports: $_got" >&2
        echo "  The checked-out source is not what is running. Rebuild and" >&2
        echo "  reinstall, or find out which tree the binary really came from." >&2
        return 1
    fi

    echo "  PASS: installed binary and deploy tree agree ($_got)"
    return 0
}

# ---------------------------------------------------------------------------
# Selftest. The box is not reachable from the build host, so the rule is
# proven against a local fixture instead: a real git repo plus a stub
# binary whose reported id we control. A checker that cannot be made to
# fail is indistinguishable from a clean host -- the exact failure mode
# this class of check exists to catch.
# ---------------------------------------------------------------------------
if [ "$selftest" -eq 1 ]; then
    echo "=== self-testing the deploy build-id checker ==="
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    mkdir -p "$tmp/tree"
    git -C "$tmp/tree" init -q
    git -C "$tmp/tree" config user.email selftest@example.invalid
    git -C "$tmp/tree" config user.name  selftest
    echo x > "$tmp/tree/f"
    git -C "$tmp/tree" add f
    git -C "$tmp/tree" commit -qm "fixture"
    real=$(git -C "$tmp/tree" describe --always --dirty)

    # (a) matching binary -> must PASS
    printf '#!/bin/sh\necho "%s"\n' "$real" > "$tmp/match"
    chmod +x "$tmp/match"
    if check_one "$tmp/tree" "$tmp/match" >/dev/null 2>&1; then
        echo "  PASS: agrees when the ids match"
    else
        echo "  FAIL: checker rejected a MATCHING binary" >&2; exit 1
    fi

    # (b) mismatched binary -> must FAIL (the case that matters)
    printf '#!/bin/sh\necho "deadbee-not-this-tree"\n' > "$tmp/mismatch"
    chmod +x "$tmp/mismatch"
    if check_one "$tmp/tree" "$tmp/mismatch" >/dev/null 2>&1; then
        echo "  FAIL: checker ACCEPTED a mismatched binary — it cannot fail" >&2
        exit 1
    else
        echo "  PASS: fails when the installed id differs from the tree"
    fi

    # (c) a binary with no --version -> must FAIL, not silently pass
    printf '#!/bin/sh\nexit 1\n' > "$tmp/noversion"
    chmod +x "$tmp/noversion"
    if check_one "$tmp/tree" "$tmp/noversion" >/dev/null 2>&1; then
        echo "  FAIL: checker accepted a binary with no --version" >&2; exit 1
    else
        echo "  PASS: fails when the binary cannot report a build id"
    fi

    # (d) absent tree -> SKIP, exit 0 (safe on a build host)
    if check_one "$tmp/nonexistent" "$tmp/match" >/dev/null 2>&1; then
        echo "  PASS: skips cleanly when there is no deploy tree"
    else
        echo "  FAIL: should SKIP, not fail, with no deploy tree" >&2; exit 1
    fi

    echo "=== deploy build-id checker selftest OK ==="
    exit 0
fi

echo "=== checking installed binary against the deploy tree ==="
check_one "$TREE" "$BIN"
