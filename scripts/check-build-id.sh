#!/bin/sh
# Build-id provenance test (v0.2.1 Fix 2).
#
# v0.2.0 shipped node_config entries reading build_id="unknown" for the
# whole deploy window. The value was never missing -- -DVIRP_BUILD_ID was
# placed on the virp_onode_prod.c compile line, while the code that used
# it (virp_onode.c) is archived into libvirp.a and compiled without the
# define. A macro on the wrong translation unit fails silently.
#
# Asserts, against the built prod binary:
#   1. it self-reports exactly what the tree describes;
#   2. it does not report the "unknown" placeholder, or an empty string;
#   3. the generator falls back to $VIRP_BUILD_ID outside a git worktree;
#   4. the generator REFUSES when it has neither -- a build with no
#      provenance is not a build we are willing to ship.
set -eu

BIN="${1:?usage: check-build-id.sh <prod-binary>}"
here=$(cd "$(dirname "$0")" && pwd)

echo "=== build id provenance ==="

want=$(git describe --always --dirty 2>/dev/null || true)
got=$("$BIN" --version)

if [ "$want" != "$got" ]; then
    echo "  FAIL: prod binary reports '$got', tree describes '$want'" >&2
    exit 1
fi
echo "  PASS: prod binary self-reports $got"

case "$got" in
    unknown)
        echo "  FAIL: prod binary reports the v0.2.0 placeholder" >&2; exit 1 ;;
    "")
        echo "  FAIL: prod binary reports an empty build id" >&2; exit 1 ;;
esac
echo "  PASS: not the \"unknown\" placeholder"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# (3) no git, but VIRP_BUILD_ID set -> use it
if ( cd "$tmp" && VIRP_BUILD_ID=env-fallback-id \
        "$here/gen-build-id.sh" "$tmp/o.c" >/dev/null 2>&1 ) \
   && grep -q 'env-fallback-id' "$tmp/o.c"; then
    echo "  PASS: falls back to VIRP_BUILD_ID outside a git worktree"
else
    echo "  FAIL: env fallback did not take effect" >&2; exit 1
fi

# (4) no git and no env -> must refuse, not invent a placeholder
if ( cd "$tmp" && env -u VIRP_BUILD_ID \
        "$here/gen-build-id.sh" "$tmp/n.c" >/dev/null 2>&1 ); then
    echo "  FAIL: generated a build id with no git and no env — v0.2.0 behaviour" >&2
    exit 1
fi
echo "  PASS: refuses to build with no provenance at all"
