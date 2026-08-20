#!/bin/bash
#
# make-release-bundle.sh — cut a release ZIP from an exact commit and write
# the manifest that binds bundle, tree, and test evidence together.
#
# Produces, in --out DIR:
#   <name>.zip                    git archive of exactly --ref (no working-
#                                 tree files can leak in)
#   <name>.MANIFEST.sha256        sha256 of EVERY file inside the bundle,
#                                 headed by the commit and tree hash, the
#                                 sha256 of the zip itself, and the sha256 of
#                                 the test attestation
#   <name>.test-attestation.json  copy of the attestation (when provided)
#
# The manifest is the signing subject: one detached signature over it covers
# the bundle contents, the archive bytes, the exact commit, and the test
# evidence, because the manifest pins all four.
#
# If --attestation is given, the attestation's "commit" field MUST equal the
# bundled commit, its "result" must be "pass" and its tree must be clean —
# otherwise this script refuses. That refusal is the point: it is no longer
# possible to ship a bundle whose test evidence describes a nearby tree.
#
# Usage:
#   make-release-bundle.sh [--ref REF] [--out DIR] [--attestation FILE]
#                          [--name NAME]
#     --ref REF           commit-ish to archive (default HEAD)
#     --out DIR           output directory (default dist)
#     --attestation FILE  test attestation from gen-test-attestation.sh
#     --name NAME         bundle basename (default virp-<git describe REF>)
#
# Copyright (c) 2026 Third Level IT LLC — Apache 2.0

set -u

REF=HEAD
OUT=dist
ATTESTATION=""
NAME=""

while [ $# -gt 0 ]; do
    case "$1" in
        --ref) REF="${2:?--ref needs a value}"; shift 2 ;;
        --out) OUT="${2:?--out needs a value}"; shift 2 ;;
        --attestation) ATTESTATION="${2:?--attestation needs a file}"; shift 2 ;;
        --name) NAME="${2:?--name needs a value}"; shift 2 ;;
        -h|--help) sed -n '2,35p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
        *) echo "FAIL: unknown argument $1"; exit 2 ;;
    esac
done

COMMIT="$(git rev-parse --verify "${REF}^{commit}" 2>/dev/null)" || \
    { echo "FAIL: cannot resolve '$REF' to a commit"; exit 1; }
TREE="$(git rev-parse "${COMMIT}^{tree}")"
[ -n "$NAME" ] || NAME="virp-$(git describe --tags --always "$COMMIT")"

if [ -n "$ATTESTATION" ]; then
    [ -f "$ATTESTATION" ] || { echo "FAIL: attestation '$ATTESTATION' not found"; exit 1; }
    python3 - "$ATTESTATION" "$COMMIT" <<'PYEOF' || exit 1
import json, sys
doc = json.load(open(sys.argv[1]))
commit = sys.argv[2]
if doc.get("schema") != "virp-test-attestation/v1":
    sys.exit(f"FAIL: {sys.argv[1]} is not a virp-test-attestation/v1 document")
if doc.get("commit") != commit:
    sys.exit("FAIL: attestation tested commit %s but the bundle is cut from %s\n"
             "      — test evidence must prove THIS archive, not a nearby tree."
             % (doc.get("commit"), commit))
if doc.get("dirty") is not False:
    sys.exit("FAIL: attestation records a dirty tree — not usable for a release.")
if doc.get("result") != "pass":
    sys.exit("FAIL: attestation result is %r, not 'pass'." % doc.get("result"))
PYEOF
fi

mkdir -p "$OUT" || exit 1
ZIP="$OUT/$NAME.zip"
MANIFEST="$OUT/$NAME.MANIFEST.sha256"

git archive --format=zip --prefix="$NAME/" -o "$ZIP" "$COMMIT" || \
    { echo "FAIL: git archive failed"; exit 1; }

# Hash what actually ships: extract the zip we just wrote and manifest its
# contents, rather than trusting that archive == tree.
EXTRACT="$(mktemp -d)" || exit 1
trap 'rm -rf "$EXTRACT"' EXIT
python3 -m zipfile -e "$ZIP" "$EXTRACT/" || { echo "FAIL: zip unreadable"; exit 1; }

ZIP_SHA="$(sha256sum "$ZIP" | awk '{print $1}')"

ATT_LINES=""
if [ -n "$ATTESTATION" ]; then
    ATT_COPY="$OUT/$NAME.test-attestation.json"
    # cp -p then compare would race; hash the copy we actually publish.
    cp "$ATTESTATION" "$ATT_COPY" || exit 1
    ATT_SHA="$(sha256sum "$ATT_COPY" | awk '{print $1}')"
    ATT_LINES="# attestation: $NAME.test-attestation.json
# attestation-sha256: $ATT_SHA"
fi

{
    echo "# VIRP release manifest v1"
    echo "# bundle: $NAME.zip"
    echo "# bundle-sha256: $ZIP_SHA"
    echo "# commit: $COMMIT"
    echo "# tree: $TREE"
    echo "# created-utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    [ -n "$ATT_LINES" ] && echo "$ATT_LINES"
    echo "#"
    echo "# Below: sha256 of every file inside the bundle, paths as extracted."
    echo "# Verify with scripts/verify-release-bundle.sh, or manually:"
    echo "#   unzip $NAME.zip && grep -v '^#' $NAME.MANIFEST.sha256 | sha256sum -c"
    ( cd "$EXTRACT" && find "$NAME" -type f -print0 | LC_ALL=C sort -z | \
        xargs -0 sha256sum )
} > "$MANIFEST" || { echo "FAIL: could not write $MANIFEST"; exit 1; }

N_FILES="$(grep -c -v '^#' "$MANIFEST")"
echo "wrote $ZIP (commit $COMMIT)"
echo "wrote $MANIFEST ($N_FILES files manifested)"
[ -n "$ATTESTATION" ] && echo "wrote $OUT/$NAME.test-attestation.json (bound by manifest)"
echo "sign with: ssh-keygen -Y sign -f <release-key> -n virp-release $MANIFEST"
