#!/bin/bash
#
# verify-release-bundle.sh — one command for a downloader (or CI, before it
# publishes) to check that a release bundle is exactly what its manifest and
# test attestation claim.
#
# Checks, in order, failing loudly on the first miss:
#   1. sha256 of the zip matches the manifest's bundle-sha256 header;
#   2. every file inside the zip matches its manifest line, AND the zip
#      contains no file the manifest does not list (a smuggled extra file is
#      as disqualifying as a modified one);
#   3. the test attestation hashes to the manifest's attestation-sha256, its
#      commit equals the manifest's commit, its tree was clean, and its
#      result is "pass" — i.e. the test evidence proves THIS archive;
#   4. (with --signature) the detached ed25519 ssh signature over the
#      manifest verifies against the allowed_signers file.
#
# Usage:
#   verify-release-bundle.sh --bundle ZIP --manifest FILE
#       [--attestation FILE] [--expect-commit SHA]
#       [--signature FILE] [--signers FILE] [--identity PRINCIPAL]
#   verify-release-bundle.sh --selftest
#
# Defaults: --signers keys/release/allowed_signers (relative to the repo this
# script lives in), --identity virp-release@thirdlevelit.com.
#
# Copyright (c) 2026 Third Level IT LLC — Apache 2.0

set -u

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
SIGN_NAMESPACE="virp-release"

header_field() {  # header_field MANIFEST KEY -> value or empty
    sed -n "s/^# $2: //p" "$1" | head -1
}

verify() {
    local bundle="$1" manifest="$2" attestation="$3" expect_commit="$4"
    local signature="$5" signers="$6" identity="$7"
    local tmp want_sha got_sha commit

    [ -f "$bundle" ]   || { echo "FAIL: bundle '$bundle' not found"; return 1; }
    [ -f "$manifest" ] || { echo "FAIL: manifest '$manifest' not found"; return 1; }

    # 1. The zip is the zip the manifest was written for.
    want_sha="$(header_field "$manifest" bundle-sha256)"
    [ -n "$want_sha" ] || { echo "FAIL: manifest has no bundle-sha256 header"; return 1; }
    got_sha="$(sha256sum "$bundle" | awk '{print $1}')"
    if [ "$got_sha" != "$want_sha" ]; then
        echo "FAIL: bundle sha256 mismatch"
        echo "      manifest: $want_sha"
        echo "      actual:   $got_sha"
        return 1
    fi
    echo "  PASS: bundle sha256 matches manifest ($got_sha)"

    commit="$(header_field "$manifest" commit)"
    [ -n "$commit" ] || { echo "FAIL: manifest has no commit header"; return 1; }
    if [ -n "$expect_commit" ] && [ "$commit" != "$expect_commit" ]; then
        echo "FAIL: manifest is for commit $commit, expected $expect_commit"
        return 1
    fi

    # 2. Per-file hashes, both directions.
    tmp="$(mktemp -d)" || return 1
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN
    python3 -m zipfile -e "$bundle" "$tmp/extract/" || \
        { echo "FAIL: could not extract bundle"; return 1; }
    grep -v '^#' "$manifest" > "$tmp/files.sha256"
    ( cd "$tmp/extract" && sha256sum --quiet --strict -c "$tmp/files.sha256" ) || \
        { echo "FAIL: bundle contents do not match manifest"; return 1; }
    sed 's/^[0-9a-f]\{64\}  //' "$tmp/files.sha256" | LC_ALL=C sort \
        > "$tmp/listed"
    ( cd "$tmp/extract" && find . -type f | sed 's|^\./||' | LC_ALL=C sort ) \
        > "$tmp/present"
    if ! diff -u "$tmp/listed" "$tmp/present" > "$tmp/diff"; then
        echo "FAIL: bundle file set differs from manifest (extra or missing files):"
        sed -n '3,20p' "$tmp/diff"
        return 1
    fi
    echo "  PASS: all $(wc -l < "$tmp/listed") bundle files match, none unlisted"

    # 3. Test evidence proves this exact archive.
    local att_sha
    att_sha="$(header_field "$manifest" attestation-sha256)"
    if [ -n "$att_sha" ]; then
        [ -n "$attestation" ] || { echo "FAIL: manifest binds a test attestation" \
            "(sha256 $att_sha) but none was given — pass --attestation"; return 1; }
        [ -f "$attestation" ] || { echo "FAIL: attestation '$attestation' not found"; return 1; }
        got_sha="$(sha256sum "$attestation" | awk '{print $1}')"
        if [ "$got_sha" != "$att_sha" ]; then
            echo "FAIL: attestation sha256 mismatch (got $got_sha, manifest says $att_sha)"
            return 1
        fi
        python3 - "$attestation" "$commit" <<'PYEOF' || return 1
import json, sys
doc = json.load(open(sys.argv[1]))
if doc.get("commit") != sys.argv[2]:
    sys.exit("FAIL: attestation tested commit %s, bundle is commit %s\n"
             "      — this evidence proves a nearby tree, not this archive."
             % (doc.get("commit"), sys.argv[2]))
if doc.get("dirty") is not False:
    sys.exit("FAIL: attestation records a dirty tree")
if doc.get("result") != "pass":
    sys.exit("FAIL: attestation result is %r, not 'pass'" % doc.get("result"))
PYEOF
        echo "  PASS: test attestation pins this commit ($commit), clean tree, result pass"
    elif [ -n "$attestation" ]; then
        echo "FAIL: --attestation given but the manifest binds none" \
             "(no attestation-sha256 header)"
        return 1
    else
        echo "  NOTE: manifest binds no test attestation (none was checked)"
    fi

    # 4. Signature over the manifest covers everything above.
    if [ -n "$signature" ]; then
        [ -f "$signature" ] || { echo "FAIL: signature '$signature' not found"; return 1; }
        [ -f "$signers" ]   || { echo "FAIL: allowed_signers '$signers' not found"; return 1; }
        if ! ssh-keygen -Y verify -f "$signers" -I "$identity" \
                -n "$SIGN_NAMESPACE" -s "$signature" < "$manifest" >/dev/null; then
            echo "FAIL: manifest signature does NOT verify for '$identity'"
            return 1
        fi
        echo "  PASS: manifest signature verifies ($identity, namespace $SIGN_NAMESPACE)"
    else
        echo "  NOTE: no --signature given (manifest signature not checked)"
    fi

    echo "  PASS: release bundle verified — commit $commit"
    return 0
}

selftest() {
    # End-to-end over the three release scripts: attest -> bundle -> verify,
    # then prove every guard actually rejects what it claims to reject.
    local tmp rc
    tmp="$(mktemp -d)" || exit 1
    # shellcheck disable=SC2064  # expand now: $tmp is function-local
    trap "rm -rf '$tmp'" EXIT

    git -C "$tmp" init -q -b selftest
    git -C "$tmp" config user.email selftest@example.invalid
    git -C "$tmp" config user.name selftest
    mkdir -p "$tmp/sub"
    echo alpha > "$tmp/alpha.txt"
    echo beta > "$tmp/sub/beta.txt"
    git -C "$tmp" add -A && git -C "$tmp" commit -qm selftest

    ( cd "$tmp" && "$SCRIPT_DIR/gen-test-attestation.sh" --out att.json "true" ) \
        >/dev/null || { echo "FAIL selftest: attestation step failed"; return 1; }
    ( cd "$tmp" && "$SCRIPT_DIR/make-release-bundle.sh" --out dist \
        --name testrel --attestation att.json ) >/dev/null || \
        { echo "FAIL selftest: bundle step failed"; return 1; }

    # Happy path, including a signature with a throwaway key.
    ssh-keygen -q -t ed25519 -N '' -C selftest -f "$tmp/relkey" || return 1
    echo "virp-release@thirdlevelit.com $(cut -d' ' -f1-2 "$tmp/relkey.pub")" \
        > "$tmp/allowed_signers"
    ssh-keygen -Y sign -f "$tmp/relkey" -n "$SIGN_NAMESPACE" \
        "$tmp/dist/testrel.MANIFEST.sha256" >/dev/null 2>&1 || \
        { echo "FAIL selftest: signing failed"; return 1; }
    verify "$tmp/dist/testrel.zip" "$tmp/dist/testrel.MANIFEST.sha256" \
        "$tmp/dist/testrel.test-attestation.json" "" \
        "$tmp/dist/testrel.MANIFEST.sha256.sig" "$tmp/allowed_signers" \
        "virp-release@thirdlevelit.com" >/dev/null || \
        { echo "FAIL selftest: known-good bundle did not verify"; return 1; }

    # Guard 1: tampered manifest -> signature check must fail.
    sed 's/^# created-utc: /# created-utc: 1999/' \
        "$tmp/dist/testrel.MANIFEST.sha256" > "$tmp/tampered.MANIFEST.sha256"
    if verify "$tmp/dist/testrel.zip" "$tmp/tampered.MANIFEST.sha256" \
        "$tmp/dist/testrel.test-attestation.json" "" \
        "$tmp/dist/testrel.MANIFEST.sha256.sig" "$tmp/allowed_signers" \
        "virp-release@thirdlevelit.com" >/dev/null 2>&1; then
        echo "FAIL selftest: tampered manifest verified"; return 1
    fi

    # Guard 2: tampered bundle -> content check must fail.
    cp "$tmp/dist/testrel.zip" "$tmp/evil.zip"
    printf 'x' >> "$tmp/evil.zip"
    if verify "$tmp/evil.zip" "$tmp/dist/testrel.MANIFEST.sha256" \
        "$tmp/dist/testrel.test-attestation.json" "" "" "" "" >/dev/null 2>&1; then
        echo "FAIL selftest: tampered bundle verified"; return 1
    fi

    # Guard 3: attestation for a DIFFERENT commit -> bundling must refuse.
    # This is the exact reviewer finding (report for f200e621, zip of
    # cd351af6) reproduced in miniature.
    echo gamma > "$tmp/gamma.txt"
    git -C "$tmp" add -A && git -C "$tmp" commit -qm second
    if ( cd "$tmp" && "$SCRIPT_DIR/make-release-bundle.sh" --out dist2 \
        --name testrel2 --attestation att.json ) >/dev/null 2>&1; then
        echo "FAIL selftest: bundle accepted evidence for a nearby tree"; return 1
    fi

    # Guard 4: failing attestation -> bundling must refuse.
    ( cd "$tmp" && "$SCRIPT_DIR/gen-test-attestation.sh" --out attfail.json \
        "false" ) >/dev/null 2>&1
    if ( cd "$tmp" && "$SCRIPT_DIR/make-release-bundle.sh" --out dist3 \
        --name testrel3 --attestation attfail.json ) >/dev/null 2>&1; then
        echo "FAIL selftest: bundle accepted a FAILING test attestation"; return 1
    fi

    echo "  PASS: verify-release-bundle.sh selftest (e2e + 4 rejection guards)"
    return 0
}

BUNDLE="" MANIFEST="" ATTESTATION="" EXPECT_COMMIT=""
SIGNATURE="" SIGNERS="" IDENTITY="virp-release@thirdlevelit.com"

[ $# -gt 0 ] || { sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
while [ $# -gt 0 ]; do
    case "$1" in
        --selftest) selftest; exit $? ;;
        --bundle) BUNDLE="${2:?}"; shift 2 ;;
        --manifest) MANIFEST="${2:?}"; shift 2 ;;
        --attestation) ATTESTATION="${2:?}"; shift 2 ;;
        --expect-commit) EXPECT_COMMIT="${2:?}"; shift 2 ;;
        --signature) SIGNATURE="${2:?}"; shift 2 ;;
        --signers) SIGNERS="${2:?}"; shift 2 ;;
        --identity) IDENTITY="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
        *) echo "FAIL: unknown argument $1"; exit 2 ;;
    esac
done

[ -n "$BUNDLE" ] && [ -n "$MANIFEST" ] || \
    { echo "FAIL: --bundle and --manifest are required"; exit 2; }
[ -n "$SIGNERS" ] || SIGNERS="$SCRIPT_DIR/../keys/release/allowed_signers"

verify "$BUNDLE" "$MANIFEST" "$ATTESTATION" "$EXPECT_COMMIT" \
       "$SIGNATURE" "$SIGNERS" "$IDENTITY"
