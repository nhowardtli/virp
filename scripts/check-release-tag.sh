#!/bin/sh
# Is this tag one whose message can safely BE the GitHub Release body?
#
# The release pipeline publishes with `gh release create --notes-from-tag`,
# so the Release body is whatever the tag carries. That is deliberate: the
# tag message holds the feature summary, the KNOWN LIMITATIONS, and the
# verify commands, and those must reach the Release body unedited.
#
# The failure this guards is not theoretical and is not loud. A LIGHTWEIGHT
# tag (`git tag v0.2.1`) is a ref to a commit, not a tag object. Asking git
# for its message returns THE COMMIT MESSAGE. So publishing a lightweight
# tag does not produce an empty release body -- it produces a release whose
# body is the last commit subject, with the limitations list silently
# missing. Nobody reviewing the tag locally would see anything wrong.
#
# Refuse that before anything is published.
#
# Usage: check-release-tag.sh <tag>
#        check-release-tag.sh --selftest
set -eu

SELF=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")

fail() { echo "FAIL: $*" >&2; exit 1; }

check_tag() {
    _tag="$1"

    git rev-parse -q --verify "refs/tags/$_tag" >/dev/null 2>&1 \
        || fail "no such tag: $_tag"

    # An annotated tag is its own object. A lightweight tag resolves
    # straight to the commit -- and would publish the COMMIT message.
    _type=$(git cat-file -t "refs/tags/$_tag" 2>/dev/null || echo unknown)
    if [ "$_type" != "tag" ]; then
        echo "FAIL: '$_tag' is a LIGHTWEIGHT tag (resolves to a $_type)." >&2
        echo "  --notes-from-tag would publish the COMMIT message as the" >&2
        echo "  Release body, silently dropping the release notes and the" >&2
        echo "  known-limitations section. Re-create it annotated:" >&2
        echo "    git tag -a $_tag -F <notes-file>" >&2
        exit 1
    fi

    # The message of the tag OBJECT (not the commit it points at).
    _msg=$(git for-each-ref "refs/tags/$_tag" --format='%(contents)')

    # Strip a trailing signature block before measuring length.
    _body=$(printf '%s\n' "$_msg" | sed '/-----BEGIN PGP SIGNATURE-----/,$d;/-----BEGIN SSH SIGNATURE-----/,$d')

    _lines=$(printf '%s\n' "$_body" | grep -c '[^[:space:]]' || true)
    if [ "$_lines" -lt 5 ]; then
        echo "FAIL: '$_tag' has only $_lines non-blank line(s) of message." >&2
        echo "  This becomes the entire Release body. A release note that" >&2
        echo "  short is almost certainly a placeholder rather than the" >&2
        echo "  intended notes." >&2
        exit 1
    fi

    echo "  PASS: '$_tag' is annotated with $_lines non-blank lines of notes"
}

if [ "${1:-}" = "--selftest" ]; then
    echo "=== self-testing the release tag checker ==="
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    (
      cd "$tmp"
      git init -q .
      git config user.email selftest@example.invalid
      git config user.name selftest
      echo x > f && git add f
      git commit -qm "docs: a perfectly ordinary commit subject"
      git tag v-light
      git tag -a v-short -m "one line"
      git tag -a v-good -F - <<'NOTES'
VIRP vX: a real release

What this release contains:
- a thing
- another thing

Known limitations:
- something honest
NOTES
    )

    # (a) lightweight -> must FAIL, and must not silently pass with the
    #     commit message as the body
    if ( cd "$tmp" && "$SELF" v-light ) >/dev/null 2>&1; then
        fail "checker ACCEPTED a lightweight tag"
    fi
    echo "  PASS: rejects a lightweight tag"

    # (b) annotated but trivially short -> must FAIL
    if ( cd "$tmp" && "$SELF" v-short ) >/dev/null 2>&1; then
        fail "checker ACCEPTED a one-line placeholder message"
    fi
    echo "  PASS: rejects a placeholder-length message"

    # (c) proper annotated notes -> must PASS
    if ( cd "$tmp" && "$SELF" v-good ) >/dev/null 2>&1; then
        echo "  PASS: accepts a real annotated release message"
    else
        fail "checker REJECTED a valid annotated tag"
    fi

    # (d) missing tag -> must FAIL
    if ( cd "$tmp" && "$SELF" v-nope ) >/dev/null 2>&1; then
        fail "checker ACCEPTED a nonexistent tag"
    fi
    echo "  PASS: rejects a nonexistent tag"

    echo "=== release tag checker selftest OK ==="
    exit 0
fi

echo "=== checking the release tag can be the Release body ==="
check_tag "${1:?usage: check-release-tag.sh <tag>}"
