#!/bin/bash
#
# check-unit-drift.sh — compare the systemd units RUNNING on this host
# against the ones tracked in the repo.
#
# `make check-deploy-unit` used to read only the repo copies. It
# therefore passed green from 2026-08-01 to 2026-08-09 while
# /etc/systemd/system/virp-onode.service carried
# `Environment=VIRP_WAZUH_INSECURE=1` — a line the tracked unit had
# deliberately removed, and which the same check asserts must never
# appear there. The assertion was true of the file in git and false of
# the file that boots the daemon, and nothing compared the two.
#
# What this checks:
#   1. every pair in deploy/unit-manifest.txt is byte-identical
#      (comments included — see the manifest for why)
#   2. no virp-* unit or O-Node drop-in exists on the host without
#      being named in the manifest
#
# Differences are forgiven ONLY if every differing line matches a
# pattern in deploy/unit-drift-allowlist.txt, which ships empty.
#
# Reads only. Never writes, never touches systemd state. Needs no root:
# unit files are 0644 and the directories are world-searchable.
#
# Env:
#   VIRP_UNIT_DIR   override /etc/systemd/system (used by the self-test)
#
# Exit: 0 clean or nothing installed, 1 drift or untracked unit.
#
# Copyright (c) 2026 Third Level IT LLC. All rights reserved.

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_DIR="${VIRP_UNIT_DIR:-/etc/systemd/system}"
MANIFEST="$REPO_ROOT/deploy/unit-manifest.txt"
ALLOWLIST="$REPO_ROOT/deploy/unit-drift-allowlist.txt"

# ── self-test ─────────────────────────────────────────────────────────
#
# A drift checker that always passes looks exactly like a clean host,
# which is the failure this whole file exists to prevent — so the
# checker proves BOTH answers against synthetic unit dirs before anyone
# trusts either. Builds fixtures in a temp dir; touches nothing real.
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/virp-onode.service.d"

    # Clean fixture: every manifest pair installed verbatim.
    while read -r tracked installed rest; do
        case "${tracked:-}" in ''|'#'*) continue ;; esac
        [ -n "${installed:-}" ] || continue
        [ -f "$REPO_ROOT/$tracked" ] || continue
        dest="$tmp/${installed#/etc/systemd/system/}"
        mkdir -p "$(dirname "$dest")"
        cp "$REPO_ROOT/$tracked" "$dest"
    done < "$MANIFEST"

    if VIRP_UNIT_DIR="$tmp" "$0" >/dev/null 2>&1; then
        echo "  selftest 1/3 PASS: clean fixture reports clean"
    else
        echo "  selftest 1/3 FAIL: clean fixture reported drift"; exit 1
    fi

    # Drifted fixture: one added line in the daemon unit.
    echo 'Environment=SOMETHING_NEW=1' >> "$tmp/virp-onode.service"
    if VIRP_UNIT_DIR="$tmp" "$0" >/dev/null 2>&1; then
        echo "  selftest 2/3 FAIL: a one-line edit went undetected"; exit 1
    else
        echo "  selftest 2/3 PASS: one added line is detected"
    fi

    # Untracked fixture: a unit nobody named.
    git -C "$REPO_ROOT" show HEAD:deploy/virp-autopilot.timer \
        > "$tmp/virp-rogue.service" 2>/dev/null || \
        echo "[Unit]" > "$tmp/virp-rogue.service"
    if VIRP_UNIT_DIR="$tmp" "$0" >/dev/null 2>&1; then
        echo "  selftest 3/3 FAIL: an untracked unit went undetected"; exit 1
    else
        echo "  selftest 3/3 PASS: an untracked unit is detected"
    fi
    exit 0
fi

fail=0
compared=0
skipped=0

echo "=== checking installed units match tracked units ==="
echo "    tracked:   $REPO_ROOT"
echo "    installed: $UNIT_DIR"

if [ ! -r "$MANIFEST" ]; then
    echo "FAIL: $MANIFEST missing — the checker cannot know what maps to what."
    exit 1
fi

# A host with nothing installed (build box, CI) is not drifted.
if ! ls "$UNIT_DIR"/virp-* >/dev/null 2>&1; then
    echo "  SKIP: no virp-* units installed under $UNIT_DIR"
    exit 0
fi

# ── allowlist ─────────────────────────────────────────────────────────
allow_patterns=()
if [ -r "$ALLOWLIST" ]; then
    while IFS= read -r line; do
        case "$line" in
            ''|'#'*) continue ;;
        esac
        allow_patterns+=("$line")
    done < "$ALLOWLIST"
fi
if [ ${#allow_patterns[@]} -gt 0 ]; then
    echo "    allowlist: ${#allow_patterns[@]} pattern(s) — every one is a line"
    echo "               nobody is checking any more"
fi

line_allowed() {
    local l="$1" p
    [ ${#allow_patterns[@]} -eq 0 ] && return 1
    for p in "${allow_patterns[@]}"; do
        if printf '%s' "$l" | grep -Eq -- "$p"; then return 0; fi
    done
    return 1
}

# ── 1. tracked vs installed ───────────────────────────────────────────
declare -A known_installed=()

while read -r tracked installed rest; do
    case "${tracked:-}" in
        ''|'#'*) continue ;;
    esac
    [ -n "${installed:-}" ] || continue

    # The manifest records real install paths. When VIRP_UNIT_DIR points
    # somewhere else (the self-test), rebase onto it — and key the
    # "is it tracked" map on the SAME rebased path the reverse scan
    # walks, or every fixture file reads as untracked.
    installed="${installed/#\/etc\/systemd\/system/$UNIT_DIR}"
    known_installed["$installed"]=1

    if [ ! -f "$REPO_ROOT/$tracked" ]; then
        echo "FAIL: manifest names $tracked, which is not in the repo"
        fail=1
        continue
    fi

    if [ ! -e "$installed" ]; then
        skipped=$((skipped + 1))
        printf "    not installed: %s\n" "$installed"
        continue
    fi

    compared=$((compared + 1))

    # Bytes are not the whole of "the same unit". A unit file that is
    # group- or world-writable can be edited by anyone who can write it,
    # after this check has passed, and systemd will happily run it.
    perm="$(stat -c '%a %U:%G' "$installed" 2>/dev/null || echo '? ?')"
    mode="${perm%% *}"; owner="${perm##* }"
    if [ "$UNIT_DIR" = "/etc/systemd/system" ]; then
        case "$mode" in
            *[2367])  echo "FAIL: $installed is group/world writable (mode $mode)"; fail=1 ;;
        esac
        if [ "$owner" != "root:root" ]; then
            echo "FAIL: $installed is owned by $owner, expected root:root"
            fail=1
        fi
    fi

    if diff -q "$REPO_ROOT/$tracked" "$installed" >/dev/null 2>&1; then
        printf "    match:  %s\n" "$installed"
        continue
    fi

    # Differing lines only, diff markers stripped.
    mapfile -t difflines < <(diff "$REPO_ROOT/$tracked" "$installed" \
                             | grep -E '^[<>]' | sed -E 's/^[<>] ?//')

    unforgiven=0
    for l in "${difflines[@]}"; do
        line_allowed "$l" || unforgiven=1
    done

    if [ $unforgiven -eq 0 ] && [ ${#difflines[@]} -gt 0 ]; then
        printf "    ALLOWED drift: %s (%d line(s), all allowlisted)\n" \
               "$installed" "${#difflines[@]}"
        continue
    fi

    fail=1
    echo ""
    echo "FAIL: installed unit does not match tracked unit"
    echo "      tracked:   $tracked"
    echo "      installed: $installed"
    echo "      The running configuration is not the reviewed one. Until"
    echo "      these agree, every assertion this repo makes about the"
    echo "      unit is a statement about a file that is not in charge."
    echo ""
    diff -u "$REPO_ROOT/$tracked" "$installed" | sed 's/^/      /'
    echo ""
done < "$MANIFEST"

# ── 2. installed units nobody tracks ──────────────────────────────────
echo ""
echo "=== checking every installed virp-* unit is tracked ==="
for f in "$UNIT_DIR"/virp-* "$UNIT_DIR"/virp-onode.service.d/*; do
    [ -f "$f" ] || continue
    if [ -z "${known_installed[$f]:-}" ]; then
        fail=1
        echo "FAIL: $f is installed but named in no manifest entry."
        echo "      An untracked unit is one nobody reviews, nobody diffs,"
        echo "      and nobody restores after a rebuild. Either add it to"
        echo "      deploy/ and to deploy/unit-manifest.txt, or remove it"
        echo "      from the host."
    fi
done

# ── 3. tracked units nobody put in the manifest ───────────────────────
#
# The reverse scan above catches installed-but-untracked. This catches
# the mirror image: a new deploy/*.service that nobody adds here would
# be compared against nothing and would look fine forever — the same
# shape of blind spot as the source-only check this file replaces.
echo ""
echo "=== checking every tracked unit is named in the manifest ==="
for t in "$REPO_ROOT"/deploy/*.service "$REPO_ROOT"/deploy/*.timer \
         "$REPO_ROOT"/deploy/*.dropin.conf "$REPO_ROOT"/broker/*.service; do
    [ -f "$t" ] || continue
    rel="${t#$REPO_ROOT/}"
    if ! grep -Eq "^[[:space:]]*${rel}[[:space:]]" "$MANIFEST"; then
        fail=1
        echo "FAIL: $rel is tracked but named in no manifest entry —"
        echo "      it would be compared against nothing. Add it to"
        echo "      deploy/unit-manifest.txt with its install path."
    fi
done

echo ""
if [ $fail -eq 0 ]; then
    echo "  PASS: $compared installed unit(s) match tracked ($skipped not installed)"
else
    echo "  FAIL: installed units disagree with the repo (see above)"
fi
exit $fail
