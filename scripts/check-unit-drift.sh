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
# VIRP_DRIFT_REPO_ROOT points the SOURCE-side checks at a synthetic tree.
# It exists for --selftest alone (the exec-coverage check has to be shown
# failing against a unit that names an uncovered script, and the real
# tree must not be edited to stage that).
REPO_ROOT="${VIRP_DRIFT_REPO_ROOT:-$REPO_ROOT}"
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
# Manifest install paths are absolute under /etc. VIRP_ETC_ROOT prefixes
# them so the self-test can build a fixture tree without ever reading
# the real /etc — the manifest now also covers a file outside
# /etc/systemd/system (the netclaw nft ruleset), so rebasing has to be
# general rather than a unit-directory swap.
ETC_ROOT="${VIRP_ETC_ROOT:-}"
UNIT_DIR="$ETC_ROOT/etc/systemd/system"
MANIFEST="$REPO_ROOT/deploy/unit-manifest.txt"
ALLOWLIST="$REPO_ROOT/deploy/unit-drift-allowlist.txt"
EXEC_EXEMPT="$REPO_ROOT/deploy/unit-exec-exempt.txt"

# ── self-test ─────────────────────────────────────────────────────────
#
# A drift checker that always passes looks exactly like a clean host,
# which is the failure this whole file exists to prevent — so the
# checker proves BOTH answers against synthetic unit dirs before anyone
# trusts either. Builds fixtures in a temp dir; touches nothing real.
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT

    # Clean fixture: every manifest pair installed verbatim, at the same
    # absolute path rebased under $tmp.
    while read -r tracked installed rest; do
        case "${tracked:-}" in ''|'#'*) continue ;; esac
        [ -n "${installed:-}" ] || continue
        [ -f "$REPO_ROOT/$tracked" ] || continue
        dest="$tmp$installed"
        mkdir -p "$(dirname "$dest")"
        cp "$REPO_ROOT/$tracked" "$dest"
    done < "$MANIFEST"

    if VIRP_ETC_ROOT="$tmp" "$SELF" >/dev/null 2>&1; then
        echo "  selftest 1/8 PASS: clean fixture reports clean"
    else
        echo "  selftest 1/8 FAIL: clean fixture reported drift"
        VIRP_ETC_ROOT="$tmp" "$SELF" | sed 's/^/      /'
        exit 1
    fi

    # Drifted fixture: one added line in the daemon unit.
    echo 'Environment=SOMETHING_NEW=1' \
        >> "$tmp/etc/systemd/system/virp-onode.service"
    if VIRP_ETC_ROOT="$tmp" "$SELF" >/dev/null 2>&1; then
        echo "  selftest 2/8 FAIL: a one-line edit went undetected"; exit 1
    else
        echo "  selftest 2/8 PASS: one added line is detected"
    fi

    # Drifted fixture, NON-unit file: the manifest also covers a plain
    # config file (the nft ruleset), so prove that side too.
    cp "$REPO_ROOT/deploy/virp-onode.service" \
       "$tmp/etc/systemd/system/virp-onode.service"
    if [ -f "$tmp/etc/nftables-virp-netclaw-egress.nft" ]; then
        echo '# stray line' >> "$tmp/etc/nftables-virp-netclaw-egress.nft"
        if VIRP_ETC_ROOT="$tmp" "$SELF" >/dev/null 2>&1; then
            echo "  selftest 3/8 FAIL: non-unit file drift went undetected"
            exit 1
        else
            echo "  selftest 3/8 PASS: non-unit file drift is detected"
        fi
        git -C "$REPO_ROOT" show HEAD:deploy/nftables-virp-netclaw-egress.nft \
            > "$tmp/etc/nftables-virp-netclaw-egress.nft" 2>/dev/null || \
            cp "$REPO_ROOT/deploy/nftables-virp-netclaw-egress.nft" \
               "$tmp/etc/nftables-virp-netclaw-egress.nft"
    else
        echo "  selftest 3/8 SKIP: no non-unit file in the manifest"
    fi

    # Untracked fixture: a unit nobody named.
    echo "[Unit]" > "$tmp/etc/systemd/system/virp-rogue.service"
    if VIRP_ETC_ROOT="$tmp" "$SELF" >/dev/null 2>&1; then
        echo "  selftest 4/8 FAIL: an untracked unit went undetected"; exit 1
    else
        echo "  selftest 4/8 PASS: an untracked unit is detected"
    fi
    rm -f "$tmp/etc/systemd/system/virp-rogue.service"

    # Untracked DROP-IN under a NON-onode unit's .d directory. The reverse
    # scan used to enumerate only virp-onode.service.d/*, so a rogue
    # drop-in on any other virp unit (e.g. one re-adding VIRP_WAZUH_INSECURE
    # on the autopilot units that read the chain) was invisible. This is
    # the installed-side twin of the canonical-unit-only Wazuh check.
    mkdir -p "$tmp/etc/systemd/system/virp-autopilot.service.d"
    echo 'Environment=VIRP_WAZUH_INSECURE=1' \
        > "$tmp/etc/systemd/system/virp-autopilot.service.d/99-rogue.conf"
    if VIRP_ETC_ROOT="$tmp" "$SELF" >/dev/null 2>&1; then
        echo "  selftest 5/8 FAIL: a rogue drop-in outside onode.service.d went undetected"
        exit 1
    else
        echo "  selftest 5/8 PASS: an untracked drop-in in any virp unit's .d is detected"
    fi
    rm -rf "$tmp/etc/systemd/system/virp-autopilot.service.d"

    # A SCRIPT a unit executes, edited on the host. The unit file is
    # byte-identical and every check above passes; what changed is the
    # thing the unit runs. This is the 2026-08-10 crash-loop shape: the
    # repo copy of render-devices.sh was edited, the daemon ran the
    # installed copy, and nothing compared the two.
    script="$tmp/usr/local/lib/virp/render-devices.sh"
    if [ -f "$script" ]; then
        echo '# edited on the host' >> "$script"
        if VIRP_ETC_ROOT="$tmp" "$SELF" >/dev/null 2>&1; then
            echo "  selftest 6/8 FAIL: an edited installed script went undetected"
            exit 1
        else
            echo "  selftest 6/8 PASS: an edited installed script is detected"
        fi
        cp "$REPO_ROOT/deploy/render-devices.sh" "$script"
    else
        echo "  selftest 6/8 FAIL: render-devices.sh is not in the manifest —"
        echo "                     the script the daemon unit runs is uncovered"
        exit 1
    fi

    # SOURCE side: a tracked unit that executes a path nothing covers.
    # Built in a synthetic repo so the real tree is never edited.
    fake="$tmp/fake-repo"
    mkdir -p "$fake/deploy" "$fake/broker"
    cat > "$fake/deploy/virp-fake.service" <<'UNIT'
[Service]
ExecStartPre=+/usr/local/lib/virp/covered.sh --flag
ExecStart=/usr/bin/python3 /usr/local/lib/virp/uncovered.py run
UNIT
    echo '#!/bin/sh' > "$fake/deploy/covered.sh"
    {
        echo "deploy/virp-fake.service /etc/systemd/system/virp-fake.service"
        echo "deploy/covered.sh /usr/local/lib/virp/covered.sh"
    } > "$fake/deploy/unit-manifest.txt"
    if VIRP_DRIFT_REPO_ROOT="$fake" VIRP_ETC_ROOT="$tmp/none" "$SELF" >/dev/null 2>&1; then
        echo "  selftest 7/8 FAIL: a unit executing an uncovered script went undetected"
        exit 1
    else
        echo "  selftest 7/8 PASS: a unit executing an uncovered script is detected"
    fi
    # ...and the same tree is clean once the script is covered, so 7/8
    # failed for the reason it claims and not for some other one.
    echo '#!/usr/bin/python3' > "$fake/deploy/uncovered.py"
    echo "deploy/uncovered.py /usr/local/lib/virp/uncovered.py" \
        >> "$fake/deploy/unit-manifest.txt"
    if VIRP_DRIFT_REPO_ROOT="$fake" VIRP_ETC_ROOT="$tmp/none" "$SELF" >/dev/null 2>&1; then
        echo "  selftest 8/8 PASS: covering the script clears the failure"
    else
        echo "  selftest 8/8 FAIL: a fully covered unit still fails"
        VIRP_DRIFT_REPO_ROOT="$fake" VIRP_ETC_ROOT="$tmp/none" "$SELF" | sed 's/^/      /'
        exit 1
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

# ══ SOURCE-SIDE CHECKS ════════════════════════════════════════════════
#
# These read only the repo, so they run on EVERY host, including a build
# box or CI with nothing installed. Until 2026-11-13 the first of them
# sat below the "no virp-* units installed -> SKIP, exit 0" line, so on
# exactly the hosts where a new unit is written and reviewed it never
# ran: a guard that only executes on the deployed node cannot stop the
# change that has not been deployed yet.

# ── S1. tracked units nobody put in the manifest ──────────────────────
#
# The reverse scan below catches installed-but-untracked. This catches
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

# ── S2. every script a unit executes is covered ───────────────────────
#
# A unit file is a pointer. Comparing the pointer byte-for-byte while
# never comparing what it points AT leaves the script free to drift:
# on 2026-08-10 the repo copy of render-devices.sh was edited, the
# daemon kept running the installed copy, and the restart crash-looped
# with every unit check green. So: every absolute path under the install
# root (or the deploy tree) that appears in an Exec* line of a tracked
# unit must be an INSTALLED path in the manifest, which makes section 1
# compare its bytes, owner and mode, or be named in
# deploy/unit-exec-exempt.txt with the reason and the check that covers
# it instead. Naming neither is a failure.
echo ""
echo "=== checking every script a tracked unit executes is covered ==="
declare -A manifest_installed=()
declare -a manifest_units=()
while read -r tracked installed rest; do
    case "${tracked:-}" in ''|'#'*) continue ;; esac
    [ -n "${installed:-}" ] || continue
    manifest_installed["$installed"]=1
    case "$tracked" in
        *.service|*.conf) manifest_units+=("$tracked") ;;
    esac
done < "$MANIFEST"

declare -A exec_exempt=()
if [ -r "$EXEC_EXEMPT" ]; then
    while read -r path rest; do
        case "${path:-}" in ''|'#'*) continue ;; esac
        exec_exempt["$path"]=1
    done < "$EXEC_EXEMPT"
fi

exec_paths=0
uncovered=0
for rel in "${manifest_units[@]}"; do
    [ -f "$REPO_ROOT/$rel" ] || continue
    while IFS= read -r line; do
        # value after the first '=', minus systemd's exec prefixes
        val="${line#*=}"
        for tok in $val; do
            tok="${tok#"${tok%%[!-+!@:]*}"}"
            case "$tok" in
                /usr/local/lib/virp/*|/opt/virp/*) ;;
                *) continue ;;
            esac
            exec_paths=$((exec_paths + 1))
            if [ -n "${manifest_installed[$tok]:-}" ]; then continue; fi
            if [ -n "${exec_exempt[$tok]:-}" ]; then continue; fi
            fail=1
            uncovered=$((uncovered + 1))
            echo "FAIL: $rel executes $tok — covered by nothing"
        done
    done < <(grep -E '^Exec(Start|StartPre|StartPost|Stop|StopPost|Reload)=' \
                 "$REPO_ROOT/$rel")
done
if [ $uncovered -gt 0 ]; then
    echo "      The unit file is compared byte-for-byte and the thing it"
    echo "      runs is compared to nothing. For each path above, add"
    echo "      '<tracked-path> <that path>' to deploy/unit-manifest.txt, or"
    echo "      name it in deploy/unit-exec-exempt.txt with the check that"
    echo "      covers it instead."
fi
echo "    $exec_paths executed path reference(s) examined, $uncovered uncovered"

# A host with nothing installed (build box, CI) is not drifted — but the
# source-side verdict above still stands.
if ! ls "$UNIT_DIR"/virp-* >/dev/null 2>&1; then
    echo ""
    echo "  SKIP: no virp-* units installed under $UNIT_DIR"
    if [ $fail -ne 0 ]; then
        echo "  FAIL: source-side checks failed (see above)"
    fi
    exit $fail
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

    # Rebase onto VIRP_ETC_ROOT (empty in production) and key the
    # "is it tracked" map on the SAME rebased path the reverse scan
    # walks, or every fixture file reads as untracked.
    installed="$ETC_ROOT$installed"
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
    if [ -z "$ETC_ROOT" ]; then
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
for f in "$UNIT_DIR"/virp-* "$UNIT_DIR"/virp-*.service.d/*; do
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

echo ""
if [ $fail -eq 0 ]; then
    echo "  PASS: $compared installed unit(s) match tracked ($skipped not installed)"
else
    echo "  FAIL: installed units disagree with the repo (see above)"
fi
exit $fail
