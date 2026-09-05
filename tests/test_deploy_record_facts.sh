#!/bin/sh
# Every line of the deploy record is a claim, so every line must be
# established or the target must fail.
#
# `deploy-record` generates the DEPLOYED.md stanza that answers "what is
# running?". It used to interpolate each fact straight into an echo:
#
#     @echo "- **Commit**: \`$(git rev-parse HEAD)\`"
#     @echo "- **sha256**: \`$(sha256sum $(VIRP_INSTALL_BIN) | awk '{print $1}')\`"
#
# A command substitution that fails expands to nothing, so a failure
# printed `- **Commit**: ``' or an empty hash and exited 0 -- a record
# with a hole in it, in the file that is supposed to be authoritative.
# The sha256 lines were the worse half: the pipe into awk discards
# sha256sum's exit status outright, and only the daemon binary had a
# `test -f` in front of it.
#
# Each case runs the REAL deploy-record recipe against a sandbox
# install directory (VIRP_INSTALL_DIR is ?=, so it overrides) inside a
# throwaway git repo holding a copy of the Makefile and scripts/.
# Reads no production path and writes none.
set -u

here=$(cd "$(dirname "$0")/.." && pwd)

fails=0
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1" >&2; fails=$((fails + 1)); }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM HUP

GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_SYSTEM=/dev/null
export GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM

# A committed sandbox tree: the real Makefile and the real scripts/, so
# the recipe under test is the shipped one.
repo="$tmp/repo"
mkdir -p "$repo"
cp "$here/Makefile" "$repo/Makefile"
cp -r "$here/scripts" "$repo/scripts"
git -C "$repo" init -q
git -C "$repo" add -A
git -C "$repo" -c user.name=t -c user.email=t@example.invalid \
    commit -qm "sandbox tree"

# The install directory the record is supposed to describe.
inst="$tmp/inst"
mkdir -p "$inst/autopilot"
make_install() {
    rm -rf "$inst"
    mkdir -p "$inst/autopilot"
    for f in virp-onode-prod virp-tool virp render-devices.sh \
             config-backup-access.sh evidence-access.sh netclaw-access.sh; do
        echo "$f contents" > "$inst/$f"
    done
    for f in virp_autopilot.py virp_config_backup.py virp_evidence.py; do
        echo "$f contents" > "$inst/autopilot/$f"
    done
}

# record <outfile> <errfile> -> exit status of deploy-record
record() {
    ( cd "$repo" && make --no-print-directory \
        VIRP_INSTALL_DIR="$inst" deploy-record ) >"$1" 2>"$2"
}

echo "=== deploy record: every fact established or the target fails ==="

# -------------------------------------------------------------------------
# 1. Baseline: a complete install produces a complete stanza. Without
#    this the rest could pass with a target that always refuses.
# -------------------------------------------------------------------------
make_install
if record "$tmp/ok.out" "$tmp/ok.err"; then
    if grep -q '``' "$tmp/ok.out"; then
        fail "complete install still emitted an empty backticked field"
        grep -n '``' "$tmp/ok.out" | sed 's/^/        /' >&2
    elif [ "$(grep -c '^- \*\*sha256' "$tmp/ok.out")" -ne 9 ]; then
        fail "expected 9 sha256 lines, got $(grep -c '^- \*\*sha256' "$tmp/ok.out")"
        sed 's/^/        /' "$tmp/ok.out" >&2
    elif ! grep -qE '^- \*\*Commit\*\*: `[0-9a-f]{40}`$' "$tmp/ok.out"; then
        fail "commit line is not a full 40-hex hash"
        sed 's/^/        /' "$tmp/ok.out" >&2
    else
        pass "complete install produces a complete stanza"
    fi
else
    fail "deploy-record refused a complete install"
    sed 's/^/        /' "$tmp/ok.err" >&2
fi

# -------------------------------------------------------------------------
# 2. A missing artifact must FAIL, not record an empty hash. Every class
#    is exercised: only the daemon binary ever had a test -f.
# -------------------------------------------------------------------------
check_missing() {
    _label="$1"; _path="$2"
    make_install
    rm -f "$_path"
    if record "$tmp/m.out" "$tmp/m.err"; then
        fail "$_label missing: deploy-record SUCCEEDED"
        sed 's/^/        /' "$tmp/m.out" >&2
        return
    fi
    if grep -q '``' "$tmp/m.out"; then
        fail "$_label missing: recorded an empty field before failing"
        grep -n '``' "$tmp/m.out" | sed 's/^/        /' >&2
        return
    fi
    pass "$_label missing refuses, with no empty field recorded"
}

check_missing "daemon binary"   "$inst/virp-onode-prod"
check_missing "virp-tool"       "$inst/virp-tool"
check_missing "a helper script" "$inst/render-devices.sh"
check_missing "an autopilot module" "$inst/autopilot/virp_evidence.py"

# -------------------------------------------------------------------------
# 3. An unreadable artifact: it exists, so `test -f` passes, and
#    sha256sum is what fails. This is the case the awk pipe hid.
# -------------------------------------------------------------------------
if [ "$(id -u)" -eq 0 ]; then
    echo "  NOTE: running as root — chmod 000 does not deny root, so the"
    echo "        unreadable-artifact case is SKIPPED."
else
    make_install
    chmod 000 "$inst/virp-tool"
    if record "$tmp/u.out" "$tmp/u.err"; then
        fail "unreadable virp-tool: deploy-record SUCCEEDED"
        sed 's/^/        /' "$tmp/u.out" >&2
    elif grep -q '``' "$tmp/u.out"; then
        fail "unreadable virp-tool: recorded an empty hash before failing"
        grep -n '``' "$tmp/u.out" | sed 's/^/        /' >&2
    else
        pass "unreadable artifact refuses, with no empty hash recorded"
    fi
    chmod 644 "$inst/virp-tool"
fi

# -------------------------------------------------------------------------
# 4. `git rev-parse HEAD` with no commits. The dirty-tree guard passes
#    here -- an empty repo whose files are all ignored is genuinely
#    clean and git genuinely exits 0 -- so this reaches the commit line
#    with an unborn HEAD, which is precisely where the old recipe
#    printed `- **Commit**: ``'.
# -------------------------------------------------------------------------
unborn="$tmp/unborn"
mkdir -p "$unborn"
cp "$here/Makefile" "$unborn/Makefile"
cp -r "$here/scripts" "$unborn/scripts"
git -C "$unborn" init -q
printf '*\n' > "$unborn/.gitignore"

guard_out=$( cd "$unborn" && scripts/require-clean-tree.sh "precondition" 2>&1 )
guard_rc=$?
if [ "$guard_rc" -ne 0 ]; then
    fail "precondition: the unborn-HEAD repo does not read as clean (rc=$guard_rc)"
    printf '%s\n' "$guard_out" | sed 's/^/        /' >&2
else
    make_install
    ( cd "$unborn" && make --no-print-directory \
        VIRP_INSTALL_DIR="$inst" deploy-record ) >"$tmp/h.out" 2>"$tmp/h.err"
    rc=$?
    if [ "$rc" -eq 0 ]; then
        fail "unborn HEAD: deploy-record SUCCEEDED"
        sed 's/^/        /' "$tmp/h.out" >&2
    elif grep -q '``' "$tmp/h.out"; then
        fail "unborn HEAD: recorded an empty commit before failing"
        grep -n '``' "$tmp/h.out" | sed 's/^/        /' >&2
    elif ! grep -q 'git rev-parse HEAD failed' "$tmp/h.err"; then
        fail "unborn HEAD: refused, but not as a rev-parse failure"
        sed 's/^/        /' "$tmp/h.err" >&2
    else
        pass "unborn HEAD refuses at the commit line, past the clean-tree guard"
    fi
fi

# -------------------------------------------------------------------------
# 5. The shape lock: no fact in the recipe may be interpolated straight
#    into an echo again, and the sha256 pipe into awk must stay gone.
# -------------------------------------------------------------------------
body=$(awk '
    /^deploy-record:/ {inrule=1; next}
    inrule && /^[^\t#]/ && NF {exit}
    inrule {print}
' "$here/Makefile")

if [ -z "$body" ]; then
    fail "could not read the deploy-record recipe out of the Makefile"
else
    if printf '%s\n' "$body" | grep -q 'sha256sum.*|.*awk'; then
        fail "deploy-record still pipes sha256sum into awk (exit status discarded)"
    else
        pass "no sha256sum|awk pipe left in deploy-record"
    fi
    if printf '%s\n' "$body" | grep -qE 'echo "[^"]*\$\$\(git '; then
        fail "deploy-record still interpolates a git command straight into an echo"
        printf '%s\n' "$body" | grep -nE 'echo "[^"]*\$\$\(git ' | sed 's/^/        /' >&2
    else
        pass "no git substitution interpolated straight into an echo"
    fi
fi

echo
if [ "$fails" -ne 0 ]; then
    echo "=== deploy record: $fails FAILED ==="
    exit 1
fi
echo "=== deploy record: all checks passed ==="
