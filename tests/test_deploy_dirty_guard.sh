#!/bin/sh
# The deploy dirty-tree guard must fail CLOSED.
#
# scripts/require-clean-tree.sh replaced four hand-copied guards that
# discarded git's exit status:
#
#     st=$(git status --porcelain 2>/dev/null)
#     if [ -n "$st" ]; then ... exit 1; fi
#
# Empty output meant "clean", so any git that FAILED to answer -- rather
# than answering "clean" -- let the install proceed and let DEPLOYED.md
# claim a commit hash nobody had checked the tree against. The headline
# case is the ordinary one: these targets need root, and `sudo make
# install-prod` against a worktree owned by the invoking user is exactly
# what git refuses as dubious ownership.
#
# Every case here runs the guard through a real `make` recipe with a
# sentinel action after it, so the assertion is "the target failed AND
# did not proceed", not merely "the script exited nonzero".
#
# Reads no production path and writes none; everything happens in a
# throwaway directory.
set -u

here=$(cd "$(dirname "$0")/.." && pwd)
GUARD="$here/scripts/require-clean-tree.sh"

fails=0
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1" >&2; fails=$((fails + 1)); }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM HUP

# Never let the caller's ~/.gitconfig decide the outcome: safe.directory
# must be UNSET for the ownership case to mean anything.
GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_SYSTEM=/dev/null
export GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM

# A sandbox Makefile shaped like the real install targets: guard first,
# then the thing the guard exists to prevent.
make_sandbox_makefile() {
    cat > "$1/Makefile" <<EOF
.PHONY: install-sim
install-sim:
	@$GUARD "refusing to install from a dirty tree"
	@echo installed > \$(SENTINEL)
	@echo "PROCEEDED"
EOF
}

new_repo() {
    _d="$1"
    mkdir -p "$_d"
    git -C "$_d" init -q
    echo one > "$_d/tracked.txt"
    git -C "$_d" add tracked.txt
    git -C "$_d" -c user.name=t -c user.email=t@example.invalid \
        commit -qm "fixture"
    make_sandbox_makefile "$_d"
    # The sandbox Makefile is itself untracked, which would read as a
    # dirty tree. Track it so "clean" is actually clean.
    git -C "$_d" add Makefile
    git -C "$_d" -c user.name=t -c user.email=t@example.invalid \
        commit -qm "sandbox makefile"
}

# run_case <name> <dir> <expect: pass|refuse> [env assignments...]
# Runs `make install-sim` in <dir> and checks BOTH the exit status and
# whether the post-guard action ran.
run_case() {
    _name="$1"; _dir="$2"; _expect="$3"; shift 3
    _sentinel="$_dir/PROCEEDED.marker"
    rm -f "$_sentinel"
    _out="$tmp/out.$$"; _errf="$tmp/err.$$"
    ( cd "$_dir" && env "$@" make --no-print-directory \
        SENTINEL="$_sentinel" install-sim ) >"$_out" 2>"$_errf"
    _rc=$?

    if [ "$_expect" = "pass" ]; then
        if [ "$_rc" -ne 0 ]; then
            fail "$_name: guard refused a clean tree (rc=$_rc)"
            sed 's/^/        /' "$_errf" >&2
            return
        fi
        [ -f "$_sentinel" ] || { fail "$_name: clean tree did not proceed"; return; }
        pass "$_name"
        return
    fi

    if [ "$_rc" -eq 0 ]; then
        fail "$_name: target SUCCEEDED — the guard is fail-open"
        return
    fi
    if [ -f "$_sentinel" ]; then
        fail "$_name: target failed but the install ALREADY RAN"
        return
    fi
    pass "$_name"
}

# Same as run_case but additionally requires the "unable to establish
# repository state" wording, which is what distinguishes a git that
# FAILED from a tree that is merely dirty.
run_state_case() {
    _name="$1"; _dir="$2"; shift 2
    _sentinel="$_dir/PROCEEDED.marker"
    rm -f "$_sentinel"
    _errf="$tmp/err.state.$$"
    _outf="$tmp/out.state.$$"
    ( cd "$_dir" && env "$@" make --no-print-directory \
        SENTINEL="$_sentinel" install-sim ) >"$_outf" 2>"$_errf"
    _rc=$?
    if [ "$_rc" -eq 0 ]; then
        fail "$_name: target SUCCEEDED — the guard is fail-open"; return
    fi
    if [ -f "$_sentinel" ]; then
        fail "$_name: target failed but the install ALREADY RAN"; return
    fi
    if ! grep -q 'unable to establish repository state' "$_errf"; then
        fail "$_name: refused, but not as unestablished repository state"
        sed 's/^/        /' "$_errf" >&2
        return
    fi
    pass "$_name"
}

echo "=== deploy dirty-tree guard: fail-closed regression ==="

# -------------------------------------------------------------------------
# 1. Baseline. A clean tree still deploys, and a dirty one still refuses.
#    Without these the rest could pass with a guard that refuses always.
# -------------------------------------------------------------------------
new_repo "$tmp/clean"
run_case "clean tree proceeds" "$tmp/clean" pass

new_repo "$tmp/dirty"
echo two >> "$tmp/dirty/tracked.txt"
run_case "dirty tree refuses" "$tmp/dirty" refuse

new_repo "$tmp/untracked"
echo new > "$tmp/untracked/stray.txt"
run_case "untracked file refuses" "$tmp/untracked" refuse

# -------------------------------------------------------------------------
# 2. THE CASE THIS EXISTS FOR: a UID git considers unsafe.
#
#    safe.directory unset (forced above), worktree owned by another uid.
#    Creating that needs the privilege to chown, so it runs for real when
#    the suite has it -- including under `sudo make test-deploy-dirty-guard`,
#    which is the same privilege the install targets themselves run with.
#
#    Without it the identical git contract is exercised against a stub
#    that reproduces git 2.43's dubious-ownership failure verbatim: exit
#    128, the fatal text on stderr, NOTHING on stdout. That last part is
#    the whole defect -- the old guard saw an empty $st and called it
#    clean. The unprivileged tier proves the guard's response to that
#    contract; the privileged tier proves git really produces it.
# -------------------------------------------------------------------------
ownership_ran=0

if [ "$(id -u)" -eq 0 ]; then
    new_repo "$tmp/owned"
    chown -R 65534:65534 "$tmp/owned"
    # Root is exempted for directories owned by root, and by SUDO_UID
    # when set. 65534 is neither, so git refuses.
    run_state_case "differently-owned worktree refuses (real, as root)" \
        "$tmp/owned" SUDO_UID= SUDO_GID=
    ownership_ran=1
elif sudo -n true 2>/dev/null; then
    new_repo "$tmp/owned"
    sudo -n chown -R 65534:65534 "$tmp/owned"
    _sent="$tmp/owned/PROCEEDED.marker"
    rm -f "$_sent"
    ( cd "$tmp/owned" && sudo -n env -u SUDO_UID -u SUDO_GID \
        GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
        make --no-print-directory SENTINEL="$_sent" install-sim ) \
        >"$tmp/o.out" 2>"$tmp/o.err"
    _rc=$?
    if [ "$_rc" -eq 0 ]; then
        fail "differently-owned worktree (real, via sudo): target SUCCEEDED"
    elif [ -f "$_sent" ]; then
        fail "differently-owned worktree (real, via sudo): install ALREADY RAN"
    elif ! grep -q 'unable to establish repository state' "$tmp/o.err"; then
        fail "differently-owned worktree (real, via sudo): wrong refusal"
        sed 's/^/        /' "$tmp/o.err" >&2
    else
        pass "differently-owned worktree refuses (real, via sudo)"
    fi
    sudo -n rm -rf "$tmp/owned" 2>/dev/null || true
    ownership_ran=1
fi

if [ "$ownership_ran" -eq 0 ]; then
    echo "  NOTE: cannot chown a worktree to another uid unprivileged —"
    echo "        the real-ownership tier is SKIPPED here. Run"
    echo "        \`sudo make test-deploy-dirty-guard\` to exercise it."
fi

# Stub tier: git's dubious-ownership contract, always run.
new_repo "$tmp/dubious"
mkdir -p "$tmp/stubbin"
cat > "$tmp/stubbin/git" <<'STUB'
#!/bin/sh
# git 2.43 on a worktree owned by another uid with no safe.directory
# exception. Note what does NOT happen: nothing is written to stdout.
cat >&2 <<EOF
fatal: detected dubious ownership in repository at '$PWD'
To add an exception for this directory, call:

	git config --global --add safe.directory $PWD
EOF
exit 128
STUB
chmod +x "$tmp/stubbin/git"
run_state_case "dubious ownership (git contract) refuses" "$tmp/dubious" \
    PATH="$tmp/stubbin:$PATH"

# -------------------------------------------------------------------------
# 3. The other two ways git declines to answer.
# -------------------------------------------------------------------------
mkdir -p "$tmp/norepo"
make_sandbox_makefile "$tmp/norepo"
run_state_case "not a repository refuses" "$tmp/norepo"

# git absent from PATH. The guard needs mktemp and rm and nothing else,
# so a PATH holding exactly those proves it is git's absence being
# caught rather than the script falling over.
new_repo "$tmp/nogit"
mkdir -p "$tmp/minbin"
for t in mktemp rm; do
    p=$(command -v "$t") && ln -sf "$p" "$tmp/minbin/$t"
done
# `make` itself has to be reachable to run the recipe at all.
mp=$(command -v make) && ln -sf "$mp" "$tmp/minbin/make"
ln -sf "$(command -v echo 2>/dev/null || echo /bin/echo)" "$tmp/minbin/echo" 2>/dev/null || true
run_state_case "git missing from PATH refuses" "$tmp/nogit" PATH="$tmp/minbin"

# -------------------------------------------------------------------------
# 4. stdout stays empty. deploy-record pipes its own stdout into
#    DEPLOYED.md; a guard that chattered there would corrupt the record
#    it protects.
# -------------------------------------------------------------------------
out=$("$GUARD" --tree "$tmp/clean" "quiet check" 2>/dev/null)
if [ -n "$out" ]; then
    fail "guard wrote to stdout on success: $out"
else
    pass "silent on stdout when the tree is clean"
fi
out=$("$GUARD" --tree "$tmp/norepo" "quiet check" 2>/dev/null)
if [ -n "$out" ]; then
    fail "guard wrote to stdout on refusal: $out"
else
    pass "silent on stdout when it refuses"
fi

# -------------------------------------------------------------------------
# 5. The real Makefile uses the helper everywhere and nowhere keeps a
#    private copy. Four hand-copied guards drifting apart is how this
#    defect survived; this is the lock that stops a fifth appearing.
# -------------------------------------------------------------------------
mk="$here/Makefile"
if [ ! -f "$mk" ]; then
    fail "cannot read $mk — the Makefile assertions below prove nothing"
elif grep -n 'git status --porcelain' "$mk" | grep -q '2>/dev/null'; then
    fail "Makefile still has a fail-open 'git status --porcelain 2>/dev/null' guard"
    grep -n 'git status --porcelain' "$mk" | grep '2>/dev/null' | sed 's/^/        /' >&2
else
    pass "no fail-open porcelain guard left in the Makefile"
fi

for t in install-prod deploy-record install-units install-devices-template; do
    body=$(awk -v t="^$t:" '
        $0 ~ t {inrule=1; next}
        inrule && /^[^\t#]/ && NF {exit}
        inrule {print}
    ' "$mk")
    if printf '%s\n' "$body" | grep -q 'require-clean-tree.sh'; then
        pass "$t calls the shared guard"
    else
        fail "$t does not call scripts/require-clean-tree.sh"
    fi
done

echo
if [ "$fails" -ne 0 ]; then
    echo "=== deploy dirty-tree guard: $fails FAILED ==="
    exit 1
fi
echo "=== deploy dirty-tree guard: all checks passed ==="
