#!/bin/bash
# test-witness-noshell.sh — the witness executes ARGV, never a shell.
#
# Proves the three claims of the 2026-08-09 eval removal:
#
#   1. EQUIVALENCE — for every grammar-conformant command (the only kind
#      the VIRP driver can deliver: the separator gate refuses the rest
#      upstream, pinned in tests/test_driver_linux_gate.c), the witness
#      produces BYTE-IDENTICAL stdout, stderr and exit status to the old
#      eval implementation. The eval reference is computed live with
#      `sh -c` — which is exactly what eval did — not from a recording.
#
#   2. NO SHELL — a command carrying shell metacharacters that somehow
#      reached the witness (SHADOW mode, a classifier bug, a direct ssh)
#      gets NO shell interpretation: `;`, `|`, `$( )`, backticks, `>`,
#      `$VAR` and glob characters are literal argv bytes. The canary for
#      each vector is a file that eval WOULD have created; the test
#      asserts it does not exist afterwards.
#
#   3. FIDELITY — exit status passes through unchanged, including
#      non-zero.
#
# Runs anywhere with /bin/sh + a POSIX toolbox; no root, no sshd, no
# container needed. vtysh is stubbed on PATH: the stub prints one line
# per argv element, so the parse itself is asserted, not inferred.

set -u

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WITNESS="$SELF_DIR/virp-witness"

TMP=$(mktemp -d) || exit 1
trap 'rm -rf "$TMP"' EXIT

STUB="$TMP/bin"
mkdir -p "$STUB"

# vtysh stub: one line per argv element, so quoting mistakes are visible.
cat > "$STUB/vtysh" <<'EOF'
#!/bin/sh
for a in "$@"; do printf 'ARG:%s\n' "$a"; done
EOF
chmod +x "$STUB/vtysh"

# failing stub: proves rc passthrough.
cat > "$STUB/failcmd" <<'EOF'
#!/bin/sh
echo "about to fail"
exit 7
EOF
chmod +x "$STUB/failcmd"

run_witness() {
    # $1 = command string. Witness output on stdout, rc in $?.
    SSH_ORIGINAL_COMMAND="$1" PATH="$STUB:$PATH" sh "$WITNESS"
}

eval_reference() {
    # What the old implementation did: the command bytes handed to a shell.
    PATH="$STUB:$PATH" sh -c "$1"
}

tests_run=0; tests_passed=0
TEST() { tests_run=$((tests_run + 1)); printf '  [%d] %s ... ' "$tests_run" "$1"; }
PASS() { tests_passed=$((tests_passed + 1)); echo "PASS"; }
FAIL() { echo "FAIL: $*"; exit 1; }

echo "=== Equivalence — conformant commands byte-identical to eval ==="

for cmd in \
    'vtysh -c "show ip ospf neighbor"' \
    'vtysh -c "show version"' \
    'vtysh  -c  "show  running-config"' \
    '  vtysh -c "show ip route 10.0.0.0/8"  ' \
    'failcmd' \
    'echo plain words no quotes'
do
    TEST "witness == eval for: $cmd"
    got=$(run_witness "$cmd" 2>&1); got_rc=$?
    want=$(eval_reference "$cmd" 2>&1); want_rc=$?
    [ "$got" = "$want" ] || FAIL "output differs: got '$got' want '$want'"
    [ "$got_rc" = "$want_rc" ] || FAIL "rc differs: got $got_rc want $want_rc"
    PASS
done

TEST "vtysh parse is the 2-element argv [-c, <arg>] exactly"
got=$(run_witness 'vtysh -c "show ip ospf neighbor"')
want=$(printf 'ARG:-c\nARG:show ip ospf neighbor')
[ "$got" = "$want" ] || FAIL "got '$got'"
PASS

TEST "whitespace runs collapse between fixed tokens, arg preserved"
got=$(run_witness 'vtysh   -c   "show  ip  ospf"')
want=$(printf 'ARG:-c\nARG:show  ip  ospf')
[ "$got" = "$want" ] || FAIL "got '$got'"
PASS

TEST "non-zero exit status passes through (rc=7)"
run_witness 'failcmd' > /dev/null 2>&1
[ $? -eq 7 ] || FAIL "rc not 7"
PASS

echo ""
echo "=== No shell — metacharacters are literal argv bytes ==="

TEST "semicolon does not chain: echo hi; touch canary"
rm -f "$TMP/canary"
out=$(run_witness "echo hi; touch $TMP/canary")
[ ! -e "$TMP/canary" ] || FAIL "canary created — shell ran the second command"
[ "$out" = "hi; touch $TMP/canary" ] || FAIL "got '$out'"
PASS

TEST "pipe does not pipe: echo hi | tee canary"
rm -f "$TMP/canary"
out=$(run_witness "echo hi | tee $TMP/canary")
[ ! -e "$TMP/canary" ] || FAIL "canary created — shell honoured the pipe"
[ "$out" = "hi | tee $TMP/canary" ] || FAIL "got '$out'"
PASS

TEST "command substitution is literal: echo \$(touch canary)"
rm -f "$TMP/canary"
out=$(run_witness "echo \$(touch $TMP/canary)")
[ ! -e "$TMP/canary" ] || FAIL "canary created — \$() was executed"
PASS

TEST "backticks are literal"
rm -f "$TMP/canary"
out=$(run_witness "echo \`touch $TMP/canary\`")
[ ! -e "$TMP/canary" ] || FAIL "canary created — backticks were executed"
PASS

TEST "redirection is literal: echo hi > canary"
rm -f "$TMP/canary"
out=$(run_witness "echo hi > $TMP/canary")
[ ! -e "$TMP/canary" ] || FAIL "canary created — '>' was honoured"
[ "$out" = "hi > $TMP/canary" ] || FAIL "got '$out'"
PASS

TEST "&& does not chain"
rm -f "$TMP/canary"
out=$(run_witness "true && touch $TMP/canary")
[ ! -e "$TMP/canary" ] || FAIL "canary created — '&&' chained"
PASS

TEST "variable expansion is inert: echo \$HOME"
out=$(run_witness 'echo $HOME')
[ "$out" = '$HOME' ] || FAIL "got '$out' — \$HOME was expanded"
PASS

TEST "glob is inert: echo *"
out=$(run_witness 'echo *')
[ "$out" = '*' ] || FAIL "got '$out' — glob expanded"
PASS

TEST "metacharacters inside the vtysh arg stay one literal argument"
out=$(run_witness 'vtysh -c "show version; reload"')
want=$(printf 'ARG:-c\nARG:show version; reload')
[ "$out" = "$want" ] || FAIL "got '$out'"
PASS

TEST "embedded newline never yields a second command"
rm -f "$TMP/canary"
out=$(run_witness "echo hi
touch $TMP/canary")
[ ! -e "$TMP/canary" ] || FAIL "canary created — newline chained"
PASS

echo ""
echo "=== Results: $tests_passed/$tests_run passed ==="
[ "$tests_passed" -eq "$tests_run" ]
