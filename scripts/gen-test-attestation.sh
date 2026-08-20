#!/bin/bash
#
# gen-test-attestation.sh — run the named test commands and write a
# machine-readable attestation pinning EXACTLY which tree they ran against.
#
# The hole this closes: a hand-written test report can (and did) describe a
# nearby tree rather than the tree a release archive actually contains — the
# 2026-08-18 full-suite summary tested f200e621 while the release archive was
# cut from cd351af6. "Roughly this code passed" is not evidence for "exactly
# this bundle passed". This script removes the human transcription step:
#
#   - it records `git rev-parse HEAD` and `HEAD^{tree}` of the working tree
#     the commands ACTUALLY ran in, at the moment they ran;
#   - it refuses to attest a dirty tree (uncommitted changes mean the tested
#     code is not any commit), unless --allow-dirty, which stamps
#     "dirty": true so verifiers reject the attestation anyway;
#   - it records the real exit code of every command. A failure is written
#     down as a failure — the JSON is still produced, with "result": "fail",
#     and the script exits nonzero.
#
# Usage:
#   gen-test-attestation.sh --out FILE [--allow-dirty] CMD [CMD ...]
#       Each CMD is one shell command string, run with `bash -c`.
#   gen-test-attestation.sh --selftest
#
# Exit status: 0 iff the tree was attestable and every command exited 0.
#
# Copyright (c) 2026 Third Level IT LLC — Apache 2.0

set -u

SCHEMA="virp-test-attestation/v1"

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

write_json() {
    # write_json OUT COMMIT TREE DESCRIBE DIRTY RESULT CMD EXIT SECS [CMD EXIT SECS ...]
    # All JSON encoding happens in python3 so no shell-quoting bug can
    # corrupt the record.
    python3 - "$@" <<'PYEOF'
import json, platform, subprocess, sys, os, datetime

out, commit, tree, describe, dirty, result, *rest = sys.argv[1:]
assert len(rest) % 3 == 0, "command records must be (cmd, exit, seconds) triples"

def first_line(argv):
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=10).stdout.splitlines()[0]
    except Exception:
        return "unknown"

commands = [
    {"argv": rest[i], "exit": int(rest[i + 1]), "seconds": int(rest[i + 2])}
    for i in range(0, len(rest), 3)
]

doc = {
    "schema": "virp-test-attestation/v1",
    "commit": commit,
    "tree": tree,
    "describe": describe,
    "dirty": dirty == "true",
    "result": result,
    "timestamp_utc": datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ"),
    "host": platform.node(),
    "ci": {
        "github_actions": os.environ.get("GITHUB_ACTIONS") == "true",
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "workflow": os.environ.get("GITHUB_WORKFLOW"),
    },
    "toolchain": {
        "cc": first_line(["gcc", "--version"]),
        "python": first_line(["python3", "--version"]),
    },
    "commands": commands,
}

with open(out, "w") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
PYEOF
}

selftest() {
    local self tmp rc
    self="$(readlink -f "$0")"
    tmp="$(mktemp -d)" || exit 1
    # shellcheck disable=SC2064  # expand now: $tmp is function-local
    trap "rm -rf '$tmp'" EXIT

    git -C "$tmp" init -q -b selftest
    git -C "$tmp" config user.email selftest@example.invalid
    git -C "$tmp" config user.name selftest
    echo content > "$tmp/file"
    git -C "$tmp" add file
    git -C "$tmp" commit -qm selftest
    local commit
    commit="$(git -C "$tmp" rev-parse HEAD)"

    # 1. Passing commands -> exit 0, result "pass", commit pinned exactly.
    ( cd "$tmp" && "$self" --out att.json "true" "exit 0" ) >/dev/null || \
        { echo "FAIL selftest: passing run did not exit 0"; return 1; }
    python3 - "$tmp/att.json" "$commit" <<'PYEOF' || return 1
import json, sys
doc = json.load(open(sys.argv[1]))
assert doc["result"] == "pass", doc["result"]
assert doc["commit"] == sys.argv[2], "commit not pinned to the tested tree"
assert doc["dirty"] is False
assert [c["exit"] for c in doc["commands"]] == [0, 0]
PYEOF

    # 2. A failing command -> nonzero exit AND an honest "fail" record.
    ( cd "$tmp" && "$self" --out att2.json "true" "false" ) >/dev/null 2>&1
    rc=$?
    [ "$rc" -ne 0 ] || { echo "FAIL selftest: failing run exited 0"; return 1; }
    python3 - "$tmp/att2.json" <<'PYEOF' || return 1
import json, sys
doc = json.load(open(sys.argv[1]))
assert doc["result"] == "fail", "failure was not recorded as failure"
assert [c["exit"] for c in doc["commands"]] == [0, 1]
PYEOF

    # 3. Dirty tree -> refused without --allow-dirty; poisoned with it.
    echo drift >> "$tmp/file"
    if ( cd "$tmp" && "$self" --out att3.json "true" ) >/dev/null 2>&1; then
        echo "FAIL selftest: dirty tree was attested"; return 1
    fi
    ( cd "$tmp" && "$self" --allow-dirty --out att4.json "true" ) >/dev/null 2>&1
    python3 - "$tmp/att4.json" <<'PYEOF' || return 1
import json, sys
doc = json.load(open(sys.argv[1]))
assert doc["dirty"] is True, "--allow-dirty must stamp dirty:true"
PYEOF

    echo "  PASS: gen-test-attestation.sh selftest (pin, honest fail, dirty guard)"
    return 0
}

OUT=""
ALLOW_DIRTY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --selftest) selftest; exit $? ;;
        --out) OUT="${2:?--out needs a path}"; shift 2 ;;
        --allow-dirty) ALLOW_DIRTY=1; shift ;;
        -h|--help) usage ;;
        --) shift; break ;;
        -*) echo "FAIL: unknown option $1"; usage ;;
        *) break ;;
    esac
done

[ -n "$OUT" ] || { echo "FAIL: --out FILE is required"; usage; }
[ $# -gt 0 ] || { echo "FAIL: no commands given — nothing to attest"; usage; }

COMMIT="$(git rev-parse HEAD 2>/dev/null)" || \
    { echo "FAIL: not inside a git repository — cannot pin a tree"; exit 1; }
TREE="$(git rev-parse 'HEAD^{tree}')"
DESCRIBE="$(git describe --tags --always HEAD 2>/dev/null || echo "$COMMIT")"

DIRTY=false
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    DIRTY=true
    if [ "$ALLOW_DIRTY" -ne 1 ]; then
        echo "FAIL: working tree has uncommitted changes — the tested code"
        echo "      is not commit $COMMIT and an attestation naming that"
        echo "      commit would be false. Commit or stash, or pass"
        echo "      --allow-dirty to record a dirty (verifier-rejected) run."
        exit 1
    fi
    echo "WARNING: attesting a DIRTY tree — verifiers will reject this file."
fi

RECORDS=()
OVERALL=pass
for CMD in "$@"; do
    echo "=== attested run [$COMMIT]: $CMD ==="
    START="$(date +%s)"
    bash -c "$CMD"
    RC=$?
    SECS=$(( $(date +%s) - START ))
    RECORDS+=("$CMD" "$RC" "$SECS")
    [ "$RC" -eq 0 ] || OVERALL=fail
    echo "=== exit $RC after ${SECS}s: $CMD ==="
done

write_json "$OUT" "$COMMIT" "$TREE" "$DESCRIBE" "$DIRTY" "$OVERALL" "${RECORDS[@]}" || \
    { echo "FAIL: could not write $OUT"; exit 1; }

echo "wrote $OUT (commit $COMMIT, result $OVERALL)"
[ "$OVERALL" = pass ]
