#!/usr/bin/env bash
#
# drift-check.sh — judge a deployed_state/1 document. Never touch a node.
#
# Copyright (c) 2026 Third Level IT LLC. All rights reserved.
#
# ─────────────────────────────────────────────────────────────────────
# THE SPLIT, AND WHY IT IS LOAD-BEARING
#
# deployed-state.sh OBSERVES: it runs on a node, reads that node, and
# signs what it saw. This program JUDGES: it reads documents and git
# objects and says what moved. It has no ssh, no socket, no node.
#
# That separation is not tidiness. A checker that must reach a box can
# only run where the box is reachable, and it inherits the box's
# availability, its credentials, and its ability to lie to whoever asks.
# This one reads a signed document and a git ref, so it runs on a
# laptop, in CI, or later against a bundle with no live infrastructure
# at all — including a document from a node that has since been rebuilt
# or destroyed.
#
# ─────────────────────────────────────────────────────────────────────
# WHAT IT COMPARES
#
#   against a git ref (default origin/main)
#     unit file and drop-in hashes, via unit-manifest.txt AS OF THAT REF
#     device template hash and its device count
#     where the deploy tree's HEAD sits relative to the ref
#
#   against a previous document from the same node
#     every stable field that moved, with restarts called out as such
#
# It reads git OBJECTS, never a working tree, so the answer does not
# depend on what happens to be checked out.
#
# ─────────────────────────────────────────────────────────────────────
# IT DOES NOT FETCH
#
# A judgement that silently mutates the repo it judges from is not a
# judgement. The ref is read as this clone already knows it, and the
# ref's own sha and fetch time are PRINTED with every verdict so a
# reader can see how stale the baseline is rather than assume it is
# current.
#
# ─────────────────────────────────────────────────────────────────────
# EXIT CODES
#
#   0  every comparison ran, nothing drifted
#   1  DRIFT — one or more of the three conditions that have actually
#      bitten this system:
#        · the running binary differs from the installed one
#          (the state that hides a rollback behind a current binary)
#        · the deploy tree is dirty
#          (the box carries changes no ref describes)
#        · the device count moved
#          (against the tracked template, or against the last document)
#   2  usage, or an input that could not be read
#   4  nothing drifted, but a comparison COULD NOT BE MADE
#
# 4 exists because "clean" and "I could not check" must never print the
# same. This repo has already run a unit-drift check that passed green
# for eight days while the installed unit said the opposite of the
# tracked one, because the check read only the file in git. A node whose
# device config has no tracked source cannot be compared against one,
# and that fact has to leave a mark.
#
# Findings that are neither of those — a tree behind the ref, a daemon
# restart, an approver enrolled — print as INFO and do not change the
# exit code. Being behind origin/main is a normal state for a node, not
# an alarm, and an alarm that fires on normal states stops being read.
#

set -euo pipefail

PROG="$(basename "$0")"
SELF="$(readlink -f "$0")"

STATE=""
PREVIOUS=""
REPO=""
REF="origin/main"
JSON=0

die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 2; }

usage() {
    cat >&2 <<USAGE
usage: $PROG --state PATH [options]

  --state PATH      the deployed_state/1 document to judge   (required)
  --previous PATH   an earlier document from the SAME node, to diff against
  --repo PATH       git repo holding the tracked deploy/ files
                    (default: the repo this script lives in)
  --ref REF         ref to compare against          (default: $REF)
  --json            emit findings as JSON instead of text

exit: 0 clean · 1 drift · 2 usage/IO · 4 a comparison could not be made
USAGE
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --state)    shift; [ $# -gt 0 ] || usage; STATE="$1" ;;
        --previous) shift; [ $# -gt 0 ] || usage; PREVIOUS="$1" ;;
        --repo)     shift; [ $# -gt 0 ] || usage; REPO="$1" ;;
        --ref)      shift; [ $# -gt 0 ] || usage; REF="$1" ;;
        --json)     JSON=1 ;;
        -h|--help)  usage ;;
        *) printf '%s: unknown argument %s\n' "$PROG" "$1" >&2; usage ;;
    esac
    shift
done

[ -n "$STATE" ] || usage
[ -r "$STATE" ] || die "cannot read state document: $STATE"
[ -z "$PREVIOUS" ] || [ -r "$PREVIOUS" ] \
    || die "cannot read previous document: $PREVIOUS"

command -v git >/dev/null 2>&1 || die "git not found"
command -v python3 >/dev/null 2>&1 || die "python3 not found"

# Default the repo to the one this script is committed in, so the
# common case needs no flag and the baseline is unambiguous.
if [ -z "$REPO" ]; then
    REPO="$(git -C "$(dirname "$SELF")" rev-parse --show-toplevel 2>/dev/null || true)"
    [ -n "$REPO" ] || die "not inside a git repo and no --repo given"
fi
[ -d "$REPO/.git" ] || [ -f "$REPO/.git" ] \
    || die "not a git repo: $REPO"

git -C "$REPO" rev-parse --verify --quiet "$REF^{commit}" >/dev/null \
    || die "ref '$REF' does not exist in $REPO — this program never fetches, so a ref it has not seen is an error, not something to go and get"

DC_STATE="$STATE" DC_PREV="$PREVIOUS" DC_REPO="$REPO" DC_REF="$REF" \
DC_JSON="$JSON" exec python3 - <<'PY'
import hashlib, json, os, subprocess, sys, textwrap, time

E = os.environ
STATE, PREV = E["DC_STATE"], E.get("DC_PREV") or ""
REPO, REF = E["DC_REPO"], E["DC_REF"]
AS_JSON = E.get("DC_JSON") == "1"


def die(msg):
    """Exit 2, never 1. Exit 1 means DRIFT and must mean nothing else,
    or a CI gate cannot tell 'the node moved' from 'you handed me the
    wrong file'. sys.exit(str) would use code 1, which is exactly that
    collision."""
    print("drift-check: %s" % msg, file=sys.stderr)
    sys.exit(2)


def load(path, label):
    try:
        with open(path) as f:
            d = json.load(f)
    except Exception as e:
        die("%s document %s is unreadable or not JSON: %s" % (label, path, e))
    if d.get("schema") != "deployed_state/1":
        die("%s document %s has schema %r, not deployed_state/1"
            % (label, path, d.get("schema")))
    return d


cur = load(STATE, "state")
prev = load(PREV, "previous") if PREV else None

# The document's own sha256 is what the chain entry commits to, so
# printing it closes the loop: a reader can look this exact document up
# as artifact depstate-<first 16> without re-deriving anything. This
# program does NOT check that the lookup succeeds — that would mean
# reading a chain, which means reaching a node, which is the one thing
# it must not do.
state_sha = hashlib.sha256(open(STATE, "rb").read()).hexdigest()


def git(*args):
    return subprocess.run(("git", "-C", REPO) + args,
                          capture_output=True, text=True)


def blob(path):
    """A tracked file's bytes AT THE REF. Returns None if the ref does
    not carry that path — which is a real answer (the file is untracked
    there), not an error."""
    r = subprocess.run(("git", "-C", REPO, "show", "%s:%s" % (REF, path)),
                       capture_output=True)
    return r.stdout if r.returncode == 0 else None


findings = []

def add(sev, axis, what, detail, was=None, now=None):
    findings.append({"severity": sev, "axis": axis, "what": what,
                     "detail": detail, "was": was, "now": now})

DRIFT, INFO, UNCHECKED = "DRIFT", "INFO", "UNCHECKED"

# ── the ref's own identity, printed with every verdict ────────────────
ref_sha = git("rev-parse", REF).stdout.strip()
fetch_head = os.path.join(REPO, ".git", "FETCH_HEAD")
ref_fetched = None
if os.path.exists(fetch_head):
    ref_fetched = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                time.gmtime(os.path.getmtime(fetch_head)))

# =====================================================================
# 1. The three conditions that have actually bitten
# =====================================================================

# 1a — running vs installed. The document states this itself rather than
# leaving two hashes for a reader to diff by eye, and this re-derives it
# rather than trusting the flag: a document whose flag disagrees with
# its own hashes is a bug worth catching.
d = cur["daemon"]
claimed = d.get("running_matches_installed")
actual = d.get("running_sha256") == d.get("installed_sha256")
if claimed != actual:
    add(DRIFT, "self", "running_matches_installed",
        "the document's own flag (%r) disagrees with its own hashes (%r) "
        "— the document is internally inconsistent and cannot be trusted "
        "on this point" % (claimed, actual))
if not actual:
    add(DRIFT, "self", "running binary != installed binary",
        "the daemon is executing a binary that is not the one on disk. "
        "This is the state that hides a rollback: `sha256sum` of the "
        "installed file looks current while the process serving traffic "
        "is something else.",
        was="installed %s" % d.get("installed_sha256"),
        now="running   %s" % d.get("running_sha256"))

# 1b — dirty tree.
tree = cur["deploy_tree"]
if tree.get("dirty"):
    add(DRIFT, "self", "deploy tree is dirty",
        "%d entry/entries differ from HEAD in %s. The box carries changes "
        "no ref describes, so no ref describes what was built there."
        % (tree.get("dirty_entries", 0), tree.get("path")))

# =====================================================================
# 2. Against the ref
# =====================================================================

# The tracked->installed mapping AS OF THE REF, not as of whatever is
# checked out. A checker whose mapping came from the working tree would
# answer differently depending on the operator's branch.
manifest_raw = blob("deploy/unit-manifest.txt")
manifest = {}
if manifest_raw is None:
    add(UNCHECKED, "repo", "unit-manifest.txt",
        "%s carries no deploy/unit-manifest.txt, so no unit can be "
        "mapped to a tracked source" % REF)
else:
    for line in manifest_raw.decode().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) == 2:
            manifest[parts[1]] = parts[0]       # installed -> tracked

def cmp_tracked(installed_path, installed_sha, label):
    tracked = manifest.get(installed_path)
    if tracked is None:
        add(UNCHECKED, "repo", label,
            "%s is not named in unit-manifest.txt at %s — it exists on the "
            "node with no tracked source, which is exactly the shape that "
            "hid the netclaw egress ruleset. It cannot be compared."
            % (installed_path, REF))
        return
    b = blob(tracked)
    if b is None:
        add(UNCHECKED, "repo", label,
            "the manifest maps %s -> %s but %s carries no such file"
            % (installed_path, tracked, REF))
        return
    want = hashlib.sha256(b).hexdigest()
    if want != installed_sha:
        add(INFO, "repo", label,
            "installed copy differs from %s:%s. Comments count: a comment "
            "that misdescribes the policy is how the last drift stayed "
            "invisible. NOTE: this cannot distinguish 'drifted from its "
            "tracked source' from 'this node has a different role and no "
            "tracked file of its own' — the manifest maps one tracked "
            "file per installed path, so a second node role sharing that "
            "path reads as drift." % (REF, tracked),
            was="tracked   %s" % want, now="installed %s" % installed_sha)

cmp_tracked(cur["unit"]["path"], cur["unit"]["sha256"],
            "unit %s" % cur["unit"]["name"])

unit_dir = cur["unit"]["path"] + ".d"
for dr in cur["unit"].get("dropins", []):
    cmp_tracked("%s/%s" % (unit_dir, dr["name"]), dr["sha256"],
                "drop-in %s" % dr["name"])

# ── device template, and the count ───────────────────────────────────
#
# The template is not a systemd unit and is deliberately not in
# unit-manifest.txt: node2 maps a DIFFERENT tracked template to the same
# installed path, and that manifest is one tracked file per installed
# path. The mapping lives here instead, declared rather than guessed.
# KEYED ON NODE_ID, not on the installed path alone. Every node renders
# from /etc/virp/devices.template.json, but they render DIFFERENT tracked
# templates into it — virp-lab's 43-device fleet, the home node's 38.
# A path-only map has to pick one, and then reports every other node as
# having drifted by the whole difference between two fleets: the first
# run of this check against the home node claimed its device count had
# moved 43 -> 38, which is two nodes being compared to each other, not
# drift.
#
# unit-manifest.txt cannot express this, which is why the templates are
# deliberately absent from it: that file maps one tracked file per
# installed path and has no notion of which host it is talking about.
# This program does — the state document names its node — so the
# per-node comparison belongs here.
TEMPLATE_MAP = {
    ("00000001", "/etc/virp/devices.template.json"):
        "deploy/devices.template.json",
    ("0000000D", "/etc/virp/devices.template.json"):
        "deploy/devices.home.template.json",
    ("00000002", "/etc/virp/devices.template.json"):
        "deploy/devices.node2.template.json",
}

dev = cur["device_config"]
tmpl_installed = dev.get("template_path")
tracked_count = None

if tmpl_installed is None:
    # Not a failure of this program — a statement about the node. A node
    # whose fleet exists only on the box is the 43-device failure, and
    # the checker must not print "clean" over it.
    add(UNCHECKED, "repo", "device count vs tracked template",
        "this node's device config (%s, %d devices) is %r — it has no "
        "template, so there is no tracked source to compare its fleet "
        "against. The count cannot be checked here; it can still be "
        "checked against a previous document."
        % (dev["path"], dev["device_count"], dev.get("source")))
else:
    node_id = cur["node"].get("node_id", "")
    tracked_path = TEMPLATE_MAP.get((node_id, tmpl_installed))
    if tracked_path is None:
        add(UNCHECKED, "repo", "device template",
            "node %s installs a template at %s, and this program's "
            "TEMPLATE_MAP has no entry for that pair, so it cannot be "
            "compared. Add one rather than letting it pass unchecked — "
            "and do NOT reuse another node's tracked template, which "
            "would report the difference between two fleets as drift."
            % (node_id or "(unknown)", tmpl_installed))
    else:
        b = blob(tracked_path)
        if b is None:
            add(UNCHECKED, "repo", "device template",
                "%s carries no %s" % (REF, tracked_path))
        else:
            want = hashlib.sha256(b).hexdigest()
            if want != dev.get("template_sha256"):
                add(INFO, "repo", "device template %s" % tmpl_installed,
                    "installed template differs from %s:%s"
                    % (REF, tracked_path),
                    was="tracked   %s" % want,
                    now="installed %s" % dev.get("template_sha256"))
            try:
                tracked_count = len(json.loads(b)["devices"])
            except Exception as e:
                add(UNCHECKED, "repo", "device count vs tracked template",
                    "%s:%s could not be parsed for a device count: %s"
                    % (REF, tracked_path, e))
            if tracked_count is not None \
                    and tracked_count != dev["device_count"]:
                add(DRIFT, "repo", "device count moved",
                    "the node runs a different number of devices than the "
                    "tracked template declares. The tracked template said "
                    "nine devices for a month while the box ran "
                    "forty-three, and nothing noticed.",
                    was="%s:%s  %d devices" % (REF, tracked_path,
                                               tracked_count),
                    now="%s  %d devices" % (dev["path"],
                                            dev["device_count"]))

# ── where the deploy tree sits relative to the ref ───────────────────
rev = tree.get("rev")
if not rev:
    add(UNCHECKED, "repo", "deploy tree position",
        "the document records no deploy tree (%s), so its position "
        "relative to %s cannot be judged"
        % (tree.get("absent_reason") or "reason not given", REF))
elif git("cat-file", "-e", rev + "^{commit}").returncode != 0:
    add(UNCHECKED, "repo", "deploy tree position",
        "commit %s is not in this clone, so its position relative to %s "
        "cannot be judged. This program never fetches; if the commit is "
        "real, fetch first and re-run." % (rev[:12], REF))
else:
    is_anc = git("merge-base", "--is-ancestor", rev, REF).returncode == 0
    behind = git("rev-list", "--count", "%s..%s" % (rev, REF)).stdout.strip()
    ahead = git("rev-list", "--count", "%s..%s" % (REF, rev)).stdout.strip()
    if rev == ref_sha:
        add(INFO, "repo", "deploy tree position",
            "HEAD is exactly %s (%s)" % (REF, rev[:12]))
    elif is_anc:
        add(INFO, "repo", "deploy tree position",
            "HEAD %s is %s commit(s) behind %s. Being behind is a normal "
            "state for a node and is reported, not alarmed."
            % (rev[:12], behind, REF))
    else:
        add(INFO, "repo", "deploy tree carries unpushed commits",
            "HEAD %s is NOT an ancestor of %s: %s commit(s) ahead, %s "
            "behind. Whatever those commits are, no pushed ref describes "
            "what is running here." % (rev[:12], REF, ahead, behind))

# =====================================================================
# 3. Against a previous document
# =====================================================================

# Fields whose change is expected on every single run and says nothing.
VOLATILE = {"collected.at", "collected.at_ns"}
# Fields whose change is real but is a restart, not drift.
RESTART = {"daemon.pid", "daemon.started_at"}


def flatten(o, prefix=""):
    out = {}
    if isinstance(o, dict):
        for k, v in o.items():
            out.update(flatten(v, "%s.%s" % (prefix, k) if prefix else str(k)))
    elif isinstance(o, list):
        # Lists here are small and identity-bearing (drop-ins, approvers,
        # uid ceilings). Comparing them as a whole says "this list moved"
        # without pretending index 2 of one is index 2 of the other.
        out[prefix] = json.dumps(o, sort_keys=True)
    else:
        out[prefix] = o
    return out


if prev is not None:
    if prev["node"].get("node_id") != cur["node"].get("node_id") \
            or prev["node"].get("hostname") != cur["node"].get("hostname"):
        die("the two documents are from DIFFERENT nodes (%s/%s vs %s/%s). "
            "Diffing them would manufacture drift out of a mismatch."
            % (prev["node"].get("hostname"), prev["node"].get("node_id"),
               cur["node"].get("hostname"), cur["node"].get("node_id")))

    if prev["collected"].get("at_ns", 0) > cur["collected"].get("at_ns", 0):
        add(INFO, "previous", "documents are out of order",
            "the --previous document (%s) is NEWER than --state (%s); the "
            "diff below reads backwards"
            % (prev["collected"].get("at"), cur["collected"].get("at")))

    a, b = flatten(prev), flatten(cur)
    restarted = False
    for k in sorted(set(a) | set(b)):
        if k in VOLATILE:
            continue
        av, bv = a.get(k, "<absent>"), b.get(k, "<absent>")
        if av == bv:
            continue
        if k in RESTART:
            restarted = True
            continue
        if k == "device_config.device_count":
            add(DRIFT, "previous", "device count moved",
                "the fleet changed size between these two documents",
                was=av, now=bv)
        else:
            add(INFO, "previous", k, "changed since %s"
                % prev["collected"].get("at"), was=av, now=bv)
    if restarted:
        add(INFO, "previous", "daemon restarted",
            "pid %s -> %s, started %s -> %s"
            % (prev["daemon"].get("pid"), cur["daemon"].get("pid"),
               prev["daemon"].get("started_at"),
               cur["daemon"].get("started_at")))
else:
    # INFO, not UNCHECKED. Omitting --previous is a caller's choice, and
    # the first run on any node has nothing to diff against. Grading it
    # UNCHECKED would make exit 4 the permanent default and drain the
    # meaning out of the one code that says "a comparison I was supposed
    # to be able to make did not happen".
    add(INFO, "previous", "no previous document",
        "nothing was passed to --previous, so nothing was compared over "
        "time. The repo-side comparison above still ran in full.")

# =====================================================================
# Report
# =====================================================================

n_drift = sum(1 for f in findings if f["severity"] == DRIFT)
n_unchecked = sum(1 for f in findings if f["severity"] == UNCHECKED)
n_info = sum(1 for f in findings if f["severity"] == INFO)

if n_drift:
    code, verdict = 1, "DRIFT"
elif n_unchecked:
    code, verdict = 4, "INCOMPLETE"
else:
    code, verdict = 0, "CLEAN"

if AS_JSON:
    print(json.dumps({
        "schema": "drift_check/1",
        "verdict": verdict,
        "exit_code": code,
        "node": cur["node"],
        "state_collected_at": cur["collected"].get("at"),
        "state_sha256": state_sha,
        "state_artifact_id": "depstate-%s" % state_sha[:16],
        "previous_collected_at": (prev or {}).get("collected", {}).get("at"),
        "ref": {"name": REF, "sha": ref_sha, "fetched_at": ref_fetched},
        "counts": {"drift": n_drift, "info": n_info,
                   "unchecked": n_unchecked},
        "findings": findings,
    }, indent=2, sort_keys=True))
    sys.exit(code)

W = 72
print("=" * W)
print("deployed-state drift check — %s (%s)"
      % (cur["node"].get("hostname"), cur["node"].get("node_id")))
print("=" * W)
print("  state       %s   collected %s"
      % (STATE, cur["collected"].get("at")))
print("              sha256 %s" % state_sha)
print("              on-chain as artifact depstate-%s (not verified here)"
      % state_sha[:16])
print("  previous    %s" % (PREV if PREV else "(none)"))
print("  baseline    %s = %s" % (REF, ref_sha[:12] if ref_sha else "?"))
print("              last fetched %s — NOT refreshed by this program"
      % (ref_fetched or "unknown"))
print()

for sev, title in ((DRIFT, "DRIFT — the conditions that have bitten"),
                   (UNCHECKED, "COULD NOT BE CHECKED"),
                   (INFO, "REPORTED (not fatal)")):
    group = [f for f in findings if f["severity"] == sev]
    if not group:
        continue
    print("%s  [%d]" % (title, len(group)))
    print("-" * W)
    for f in group:
        print("  * %s" % f["what"])
        for line in textwrap.wrap(f["detail"], W - 6):
            print("      %s" % line)
        if f["was"] is not None:
            print("      was : %s" % f["was"])
        if f["now"] is not None:
            print("      now : %s" % f["now"])
        print()
    print()

print("=" * W)
print("VERDICT: %s   (drift %d, unchecked %d, info %d)  exit %d"
      % (verdict, n_drift, n_unchecked, n_info, code))
if code == 4:
    print("  INCOMPLETE is not CLEAN. Something above could not be")
    print("  compared, and a checker that could not check must not")
    print("  report green — that is how a unit-drift check passed for")
    print("  eight days over a file that said the opposite of tracked.")
print("=" * W)
sys.exit(code)
PY
