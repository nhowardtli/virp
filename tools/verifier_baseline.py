#!/usr/bin/env python3
"""
verifier_baseline.py — did the verifier change what it says about a real
chain?

HAM review 2026-09-06, item 7 (and the deploy gate for items 9, 10, 12).
Those changes alter what the verifier concludes, or what the ingress
accepts, and neither may be installed anywhere until somebody has proved
that the conclusion about the EXISTING corpus is unchanged.

This script proves it, or fails to. It does not decide anything: it
produces a per-session diff and leaves the reading of that diff to a
human.

WHAT IT DOES

  1. Copies the database and its sidecars to a private temp directory.
     The daemon's files are only ever READ. The copy is fingerprinted
     before and after and retried if the source moved underneath it.

  2. CHECKPOINTS THE WAL ON THE COPY, before anything reads it.

     This is the Sep 4 trap, and it is why the -wal and -shm must come
     with the copy. A chain database opened with immutable=1 does not
     replay the write-ahead log, so every committed-but-not-checkpointed
     entry is INVISIBLE. Measured on this code path once already: a WAL
     database holding 50 committed rows reported 50 under mode=ro and 1
     under immutable=1. For an integrity baseline that is the worst
     available failure, because a truncated chain does not look like an
     error -- it looks like a shorter chain that verifies clean. The
     script reports the row count before and after the checkpoint so the
     replay is visible rather than assumed.

  3. Runs the OLD verifier and the NEW verifier against that one
     checkpointed copy. Python always; C too, when a built virp-tool is
     supplied for each side.

  4. Emits a per-session verdict diff.

WHICH SIDE ANSWERS WHICH QUESTION

  The Python verifier was already correct about session signed-ness
  (report/verify.py has always asked the per-session question). Item 7
  fixed the C verifier to MATCH it. So:

    - the C diff is the one that answers item 7. Expect pre-signing
      sessions to move from BROKEN to VALID on a chain that predates
      chain signing, and NOTHING to move the other way.
    - the Python diff should be EMPTY for item 7, and empty for items 9,
      10 and 12 as well, because those are ingress changes: they refuse
      new requests, they do not reinterpret stored entries. A non-empty
      Python diff means something is reinterpreting stored data, which
      was not the intent. Stop and read it.

  Run it with --old-tool and --new-tool. Without them the C half is
  SKIPPED and the script says so rather than implying item 7 was covered.

WHAT IT DOES NOT DO

  It does not contact any host. Point it at a copy you have already
  taken from 313 or .211, or at a local chain.

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def _is_repo(path):
    if not path or not os.path.isdir(path):
        return False
    out = subprocess.run(["git", "-C", path, "rev-parse", "--show-toplevel"],
                         capture_output=True, check=False)
    return out.returncode == 0


def repo_root(explicit=None):
    """The git repo to read the two revisions out of.

    Tried in order: --repo, the current directory, this script's parent.
    NOT derived from the script's own path alone: this file gets copied
    around -- into a scratch directory, onto a host -- and inferring the
    repo from where it happens to sit produced a bare
    `fatal: not a git repository` the first time it ran from anywhere
    but tools/. When none of the three is a repo it says so and names
    the flag, rather than guessing and failing later with git's message
    instead of ours."""
    for cand in (explicit, os.getcwd(), os.path.dirname(HERE)):
        if _is_repo(cand):
            return subprocess.run(
                ["git", "-C", cand, "rev-parse", "--show-toplevel"],
                capture_output=True, check=False).stdout.decode().strip()
    raise SystemExit(
        "verifier_baseline: no git repository found. Tried --repo (%r), the "
        "current directory (%s) and this script's parent (%s). The two "
        "verifier revisions are read from a repo with `git archive`, so one "
        "is required: pass --repo /path/to/virp."
        % (explicit, os.getcwd(), os.path.dirname(HERE)))


ROOT = None          # set from --repo in main()

SIDECARS = ("-wal", "-shm")
COPY_ATTEMPTS = 3


# ── the copy, and the checkpoint ───────────────────────────────────────

def source_fingerprint(path):
    out = []
    for p in (path,) + tuple(path + s for s in SIDECARS):
        try:
            st = os.stat(p)
            out.append((p, st.st_size, st.st_mtime_ns))
        except OSError:
            out.append((p, None, None))
    return tuple(out)


def copy_database(src, dest_dir):
    """Copy db + sidecars, refusing a torn copy. Returns the copy path."""
    dest = os.path.join(dest_dir, "chain.db")
    last = None
    for attempt in range(COPY_ATTEMPTS):
        before = source_fingerprint(src)
        shutil.copyfile(src, dest)
        for suffix in SIDECARS:
            s = src + suffix
            if os.path.exists(s):
                shutil.copyfile(s, dest + suffix)
            elif os.path.exists(dest + suffix):
                os.unlink(dest + suffix)
        after = source_fingerprint(src)
        if before == after:
            return dest
        last = "source changed during copy (attempt %d)" % (attempt + 1)
    raise SystemExit("verifier_baseline: %s" % last)


def checkpoint(copy_path):
    """Replay the WAL into the copy, and PROVE it replayed.

    Returns a dict with the row count seen before and after, the
    checkpoint result, and the integrity_check verdict."""
    info = {}

    # Count what an immutable=1 reader would have seen: the main file
    # alone, WAL unreplayed. This is the number the Sep 4 trap produces.
    uri = "file:%s?immutable=1" % copy_path.replace("?", "%3f")
    try:
        conn = sqlite3.connect(uri, uri=True)
        try:
            info["entries_without_wal_replay"] = conn.execute(
                "SELECT count(*) FROM chain_entries").fetchone()[0]
        finally:
            conn.close()
    except sqlite3.Error as exc:
        info["entries_without_wal_replay"] = "unreadable: %s" % exc

    conn = sqlite3.connect(copy_path)
    try:
        row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        info["wal_checkpoint"] = list(row) if row else None
        ic = conn.execute("PRAGMA integrity_check").fetchone()
        info["integrity_check"] = ic[0] if ic else None
        info["entries_after_wal_replay"] = conn.execute(
            "SELECT count(*) FROM chain_entries").fetchone()[0]
        info["sessions"] = conn.execute(
            "SELECT count(DISTINCT session_id) FROM chain_entries"
        ).fetchone()[0]
        try:
            info["heads"] = conn.execute(
                "SELECT count(*) FROM chain_heads").fetchone()[0]
        except sqlite3.OperationalError:
            info["heads"] = None          # pre-2026-08-01 database
    finally:
        conn.close()

    if info.get("integrity_check") != "ok":
        raise SystemExit("verifier_baseline: integrity_check on the copy "
                         "returned %r — refusing to baseline a damaged copy"
                         % info.get("integrity_check"))
    return info


# ── the Python verifier, one ref at a time, in its own interpreter ─────

RUNNER = r'''
import json, sqlite3, sys
sys.path.insert(0, sys.argv[1])                 # the extracted report/
import verify

db, chain_key_path, pubkey_path, okey_path = sys.argv[2:6]

def load_key(p):
    if not p:
        return None
    try:
        return verify.load_key(p)
    except Exception as exc:                    # noqa: BLE001
        print("runner: key %s unusable: %s" % (p, exc), file=sys.stderr)
        return None

conn = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
conn.row_factory = sqlite3.Row
entries = [dict(r) for r in conn.execute(
    "SELECT " + ",".join(verify.ENTRY_COLUMNS) +
    " FROM chain_entries ORDER BY session_id, sequence")]
artifacts = {(r["artifact_id"], r["artifact_hash"]): r["artifact_content"]
             for r in conn.execute("SELECT artifact_id, artifact_hash, "
                                   "artifact_content FROM artifacts")}
try:
    heads = {r["session_id"]: dict(r) for r in conn.execute(
        "SELECT * FROM chain_heads")}
except sqlite3.OperationalError:
    heads = None
conn.close()

okey = load_key(okey_path)
chain_key = load_key(chain_key_path)

verifications, summary = verify.verify_chain(
    entries, artifacts, okey=okey, chain_key=chain_key, heads=heads,
    selection_complete=True)

per_session = {}
for v in verifications:
    sid = v.entry["session_id"]
    d = per_session.setdefault(sid, {
        "entries": 0, "rollup": {}, "failed": 0, "unverifiable": 0})
    d["entries"] += 1
    r = getattr(v, "rollup", "FAIL")
    d["rollup"][r] = d["rollup"].get(r, 0) + 1

head_res = summary.get("heads", {}).get("per_session", {}) if isinstance(
    summary.get("heads"), dict) else {}
for sid, verdict in head_res.items():
    if isinstance(verdict, (list, tuple)):
        verdict = verdict[0]
    per_session.setdefault(sid, {"entries": 0, "rollup": {},
                                 "failed": 0, "unverifiable": 0})
    per_session[sid]["head"] = verdict

sig = {}
if pubkey_path:
    try:
        pub = verify.load_chainsign_pub(pubkey_path)
        sig = verify.verify_chain_signatures(entries, heads, pub,
                                             selection_complete=True)
    except Exception as exc:                    # noqa: BLE001
        sig = {"__error__": str(exc)}
for sid, res in sig.items():
    if sid == "__error__":
        continue
    per_session.setdefault(sid, {"entries": 0, "rollup": {},
                                 "failed": 0, "unverifiable": 0})
    per_session[sid]["signature"] = res.get("verdict")
    per_session[sid]["entries_signed"] = res.get("entries_signed")

print(json.dumps({
    "totals": {
        "entries": summary["entries"],
        "sessions": summary["sessions"],
        "failed_entries": len(summary["failed_entries"]),
        "unverifiable_entries": len(summary["unverifiable_entries"]),
        "entry_hash": summary["entry_hash"],
        "link": summary["link"],
        "chain_hmac": summary["chain_hmac"],
        "artifact_bind": summary["artifact_bind"],
        "obs_hmac": summary["obs_hmac"],
        "verifier_error": summary.get("verifier_error"),
    },
    "sessions": per_session,
    "signature_error": sig.get("__error__"),
}, sort_keys=True))
'''


def extract_report(ref, dest_dir):
    """Pull report/ out of a git ref, without a worktree or a checkout."""
    out = os.path.join(dest_dir, "report")
    os.makedirs(out, exist_ok=True)
    tar = subprocess.run(["git", "-C", ROOT, "archive", ref, "report"],
                         capture_output=True)
    if tar.returncode != 0:
        raise SystemExit("verifier_baseline: git archive %s failed: %s"
                         % (ref, tar.stderr.decode().strip()))
    untar = subprocess.run(["tar", "-x", "-C", dest_dir],
                           input=tar.stdout, capture_output=True)
    if untar.returncode != 0:
        raise SystemExit("verifier_baseline: untar of %s failed: %s"
                         % (ref, untar.stderr.decode().strip()))
    return out


def run_python_side(report_dir, db, chain_key, pubkey, okey, label):
    runner = os.path.join(os.path.dirname(report_dir), "runner.py")
    with open(runner, "w") as f:
        f.write(RUNNER)
    proc = subprocess.run(
        [sys.executable, runner, report_dir, db,
         chain_key or "", pubkey or "", okey or ""],
        capture_output=True)
    if proc.returncode != 0:
        raise SystemExit("verifier_baseline: the %s Python verifier did not "
                         "complete:\n%s" % (label, proc.stderr.decode()))
    if proc.stderr:
        for line in proc.stderr.decode().splitlines():
            print("  [%s] %s" % (label, line))
    return json.loads(proc.stdout.decode())


# ── the C verifier, one built binary at a time ─────────────────────────

def run_c_side(tool, db, chain_key, pubkey, label):
    cmd = [tool, "chain", "verify", "--db", db]
    if chain_key:
        cmd += ["--key", chain_key]
    if pubkey:
        cmd += ["--pubkey", pubkey]
    if not chain_key and not pubkey:
        cmd += ["--keyless"]
    proc = subprocess.run(cmd, capture_output=True)
    lines = proc.stdout.decode().splitlines()
    per_session, totals = {}, None
    for line in lines:
        if line.startswith("sessions="):
            totals = line.strip()
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        per_session[parts[0]] = " ".join(parts[1:])
    return {"per_session": per_session, "totals": totals,
            "exit": proc.returncode,
            "stderr": proc.stderr.decode().strip()}


# ── the diff ───────────────────────────────────────────────────────────

def diff_dicts(old, new, what):
    """Every key whose value moved, in a form a human can read."""
    rows = []
    for k in sorted(set(old) | set(new)):
        a, b = old.get(k), new.get(k)
        if a != b:
            rows.append((k, a, b))
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Per-session verifier diff across two revisions, "
                    "against one WAL-checkpointed copy of a chain.")
    ap.add_argument("db", help="path to a chain.db (a COPY you took, or a "
                               "local chain). Only ever read.")
    ap.add_argument("--old-ref", default="origin/main",
                    help="git ref for the CURRENTLY INSTALLED verifier "
                         "(default origin/main)")
    ap.add_argument("--new-ref", default="HEAD",
                    help="git ref for the candidate verifier (default HEAD)")
    ap.add_argument("--chain-key", help="K_chain, symmetric tier")
    ap.add_argument("--pubkey", help="chain-signing PUBLIC key, asymmetric "
                                     "tier. This is the one item 7 is about.")
    ap.add_argument("--okey", help="O-Key, for observation HMACs")
    ap.add_argument("--old-tool", help="built virp-tool at the old revision")
    ap.add_argument("--new-tool", help="built virp-tool at the new revision")
    ap.add_argument("--out", help="directory to write the JSON artifacts to")
    ap.add_argument("--keep", action="store_true",
                    help="keep the checkpointed copy (prints its path)")
    ap.add_argument("--repo",
                    help="the virp git repository to read --old-ref and "
                         "--new-ref out of. Defaults to the current "
                         "directory, then this script's parent.")
    a = ap.parse_args(argv)

    global ROOT
    ROOT = repo_root(a.repo)

    if not os.path.exists(a.db):
        raise SystemExit("verifier_baseline: no such file: %s" % a.db)

    tmp = tempfile.mkdtemp(prefix="virp-baseline-")
    print("=== copy and checkpoint")
    copy = copy_database(a.db, tmp)
    info = checkpoint(copy)
    print("  source                    : %s" % os.path.abspath(a.db))
    print("  copy                      : %s" % copy)
    print("  entries WITHOUT wal replay: %s   <-- what immutable=1 would see"
          % info["entries_without_wal_replay"])
    print("  entries AFTER  wal replay : %s" % info["entries_after_wal_replay"])
    print("  wal_checkpoint            : %s" % info["wal_checkpoint"])
    print("  integrity_check           : %s" % info["integrity_check"])
    print("  sessions                  : %s" % info["sessions"])
    print("  head records              : %s" % info["heads"])
    if info["entries_without_wal_replay"] != info["entries_after_wal_replay"]:
        print("  NOTE: the WAL held %s entries that an unreplayed read would "
              "have missed. This is the trap the checkpoint exists to close."
              % (info["entries_after_wal_replay"]
                 - info["entries_without_wal_replay"]))

    print()
    print("=== python verifier: %s -> %s" % (a.old_ref, a.new_ref))
    old_dir = extract_report(a.old_ref, os.path.join(tmp, "old"))
    new_dir = extract_report(a.new_ref, os.path.join(tmp, "new"))
    old = run_python_side(old_dir, copy, a.chain_key, a.pubkey, a.okey, "old")
    new = run_python_side(new_dir, copy, a.chain_key, a.pubkey, a.okey, "new")

    tdiff = diff_dicts(old["totals"], new["totals"], "totals")
    print("  totals: %s" % ("UNCHANGED" if not tdiff
                            else "%d field(s) MOVED" % len(tdiff)))
    for k, x, y in tdiff:
        print("    %-22s %r  ->  %r" % (k, x, y))

    sdiff = []
    for sid in sorted(set(old["sessions"]) | set(new["sessions"])):
        x, y = old["sessions"].get(sid), new["sessions"].get(sid)
        if x != y:
            sdiff.append((sid, x, y))
    print("  sessions: %d of %d MOVED"
          % (len(sdiff), len(set(old["sessions"]) | set(new["sessions"]))))
    for sid, x, y in sdiff:
        print("    %s" % sid)
        print("      old: %s" % json.dumps(x, sort_keys=True))
        print("      new: %s" % json.dumps(y, sort_keys=True))

    print()
    print("=== C verifier")
    cdiff = None
    if a.old_tool and a.new_tool:
        cold = run_c_side(a.old_tool, copy, a.chain_key, a.pubkey, "old")
        cnew = run_c_side(a.new_tool, copy, a.chain_key, a.pubkey, "new")
        print("  old totals: %s (exit %d)" % (cold["totals"], cold["exit"]))
        print("  new totals: %s (exit %d)" % (cnew["totals"], cnew["exit"]))
        cdiff = diff_dicts(cold["per_session"], cnew["per_session"], "c")
        print("  sessions: %d of %d MOVED"
              % (len(cdiff),
                 len(set(cold["per_session"]) | set(cnew["per_session"]))))
        for sid, x, y in cdiff:
            print("    %s" % sid)
            print("      old: %s" % x)
            print("      new: %s" % y)
    else:
        print("  SKIPPED: --old-tool and --new-tool were not both given.")
        print("  Item 7 is a C-verifier change. Without both binaries this")
        print("  run says NOTHING about it. Build virp-tool at each")
        print("  revision and pass both paths.")

    if a.out:
        os.makedirs(a.out, exist_ok=True)
        for name, obj in (("copy-info.json", info),
                          ("python-old.json", old),
                          ("python-new.json", new)):
            with open(os.path.join(a.out, name), "w") as f:
                json.dump(obj, f, indent=1, sort_keys=True)
        print("\n  artifacts written to %s" % a.out)

    if a.keep:
        print("\n  checkpointed copy kept at %s" % copy)
    else:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("=== READ THIS YOURSELF")
    print("  The Python diff should be EMPTY. Items 9, 10 and 12 are ingress")
    print("  changes: they refuse new requests, they do not reinterpret")
    print("  stored entries. A non-empty Python diff means something IS")
    print("  reinterpreting stored data. Stop and read it.")
    print("  The C diff is item 7. On a chain that predates chain signing,")
    print("  expect pre-signing sessions to move BROKEN -> VALID and nothing")
    print("  to move the other way. A session moving VALID -> BROKEN is a")
    print("  regression, not a finding about the chain.")
    print("  This script does not decide. It reports.")

    moved = bool(tdiff) or bool(sdiff) or bool(cdiff)
    return 2 if moved else 0


if __name__ == "__main__":
    sys.exit(main())
