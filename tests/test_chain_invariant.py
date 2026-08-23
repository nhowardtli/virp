#!/usr/bin/env python3
"""
Chain canonical-bytes INVARIANT — Python half (D-1 gate).

The C half (tests/test_chain_invariant.c) locks src/virp_chain.c's static
canonical builders to the D-0 Appendix A fixtures. This half closes the
loop from the OTHER side, so the lock is not self-referential:

  1. The ceremony evidence files under tools/seal/ still hash to the
     values recorded in seal-2026-08.json evidence_files.
  2. seal_verify.py (the ceremony's own verifier) reproduces Appendix A
     ("FIXTURE GATE: PASS").
  3. report/verify.py — the independent pure-Python verifier shipped in
     this tree — rebuilds every Appendix A canonical byte-for-byte, and
     its sha256 matches chain_entry_hash; likewise head and genesis.
  4. The seal's Merkle root recomputes from its own sessions[] under the
     stated leaf/node rules, and headset.json agrees with sessions[].
  5. (when given the C test binary) the C test's end-to-end chain DB —
     written by the LIVE append path — verifies clean under
     report/verify.py with the fixed test key: every entry PASS, head PASS.

`--print-goldens` emits the verify.py-derived values embedded in the C
half (GOLD_* macros) so they can be regenerated, never hand-edited.

Pure stdlib + report/verify.py. No network.
"""

import hashlib
import hmac
import json
import os
import sqlite3
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SEAL_DIR = os.path.join(ROOT, "tools", "seal")
SEAL_JSON = os.path.join(SEAL_DIR, "seal-2026-08.json")
FIXTURES = os.path.join(SEAL_DIR, "fixtures-appendix-a.json")
HEADSET = os.path.join(SEAL_DIR, "headset.json")
SEAL_VERIFY = os.path.join(SEAL_DIR, "seal_verify.py")

sys.path.insert(0, os.path.join(ROOT, "report"))
import verify  # noqa: E402

TEST_KEY = bytes(range(1, 33))

passed = 0
failed = 0


def check(name, ok, detail=""):
    global passed, failed
    print("  [%s] %-64s %s" % ("PASS" if ok else "FAIL", name, detail))
    if ok:
        passed += 1
    else:
        failed += 1
    return ok


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# 1. evidence files match the seal
# ---------------------------------------------------------------------------
def test_evidence_files(seal):
    ev = seal["evidence_files"]
    check("fixtures-appendix-a.json sha256 == seal evidence_files",
          sha256_file(FIXTURES) == ev["fixtures_appendix_a_sha256"])
    check("headset.json sha256 == seal evidence_files",
          sha256_file(HEADSET) == ev["headset_sha256"])
    check("seal_verify.py sha256 == seal host.verifier_tool_sha256",
          sha256_file(SEAL_VERIFY) == seal["host"]["verifier_tool_sha256"])


# ---------------------------------------------------------------------------
# 2. the ceremony verifier reproduces its own fixtures
# ---------------------------------------------------------------------------
def test_seal_verify_fixtures():
    r = subprocess.run([sys.executable, SEAL_VERIFY, "fixtures",
                        "--fixtures", FIXTURES],
                       capture_output=True, text=True)
    ok = r.returncode == 0 and "FIXTURE GATE: PASS" in r.stdout
    check("seal_verify.py fixtures -> FIXTURE GATE: PASS", ok,
          "" if ok else (r.stdout[-400:] + r.stderr[-400:]))


# ---------------------------------------------------------------------------
# 3. report/verify.py rebuilds Appendix A
# ---------------------------------------------------------------------------
def test_verifypy_against_fixtures(fx):
    for fid, e in sorted(fx["entries"].items()):
        fields = json.loads(e["canonical_utf8"])
        canon = verify.canonical_json(fields)
        check("verify.py canonical == Appendix %s utf8" % fid,
              canon == e["canonical_utf8"])
        check("verify.py canonical length == Appendix %s canonical_len" % fid,
              len(canon.encode("utf-8")) == e["canonical_len"])
        if e.get("canonical_hex"):
            check("verify.py canonical == Appendix %s hex dump" % fid,
                  canon.encode("utf-8") == bytes.fromhex(e["canonical_hex"]))
        check("verify.py sha256(canonical) == Appendix %s chain_entry_hash" % fid,
              hashlib.sha256(canon.encode("utf-8")).hexdigest()
              == e["chain_entry_hash"])
        body = e.get("artifact_content")
        if body:
            raw = verify.decode_artifact(body)
            check("verify.py artifact bytes hash to Appendix %s artifact_hash" % fid,
                  hashlib.sha256(raw).hexdigest() == fields["artifact_hash"])

    for g in fx["genesis"]:
        if g.get("genesis_hash"):
            check("verify.py genesis(%s)" % g["session_id"],
                  verify.genesis_hash(g["session_id"]) == g["genesis_hash"])
    a = json.loads(fx["entries"]["A"]["canonical_utf8"])
    check("verify.py genesis == Appendix A previous_entry_hash (seq 0)",
          a["sequence"] == 0 and
          verify.genesis_hash(a["session_id"]) == a["previous_entry_hash"])

    hd = fx["head"]
    hc = verify.head_canonical(hd["session_id"], hd["last_sequence"],
                               hd["last_entry_hash"])
    check("verify.py head canonical == Appendix utf8", hc == hd["canonical_utf8"])
    if hd.get("canonical_hex"):
        check("verify.py head canonical == Appendix hex dump",
              hc.encode("utf-8") == bytes.fromhex(hd["canonical_hex"]))


# ---------------------------------------------------------------------------
# 4. Merkle root + headset consistency
# ---------------------------------------------------------------------------
def merkle_root(sessions):
    leaves = []
    for s in sessions:
        leaf = (b"\x00" + s["session_id"].encode("utf-8") + b"\x1f"
                + str(int(s["entry_count"])).encode("ascii") + b"\x1f"
                + s["head_hash"].encode("ascii"))
        leaves.append(hashlib.sha256(leaf).digest())
    level = leaves
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest())
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0].hex()


def test_seal_merkle(seal, headset):
    sessions = seal["sessions"]
    check("seal sessions[] sorted ascending by UTF-8 session_id",
          [s["session_id"].encode("utf-8") for s in sessions]
          == sorted(s["session_id"].encode("utf-8") for s in sessions))
    check("seal merkle.leaf_count == len(sessions)",
          seal["merkle"]["leaf_count"] == len(sessions))
    check("seal merkle.root recomputes from sessions[]",
          merkle_root(sessions) == seal["merkle"]["root"])
    check("seal totals.entries == sum(entry_count)",
          sum(s["entry_count"] for s in sessions) == seal["totals"]["entries"])
    key = lambda s: (s["session_id"], s["entry_count"], s["head_hash"])  # noqa: E731
    check("headset.json sessions == seal sessions (id, count, head)",
          sorted(map(key, headset["sessions"])) == sorted(map(key, sessions)))
    check("headset snapshot sha256 == seal snapshot sha256",
          headset["snapshot_sha256"] == seal["snapshot"]["sha256"])


# ---------------------------------------------------------------------------
# 5. live append path (C binary) re-verified by verify.py
# ---------------------------------------------------------------------------
def test_e2e_db(c_binary):
    with tempfile.TemporaryDirectory(prefix="virp-inv-") as td:
        db = os.path.join(td, "e2e.db")
        env = dict(os.environ, VIRP_INVARIANT_DB=db, VIRP_FIXTURES=FIXTURES)
        r = subprocess.run([c_binary], env=env, cwd=ROOT,
                           capture_output=True, text=True)
        if not check("C invariant binary exit 0", r.returncode == 0,
                     "" if r.returncode == 0 else r.stdout[-600:]):
            return
        conn = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
        conn.row_factory = sqlite3.Row
        entries = [dict(r) for r in conn.execute(
            "SELECT " + ",".join(verify.ENTRY_COLUMNS) +
            " FROM chain_entries ORDER BY session_id, sequence")]
        artifacts = {(r["artifact_id"], r["artifact_hash"]): r["artifact_content"]
                     for r in conn.execute(
                         "SELECT artifact_id, artifact_hash, artifact_content "
                         "FROM artifacts")}
        heads = {r["session_id"]: dict(r) for r in conn.execute(
            "SELECT session_id, last_sequence, last_entry_hash, head_hmac "
            "FROM chain_heads")}
        conn.close()

        check("e2e DB holds the 3 appended entries", len(entries) == 3)
        vs, summary = verify.verify_chain(entries, artifacts, okey=None,
                                          chain_key=TEST_KEY, heads=heads,
                                          selection_complete=True)
        for v in vs:
            check("verify.py entry %d: hash PASS, link PASS, chain_hmac PASS"
                  % v.entry["sequence"],
                  v.entry_hash == verify.PASS and v.link == verify.PASS
                  and v.chain_hmac == verify.PASS,
                  "" if v.entry_hash == v.link == v.chain_hmac == verify.PASS
                  else str(v.failures))
        per = summary["heads"]["per_session"]
        check("verify.py head verdict PASS for inv-e2e",
              per.get("inv-e2e", (None,))[0] == verify.PASS,
              str(per.get("inv-e2e")))


# ---------------------------------------------------------------------------
def print_goldens():
    sid = "inv-lock-1"
    gen = verify.genesis_hash(sid)
    e0 = dict(session_id=sid, sequence=0, previous_entry_hash=gen,
              timestamp_ns=1787000000123456789, monotonic_ns=123456789012345,
              artifact_type="observation", artifact_id="obs:inv-lock:0001",
              artifact_hash="00" * 32, artifact_hash_alg="sha256",
              artifact_schema_version="1", signer_node_id=1,
              signer_org_id="local")
    c0 = verify.canonical_json(e0)
    h0 = hashlib.sha256(c0.encode()).hexdigest()
    e1 = dict(session_id=sid, sequence=1, previous_entry_hash=h0,
              timestamp_ns=18446744073709551615,
              monotonic_ns=9223372036854775807,
              artifact_type="comparator_verd", artifact_id="cmp:inv-lock:0002",
              artifact_hash="ff" * 32, artifact_hash_alg="sha256",
              artifact_schema_version="1", signer_node_id=4294967295,
              signer_org_id="test-org")
    c1 = verify.canonical_json(e1)
    h1 = hashlib.sha256(c1.encode()).hexdigest()
    hc = verify.head_canonical(sid, 1, h1)
    out = {
        "GOLD_GENESIS": gen,
        "GOLD_C0": c0, "GOLD_H0": h0,
        "GOLD_M0": hmac.new(TEST_KEY, c0.encode(), hashlib.sha256).hexdigest(),
        "GOLD_C1": c1, "GOLD_H1": h1,
        "GOLD_M1": hmac.new(TEST_KEY, c1.encode(), hashlib.sha256).hexdigest(),
        "GOLD_HEAD": hc,
        "GOLD_HEAD_MAC": hmac.new(TEST_KEY, hc.encode(), hashlib.sha256).hexdigest(),
    }
    for k, v in out.items():
        print("%s = %s" % (k, v))
    return out


def test_goldens_match_c_source():
    """The GOLD_* values embedded in the C half must be the ones verify.py
    produces today — catches a hand-edited or stale golden."""
    src = open(os.path.join(HERE, "test_chain_invariant.c"), encoding="utf-8").read()
    gold = _goldens_quiet()
    for k in ("GOLD_GENESIS", "GOLD_H0", "GOLD_M0", "GOLD_H1", "GOLD_M1",
              "GOLD_HEAD_MAC"):
        check("C source embeds verify.py %s" % k, gold[k] in src)


def _goldens_quiet():
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        return print_goldens()


def main(argv):
    if "--print-goldens" in argv:
        print_goldens()
        return 0
    c_binary = None
    for a in argv[1:]:
        if not a.startswith("--"):
            c_binary = a

    print("\n=== VIRP Chain Canonical-Bytes INVARIANT — Python half ===\n")
    seal = json.load(open(SEAL_JSON, encoding="utf-8"))
    fx = json.load(open(FIXTURES, encoding="utf-8"))
    headset = json.load(open(HEADSET, encoding="utf-8"))

    test_evidence_files(seal)
    test_seal_verify_fixtures()
    test_verifypy_against_fixtures(fx)
    test_seal_merkle(seal, headset)
    test_goldens_match_c_source()
    if c_binary:
        test_e2e_db(c_binary)
    else:
        print("  (no C binary given — end-to-end DB cross-check not run)")

    print("\n=== Results: %d passed, %d failed ===\n" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
