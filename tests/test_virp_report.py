#!/usr/bin/env python3
"""
Tests for `virp report` — the consumer-side chain PDF generator.

Two tiers, deliberately separated so this suite passes on a build host as
well as on a deployed node (the lesson recorded in commit c0ee428: a test that
reads ambient deployed state passes on one host and fails on another):

  SYNTHETIC — a complete, valid VIRP chain is constructed in a temp directory
    from the same rules the C daemon uses (per-session genesis, canonical
    JSON, K_chain HMAC, O-Key-signed observation wire messages). These tests
    run anywhere and own their inputs, so they can tamper freely.

  LIVE — run only when a real chain.db is present. These confirm the
    read-only access path works against a running daemon and that the
    report's integrity numbers agree with an INDEPENDENT count taken from the
    same database by separate code.

Run: make test-virp-report   (or python3 tests/test_virp_report.py)
"""

import hashlib
import hmac as hmac_mod
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
REPORT_DIR = os.path.join(REPO_ROOT, "report")
sys.path.insert(0, REPORT_DIR)

import chain_read  # noqa: E402
import verify  # noqa: E402
import virp_report  # noqa: E402

LIVE_DB = "/var/lib/virp/chain.db"
LIVE_OKEY = "/etc/virp/keys/onode.key"
LIVE_CHAIN_KEY = "/etc/virp/keys/chain.key"

TEST_OKEY = bytes(range(32))
TEST_CHAIN_KEY = bytes((i * 7 + 3) & 0xFF for i in range(32))

CREATE_SQL = """
CREATE TABLE chain_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
  sequence INTEGER NOT NULL, chain_entry_hash TEXT NOT NULL,
  previous_entry_hash TEXT NOT NULL, timestamp_ns INTEGER NOT NULL,
  monotonic_ns INTEGER NOT NULL, artifact_type TEXT NOT NULL,
  artifact_id TEXT NOT NULL, artifact_hash TEXT NOT NULL,
  artifact_hash_alg TEXT NOT NULL DEFAULT 'sha256',
  artifact_schema_version TEXT NOT NULL DEFAULT '1',
  signer_node_id INTEGER NOT NULL,
  signer_org_id TEXT NOT NULL DEFAULT 'local',
  chain_hmac TEXT NOT NULL, UNIQUE(session_id, sequence));
CREATE TABLE artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, artifact_id TEXT NOT NULL,
  artifact_type TEXT NOT NULL, artifact_content TEXT NOT NULL,
  artifact_hash TEXT NOT NULL, session_id TEXT NOT NULL,
  created_at_ns INTEGER NOT NULL, UNIQUE(artifact_id));
"""


def sign_observation(okey, payload, node_id=0x0A000A01, tier=0x01,
                     seq_num=1, timestamp_ns=1785300000000000000,
                     obs_type=0x07, obs_scope=0x01):
    """Build a VIRP-format signed observation, matching virp_build_observation.

    Header is 56 bytes big-endian; the HMAC covers header[0:24] || payload,
    with the 32-byte HMAC living at header[24:56].
    """
    body = struct.pack("!BBH", obs_type, obs_scope, len(payload)) + payload
    total = verify.VIRP_HEADER_SIZE + len(body)
    head = struct.pack("!BBHIBBHIQ", 1, 0x01, total, node_id, 0x01, tier,
                       0, seq_num, timestamp_ns)
    mac = hmac_mod.new(okey, head + body, hashlib.sha256).digest()
    return head + mac + body


class ChainBuilder:
    """Builds a valid chain database the way the daemon would."""

    def __init__(self, path, chain_key=TEST_CHAIN_KEY, okey=TEST_OKEY):
        self.path = path
        self.chain_key = chain_key
        self.okey = okey
        self.conn = sqlite3.connect(path)
        self.conn.executescript(CREATE_SQL)
        self.heads = {}
        self.ts = 1785300000000000000

    def append(self, session_id, artifact_type, artifact_id, artifact_hash,
               artifact_content=None):
        seq = self.heads.get(session_id, (-1, None))[0] + 1
        prev = (verify.genesis_hash(session_id) if seq == 0
                else self.heads[session_id][1])
        self.ts += 1_000_000
        entry = {
            "session_id": session_id, "sequence": seq,
            "previous_entry_hash": prev, "timestamp_ns": self.ts,
            "monotonic_ns": self.ts // 2, "artifact_type": artifact_type,
            "artifact_id": artifact_id, "artifact_hash": artifact_hash,
            "artifact_hash_alg": "sha256", "artifact_schema_version": "1",
            "signer_node_id": 1, "signer_org_id": "local",
        }
        canonical = verify.canonical_json(entry)
        entry["chain_entry_hash"] = hashlib.sha256(
            canonical.encode()).hexdigest()
        entry["chain_hmac"] = hmac_mod.new(
            self.chain_key, canonical.encode(), hashlib.sha256).hexdigest()

        self.conn.execute(
            "INSERT INTO chain_entries (" + ",".join(verify.ENTRY_COLUMNS) +
            ") VALUES (" + ",".join("?" * len(verify.ENTRY_COLUMNS)) + ")",
            [entry[c] for c in verify.ENTRY_COLUMNS])
        if artifact_content is not None:
            self.conn.execute(
                "INSERT INTO artifacts (artifact_id, artifact_type, "
                "artifact_content, artifact_hash, session_id, created_at_ns) "
                "VALUES (?,?,?,?,?,?)",
                (artifact_id, artifact_type, artifact_content, artifact_hash,
                 session_id, self.ts))
        self.heads[session_id] = (seq, entry["chain_entry_hash"])
        self.conn.commit()
        return entry

    def add_observation(self, session_id, device, text, tier=0x01):
        import base64
        raw = sign_observation(self.okey, text.encode(), tier=tier)
        digest = hashlib.sha256(raw).hexdigest()
        aid = "obs:%s:%d" % (device, self.ts)
        return self.append(session_id, "observation", aid, digest,
                           "base64:" + base64.b64encode(raw).decode())

    def add_json(self, session_id, atype, artifact_id, obj):
        blob = json.dumps(obj, sort_keys=True)
        return self.append(session_id, atype, artifact_id,
                           hashlib.sha256(blob.encode()).hexdigest(), blob)

    def close(self):
        self.conn.close()


def build_reference_chain(path):
    """A chain exercising every shape the report renders."""
    b = ChainBuilder(path)
    for i in range(4):
        b.add_observation("autopilot:test", "dev%d" % (i % 2),
                          "dev%d$ show ip ospf neighbor\nFull/DR" % (i % 2))
    b.add_observation("autopilot:test", "dev0",
                      "dev0$ vtysh -c \"configure terminal\"\ndenied",
                      tier=0x03)

    pid = "a" * 32
    b.add_json("approval:dev0", "proposal", "proposal:" + pid,
               {"proposal_id": pid, "device": "dev0", "tier": "RED",
                "command": "vtysh -c \"configure terminal\"",
                "command_hash": "b" * 64, "proposer": "test"})
    b.add_json("approval:dev0", "approval", "approval:" + pid,
               {"proposal_id": pid, "device": "dev0", "operator": "tester",
                "approver_key_id": "c" * 32, "ttl_seconds": 300})
    b.add_json("approval:dev0", "outcome", "outcome:" + pid,
               {"proposal_id": pid, "device": "dev0", "success": True,
                "proposal_entry_hash": "d" * 64,
                "approval_entry_hash": "e" * 64})

    # A proposal that was never approved or applied.
    pid2 = "f" * 32
    b.add_json("approval:dev1", "proposal", "proposal:" + pid2,
               {"proposal_id": pid2, "device": "dev1", "tier": "RED",
                "command": "reload", "command_hash": "0" * 64,
                "proposer": "test"})

    # Gate rejection: hash commitment only, no body at all.
    b.append("gate-enforce:dev0", "gate_rejection", "gatereject-1234abcd",
             hashlib.sha256(b"blocked: tier RED").hexdigest(), None)

    # Comparator verdict with a disagreement and a dead peer.
    b.add_json("autopilot-comparator:test", "comparator_verdict",
               "comparator:1", {
                   "node": "nodeA", "peer": "nodeB", "peer_live": False,
                   "disagreements": [{"check": "observer_disagreement",
                                      "target": "wazuh_active",
                                      "local": 5, "peer": None}],
                   "peer_chain_head": {"entry_hash": "abcdef0123456789",
                                       "seq": 3},
                   "verification_note": "peer signature not verifiable"})
    b.close()


def independent_counts(db_path):
    """Count the chain with separate, deliberately naive code.

    This does NOT import the report's helpers: it opens the file itself and
    recomputes hashes inline, so agreement with the report is corroboration
    rather than the same code agreeing with itself.
    """
    # mode=ro still needs a WRITABLE DIRECTORY on a WAL database, because
    # SQLite must create the -wal/-shm sidecars to attach. Against the live
    # /var/lib/virp/chain.db (0750 virp:virp, WAL) a non-virp reader gets
    # "attempt to write a readonly database" — and only intermittently,
    # depending on whether the daemon happens to be holding the sidecars
    # open. That made this suite non-deterministic. immutable=1 reads the
    # main file without touching the directory. Kept deliberately naive and
    # self-contained: this helper must not import report/chain_read.py, or
    # its agreement with the report stops being corroboration.
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
        conn.execute("SELECT count(*) FROM chain_entries").fetchone()
    except sqlite3.OperationalError:
        conn = sqlite3.connect("file:%s?immutable=1" % db_path, uri=True)
    conn.row_factory = sqlite3.Row
    rows = list(conn.execute(
        "SELECT * FROM chain_entries ORDER BY session_id, sequence"))
    arts = {r["artifact_id"]: r["artifact_content"]
            for r in conn.execute(
                "SELECT artifact_id, artifact_content FROM artifacts")}
    conn.close()

    total = len(rows)
    observations = sum(1 for r in rows if r["artifact_type"] == "observation")
    sessions = len({r["session_id"] for r in rows})

    hash_ok = 0
    for r in rows:
        canonical = (
            '{"artifact_hash":"%s","artifact_hash_alg":"%s","artifact_id":"%s",'
            '"artifact_schema_version":"%s","artifact_type":"%s",'
            '"monotonic_ns":%d,"previous_entry_hash":"%s","sequence":%d,'
            '"session_id":"%s","signer_node_id":%d,"signer_org_id":"%s",'
            '"timestamp_ns":%d}') % (
            r["artifact_hash"], r["artifact_hash_alg"], r["artifact_id"],
            r["artifact_schema_version"], r["artifact_type"],
            r["monotonic_ns"], r["previous_entry_hash"], r["sequence"],
            r["session_id"], r["signer_node_id"], r["signer_org_id"],
            r["timestamp_ns"])
        if hashlib.sha256(canonical.encode()).hexdigest() == \
                r["chain_entry_hash"]:
            hash_ok += 1

    links_ok = 0
    prev = {}
    for r in rows:
        sid = r["session_id"]
        expect = (hashlib.sha256(
            ("VIRP_CHAIN_GENESIS:" + sid).encode()).hexdigest()
            if r["sequence"] == 0 else prev.get(sid))
        if expect is not None and r["previous_entry_hash"] == expect:
            links_ok += 1
        prev[sid] = r["chain_entry_hash"]

    return {"total": total, "observations": observations,
            "sessions": sessions, "hash_ok": hash_ok, "links_ok": links_ok,
            "artifacts": len(arts)}


def flip_byte_changing_row(db_path, rowid, column):
    """Flip exactly one byte in the FILE so that chain_entries.<column> for
    <rowid> changes as seen through SQL.

    A hash value is not unique in the file — the same 64 hex characters also
    appear as the successor's previous_entry_hash and often inside an
    artifact body — so a naive "find the string and flip its first byte"
    corrupts a different record than intended. Every occurrence is tried in
    turn and the one that actually moves the target row is kept.

    Returns the byte offset that was flipped.
    """
    conn = sqlite3.connect(db_path)
    original = conn.execute(
        "SELECT %s FROM chain_entries WHERE id=?" % column,
        (rowid,)).fetchone()[0]
    conn.close()

    with open(db_path, "rb") as fh:
        pristine = fh.read()

    needle = original.encode()
    start = 0
    while True:
        idx = pristine.find(needle, start)
        if idx < 0:
            raise AssertionError(
                "no byte offset of %s flips row %d's %s"
                % (original[:16], rowid, column))
        start = idx + 1

        blob = bytearray(pristine)
        blob[idx] = ord("f") if chr(blob[idx]) != "f" else ord("0")
        with open(db_path, "wb") as fh:
            fh.write(bytes(blob))

        conn = sqlite3.connect(db_path)
        try:
            now = conn.execute(
                "SELECT %s FROM chain_entries WHERE id=?" % column,
                (rowid,)).fetchone()[0]
        finally:
            conn.close()
        if now != original:
            return idx

        with open(db_path, "wb") as fh:   # restore and try the next one
            fh.write(pristine)


def run_report(db, out, extra=()):
    """Invoke the CLI in-process. Returns (exit_code, summary)."""
    argv = ["--db", db, "--out", out] + list(extra)
    code = virp_report.main(argv)
    return code


def analyse(db, okey=TEST_OKEY, chain_key=TEST_CHAIN_KEY):
    """Load + verify a chain the way the report does, returning the summary."""
    with chain_read.open_chain(db) as reader:
        entries, artifacts = virp_report.load_evidence(reader)
        return verify.verify_chain(entries, artifacts, okey=okey,
                                   chain_key=chain_key)


# ── synthetic-chain tests ─────────────────────────────────────────────────

class TestChainReadHelper(unittest.TestCase):
    """The read-only access helper and its documented method ordering."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="virp-report-test-")
        self.db = os.path.join(self.tmp, "chain.db")
        build_reference_chain(self.db)

    def tearDown(self):
        os.chmod(self.tmp, 0o755)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_prefers_live_read_only(self):
        with chain_read.open_chain(self.db) as ch:
            self.assertEqual(ch.method, chain_read.METHOD_RO)
            self.assertEqual(ch.attempts, [(chain_read.METHOD_RO, "ok")])

    def test_does_not_write_to_the_source(self):
        """Reading must not touch the database or create sidecars."""
        before = os.stat(self.db).st_mtime_ns
        listing_before = sorted(os.listdir(self.tmp))
        with chain_read.open_chain(self.db) as ch:
            ch.conn.execute("SELECT count(*) FROM chain_entries").fetchone()
        self.assertEqual(os.stat(self.db).st_mtime_ns, before)
        self.assertEqual(sorted(os.listdir(self.tmp)), listing_before)

    def test_snapshot_fallback_recovers_a_wal_that_ro_cannot(self):
        """The failure mode the peer-head probe hits: a WAL that needs
        recovery with no writer around and no usable -shm.

        The writer is SIGKILLed rather than closed, because a clean close
        checkpoints the WAL away and there would be nothing left to recover.
        The -shm is then removed and the directory made unwritable, so SQLite
        cannot rebuild it — mode=ro must fail and the snapshot copy must still
        return the complete chain.
        """
        wal_db = os.path.join(self.tmp, "wal.db")
        writer = (
            "import sqlite3, os, signal\n"
            "c = sqlite3.connect(%r)\n"
            "c.execute('PRAGMA journal_mode=wal')\n"
            "c.execute('CREATE TABLE chain_entries (i INTEGER)')\n"
            "c.executemany('INSERT INTO chain_entries VALUES (?)',\n"
            "              [(i,) for i in range(20)])\n"
            "c.commit()\n"
            "os.kill(os.getpid(), signal.SIGKILL)\n" % wal_db)
        subprocess.run([sys.executable, "-c", writer], capture_output=True)

        self.assertTrue(os.path.exists(wal_db + "-wal"),
                        "expected an un-checkpointed WAL to remain")
        if os.path.exists(wal_db + "-shm"):
            os.remove(wal_db + "-shm")
        os.chmod(self.tmp, 0o555)

        if os.geteuid() == 0:
            # root ignores the directory mode, so SQLite can rebuild the -shm
            # and mode=ro succeeds. The METHOD ORDERING cannot be exercised
            # here; test_snapshot_copy_replays_a_dirty_wal covers the fallback
            # itself for every uid.
            self.skipTest("running as root: cannot make mode=ro fail via "
                          "directory permissions")

        with chain_read.open_chain(wal_db) as ch:
            self.assertEqual(ch.method, chain_read.METHOD_SNAPSHOT)
            self.assertEqual(ch.attempts[0][0], chain_read.METHOD_RO)
            self.assertNotEqual(ch.attempts[0][1], "ok",
                                "mode=ro was expected to fail here")
            self.assertEqual(
                ch.conn.execute(
                    "SELECT count(*) FROM chain_entries").fetchone()[0], 20,
                "the snapshot copy must replay the WAL, not lose it")

    def test_snapshot_copy_replays_a_dirty_wal(self):
        """The fallback itself, exercised directly so it is covered whatever
        uid the suite runs as (root can defeat the permission trick used by
        the method-ordering test above)."""
        wal_db = os.path.join(self.tmp, "dirty.db")
        writer = (
            "import sqlite3, os, signal\n"
            "c = sqlite3.connect(%r)\n"
            "c.execute('PRAGMA journal_mode=wal')\n"
            "c.execute('CREATE TABLE chain_entries (i INTEGER)')\n"
            "c.execute('INSERT INTO chain_entries VALUES (0)')\n"
            "c.commit()\n"
            "c.execute('PRAGMA wal_checkpoint(FULL)')\n"
            "c.executemany('INSERT INTO chain_entries VALUES (?)',\n"
            "              [(i,) for i in range(1, 30)])\n"
            "c.commit()\n"
            "os.kill(os.getpid(), signal.SIGKILL)\n" % wal_db)
        subprocess.run([sys.executable, "-c", writer], capture_output=True)

        conn, tmpdir = chain_read._try_snapshot(wal_db)
        try:
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM chain_entries").fetchone()[0], 30,
                "the snapshot must include committed WAL frames")
        finally:
            conn.close()
            shutil.rmtree(tmpdir, ignore_errors=True)

        # And the source must be untouched by the copy.
        self.assertTrue(os.path.exists(wal_db + "-wal"))

    def test_immutable_is_never_chosen_implicitly(self):
        """immutable=1 can silently omit un-checkpointed WAL entries, so it
        must not be reachable without the explicit opt-in."""
        with chain_read.open_chain(self.db) as ch:
            self.assertNotEqual(ch.method, chain_read.METHOD_IMMUTABLE)
        with chain_read.open_chain(self.db, allow_immutable=True) as ch:
            # The safe method still wins when it works.
            self.assertEqual(ch.method, chain_read.METHOD_RO)

    def test_immutable_would_lose_wal_data(self):
        """The measurement that justifies rejecting immutable as a default."""
        wal_db = os.path.join(self.tmp, "loss.db")
        conn = sqlite3.connect(wal_db)
        conn.execute("PRAGMA journal_mode=wal")
        conn.execute("CREATE TABLE chain_entries (i INTEGER)")
        conn.execute("INSERT INTO chain_entries VALUES (0)")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(FULL)")
        for i in range(1, 40):
            conn.execute("INSERT INTO chain_entries VALUES (?)", (i,))
        conn.commit()

        ro = sqlite3.connect("file:%s?mode=ro" % wal_db, uri=True)
        imm = sqlite3.connect("file:%s?immutable=1" % wal_db, uri=True)
        n_ro = ro.execute("SELECT count(*) FROM chain_entries").fetchone()[0]
        n_imm = imm.execute("SELECT count(*) FROM chain_entries").fetchone()[0]
        ro.close()
        imm.close()
        conn.close()

        self.assertEqual(n_ro, 40, "mode=ro must see committed WAL data")
        self.assertLess(n_imm, n_ro,
                        "immutable=1 is expected to miss WAL entries; if this "
                        "ever stops being true the chain_read docstring and "
                        "method ordering should be revisited")

    def test_missing_database_is_a_clear_error(self):
        with self.assertRaises(chain_read.ChainReadError):
            chain_read.open_chain(os.path.join(self.tmp, "nope.db"))


class TestVerificationOnCleanChain(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="virp-report-test-")
        self.db = os.path.join(self.tmp, "chain.db")
        build_reference_chain(self.db)
        self.vs, self.summary = analyse(self.db)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_every_runnable_check_passes(self):
        s = self.summary
        self.assertEqual(s["entry_hash"][verify.FAIL], 0)
        self.assertEqual(s["link"][verify.FAIL], 0)
        self.assertEqual(s["chain_hmac"][verify.FAIL], 0)
        self.assertEqual(s["obs_hmac"][verify.FAIL], 0)
        self.assertEqual(s["failed_entries"], [])
        self.assertIsNone(s["first_broken_link"])

    def test_all_entries_hash_and_link(self):
        n = self.summary["entries"]
        self.assertEqual(self.summary["entry_hash"][verify.PASS], n)
        self.assertEqual(self.summary["link"][verify.PASS], n)

    def test_observation_hmacs_verify_under_the_okey(self):
        obs = self.summary["observations"]
        self.assertEqual(self.summary["obs_hmac"][verify.PASS], obs)

    def test_wrong_okey_fails_every_observation(self):
        _, summary = analyse(self.db, okey=b"\xff" * 32)
        self.assertEqual(summary["obs_hmac"][verify.PASS], 0)
        self.assertEqual(summary["obs_hmac"][verify.FAIL],
                         summary["observations"])

    def test_missing_keys_are_unchecked_not_passed(self):
        """A check that could not run must never be counted as a pass."""
        _, summary = analyse(self.db, okey=None, chain_key=None)
        self.assertEqual(summary["chain_hmac"][verify.PASS], 0)
        self.assertEqual(summary["chain_hmac"][verify.UNCHECKED],
                         summary["entries"])
        self.assertEqual(summary["obs_hmac"][verify.PASS], 0)

    def test_gate_rejection_binding_is_unverifiable_not_failed(self):
        """No body is stored for a gate rejection; that is a retention limit,
        not a verification failure."""
        gate = [v for v in self.vs
                if v.entry["artifact_type"] == "gate_rejection"]
        self.assertTrue(gate)
        for v in gate:
            self.assertEqual(v.artifact_bind, verify.UNVERIFIABLE)
            self.assertTrue(v.ok)

    def test_lifecycle_reconstruction(self):
        cycles = virp_report.build_lifecycles(self.vs)
        self.assertEqual(len(cycles), 2)
        by_id = {c["proposal_id"]: c for c in cycles}
        full = by_id["a" * 32]
        self.assertIsNotNone(full["proposal"])
        self.assertEqual(len(full["approvals"]), 1)
        self.assertEqual(len(full["outcomes"]), 1)
        self.assertEqual(full["flags"], [])

        orphan = by_id["f" * 32]
        self.assertIn("NO OUTCOME", [f[0] for f in orphan["flags"]])

    def test_exceptions_are_collected(self):
        ex = virp_report.collect_exceptions(self.vs)
        self.assertEqual(len(ex["gate"]), 1)
        self.assertEqual(len(ex["disagreements"]), 1)
        self.assertEqual(len(ex["outages"]), 1)
        # RED: the RED-tier observation plus the two RED proposals.
        self.assertEqual(len(ex["red"]), 3)

    def test_pdf_is_produced(self):
        out = os.path.join(self.tmp, "r.pdf")
        code = run_report(self.db, out,
                          ["--okey", self._keyfile(TEST_OKEY),
                           "--chain-key", self._keyfile(TEST_CHAIN_KEY)])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(out))
        with open(out, "rb") as fh:
            self.assertEqual(fh.read(5), b"%PDF-")
        self.assertGreater(os.path.getsize(out), 3000)

    def _keyfile(self, key):
        path = os.path.join(self.tmp, "k-%s" % key[:2].hex())
        with open(path, "wb") as fh:
            fh.write(key)
        return path


class TestTamperDetection(unittest.TestCase):
    """A tampered chain must be REPORTED, not crashed on and not hidden."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="virp-report-tamper-")
        self.db = os.path.join(self.tmp, "chain.db")
        build_reference_chain(self.db)
        self.okey_file = os.path.join(self.tmp, "okey")
        with open(self.okey_file, "wb") as fh:
            fh.write(TEST_OKEY)
        self.chain_key_file = os.path.join(self.tmp, "ckey")
        with open(self.chain_key_file, "wb") as fh:
            fh.write(TEST_CHAIN_KEY)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _flip_one_byte_of(self, where_sql, column="chain_entry_hash"):
        """Flip a single byte in the database FILE for the matching row.

        One hex digit is changed in place, keeping the length identical so
        SQLite's page structure stays valid — the point is to corrupt
        evidence, not the container.
        """
        conn = sqlite3.connect(self.db)
        rowid = conn.execute(
            "SELECT id FROM chain_entries WHERE %s" % where_sql).fetchone()[0]
        conn.close()
        return flip_byte_changing_row(self.db, rowid, column)

    def test_flipped_entry_hash_is_reported(self):
        self._flip_one_byte_of(
            "session_id='autopilot:test' AND sequence=1")
        _, summary = analyse(self.db)

        self.assertGreater(summary["entry_hash"][verify.FAIL], 0,
                           "a flipped entry hash must be reported as FAIL")
        self.assertTrue(summary["failed_entries"])
        # The successor's link to it must also break.
        self.assertGreater(summary["link"][verify.FAIL], 0)
        self.assertIsNotNone(summary["first_broken_link"])

    def test_flipped_artifact_hash_breaks_hash_hmac_and_binding(self):
        """Tampering with a field inside the canonical JSON must be caught by
        the entry hash, the chain HMAC and the artifact binding at once."""
        self._flip_one_byte_of("artifact_type='observation' LIMIT 1",
                               column="artifact_hash")
        _, summary = analyse(self.db)
        self.assertGreater(summary["entry_hash"][verify.FAIL], 0)
        self.assertGreater(summary["chain_hmac"][verify.FAIL], 0)
        self.assertGreater(summary["artifact_bind"][verify.FAIL], 0)

    def test_tampered_observation_body_fails_the_okey_hmac(self):
        """Rewriting a signed observation's payload must fail the O-Key HMAC
        rather than pass because the stored bytes were trusted."""
        conn = sqlite3.connect(self.db)
        aid, content = conn.execute(
            "SELECT artifact_id, artifact_content FROM artifacts "
            "WHERE artifact_content LIKE 'base64:%' LIMIT 1").fetchone()
        import base64
        raw = bytearray(base64.b64decode(content[7:]))
        raw[-1] ^= 0xFF  # flip a byte of the signed payload
        conn.execute("UPDATE artifacts SET artifact_content=? "
                     "WHERE artifact_id=?",
                     ("base64:" + base64.b64encode(bytes(raw)).decode(), aid))
        conn.commit()
        conn.close()

        _, summary = analyse(self.db)
        self.assertGreater(summary["obs_hmac"][verify.FAIL], 0)
        self.assertGreater(summary["artifact_bind"][verify.FAIL], 0)

    def test_report_still_renders_and_reports_nonzero_exit(self):
        """The PDF must still be produced for a broken chain — that is when it
        is most needed — and the failure must surface in the exit code."""
        self._flip_one_byte_of(
            "session_id='autopilot:test' AND sequence=1")
        out = os.path.join(self.tmp, "tampered.pdf")
        code = run_report(self.db, out,
                          ["--okey", self.okey_file,
                           "--chain-key", self.chain_key_file])
        self.assertEqual(code, 1, "a failed verification must exit non-zero")
        self.assertTrue(os.path.exists(out))
        with open(out, "rb") as fh:
            self.assertEqual(fh.read(5), b"%PDF-")

    def test_failures_appear_in_the_rendered_text(self):
        """The failure must be visible in the document, not merely counted."""
        self._flip_one_byte_of(
            "session_id='autopilot:test' AND sequence=1")
        out = os.path.join(self.tmp, "tampered.pdf")
        run_report(self.db, out, ["--okey", self.okey_file,
                                  "--chain-key", self.chain_key_file])
        text = extract_pdf_text(out)
        if text is None:
            self.skipTest("no pdftotext available to inspect the PDF")
        self.assertIn("FAILED", text)
        self.assertIn("FIRST BROKEN LINK", text)

    def test_truncated_chain_tail_is_not_a_false_failure(self):
        """Deleting the last entry of a session leaves a shorter but
        internally consistent chain. The report must not invent a failure —
        and the limitations appendix says so explicitly."""
        conn = sqlite3.connect(self.db)
        conn.execute("DELETE FROM chain_entries WHERE session_id="
                     "'autopilot:test' AND sequence=("
                     "SELECT max(sequence) FROM chain_entries "
                     "WHERE session_id='autopilot:test')")
        conn.commit()
        conn.close()
        _, summary = analyse(self.db)
        self.assertEqual(summary["failed_entries"], [])
        self.assertIsNone(summary["first_broken_link"])

    def test_deleted_middle_entry_breaks_the_chain(self):
        """A hole in the middle of a session must be caught as a sequence
        gap, which is the case truncation-detection actually can cover."""
        conn = sqlite3.connect(self.db)
        conn.execute("DELETE FROM chain_entries "
                     "WHERE session_id='autopilot:test' AND sequence=2")
        conn.commit()
        conn.close()
        _, summary = analyse(self.db)
        self.assertGreater(summary["link"][verify.FAIL], 0)
        self.assertIsNotNone(summary["first_broken_link"])


class TestCLIArgumentHandling(unittest.TestCase):
    def test_timestamp_parsing_forms(self):
        self.assertEqual(virp_report.parse_timestamp("1785300000"),
                         1785300000 * 10 ** 9)
        self.assertEqual(
            virp_report.parse_timestamp("1785300000000000000"),
            1785300000000000000)
        self.assertEqual(
            virp_report.parse_timestamp("2026-07-29T00:00:00Z"),
            int(1785283200 * 10 ** 9))
        # A bare date is midnight UTC.
        self.assertEqual(virp_report.parse_timestamp("2026-07-29"),
                         virp_report.parse_timestamp("2026-07-29T00:00:00Z"))

    def test_bad_timestamp_raises(self):
        with self.assertRaises(ValueError):
            virp_report.parse_timestamp("not-a-time")

    def test_since_after_until_is_rejected(self):
        tmp = tempfile.mkdtemp(prefix="virp-report-cli-")
        try:
            db = os.path.join(tmp, "chain.db")
            build_reference_chain(db)
            code = virp_report.main([
                "--db", db, "--out", os.path.join(tmp, "x.pdf"),
                "--since", "2026-07-30", "--until", "2026-07-29"])
            self.assertEqual(code, 2)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def extract_pdf_text(path):
    """Best-effort text extraction, for asserting on rendered content."""
    try:
        out = subprocess.run(["pdftotext", "-layout", path, "-"],
                             capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.decode("utf-8", errors="replace")


# ── live-chain tests ──────────────────────────────────────────────────────

@unittest.skipUnless(os.path.exists(LIVE_DB),
                     "no live chain at %s" % LIVE_DB)
class TestAgainstLiveChain(unittest.TestCase):
    """Read a real chain.db while the daemon may be running.

    These assert agreement with an INDEPENDENT count of the same database,
    which is the check that matters: the report's numbers must be reproducible
    by someone who did not use the report's code.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="virp-report-live-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_opens_live_chain_without_disturbing_it(self):
        before = os.stat(LIVE_DB).st_mtime_ns
        with chain_read.open_chain(LIVE_DB) as ch:
            self.assertIn(ch.method,
                          (chain_read.METHOD_RO, chain_read.METHOD_SNAPSHOT))
            n = ch.conn.execute(
                "SELECT count(*) FROM chain_entries").fetchone()[0]
        self.assertGreater(n, 0)
        # The daemon owns this file; we must not have modified it.
        self.assertEqual(os.stat(LIVE_DB).st_mtime_ns, before)

    def test_report_numbers_match_an_independent_count(self):
        """The integrity figures must agree with separately-written code.

        Both sides read inside the same moment as closely as possible, but the
        daemon may append between them, so the report's totals are allowed to
        be >= the independent snapshot taken just before. Hash/link agreement
        is asserted exactly on the overlap.
        """
        indep = independent_counts(LIVE_DB)

        okey = chain_key = None
        try:
            okey = verify.load_key(LIVE_OKEY)
        except (OSError, ValueError):
            pass
        try:
            chain_key = verify.load_key(LIVE_CHAIN_KEY)
        except (OSError, ValueError):
            pass

        with chain_read.open_chain(LIVE_DB) as reader:
            entries, artifacts = virp_report.load_evidence(reader)
            _, summary = verify.verify_chain(entries, artifacts, okey=okey,
                                            chain_key=chain_key)

        self.assertGreaterEqual(summary["entries"], indep["total"])
        self.assertGreaterEqual(summary["observations"],
                                indep["observations"])
        self.assertGreaterEqual(summary["sessions"], indep["sessions"])

        # Every entry the independent walk hashed correctly must also be
        # correct in the report, and the report must claim no more passes
        # than it has entries.
        self.assertEqual(indep["hash_ok"], indep["total"],
                         "the live chain's own entry hashes must recompute")
        self.assertEqual(indep["links_ok"], indep["total"],
                         "the live chain's links must be continuous")
        self.assertEqual(summary["entry_hash"][verify.PASS],
                         summary["entries"])
        self.assertEqual(summary["link"][verify.PASS], summary["entries"])
        self.assertEqual(summary["entry_hash"][verify.FAIL], 0)
        self.assertEqual(summary["link"][verify.FAIL], 0)

    def test_unverifiable_is_never_counted_as_pass(self):
        with chain_read.open_chain(LIVE_DB) as reader:
            entries, artifacts = virp_report.load_evidence(reader)
            _, summary = verify.verify_chain(entries, artifacts)
        for check in ("entry_hash", "link", "chain_hmac", "artifact_bind",
                      "obs_hmac"):
            tally = summary[check]
            self.assertEqual(
                sum(tally.values()), summary["entries"],
                "%s tally must account for every entry exactly once" % check)

    @unittest.skipUnless(os.access(LIVE_OKEY, os.R_OK),
                         "O-Key not readable by this user")
    def test_live_observations_verify_under_the_real_okey(self):
        okey = verify.load_key(LIVE_OKEY)
        with chain_read.open_chain(LIVE_DB) as reader:
            entries, artifacts = virp_report.load_evidence(reader)
            _, summary = verify.verify_chain(entries, artifacts, okey=okey)
        self.assertEqual(summary["obs_hmac"][verify.FAIL], 0)
        self.assertGreater(summary["obs_hmac"][verify.PASS], 0)

    def test_generates_a_pdf_from_the_live_chain(self):
        out = os.path.join(self.tmp, "live.pdf")
        code = virp_report.main(["--db", LIVE_DB, "--out", out])
        self.assertIn(code, (0, 1))
        self.assertTrue(os.path.exists(out))
        with open(out, "rb") as fh:
            self.assertEqual(fh.read(5), b"%PDF-")

    def test_tamper_on_a_copy_of_the_live_chain_is_reported(self):
        """The requested tamper drill, against real data: consolidate the live
        chain into a standalone copy, flip one byte, and confirm the report
        says so instead of crashing or quietly omitting the entry."""
        copy = os.path.join(self.tmp, "copy.db")
        with chain_read.open_chain(LIVE_DB) as reader:
            dst = sqlite3.connect(copy)
            reader.conn.backup(dst)
            dst.close()

        conn = sqlite3.connect(copy)
        rowid = conn.execute(
            "SELECT id FROM chain_entries WHERE sequence > 0 "
            "ORDER BY id LIMIT 1").fetchone()[0]
        conn.close()

        flip_byte_changing_row(copy, rowid, "chain_entry_hash")

        with chain_read.open_chain(copy) as reader:
            entries, artifacts = virp_report.load_evidence(reader)
            _, summary = verify.verify_chain(entries, artifacts)

        self.assertGreater(summary["entry_hash"][verify.FAIL], 0)
        self.assertTrue(summary["failed_entries"])

        out = os.path.join(self.tmp, "tampered-live.pdf")
        code = virp_report.main(["--db", copy, "--out", out])
        self.assertEqual(code, 1)
        self.assertTrue(os.path.exists(out))


if __name__ == "__main__":
    unittest.main(verbosity=2)
