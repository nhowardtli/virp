#!/usr/bin/env python3
"""The head/entry race in tools/bundle/virp_export_bundle.py.

The exporter reads chain_entries and chain_heads. If those two reads
straddle an append, the bundle has entries stopping at N and a head
committing to N+1 -- a healthy chain exported into a bundle that fails
head_commitment in the verifier, where it reads as a broken chain rather
than as a tool that read the database twice. The 313 full-chain export
and the public sample bundle were both produced by an exporter of this
shape (Docket's, in ~/docket) and happened not to hit it.

The fix committed in cebaeca is `BEGIN DEFERRED` around both reads plus
an invariant assert. This file is the test that was missing: it drives an
actual concurrent writer rather than describing one.

Run: python3 -m pytest tests/test_export_bundle_race.py
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
EXPORTER = os.path.join(REPO, "tools", "bundle", "virp_export_bundle.py")
sys.path.insert(0, os.path.join(REPO, "tools", "bundle"))
import virp_export_bundle as veb  # noqa: E402

SESSION = "gate-enforce:R1"

ENTRY_COLS = [
    "session_id", "sequence", "chain_entry_hash", "previous_entry_hash",
    "timestamp_ns", "monotonic_ns", "artifact_type", "artifact_id",
    "artifact_hash", "artifact_hash_alg", "artifact_schema_version",
    "signer_node_id", "signer_org_id", "chain_hmac",
]


def build_db(path, n_entries=5):
    """A minimal chain database with exactly the columns the exporter
    reads. Hashes are not real -- this test is about WHICH rows come out
    together, not about whether they verify."""
    c = sqlite3.connect(path)
    int_cols = {"sequence", "timestamp_ns", "monotonic_ns",
                "artifact_schema_version", "signer_node_id"}
    c.execute("CREATE TABLE chain_entries (%s)" % ", ".join(
        "%s %s" % (col, "INTEGER" if col in int_cols else "TEXT")
        for col in ENTRY_COLS))
    c.execute("CREATE TABLE chain_heads (session_id TEXT, last_sequence INT, "
              "last_entry_hash TEXT, head_hmac TEXT)")
    c.execute("CREATE TABLE artifacts (artifact_hash TEXT, "
              "artifact_content TEXT)")
    for i in range(n_entries):
        c.execute(
            "INSERT INTO chain_entries (%s) VALUES (%s)"
            % (", ".join(ENTRY_COLS), ", ".join("?" * len(ENTRY_COLS))),
            (SESSION, i, "%064x" % (0xa000 + i), "%064x" % (0xa000 + i - 1),
             1700000000000000000 + i, i, "gate_rejection",
             "gatereject-%02d" % i, "%064x" % (0xb000 + i), "sha256", 1,
             0x0badcafe, "local", "%064x" % (0xc000 + i)))
    c.execute("INSERT INTO chain_heads VALUES (?, ?, ?, ?)",
              (SESSION, n_entries - 1, "%064x" % (0xa000 + n_entries - 1),
               "%064x" % 0xd000))
    c.commit()
    c.close()


class ExportHeadEntryRace(unittest.TestCase):

    def test_quiet_database_exports_a_consistent_bundle(self):
        """The guard must be invisible when nothing writes."""
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "chain.db")
            build_db(db)
            out = os.path.join(tmp, "bundle")
            veb.export(db, out, "test")
            with open(os.path.join(out, "sessions", veb.safe_name(SESSION)
                                   + ".json")) as f:
                doc = json.load(f)
            self.assertEqual(doc["head"]["last_sequence"],
                             max(e["sequence"] for e in doc["entries"]))

    def test_skewed_snapshot_is_refused_and_names_both_numbers(self):
        """The state a mid-read append leaves behind. `export()` retries
        first -- and on a database that stays skewed, every retry sees the
        same thing and it gives up rather than shipping it."""
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "chain.db")
            build_db(db)
            w = sqlite3.connect(db)
            w.execute("UPDATE chain_heads SET last_sequence = 99")
            w.commit()
            w.close()

            out = os.path.join(tmp, "bundle")
            with self.assertRaises(veb.InconsistentSnapshot) as cm:
                veb.export(db, out, "test", retries=1)
            msg = str(cm.exception)
            # A reader must be able to tell an exporter race from a
            # tampered head, so the message names the session and BOTH
            # sequence numbers.
            self.assertIn(SESSION, msg)
            self.assertIn("99", msg)
            self.assertIn("4", msg)
            self.assertFalse(os.path.exists(os.path.join(out, "manifest.json")))

    def test_cli_exits_nonzero_on_a_skewed_snapshot(self):
        """Not a traceback: an operator gets the sentence and a nonzero
        status."""
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "chain.db")
            build_db(db)
            w = sqlite3.connect(db)
            w.execute("UPDATE chain_heads SET last_sequence = 99")
            w.commit()
            w.close()
            r = subprocess.run(
                [sys.executable, EXPORTER, "--db", db,
                 "--out", os.path.join(tmp, "bundle")],
                capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn(SESSION, r.stderr)
            self.assertIn("99", r.stderr)
            self.assertNotIn("Traceback", r.stderr)

    def test_concurrent_append_never_yields_a_skewed_bundle(self):
        """The race as a race: a writer appends entries and advances the
        head for the duration of the export. A racing writer is not
        deterministic and this does not pretend otherwise -- either
        outcome is allowed. What is pinned is the thing that must never
        happen: a bundle on disk whose head names a sequence its own
        entries do not contain."""
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "chain.db")
            build_db(db)
            stop = threading.Event()
            commits = [0]

            def writer():
                w = sqlite3.connect(db, timeout=5)
                seq = 5
                while not stop.is_set():
                    try:
                        w.execute(
                            "INSERT INTO chain_entries (%s) VALUES (%s)"
                            % (", ".join(ENTRY_COLS),
                               ", ".join("?" * len(ENTRY_COLS))),
                            (SESSION, seq, "%064x" % (0xa000 + seq),
                             "%064x" % (0xa000 + seq - 1),
                             1700000000000000000 + seq, seq,
                             "gate_rejection", "gatereject-%02d" % seq,
                             "%064x" % (0xb000 + seq), "sha256", 1,
                             0x0badcafe, "local", "%064x" % (0xc000 + seq)))
                        w.execute("UPDATE chain_heads SET last_sequence = ?",
                                  (seq,))
                        w.commit()
                        commits[0] += 1
                        seq += 1
                    except sqlite3.Error:
                        break
                w.close()

            t = threading.Thread(target=writer, daemon=True)
            t.start()
            out = os.path.join(tmp, "bundle")
            refused = False
            try:
                veb.export(db, out, "test", retries=2)
            except veb.InconsistentSnapshot:
                refused = True
            finally:
                stop.set()
                t.join(timeout=5)

            # If the writer never ran, this test proved nothing.
            self.assertGreater(commits[0], 0, "writer never committed")

            if refused:
                self.assertFalse(
                    os.path.exists(os.path.join(out, "manifest.json")))
                return

            with open(os.path.join(out, "sessions", veb.safe_name(SESSION)
                                   + ".json")) as f:
                doc = json.load(f)
            head = doc.get("head")
            if head is not None and doc["entries"]:
                last = max(e["sequence"] for e in doc["entries"])
                self.assertLessEqual(
                    head["last_sequence"], last,
                    "exported a head committing to sequence %s with entries "
                    "stopping at %s" % (head["last_sequence"], last))


if __name__ == "__main__":
    unittest.main()
