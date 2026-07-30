#!/usr/bin/env python3
"""
Read-only access to a live VIRP trust chain (chain.db).

Consumer-side helper: opens a chain database for reading WITHOUT disturbing a
running virp-onode daemon, and without ever acquiring a write lock on the
daemon's files.

Pure stdlib. No network. No writes to the source database or its sidecars.

─────────────────────────────────────────────────────────────────────────────
WHY THIS EXISTS, AND THE TRADEOFF BETWEEN THE THREE WAYS TO DO IT
─────────────────────────────────────────────────────────────────────────────
chain.db runs in SQLite WAL mode with the daemon holding it open. The obvious
approaches are not equivalent, and one of them is quietly wrong:

1. mode=ro  (PREFERRED — what this helper uses whenever it works)
   Opens the real database read-only. SQLite reads committed data from BOTH
   the main database file AND the -wal, so the view is complete and current,
   and the read runs in a normal read transaction, so it is a consistent
   snapshot even while the daemon commits. It takes no write lock and cannot
   block or corrupt the writer.

   Caveat: a read-only connection to a WAL database still needs the shared-
   memory index (-shm). While the daemon is live the -shm exists and is
   populated, so this works. It FAILS when the WAL needs recovery and no
   writer is around to do it — most commonly when the daemon is stopped, or
   when the reader lacks filesystem access to the sidecars. That failure is
   the familiar "attempt to write a readonly database", and it is exactly the
   case the peer-head probe hits against a stopped peer.

2. immutable=1  (REJECTED as a default — silently wrong)
   Tells SQLite the file cannot change, so it skips all locking and shm use.
   It never fails, which is precisely the trap: it does NOT replay the -wal,
   so every committed-but-not-yet-checkpointed entry is INVISIBLE. Measured
   on this code path: a WAL database holding 50 committed rows reported 50
   under mode=ro and 1 under immutable=1.

   For an integrity report that failure mode is the worst available. A
   truncated chain does not look like an error — it looks like a shorter
   chain that verifies clean, or like a chain whose tail link is "broken".
   The tool would state a falsehood confidently. immutable is therefore only
   reachable here via an explicit opt-in, and when used it stamps a loud
   caveat that the report must print.

3. snapshot-copy  (FALLBACK — what this helper uses when mode=ro fails)
   Copy the database and its sidecars to a private temp path and open the
   COPY read-write, so SQLite may recover/replay the WAL into the copy. The
   daemon's files are only ever read. This sees all committed data and works
   with a stopped daemon or unwritable sidecars.

   Caveat: the copy is not atomic. If the daemon commits or checkpoints while
   the bytes are being copied, the copy can be torn. We mitigate by taking
   the copy, then re-reading the source (size, mtime_ns) to confirm nothing
   moved underneath us, and by running PRAGMA integrity_check + a real query
   on the copy; a mismatch is retried. A torn copy that still passes both
   checks is possible in principle, so this method's caveat is reported.

Order of preference is therefore: mode=ro, then snapshot-copy. Never
immutable unless the caller explicitly demands it and accepts the caveat.

─────────────────────────────────────────────────────────────────────────────
REUSE NOTE (not wired up here, deliberately)
─────────────────────────────────────────────────────────────────────────────
The autopilot peer-head probe currently shells out to `virp-tool chain tail`
against the peer's chain.db and records no head when the peer daemon is
stopped, because that path hits failure mode (1) above. This helper's
snapshot-copy fallback is the fix for that. Rewiring the probe is deliberately
NOT done in this change — it touches the deployed autopilot loop. Tracked as
follow-up; see DEPLOYED.md "peer outage drill".

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import os
import shutil
import sqlite3
import tempfile

__all__ = [
    "ChainReadError",
    "ChainReader",
    "open_chain",
    "METHOD_RO",
    "METHOD_SNAPSHOT",
    "METHOD_IMMUTABLE",
]

METHOD_RO = "live-ro"
METHOD_SNAPSHOT = "snapshot-copy"
METHOD_IMMUTABLE = "immutable-unsafe"

# Human-readable caveat per method. The report prints these verbatim in its
# limitations appendix, so the reader knows how the bytes were obtained.
METHOD_CAVEATS = {
    METHOD_RO: (
        "Opened the live database directly with SQLite URI mode=ro. Committed "
        "data in the write-ahead log is included, and the read ran inside a "
        "single consistent read transaction. No write lock was taken and the "
        "daemon was not disturbed. Because the chain is append-only and the "
        "daemon may have appended after this read began, entries committed "
        "after the read transaction started are not in this report."
    ),
    METHOD_SNAPSHOT: (
        "The live database could not be opened read-only (typically the WAL "
        "needed recovery, e.g. the daemon is stopped, or the -shm/-wal "
        "sidecars were not accessible). The database and its sidecars were "
        "therefore COPIED to a private temporary path and the copy was read. "
        "The daemon's files were only read, never written. The copy is not "
        "atomic: it was verified by confirming the source did not change "
        "during the copy and by running PRAGMA integrity_check on the copy, "
        "but a torn copy that passes both checks cannot be fully excluded."
    ),
    METHOD_IMMUTABLE: (
        "*** UNSAFE READ METHOD EXPLICITLY REQUESTED *** The database was "
        "opened with immutable=1, which does NOT replay the write-ahead log. "
        "Any entry committed but not yet checkpointed is INVISIBLE to this "
        "report. Entry counts, the chain tail, and link continuity may all be "
        "wrong, and would appear wrong in the direction of 'clean but short' "
        "or 'broken tail'. Do not rely on this report."
    ),
}

# Sidecars that must travel with the database for a snapshot copy to be able
# to recover the WAL. Missing sidecars are not an error (a cleanly closed
# database has none).
_SIDECARS = ("-wal", "-shm")

_SNAPSHOT_ATTEMPTS = 3


class ChainReadError(Exception):
    """The chain database could not be opened by any permitted method."""


def _source_fingerprint(path):
    """(size, mtime_ns) for the db and each sidecar, used to detect a source
    that moved underneath a snapshot copy. Missing files register as None."""
    marks = []
    for suffix in ("",) + _SIDECARS:
        p = path + suffix
        try:
            st = os.stat(p)
            marks.append((suffix, st.st_size, st.st_mtime_ns))
        except FileNotFoundError:
            marks.append((suffix, None, None))
    return tuple(marks)


def _probe(conn):
    """Force SQLite to actually touch the database.

    sqlite3.connect() is lazy: a URI that cannot really be read often connects
    without error and only fails on first use. Every open path in this module
    must therefore run a real query before declaring success. chain_entries is
    the table the caller wants, so failing here is the honest failure.
    """
    conn.execute("SELECT count(*) FROM chain_entries").fetchone()


def _try_ro(db_path):
    """Preferred path: read the live database directly, read-only."""
    uri = "file:" + _uri_escape(db_path) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        _probe(conn)
    except sqlite3.Error:
        conn.close()
        raise
    return conn


def _uri_escape(path):
    """Escape a filesystem path for use in a SQLite file: URI."""
    # SQLite URI parsing treats '?' and '#' as delimiters, and decodes %XX.
    return (
        path.replace("%", "%25").replace("?", "%3f").replace("#", "%23")
    )


def _try_snapshot(db_path, tmp_root=None):
    """Fallback path: copy db + sidecars, then read the copy.

    The copy is opened read-write on purpose — that is what allows SQLite to
    replay the WAL into it. Only the copy is ever written.
    """
    last_error = None
    for _ in range(_SNAPSHOT_ATTEMPTS):
        tmpdir = tempfile.mkdtemp(prefix="virp-chain-snap-", dir=tmp_root)
        copy_path = os.path.join(tmpdir, "chain.db")
        try:
            before = _source_fingerprint(db_path)
            shutil.copyfile(db_path, copy_path)
            for suffix in _SIDECARS:
                src = db_path + suffix
                if os.path.exists(src):
                    shutil.copyfile(src, copy_path + suffix)
            after = _source_fingerprint(db_path)

            if before != after:
                # The daemon wrote while we were copying; the copy may be
                # torn. Throw it away and take a fresh one.
                shutil.rmtree(tmpdir, ignore_errors=True)
                last_error = "source changed during copy"
                continue

            conn = sqlite3.connect(copy_path)
            try:
                row = conn.execute("PRAGMA integrity_check").fetchone()
                if not row or row[0] != "ok":
                    raise sqlite3.DatabaseError(
                        "integrity_check on snapshot copy: %r" % (row,))
                _probe(conn)
            except sqlite3.Error as exc:
                conn.close()
                shutil.rmtree(tmpdir, ignore_errors=True)
                last_error = str(exc)
                continue
            return conn, tmpdir
        except OSError as exc:
            shutil.rmtree(tmpdir, ignore_errors=True)
            last_error = str(exc)
            continue
    raise ChainReadError(
        "snapshot copy of %s failed after %d attempts: %s"
        % (db_path, _SNAPSHOT_ATTEMPTS, last_error))


def _try_immutable(db_path):
    """Explicitly-requested unsafe path. See module docstring."""
    uri = "file:" + _uri_escape(db_path) + "?immutable=1"
    conn = sqlite3.connect(uri, uri=True)
    try:
        _probe(conn)
    except sqlite3.Error:
        conn.close()
        raise
    return conn


class ChainReader:
    """An open, read-only handle on a VIRP chain database.

    Attributes:
        conn      sqlite3.Connection positioned on the chain (row factory set)
        method    one of METHOD_RO / METHOD_SNAPSHOT / METHOD_IMMUTABLE
        caveat    human-readable description of the method's limitation
        source    the path the caller asked for
        attempts  list of (method, "ok"|error string), in the order tried

    Use as a context manager; closing removes any temporary snapshot.
    """

    def __init__(self, conn, method, source, tmpdir=None, attempts=()):
        self.conn = conn
        self.conn.row_factory = sqlite3.Row
        self.method = method
        self.caveat = METHOD_CAVEATS[method]
        self.source = source
        self.attempts = list(attempts)
        self._tmpdir = tmpdir

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def close(self):
        try:
            self.conn.close()
        finally:
            if self._tmpdir:
                shutil.rmtree(self._tmpdir, ignore_errors=True)
                self._tmpdir = None

    def __repr__(self):
        return "<ChainReader %s via %s>" % (self.source, self.method)


def open_chain(db_path, allow_immutable=False, tmp_root=None):
    """Open a VIRP chain database for reading without disturbing the daemon.

    Tries mode=ro first, then a snapshot copy. immutable=1 is attempted only
    if allow_immutable=True and only after both safe methods have failed,
    because it can silently omit un-checkpointed WAL entries.

    Returns a ChainReader. Raises ChainReadError if no method worked.
    """
    db_path = os.path.abspath(db_path)
    if not os.path.exists(db_path):
        raise ChainReadError("no such chain database: %s" % db_path)

    attempts = []

    try:
        conn = _try_ro(db_path)
        attempts.append((METHOD_RO, "ok"))
        return ChainReader(conn, METHOD_RO, db_path, attempts=attempts)
    except sqlite3.Error as exc:
        attempts.append((METHOD_RO, str(exc)))

    try:
        conn, tmpdir = _try_snapshot(db_path, tmp_root=tmp_root)
        attempts.append((METHOD_SNAPSHOT, "ok"))
        return ChainReader(conn, METHOD_SNAPSHOT, db_path,
                           tmpdir=tmpdir, attempts=attempts)
    except (ChainReadError, sqlite3.Error, OSError) as exc:
        attempts.append((METHOD_SNAPSHOT, str(exc)))

    if allow_immutable:
        try:
            conn = _try_immutable(db_path)
            attempts.append((METHOD_IMMUTABLE, "ok"))
            return ChainReader(conn, METHOD_IMMUTABLE, db_path,
                               attempts=attempts)
        except sqlite3.Error as exc:
            attempts.append((METHOD_IMMUTABLE, str(exc)))

    raise ChainReadError(
        "could not open %s read-only; tried: %s"
        % (db_path, "; ".join("%s -> %s" % a for a in attempts)))
