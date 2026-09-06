#!/usr/bin/env python3
"""
export_bundle.py — export a Docket evidence bundle (directory form) from a
VIRP chain database snapshot.

    python3 export_bundle.py --db <snapshot.db> --out <bundle-dir> \
        --sessions <id> [<id> ...] [--seal <seal-2026-08.json>] [--artifacts] \
        [--keys <pubfile> [<pubfile> ...]] [--seal-sig <file.minisig>] [--redacted] \
        [--witness <url> [--witness-receipts <dir>]]
    python3 export_bundle.py --db <snapshot.db> --out <bundle-dir> --all-sessions
    python3 export_bundle.py --db <snapshot.db> --list-sessions

What this script is
-------------------
An EXPORTER. It copies chain rows out of the database into the bundle format
that `docket-bundle` 0.1 / `virp-verify` read (DESIGN.md §2 in the Docket
repository). It copies hashes, HMACs and (if the D-1 columns exist)
signatures exactly as stored. It renumbers nothing, fills no gaps, lowercases
nothing, recomputes nothing. Every judgement about the chain — hashes, links,
genesis, contiguity, head commitment, signatures, seal anchoring — is
virp-verify's job. If this script "fixed" anything the bundle would be
worthless as evidence.

Structural sanity only: the expected tables and columns exist; every required
cell is present (not NULL) and of the expected type; hash/HMAC/signature
cells are hex. Anything else is exported as-is for the verifier to grade.

Safety
------
* Python 3 standard library only. No third-party imports.
* NO NETWORK, unless --witness is given. That flag is the only thing in this
  script that opens a socket, it talks to the URL the operator named and to
  nothing else, and it makes only GET requests: /v1/sth, /v1/proof and
  /v1/pubkey. It sends the witness nothing about the chain — not a session
  id, not a hash, not a head. It asks for a tree head, and for the audit path
  at a leaf index this script read out of a receipt file on this host. A
  witness that is down, slow or hostile can make rows say present=false with
  a reason; it cannot stop the export, alter a chain row, or fail the run.
* The database is opened READ-ONLY through a `file:...?mode=ro&immutable=1`
  URI. `immutable=1` additionally tells SQLite the file will not change
  underneath it, so it takes no locks and creates no `-journal`/`-wal`/`-shm`
  files beside the database. This is correct for a snapshot — which is the
  only thing this script should be pointed at — and still write-safe if it
  is pointed at a live database by mistake (reads may be torn; nothing is
  ever written).
* No PRAGMA that changes the database. `PRAGMA table_info` (read) is used for
  schema discovery; `PRAGMA query_only=ON` is set on the connection as a
  belt-and-braces guard (a connection setting, not a database change).
* Writes go ONLY under `--out`, which must not already exist.

Format facts this script relies on (from DESIGN.md and the fixture bundle)
-------------------------------------------------------------------------
manifest.json   docket_bundle_version "docket-bundle/0.1", chain_format "v1",
                producer, created_at, sessions[{session_id, path}], seal?
sessions/*.json {session_id, entries[...], head?}
  entry         the twelve canonical fields as JSON values (integers as
                numbers), chain_entry_hash, chain_hmac?, signature?
  head          session_id, last_sequence, last_entry_hash, head_hmac?,
                signature?
  signature     {signature_scheme: "ed25519-detached-v1", signing_key_id,
                signature_hex}
seal/<file>     the virp-seal/1 document, byte-for-byte.
seal/<file>.minisig  (--seal-sig only) the detached minisign SIGNATURE over
                the seal document, byte-for-byte, named in the manifest as
                "seal_signature". The signature may travel in the bundle —
                it is a claim the verifier grades. The PUBLIC KEY that
                checks it never travels in the bundle: virp-verify takes it
                out of band (--seal-key) or reports UNVERIFIABLE.
redaction       (--redacted only) a manifest BLOCK, not a file: the policy
                name, how many entries were withheld, and one record per
                withheld body (artifact_hash + original byte length). It sits
                outside every canonical byte the chain commits to: no session
                file changes, no hash changes, and virp-verify grades a
                redacted bundle exactly as it grades any hash-only one.
artifacts/<hash>  (--artifacts only) raw artifact-body bytes, one file per
                distinct artifact_hash, named in the manifest as
                {"artifact_hash": "...", "path": "artifacts/..."}. The bytes
                are recovered exactly as the producer hashed them: the
                daemon stores bodies in the `artifacts` table either as
                plain TEXT (hashed as UTF-8) or as "base64:<data>" (hashed
                as the decoded bytes). Decoding that envelope is transport
                unwrapping, not re-encoding — and the verifier recomputes
                SHA-256 over the carried bytes against each entry's
                artifact_hash, so a wrong recovery FAILS rather than
                passing. Entries whose (artifact_id, artifact_hash) pair
                has no body row export hash-only and the summary says so;
                a stored body that does not hash to its column value is
                exported AS STORED for the verifier to fail — fixing it
                here would be judging.
artifacts/<sha256>  (--referenced-artifacts only; it needs --artifacts) the
                REFERENCED artifacts as well — the files a camera record
                cites by digest but which have never travelled in a bundle:
                the segment video (segment_sha256), the validator's own
                output about it (sensor_signature.validator_output_sha256),
                and from /6 the device leaf certificate in DER
                (sensor_signature.device_chain.leaf_sha256).
                Listed in the manifest as referenced_artifacts[{sha256,
                cited_by, path, present}], separately from `artifacts`,
                because those are the record and these are the bytes the
                record is ABOUT.

                THE FILE IS NAMED BY THE CITED DIGEST, NOT BY ITS OWN HASH,
                and that is the whole point. A located file is carried
                VERBATIM whether or not it hashes to what the record cites,
                so a tampered segment lands at the cited name and the
                verifier recomputes it into a FAILED. Naming it by its own
                hash would file altered bytes under a name nobody looks up
                and turn tampering into absence — the one confusion this
                carriage cannot afford. Exports only; virp-verify judges.

                A cited artifact this exporter cannot find is listed with
                present=false and no path, NEVER omitted: "the bundle does
                not carry it" and "the record cites nothing" must not read
                the same, and the verifier grades a missing one ABSENT,
                which is not a pass.
witness/sth.json  (--witness only) the signed tree head the proofs below are
                against, as the witness served it: `sth_served` holds the
                response BYTES verbatim, so a reader sees exactly what
                arrived and the verifier checks the Ed25519 over the fields
                parsed out of those bytes. `witness_key_id` is the id the
                witness CLAIMED for itself at GET /v1/pubkey — recorded as a
                claim, exactly like keys.json, and proving nothing. The
                witness PUBLIC KEY never travels in the bundle; the examiner
                supplies it out of band (virp-verify --witness-key) or the
                result is UNVERIFIABLE.
witness/<session>.proof.json  (--witness only) one session's leaf and its
                RFC 9162 inclusion proof: the leaf (chain_id, sequence,
                head_hash, key_id, the submitter's signature over it, and the
                witness's timestamp), leaf_index, tree_size, and the audit
                path. The verifier recomputes the path to the root of the
                SIGNED head above — never to the unsigned root the proof
                endpoint also returns, which is carried only as context.

                HOW leaf_index IS RESOLVED, since this is the one thing the
                witness API cannot answer: it is read from the receipt the
                node-side submitter wrote when it submitted the head
                (~/virp-witness/deploy/node/virp-witness-submit, which writes
                <head>.witness.json beside each head under
                /var/lib/virp/witness/heads; --witness-receipts points
                elsewhere). Receipts are matched BY LEAF IDENTITY — all four
                of chain_id, sequence, head_hash and key_id must equal the
                ones this export computes from the session's own head — and
                never by file name, which is a hint and not evidence. The
                matched receipt's leaf_index is then confirmed by rebuilding
                the leaf and checking that it hashes to the leaf_hash the
                receipt carries, so the witness timestamp this bundle states
                is the one actually bound into the tree rather than one
                assumed from a neighbouring field.

                The witness API has no route from a leaf's identity to its
                index (GET /v1/proof takes leaf_index and tree_size only),
                which is why the receipt is required and why --witness alone
                is not enough on a host that never submitted.
keys.json       produced ONLY with --keys, from PUBLIC key files the operator
                supplies in either form virp-verify --pin also reads: 64 hex
                characters (the raw public key), or a docket keys.json
                object. The key_id is derived from the bytes either way.
                supplies (the chain schema has no table of public keys; the
                D-1 public half lives as a file on the daemon host, so there
                is nothing in a database to export). Without --keys nothing
                changes: no keys.json, no manifest pointer, and the bundle
                verifies as OPERATOR-ATTESTED — the expected outcome for
                every pre-D-1 (Era 2) session. With --keys, entries are
                written deterministically (sorted by key_id, normalized
                encoding) so the same inputs give byte-identical output;
                key_id is DERIVED from the key bytes (sha256-raw-16), never
                copied from a filename or label, and a stated id that does
                not re-derive is an error. A key file containing secret or
                seed material is refused: no private key material enters
                Docket, ever.

Reproducibility: SOURCE_DATE_EPOCH (unix seconds, the reproducible-builds
convention) pins the manifest's created_at so two exports of the same inputs
are byte-identical. Unset, created_at is the wall clock, as before.
canonical_utf8  NOT produced. The database does not store canonical bytes;
                the verifier rebuilds them from the twelve fields. Emitting a
                rebuilt copy would be computing, not exporting.
"""

import argparse
import base64
import binascii
import datetime
import glob
import hashlib
import json
import os
import re
import sqlite3
import sys
import urllib.parse
import urllib.request

VERSION = "0.1"
BUNDLE_VERSION = "docket-bundle/0.1"
CHAIN_FORMAT = "v1"
SIGNATURE_SCHEME = "ed25519-detached-v1"
SEAL_VERSION = "virp-seal/1"

# --- schema expectations (from src/virp_chain.c in the VIRP tree) ----------

# The twelve canonical fields, in canonical order, with the JSON type each
# must carry in the bundle ("str" or "int").
CANONICAL_FIELDS = [
    ("artifact_hash", "str"),
    ("artifact_hash_alg", "str"),
    ("artifact_id", "str"),
    ("artifact_schema_version", "str"),
    ("artifact_type", "str"),
    ("monotonic_ns", "int"),
    ("previous_entry_hash", "str"),
    ("sequence", "int"),
    ("session_id", "str"),
    ("signer_node_id", "int"),
    ("signer_org_id", "str"),
    ("timestamp_ns", "int"),
]

ENTRIES_TABLE = "chain_entries"
ENTRIES_REQUIRED = [name for name, _ in CANONICAL_FIELDS] + ["chain_entry_hash", "chain_hmac"]
ENTRIES_OPTIONAL = ["chain_sig", "chain_sig_key_id"]  # D-1; absent pre-cut-over

HEADS_TABLE = "chain_heads"
HEADS_REQUIRED = ["session_id", "last_sequence", "last_entry_hash", "head_hmac"]
HEADS_OPTIONAL = ["head_sig", "head_sig_key_id"]  # D-1; absent pre-cut-over

# Only consulted with --artifacts. The table is the daemon's body store;
# a database without it simply cannot carry bodies.
ARTIFACTS_TABLE = "artifacts"
ARTIFACTS_REQUIRED = ["artifact_id", "artifact_hash", "artifact_content"]

# The daemon's binary-body envelope in artifacts.artifact_content.
BASE64_PREFIX = "base64:"

# Cells that must be hex when present. Lengths are NOT enforced and case is
# NOT normalised: well-formedness beyond "is hex" is the verifier's call.
HEX_CELLS = {
    "chain_entry_hash",
    "previous_entry_hash",
    "chain_hmac",
    "last_entry_hash",
    "head_hmac",
    "chain_sig",
    "chain_sig_key_id",
    "head_sig",
    "head_sig_key_id",
}
HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


class ExportError(Exception):
    """A condition that stops the export. The message is the operator's
    round-trip: it names what was expected and what was found."""


# --- database ---------------------------------------------------------------


def refuse_unless_wal_is_empty(db_path):
    """A non-empty `-wal` beside the source is a REFUSAL, not a warning.

    `immutable=1` tells SQLite the file will not change, which is what
    keeps this exporter from taking locks or writing sidecars — and which
    also makes it IGNORE the write-ahead log entirely. Point it at a live
    daemon's database and it exports the last checkpointed state in
    silence: measured 2026-09-04, a 4.2 MB WAL held five freshly appended
    records and the bundle came out with fifteen entries instead of
    twenty, complete-looking and short.

    That is the same class of defect as an unreadable directory grading
    ABSENT — a quiet undercount presented as a full account — and it is
    worse here, because nothing downstream can detect it: the bundle is
    internally consistent, every hash and signature verifies, and the
    missing records leave no hole for the verifier to find.

    This REFUSES rather than checkpointing. Checkpointing writes to the
    source database, and "writes go ONLY under --out" is the invariant
    that makes this script safe to point at production. The operator
    checkpoints a COPY; the message says how."""
    wal = db_path + "-wal"
    try:
        size = os.path.getsize(wal)
    except OSError:
        return                                  # no WAL: nothing to drop
    if size == 0:
        return                                  # checkpointed already
    raise ExportError(
        f"{db_path} has a non-empty write-ahead log ({wal}, {size} bytes)\n"
        f"  This exporter opens the database with immutable=1, which IGNORES the WAL: every entry\n"
        f"  committed but not yet checkpointed would be silently missing from the bundle, and the\n"
        f"  result would look complete. Refusing rather than exporting an undercount.\n"
        f"  Checkpointing writes to the database, which this script will not do to your source.\n"
        f"  Snapshot and checkpoint a COPY, then export that:\n"
        f"    cp {db_path} /tmp/snap.db && cp {wal} /tmp/snap.db-wal\n"
        f"    python3 -c \"import sqlite3;c=sqlite3.connect('/tmp/snap.db');\"\n"
        f"             \"c.execute('PRAGMA wal_checkpoint(TRUNCATE)');c.commit()\"\n"
        f"    export_bundle.py --db /tmp/snap.db ..."
    )


def open_readonly(db_path):
    """Open the database read-only and immutable. Never creates the file."""
    if not os.path.isfile(db_path):
        raise ExportError(f"database not found: {db_path}")
    refuse_unless_wal_is_empty(db_path)
    abs_path = os.path.abspath(db_path)
    uri = "file:" + urllib.parse.quote(abs_path, safe="/") + "?mode=ro&immutable=1"
    try:
        conn = sqlite3.connect(uri, uri=True)
        conn.execute("PRAGMA query_only = ON")
        # Touch the schema so an unreadable / non-SQLite file fails here,
        # with the path in the message, rather than deep in the export.
        conn.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
    except sqlite3.Error as e:
        raise ExportError(f"cannot open {db_path} read-only: {e}") from e
    return conn


def table_columns(conn, table):
    """Column names of `table`, or None if the table does not exist."""
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    if not rows:
        return None
    return [r[1] for r in rows]


def discover_schema(conn):
    """Confirm the tables/columns this exporter needs. Returns a dict of
    which optional (D-1) columns are present. Raises ExportError naming
    expected vs found on any shortfall."""
    found_tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    problems = []
    present = {}
    for table, required, optional in (
        (ENTRIES_TABLE, ENTRIES_REQUIRED, ENTRIES_OPTIONAL),
        (HEADS_TABLE, HEADS_REQUIRED, HEADS_OPTIONAL),
    ):
        cols = table_columns(conn, table)
        if cols is None:
            problems.append(f"  table {table!r}: MISSING\n    tables found: {found_tables}")
            continue
        missing = [c for c in required if c not in cols]
        if missing:
            problems.append(
                f"  table {table!r}: missing required column(s) {missing}\n"
                f"    expected: {required}\n"
                f"    found:    {cols}"
            )
        for c in optional:
            present[c] = c in cols
    if problems:
        raise ExportError("schema drift — the snapshot does not match what this exporter expects:\n" + "\n".join(problems))
    # D-1 columns come in pairs; half a pair is drift, not a feature.
    for a, b in (("chain_sig", "chain_sig_key_id"), ("head_sig", "head_sig_key_id")):
        if present[a] != present[b]:
            raise ExportError(f"schema drift — found only one of the D-1 column pair {a!r}/{b!r}")
    return present


def list_sessions(conn):
    """(session_id, entry_count, has_head) for every session, by id."""
    entries = {
        r[0]: r[1]
        for r in conn.execute(f"SELECT session_id, COUNT(*) FROM {ENTRIES_TABLE} GROUP BY session_id")
    }
    heads = {r[0] for r in conn.execute(f"SELECT session_id FROM {HEADS_TABLE}")}
    ids = sorted(set(entries) | heads)
    return [(sid, entries.get(sid, 0), sid in heads) for sid in ids]


# --- cell checks (structural sanity only) ---------------------------------


def check_cell(where, name, value, kind):
    """`kind` is "str", "int" or "hex". Returns the value unchanged."""
    if value is None:
        raise ExportError(f"{where}: column {name!r} is NULL; the bundle format requires a value")
    if kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ExportError(f"{where}: column {name!r} expected INTEGER, found {type(value).__name__} {value!r}")
    else:
        if isinstance(value, bytes):
            raise ExportError(f"{where}: column {name!r} is a BLOB; expected TEXT")
        if not isinstance(value, str):
            raise ExportError(f"{where}: column {name!r} expected TEXT, found {type(value).__name__} {value!r}")
        if kind == "hex" and not HEX_RE.match(value):
            raise ExportError(f"{where}: column {name!r} is not hex: {value!r}")
    return value


def optional_hmac(where, name, value):
    """HMAC columns: NULL means absent (the bundle omits the key). An EMPTY
    string is exported as-is — turning it into "absent" would change the
    verifier's grade from FAILED (malformed) to "nothing attests", which is
    exactly the kind of fix this exporter must not make."""
    if value is None:
        return None
    if value == "":
        return value
    return check_cell(where, name, value, "hex")


def optional_sig(where, name, value):
    """D-1 signature columns: NULL or empty string means unsigned — that is
    the producer's own convention (`head_sig[0] != '\\0'` in virp_chain.c)."""
    if value is None or value == "":
        return None
    return check_cell(where, name, value, "hex")


# --- export -----------------------------------------------------------------


def export_session(conn, session_id, present):
    """Read one session's rows and shape them as a SessionChain object."""
    entry_cols = ENTRIES_REQUIRED + [c for c in ENTRIES_OPTIONAL if present[c]]
    sql = f"SELECT {', '.join(entry_cols)} FROM {ENTRIES_TABLE} WHERE session_id = ? ORDER BY sequence ASC"
    entries = []
    for row in conn.execute(sql, (session_id,)):
        r = dict(zip(entry_cols, row))
        where = f"{ENTRIES_TABLE} session={session_id!r} sequence={r.get('sequence')!r}"
        entry = {}
        for name, kind in CANONICAL_FIELDS:
            entry[name] = check_cell(where, name, r[name], "hex" if name in HEX_CELLS else kind)
        entry["chain_entry_hash"] = check_cell(where, "chain_entry_hash", r["chain_entry_hash"], "hex")
        hmac = optional_hmac(where, "chain_hmac", r["chain_hmac"])
        if hmac is not None:
            entry["chain_hmac"] = hmac
        if present["chain_sig"]:
            sig = optional_sig(where, "chain_sig", r["chain_sig"])
            kid = optional_sig(where, "chain_sig_key_id", r["chain_sig_key_id"])
            if (sig is None) != (kid is None):
                raise ExportError(f"{where}: chain_sig and chain_sig_key_id must both be present or both absent")
            if sig is not None:
                entry["signature"] = {
                    "signature_scheme": SIGNATURE_SCHEME,
                    "signing_key_id": kid,
                    "signature_hex": sig,
                }
        entries.append(entry)

    head_cols = HEADS_REQUIRED + [c for c in HEADS_OPTIONAL if present[c]]
    sql = f"SELECT {', '.join(head_cols)} FROM {HEADS_TABLE} WHERE session_id = ?"
    rows = conn.execute(sql, (session_id,)).fetchall()
    head = None
    if len(rows) > 1:
        raise ExportError(f"{HEADS_TABLE}: {len(rows)} head rows for session {session_id!r}; expected at most 1")
    if rows:
        r = dict(zip(head_cols, rows[0]))
        where = f"{HEADS_TABLE} session={session_id!r}"
        head = {
            "session_id": check_cell(where, "session_id", r["session_id"], "str"),
            "last_sequence": check_cell(where, "last_sequence", r["last_sequence"], "int"),
            "last_entry_hash": check_cell(where, "last_entry_hash", r["last_entry_hash"], "hex"),
        }
        hmac = optional_hmac(where, "head_hmac", r["head_hmac"])
        if hmac is not None:
            head["head_hmac"] = hmac
        if present["head_sig"]:
            sig = optional_sig(where, "head_sig", r["head_sig"])
            kid = optional_sig(where, "head_sig_key_id", r["head_sig_key_id"])
            if (sig is None) != (kid is None):
                raise ExportError(f"{where}: head_sig and head_sig_key_id must both be present or both absent")
            if sig is not None:
                head["signature"] = {
                    "signature_scheme": SIGNATURE_SCHEME,
                    "signing_key_id": kid,
                    "signature_hex": sig,
                }

    if not entries and head is None:
        raise ExportError(f"session {session_id!r}: no entries and no head in the database (use --list-sessions)")

    chain = {"session_id": session_id, "entries": entries}
    if head is not None:
        chain["head"] = head
    return chain


def discover_artifacts_schema(conn):
    """Confirm the artifacts table exists with the columns --artifacts needs."""
    cols = table_columns(conn, ARTIFACTS_TABLE)
    if cols is None:
        found_tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        raise ExportError(
            f"--artifacts: table {ARTIFACTS_TABLE!r} does not exist in this database, so it carries no bodies\n"
            f"  tables found: {found_tables}\n"
            f"  export without --artifacts for a hash-only bundle"
        )
    missing = [c for c in ARTIFACTS_REQUIRED if c not in cols]
    if missing:
        raise ExportError(
            f"--artifacts: table {ARTIFACTS_TABLE!r} is missing required column(s) {missing}\n"
            f"  expected: {ARTIFACTS_REQUIRED}\n"
            f"  found:    {cols}"
        )


def body_bytes(where, content):
    """The exact bytes the producer hashed into artifact_hash.

    Plain TEXT is hashed as its UTF-8 encoding; "base64:<data>" is hashed as
    the decoded bytes. Unwrapping that envelope recovers bytes, it does not
    re-encode content — and the verifier recomputes SHA-256 over what is
    carried, so a wrong recovery is FAILED there, never silently accepted."""
    if content is None:
        raise ExportError(f"{where}: artifact_content is NULL; the body store cannot hold an absent body")
    if isinstance(content, bytes):
        return content
    if not isinstance(content, str):
        raise ExportError(f"{where}: artifact_content expected TEXT, found {type(content).__name__}")
    if content.startswith(BASE64_PREFIX):
        try:
            return base64.b64decode(content[len(BASE64_PREFIX):], validate=True)
        except (binascii.Error, ValueError) as e:
            raise ExportError(f"{where}: artifact_content claims base64 but does not decode: {e}") from e
    return content.encode("utf-8")


def fetch_artifact_bodies(conn, chains):
    """Bodies for every entry of every selected chain.

    Returns (store, coverage): store maps artifact_hash -> bytes (exactly as
    stored, decoded from the envelope only); coverage maps session_id ->
    (entries_with_body, [hash-only sequences]). An entry with no
    (artifact_id, artifact_hash) row is hash-only — recorded, never faked.
    Two rows disagreeing on the bytes for one artifact_hash is a store
    conflict this exporter refuses to paper over."""
    store = {}
    coverage = {}
    sql = f"SELECT artifact_content FROM {ARTIFACTS_TABLE} WHERE artifact_id = ? AND artifact_hash = ?"
    for chain in chains:
        with_body = 0
        hash_only = []
        for entry in chain["entries"]:
            aid, ahash, seq = entry["artifact_id"], entry["artifact_hash"], entry["sequence"]
            rows = conn.execute(sql, (aid, ahash)).fetchall()
            if not rows:
                hash_only.append(seq)
                continue
            # UNIQUE(artifact_id, artifact_hash) means at most one row.
            where = f"{ARTIFACTS_TABLE} artifact_id={aid!r}"
            data = body_bytes(where, rows[0][0])
            if ahash in store and store[ahash] != data:
                raise ExportError(
                    f"{where}: the store holds two different bodies for artifact_hash {ahash}; "
                    f"refusing to choose one"
                )
            store[ahash] = data
            with_body += 1
        coverage[chain["session_id"]] = (with_body, hash_only)
    return store, coverage


# --- the referenced artifacts (what a camera record is ABOUT) -------------
#
# A camera_segment record commits by digest to files that have never
# travelled in a bundle: the video, and — from /3 — the validator's own
# output about that video. Measured 2026-09-04: a byte flipped in either
# survived both virp-verify and virp_camera.py audit with output
# byte-identical to the untampered run, because nothing carried the files
# and nothing recomputed the digests. Carrying them is this half of the
# fix; recomputing them is virp-verify's.
#
# The field PATHS are the vocabulary the producer's own SEGMENT PAYLOAD axis
# uses (virp_camera.py), deliberately: two tools reporting on the same two
# artifacts must name them the same way or an examiner cannot line the
# reports up.
CITED_SEGMENT = "segment_sha256"
CITED_VALIDATOR_OUTPUT = "sensor_signature.validator_output_sha256"
CITED_LEAF = "sensor_signature.device_chain.leaf_sha256"

HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


def cited_digests(body):
    """{field path: digest} for one camera_segment body, or {} for anything
    else.

    Structural only, like every other read in this exporter: a value that is
    not a 64-hex digest is not a citation this can act on, and whether the
    sensor object is WELL FORMED at its own schema version is the verifier's
    judgement, not ours. Under-reading here is safe — a citation this misses
    is simply not carried — while over-reading would invent one."""
    if not isinstance(body, dict):
        return {}
    schema = body.get("schema")
    if not isinstance(schema, str) or not schema.startswith("camera_segment/"):
        return {}
    out = {}
    seg = body.get(CITED_SEGMENT)
    if isinstance(seg, str) and HEX64.match(seg):
        out[CITED_SEGMENT] = seg
    sensor = body.get("sensor_signature")
    if isinstance(sensor, dict):
        vo = sensor.get("validator_output_sha256")
        if isinstance(vo, str) and HEX64.match(vo):
            out[CITED_VALIDATOR_OUTPUT] = vo
        chain = sensor.get("device_chain")
        if isinstance(chain, dict):
            leaf = chain.get("leaf_sha256")
            if isinstance(leaf, str) and HEX64.match(leaf):
                out[CITED_LEAF] = leaf
    return out


def referenced_patterns(field, seg_sha, digest):
    """Filename patterns under which a cited artifact may be found — the same
    two layouts `virp_camera.py audit --artifact-dir` looks in, so a file the
    producer's own auditor can check is a file this can carry:

      outbox / spool     <camera>.<seq>.<segment_sha256>.mp4
                         <camera>.<seq>.<segment_sha256>.validation.txt
                         <camera>.<seq>.<segment_sha256>.leaf.der
      replay artifacts/  <segment_sha256>.<ext>
      content-addressed  <digest>.<ext>

    Both outbox names key on the SEGMENT digest — that is how the driver
    names a segment's whole file set — so a validator output is located
    through the segment it belongs to, not through its own hash. That is
    also what lets an ALTERED validator output still be found and carried."""
    if field == CITED_SEGMENT:
        return (f"*.{seg_sha}.mp4", f"{seg_sha}.mp4")
    if field == CITED_LEAF:
        return (f"*.{seg_sha}.leaf.der", f"{seg_sha}.leaf.der", f"{digest}.der")
    return (
        f"*.{seg_sha}.validation.txt",
        f"{seg_sha}.validation.txt",
        f"*.{seg_sha}.validation_results.txt",
        f"{digest}.txt",
    )


#: the artifact is not under any search directory
REASON_NOT_FOUND = "not_found"
#: a search directory, or the file itself, could not be read
REASON_EACCES = "eacces"


def find_referenced(dirs, field, seg_sha, digest):
    """(path, reason) for this artifact.

    `(path, None)` when found and readable, `(None, REASON_NOT_FOUND)` when
    no directory holds it, `(None, REASON_EACCES)` when a directory could
    not be listed or the file could not be opened.

    THE TWO ABSENCES ARE DIFFERENT FACTS. glob() returns [] for an
    unreadable directory exactly as it does for an empty one, so an
    exporter run without permission on the spool produced a bundle
    declaring every artifact missing — a complete, confident, wrong
    statement about the evidence. "It is not there" and "I was not allowed
    to look" must not reduce to the same word, for the same reason
    "verified" and "not checked" must not.

    EACCES wins over not-found across directories: if any directory could
    not be searched, the artifact's absence is unproven, whatever the
    readable ones happened to hold."""
    blocked = False
    for d in dirs:
        if not os.access(d, os.R_OK | os.X_OK):
            blocked = True
            continue
        for pat in referenced_patterns(field, seg_sha, digest):
            try:
                hits = sorted(glob.glob(os.path.join(d, pat)))
            except OSError:
                blocked = True
                continue
            for hit in hits:
                if os.access(hit, os.R_OK):
                    return hit, None
                blocked = True          # it IS there; we cannot read it
    return None, (REASON_EACCES if blocked else REASON_NOT_FOUND)


def collect_referenced(chains, store, dirs):
    """[{sha256, cited_by, present, source}] over every camera record in the
    selected chains, sorted by digest.

    `source` is the local path the bytes came from and never reaches the
    manifest: where a file sat on the exporting machine is not a fact about
    the evidence, and the bundle already names the artifact by its digest."""
    found = {}
    for chain in chains:
        for entry in chain["entries"]:
            data = store.get(entry["artifact_hash"])
            if data is None:
                continue
            try:
                body = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                continue
            cited = cited_digests(body)
            if not cited:
                continue
            seg_sha = cited.get(CITED_SEGMENT, "")
            seq = body.get("segment_seq")
            for field, digest in sorted(cited.items()):
                rec = found.setdefault(
                    digest,
                    {"sha256": digest, "cited_by": [], "present": False,
                     "source": None, "reason": REASON_NOT_FOUND},
                )
                citation = {
                    "session_id": chain["session_id"],
                    "segment_seq": seq,
                    "field": field,
                }
                if citation not in rec["cited_by"]:
                    rec["cited_by"].append(citation)
                if rec["source"] is None:
                    path, reason = find_referenced(dirs, field, seg_sha, digest)
                    if path is not None:
                        rec["source"] = path
                        rec["present"] = True
                        rec["reason"] = None
                    elif reason == REASON_EACCES:
                        # never downgraded back to not_found by a later
                        # citation that happened to look somewhere readable
                        rec["reason"] = REASON_EACCES
    for rec in found.values():
        rec["cited_by"].sort(key=lambda c: (c["session_id"], c["segment_seq"] or 0, c["field"]))
    return [found[d] for d in sorted(found)]


def read_referenced_bytes(rec):
    """The located file's bytes, read whole. NOT checked against the digest:
    a file that does not hash to what the record cites is exactly the case
    this carriage exists to put in front of the verifier, and refusing it
    here would hide a tamper as an absence."""
    try:
        with open(rec["source"], "rb") as f:
            return f.read()
    except OSError as e:
        raise ExportError(f"cannot read referenced artifact {rec['source']}: {e}") from e


def partition_redacted(store):
    """Split a body store into (carried, withheld) under docket-mask-v1.

    A body is WITHHELD when the masking layer would mask anything in it:
    a vendor credential shape (rule 1), a generic secret shape (rule 2), or
    the fail-closed unclassifiable rule (rule 3 — not valid UTF-8, oversized,
    or carrying control characters outside whitespace). Withholding is
    omission at export, not modification: the bytes simply do not travel. The
    session files, the entries and every artifact_hash are untouched, so the
    hash still commits to the original body and the verifier grades the
    result as the hash-only bundle it now is.

    Returns (carried, withheld) where withheld maps artifact_hash -> a record
    of what was left behind."""
    import docket_mask

    carried, withheld = {}, {}
    for ahash, data in store.items():
        m = docket_mask.mask_body(data)
        if m.is_clean():
            carried[ahash] = data
            continue
        withheld[ahash] = {
            "artifact_hash": ahash,
            "bytes": len(data),
            "spans_masked": m.redactions,
            "unclassifiable": m.whole_body,
        }
    return carried, withheld


SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")


def session_file_name(session_id, taken):
    """A filesystem- and tar-safe file name for a session. Session ids
    contain ':' and other characters; the manifest maps id -> path, so the
    name only has to be unique and safe, not reversible."""
    base = SAFE_NAME_RE.sub("_", session_id).strip("._") or "session"
    name = base + ".json"
    if name in taken:
        tag = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:8]
        name = f"{base}-{tag}.json"
    taken.add(name)
    return name


def read_seal(seal_path):
    """Read the seal bytes verbatim. Sanity: parses as JSON and says it is a
    virp-seal/1 document. Nothing is altered."""
    try:
        with open(seal_path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise ExportError(f"cannot read seal {seal_path}: {e}") from e
    try:
        doc = json.loads(data)
    except ValueError as e:
        raise ExportError(f"seal {seal_path} is not valid JSON: {e}") from e
    if not isinstance(doc, dict) or doc.get("seal_version") != SEAL_VERSION:
        raise ExportError(
            f"seal {seal_path}: expected seal_version {SEAL_VERSION!r}, found "
            f"{doc.get('seal_version') if isinstance(doc, dict) else type(doc).__name__!r}"
        )
    return data


def read_seal_sig(seal_sig_path):
    """Read the detached minisign signature verbatim. Sanity only: the file
    must look like a .minisig (a base64 payload line decoding to 74 bytes
    whose algorithm tag is minisign's Ed or ED). Whether it VERIFIES is
    virp-verify's call, under a --seal-key supplied out of band."""
    try:
        with open(seal_sig_path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise ExportError(f"cannot read seal signature {seal_sig_path}: {e}") from e
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ExportError(f"seal signature {seal_sig_path} is not UTF-8 text (a .minisig is)") from e
    payload = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith(("untrusted comment:", "trusted comment:"))
    ]
    if not payload:
        raise ExportError(f"seal signature {seal_sig_path}: no base64 payload line found")
    try:
        blob = base64.b64decode(payload[0], validate=True)
    except (binascii.Error, ValueError) as e:
        raise ExportError(f"seal signature {seal_sig_path}: payload line is not base64: {e}") from e
    if len(blob) != 74 or blob[:2] not in (b"Ed", b"ED"):
        raise ExportError(
            f"seal signature {seal_sig_path}: payload is not a minisign signature blob "
            f"(74 bytes starting Ed/ED; found {len(blob)} bytes)"
        )
    return data


# --- public keys (--keys) ---------------------------------------------------

# key_id is sha256-raw-16: hex(SHA-256(raw 32 public-key bytes)[0:16]).
KEY_ID_HEX_LEN = 32
PUBLIC_KEY_HEX_LEN = 64

# Top-level JSON field names that mean the file holds more than a public key.
# Matched case-insensitively as substrings: no private key material enters
# Docket, ever — refusing the whole file beats quietly copying out the public
# half of something the operator should not be handing around.
SECRET_FIELD_WORDS = ("secret", "seed", "private")


def derive_key_id(public_key_hex):
    """sha256-raw-16 over the raw key bytes. Derived, never copied: a
    relabelled key file cannot change the id, and a stated id that does not
    re-derive is caught by the caller."""
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:KEY_ID_HEX_LEN]


# The two forms `virp-verify --pin` accepts, named in every rejection so an
# operator holding the wrong shape is told what the right ones are.
KEY_FILE_FORMS = (
    f"A key file is either {PUBLIC_KEY_HEX_LEN} hex characters — the raw Ed25519 PUBLIC key as it lives "
    'on the daemon host, trailing newline allowed — or a docket keys.json object '
    '{"keys": [{"key_id", "algorithm", "public_key_hex"}]}. Raw 32-byte binary is not accepted by '
    "either side of Docket: hex it first (xxd -p -c 64)"
)


def read_public_key_file(path):
    """One chain-signing PUBLIC key file -> normalized keys.json entries.

    Accepted forms, the same set `virp-verify --pin` reads, so one file works
    on both sides of the tool:
      * raw hex: the file is exactly 64 hex characters (plus whitespace) —
        the D-1 public half as it lives on the daemon host;
      * a docket keys.json object: {"keys": [ <key object>, ... ]};
      * a bare key object: {"public_key_hex": "64 hex"} with optional
        "algorithm" (any casing of ed25519 — the API serves "Ed25519", the
        bundle format wants lowercase), optional stated "key_id"/"key_id_hex"
        (checked against the derived id, never trusted), optional "comment".
        This is the exporter's original single-key form; it is kept because
        operators have files in it.

    Normalization on write: algorithm lowercase "ed25519", hex lowercase,
    key_id always derived. Whether the bytes are a valid curve point is the
    verifier's call, as with every other cell this exporter copies.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise ExportError(f"cannot read key file {path}: {e}") from e
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ExportError(f"key file {path} is not UTF-8 text. {KEY_FILE_FORMS}: {e}") from e

    stripped = text.strip()
    if HEX_RE.match(stripped) and len(stripped) == PUBLIC_KEY_HEX_LEN:
        docs = [{"public_key_hex": stripped}]
    else:
        try:
            doc = json.loads(stripped)
        except ValueError as e:
            raise ExportError(
                f"key file {path} is neither {PUBLIC_KEY_HEX_LEN} hex characters nor valid JSON. "
                f"{KEY_FILE_FORMS}: {e}"
            ) from e
        if not isinstance(doc, dict):
            raise ExportError(
                f"key file {path}: JSON form must be an object, found {type(doc).__name__}. {KEY_FILE_FORMS}"
            )
        if "keys" in doc:
            # The keys.json shape, exactly as this exporter emits it and as
            # --pin reads it: a round trip through the bundle format works.
            if not isinstance(doc["keys"], list):
                raise ExportError(f"key file {path}: 'keys' must be a list, found {type(doc['keys']).__name__}")
            if not doc["keys"]:
                raise ExportError(f"key file {path}: 'keys' is empty; a key file must carry at least one key")
            for k in doc["keys"]:
                if not isinstance(k, dict):
                    raise ExportError(f"key file {path}: every entry in 'keys' must be an object")
            docs = doc["keys"]
        else:
            docs = [doc]
    return [read_public_key_doc(path, d) for d in docs]


def read_public_key_doc(path, doc):
    """One key object -> a normalized keys.json entry."""
    for name in doc:
        if any(w in name.lower() for w in SECRET_FIELD_WORDS):
            raise ExportError(
                f"key file {path} carries field {name!r}, which names secret key material; "
                f"--keys takes PUBLIC key files only and no private key material enters Docket"
            )

    pub = doc.get("public_key_hex")
    if pub is None:
        raise ExportError(f"key file {path}: no 'public_key_hex' field (and the file is not raw hex)")
    if not isinstance(pub, str) or not HEX_RE.match(pub) or len(pub) != PUBLIC_KEY_HEX_LEN:
        raise ExportError(
            f"key file {path}: public_key_hex must be {PUBLIC_KEY_HEX_LEN} hex characters, found {pub!r}"
        )
    pub = pub.lower()

    algorithm = doc.get("algorithm")
    if algorithm is not None:
        if not isinstance(algorithm, str) or algorithm.lower() != "ed25519":
            raise ExportError(f"key file {path}: algorithm {algorithm!r} is not ed25519 (any casing accepted)")

    key_id = derive_key_id(pub)
    stated = doc.get("key_id", doc.get("key_id_hex"))
    if stated is not None:
        if not isinstance(stated, str) or stated.lower() != key_id:
            raise ExportError(
                f"key file {path}: stated key_id {stated!r} does not re-derive from the key bytes "
                f"(derived {key_id}); the id is sha256-raw-16 over the raw public key and is never taken on faith"
            )

    entry = {"key_id": key_id, "algorithm": "ed25519", "public_key_hex": pub}
    comment = doc.get("comment")
    if comment is not None:
        if not isinstance(comment, str):
            raise ExportError(f"key file {path}: comment must be a string, found {type(comment).__name__}")
        entry["comment"] = comment
    return entry


def read_public_keys(paths):
    """All --keys files -> deterministic keys.json entries, sorted by key_id.
    The same key supplied twice collapses to one entry; twice with differing
    comments is a conflict this exporter refuses to resolve."""
    by_id = {}
    origin = {}
    for path in paths:
        for entry in read_public_key_file(path):
            kid = entry["key_id"]
            if kid in by_id:
                if by_id[kid] != entry:
                    raise ExportError(
                        f"key files {origin[kid]} and {path} supply key_id {kid} with different metadata; "
                        f"refusing to choose"
                    )
                continue
            by_id[kid] = entry
            origin[kid] = path
    return [by_id[kid] for kid in sorted(by_id)]


def created_at_utc():
    """The manifest's created_at. SOURCE_DATE_EPOCH (unix seconds) pins it so
    a re-export is byte-identical; unset, the wall clock, as before."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is None:
        now = datetime.datetime.now(datetime.timezone.utc)
    else:
        try:
            now = datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc)
        except (ValueError, OverflowError, OSError) as e:
            raise ExportError(f"SOURCE_DATE_EPOCH={epoch!r} is not a unix timestamp in seconds: {e}") from e
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


# --- witness ---------------------------------------------------------------
#
# Everything below runs ONLY under --witness. Nothing in it can fail an
# export: a witness that is unreachable, that has never seen a head, or that
# answers something unusable produces a manifest row saying so, with the
# reason, and the bundle is written exactly as it would have been otherwise.
# That is the same rule the node-side submitter follows for the same stated
# reason — a chain whose availability depends on a third party's endpoint has
# made itself hostage to the party it exists to not have to trust.

WITNESS_STH_VERSION = "docket-witness-sth/1"
WITNESS_PROOF_VERSION = "docket-witness-proof/1"
WITNESS_LEAF_ENTRY_V = "VIRP-WITNESS-ENTRY-v1"
WITNESS_RECEIPT_VERSION = "virp-witness-receipt/1"
WITNESS_RECEIPTS_DEFAULT = "/var/lib/virp/witness/heads"
WITNESS_TIMEOUT = 20
# A tree head is ~400 bytes and an audit path is one 64-hex node per level, so
# even an absurd log gives a few kilobytes. Anything past this is not an
# answer to the question that was asked.
WITNESS_MAX_RESPONSE = 1 << 20

# Reasons a session carries no witness material. Three different facts, and
# only the first says anything about the evidence.
WITNESS_NOT_SUBMITTED = "not_submitted"
WITNESS_UNREACHABLE = "unreachable"
WITNESS_LOOKUP_FAILED = "lookup_failed"


def head_canonical_bytes(session_id, last_sequence, last_entry_hash):
    """Byte-for-byte ~/virp/src/virp_chain.c:1113, the bytes the daemon
    hashed and signed. No JSON escaping, by construction: every field that
    reaches here is a hex digest, an integer, or a session id the chain
    itself already accepted."""
    return (
        '{"last_entry_hash":"%s","last_sequence":%d,"session_id":"%s","v":"VIRP-CHAIN-HEAD-v1"}'
        % (last_entry_hash, last_sequence, session_id)
    ).encode("utf-8")


def witness_leaf_data(leaf):
    """The RFC 9162 leaf data: the bytes SHA-256(0x00 || ...) is taken over.
    Keys lexicographic; fixed-width hex, an integer and a fixed-shape
    timestamp throughout, so there is nothing to escape."""
    return (
        '{"chain_id":"%s","head_hash":"%s","key_id":"%s","sequence":%d,'
        '"signature":"%s","timestamp":"%s","v":"%s"}'
        % (
            leaf["chain_id"],
            leaf["head_hash"],
            leaf["key_id"],
            leaf["sequence"],
            leaf["signature"],
            leaf["timestamp"],
            WITNESS_LEAF_ENTRY_V,
        )
    ).encode("utf-8")


def witness_leaf_hash(leaf):
    return hashlib.sha256(b"\x00" + witness_leaf_data(leaf)).hexdigest()


def session_leaf_identity(chain):
    """What the witness's leaf for this session's head MUST say, computed
    from the head this bundle carries.

    Returns None when the session has no head, or no head signature: with no
    signing key_id there is nothing to match a leaf's key_id against, and a
    three-of-four match is not an identity."""
    head = chain.get("head")
    if not head:
        return None
    sig = head.get("signature")
    if not sig:
        return None
    canonical = head_canonical_bytes(
        head["session_id"], head["last_sequence"], head["last_entry_hash"]
    )
    return {
        # SHA-256(session_id) is the client's default mapping. An operator
        # who submitted under --chain-id (a keyed derivation, say) will not
        # match here, and the row will read not_submitted — which is why the
        # summary prints the identity it looked for.
        "chain_id": hashlib.sha256(head["session_id"].encode("utf-8")).hexdigest(),
        "sequence": head["last_sequence"],
        "head_hash": hashlib.sha256(canonical).hexdigest(),
        "key_id": sig["signing_key_id"],
    }


def load_receipts(receipts_dir):
    """Every virp-witness-receipt/1 file under `receipts_dir`, parsed.

    A file that will not parse, or that is not a receipt, is SKIPPED rather
    than fatal: this directory is the submitter's working state and may hold
    partial writes from a run that is happening right now. Returns the list
    and a list of (path, why) for anything skipped, so the summary can say
    what was ignored instead of silently ignoring it."""
    receipts, skipped = [], []
    if not os.path.isdir(receipts_dir):
        return receipts, [(receipts_dir, "not a directory")]
    try:
        names = sorted(os.listdir(receipts_dir))
    except OSError as e:
        return receipts, [(receipts_dir, str(e))]
    for name in names:
        if not name.endswith(".witness.json"):
            continue
        path = os.path.join(receipts_dir, name)
        try:
            with open(path, "rb") as f:
                doc = json.loads(f.read().decode("utf-8"))
        except (OSError, ValueError, UnicodeDecodeError) as e:
            skipped.append((path, str(e)))
            continue
        if not isinstance(doc, dict) or doc.get("v") != WITNESS_RECEIPT_VERSION:
            skipped.append((path, "not a %s document" % WITNESS_RECEIPT_VERSION))
            continue
        sub, rec = doc.get("submission"), doc.get("receipt")
        if not isinstance(sub, dict) or not isinstance(rec, dict):
            skipped.append((path, "receipt is missing submission or receipt"))
            continue
        receipts.append((path, doc))
    return receipts, skipped


def match_receipt(receipts, identity):
    """The receipt whose leaf IS this head's leaf.

    Matched on all four identity fields at once. The file name is never
    consulted: it is derived from the session id and the sequence and is a
    convenience for an operator reading the directory, not evidence about
    what the file contains."""
    for path, doc in receipts:
        sub = doc["submission"]
        if (
            sub.get("chain_id") == identity["chain_id"]
            and sub.get("sequence") == identity["sequence"]
            and sub.get("head_hash") == identity["head_hash"]
            and sub.get("key_id") == identity["key_id"]
        ):
            return path, doc
    return None, None


def witness_get(base_url, path):
    """One GET. Returns the response body as text, or raises ExportError with
    the reason — which becomes a manifest row, never a failed export."""
    url = base_url.rstrip("/") + path
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ExportError("--witness: %s is not an http:// or https:// URL" % url)
    req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=WITNESS_TIMEOUT) as r:  # noqa: S310 (scheme checked above)
            raw = r.read(WITNESS_MAX_RESPONSE + 1)
    except Exception as e:  # urllib raises a wide family; the reason is what matters
        raise ExportError("%s: %s" % (url, e)) from e
    if len(raw) > WITNESS_MAX_RESPONSE:
        raise ExportError("%s: response exceeds %d bytes" % (url, WITNESS_MAX_RESPONSE))
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ExportError("%s: response is not UTF-8: %s" % (url, e)) from e


def collect_witness(chains, witness_url, receipts_dir):
    """Resolve, fetch and assemble everything --witness carries.

    Returns (sth_file, rows, notes) where `rows` is one record per session in
    export order and `notes` are lines for the summary. `sth_file` is None
    when the witness could not be reached at all — in which case every row is
    present=false / unreachable, and the export goes on."""
    notes = []
    receipts, skipped = load_receipts(receipts_dir)
    for path, why in skipped:
        notes.append("ignored %s: %s" % (path, why))
    notes.append("%d receipt(s) readable under %s" % (len(receipts), receipts_dir))

    # One tree head for the whole export: every proof is against the same
    # tree, so a reader compares one signature rather than one per session.
    sth_served = None
    witness_key_id = ""
    unreachable = None
    try:
        sth_served = witness_get(witness_url, "/v1/sth")
        sth = json.loads(sth_served)
        tree_size = int(sth["tree_size"])
    except (ExportError, ValueError, KeyError, TypeError) as e:
        unreachable = str(e)
        sth_served, tree_size = None, 0
    if sth_served is not None:
        try:
            witness_key_id = str(json.loads(witness_get(witness_url, "/v1/pubkey"))["key_id"])
        except (ExportError, ValueError, KeyError, TypeError) as e:
            # A claim this script could not collect is an empty claim, not a
            # failure: nothing is graded from it either way.
            notes.append("could not read the witness's claimed key_id: %s" % e)

    rows = []
    for chain in chains:
        sid = chain["session_id"]
        row = {"session_id": sid, "present": False, "reason": WITNESS_NOT_SUBMITTED, "proof": None}
        rows.append(row)
        if unreachable is not None:
            row["reason"] = WITNESS_UNREACHABLE
            row["detail"] = unreachable
            continue
        identity = session_leaf_identity(chain)
        if identity is None:
            row["reason"] = WITNESS_LOOKUP_FAILED
            row["detail"] = "this session carries no signed head, so it has no leaf identity"
            continue
        path, doc = match_receipt(receipts, identity)
        if doc is None:
            row["detail"] = "no receipt under %s matches head_hash %s at sequence %d under key_id %s" % (
                receipts_dir, identity["head_hash"], identity["sequence"], identity["key_id"]
            )
            continue

        rec = doc["receipt"]
        leaf = {
            "chain_id": identity["chain_id"],
            "sequence": identity["sequence"],
            "head_hash": identity["head_hash"],
            "key_id": identity["key_id"],
            "signature": doc["submission"].get("signature", ""),
            # The receipt's timestamp is the STH timestamp, which the witness
            # signs at the same instant it stamps the leaf. That is an
            # implementation fact this script does not take on trust: the
            # leaf is rebuilt with it and must hash to the leaf_hash the
            # receipt carries, below. If it ever stops being the same
            # instant, this check fails closed and the row says lookup_failed
            # instead of stating a time that is not in the tree.
            "timestamp": rec.get("timestamp", ""),
        }
        try:
            leaf_index = int(rec["leaf_index"])
        except (KeyError, TypeError, ValueError) as e:
            row["reason"] = WITNESS_LOOKUP_FAILED
            row["detail"] = "%s: unusable leaf_index: %s" % (path, e)
            continue
        rebuilt = witness_leaf_hash(leaf)
        if rebuilt != rec.get("leaf_hash"):
            row["reason"] = WITNESS_LOOKUP_FAILED
            row["detail"] = (
                "%s: the leaf rebuilt from this receipt hashes to %s and the receipt says %s; "
                "refusing to carry a leaf whose bytes are not the ones in the tree" % (path, rebuilt, rec.get("leaf_hash"))
            )
            continue
        if leaf_index >= tree_size:
            row["reason"] = WITNESS_LOOKUP_FAILED
            row["detail"] = "leaf_index %d is outside the witness's current tree of %d leaf/leaves" % (
                leaf_index, tree_size
            )
            continue
        try:
            proof_served = witness_get(
                witness_url, "/v1/proof?leaf_index=%d&tree_size=%d" % (leaf_index, tree_size)
            )
            proof = json.loads(proof_served)
            audit_path = [str(h) for h in proof["inclusion_proof"]]
        except (ExportError, ValueError, KeyError, TypeError) as e:
            row["reason"] = WITNESS_LOOKUP_FAILED
            row["detail"] = str(e)
            continue

        row["present"] = True
        row["reason"] = None
        row["proof"] = {
            "v": WITNESS_PROOF_VERSION,
            "session_id": sid,
            "leaf": leaf,
            "leaf_index": leaf_index,
            "tree_size": tree_size,
            "audit_path": audit_path,
            "proof_served": proof_served,
        }
        notes.append("%s -> leaf %d of tree %d (receipt %s)" % (sid, leaf_index, tree_size, os.path.basename(path)))

    sth_file = None
    if sth_served is not None:
        sth_file = {
            "v": WITNESS_STH_VERSION,
            "witness_url": witness_url,
            "witness_key_id": witness_key_id,
            "fetched_at": created_at_utc(),
            "sth_served": sth_served,
        }
    return sth_file, rows, notes, tree_size


def write_json(path, obj):
    data = json.dumps(obj, indent=2, ensure_ascii=True).encode("utf-8") + b"\n"
    with open(path, "xb") as f:
        f.write(data)
    return hashlib.sha256(data).hexdigest()


def write_bytes(path, data):
    with open(path, "xb") as f:
        f.write(data)
    return hashlib.sha256(data).hexdigest()


def run_export(
    db_path, out_dir, session_ids, seal_path, all_sessions, artifacts=False, key_paths=None,
    seal_sig_path=None, redacted=False, referenced_dirs=None, witness_url=None,
    witness_receipts=None,
):
    referenced_dirs = list(referenced_dirs or [])
    if witness_receipts is not None and witness_url is None:
        raise ExportError(
            "--witness-receipts says where the node's receipts live, and without --witness nothing reads them\n"
            "  add --witness <url>, or drop --witness-receipts"
        )
    witness_receipts = witness_receipts or WITNESS_RECEIPTS_DEFAULT
    if referenced_dirs and not artifacts:
        raise ExportError(
            "--referenced-artifacts carries the files the camera BODIES cite, and a bundle without "
            "--artifacts carries no bodies to read the citations out of\n"
            "  add --artifacts: there is nothing to reference from otherwise"
        )
    for d in referenced_dirs:
        if not os.path.isdir(d):
            raise ExportError(f"--referenced-artifacts: not a directory: {d}")
    if redacted and not artifacts:
        raise ExportError(
            "--redacted withholds bodies that carry secrets, and a bundle without --artifacts carries "
            "no bodies at all\n"
            "  add --artifacts, or drop --redacted: a hash-only bundle is already body-free"
        )
    if redacted:
        # Resolved before anything is read or written: a missing pattern table
        # must not leave a half-written bundle, and must never silently
        # degrade to "no rules".
        try:
            import docket_mask

            docket_mask.policy()
        except Exception as e:
            raise ExportError(f"--redacted: cannot load the masking policy: {e}") from e
    if os.path.lexists(out_dir):
        raise ExportError(f"output directory already exists: {out_dir} (refusing to overwrite; choose a new --out)")
    if seal_sig_path and not seal_path:
        raise ExportError("--seal-sig is a signature over the seal document; it needs --seal")
    if seal_sig_path and os.path.basename(seal_sig_path) == os.path.basename(seal_path):
        raise ExportError(
            f"--seal and --seal-sig share the file name {os.path.basename(seal_path)!r}; "
            f"both land in seal/ and would collide"
        )

    # Key files, the seal signature and created_at are resolved before the
    # output directory exists, like every other input: a bad file leaves
    # nothing on disk.
    key_entries = read_public_keys(key_paths) if key_paths else None
    seal_sig_bytes = read_seal_sig(seal_sig_path) if seal_sig_path else None
    created_at = created_at_utc()

    conn = open_readonly(db_path)
    try:
        present = discover_schema(conn)
        if artifacts:
            discover_artifacts_schema(conn)
        available = list_sessions(conn)
        available_ids = [s[0] for s in available]

        if all_sessions:
            selected = available_ids
        else:
            unknown = [s for s in session_ids if s not in available_ids]
            if unknown:
                raise ExportError(
                    f"session id(s) not in the database: {unknown}\n"
                    f"  the database holds {len(available_ids)} session(s); run --list-sessions to see them"
                )
            # Preserve the operator's order, drop duplicates.
            selected = list(dict.fromkeys(session_ids))
        if not selected:
            raise ExportError("no sessions selected")

        seal_bytes = read_seal(seal_path) if seal_path else None

        # Read everything BEFORE creating the output directory, so a sanity
        # failure leaves nothing on disk.
        chains = [export_session(conn, sid, present) for sid in selected]
        body_store, body_coverage = fetch_artifact_bodies(conn, chains) if artifacts else ({}, {})
    finally:
        conn.close()

    withheld = {}
    if redacted:
        body_store, withheld = partition_redacted(body_store)

    # Collected from the bodies that will actually be CARRIED, after any
    # redaction: the verifier re-derives the citations from those same bytes,
    # so listing a citation whose body was withheld would name something the
    # verifier cannot confirm the bundle ever cited.
    referenced = collect_referenced(chains, body_store, referenced_dirs) if referenced_dirs else []

    # Asked for AFTER every chain row is in hand and BEFORE anything is
    # written, like every other input: whatever the witness says, the bundle
    # that gets written is the same bundle.
    witness_sth = witness_rows = None
    witness_notes = []
    witness_tree_size = 0
    if witness_url:
        witness_sth, witness_rows, witness_notes, witness_tree_size = collect_witness(
            chains, witness_url, witness_receipts
        )

    written = []  # (relative path, sha256)
    os.makedirs(os.path.join(out_dir, "sessions"), exist_ok=False)
    taken = set()
    manifest_sessions = []
    for chain in chains:
        name = session_file_name(chain["session_id"], taken)
        rel = "sessions/" + name
        digest = write_json(os.path.join(out_dir, rel), chain)
        written.append((rel, digest))
        manifest_sessions.append({"session_id": chain["session_id"], "path": rel})

    manifest = {
        "docket_bundle_version": BUNDLE_VERSION,
        "chain_format": CHAIN_FORMAT,
        "producer": f"docket export_bundle.py {VERSION} (db={os.path.basename(db_path)})",
        "created_at": created_at,
        "sessions": manifest_sessions,
    }
    if key_entries is not None:
        digest = write_json(os.path.join(out_dir, "keys.json"), {"keys": key_entries})
        written.append(("keys.json", digest))
        manifest["keys"] = "keys.json"
    if seal_bytes is not None:
        os.makedirs(os.path.join(out_dir, "seal"), exist_ok=False)
        rel = "seal/" + os.path.basename(seal_path)
        digest = write_bytes(os.path.join(out_dir, rel), seal_bytes)
        written.append((rel, digest))
        manifest["seal"] = rel
        if seal_sig_bytes is not None:
            rel = "seal/" + os.path.basename(seal_sig_path)
            digest = write_bytes(os.path.join(out_dir, rel), seal_sig_bytes)
            written.append((rel, digest))
            manifest["seal_signature"] = rel
    if artifacts:
        os.makedirs(os.path.join(out_dir, "artifacts"), exist_ok=False)
        manifest["artifacts"] = []
        for ahash in sorted(body_store):
            rel = "artifacts/" + ahash
            digest = write_bytes(os.path.join(out_dir, rel), body_store[ahash])
            written.append((rel, digest))
            manifest["artifacts"].append({"artifact_hash": ahash, "path": rel})
    if referenced_dirs:
        manifest["referenced_artifacts"] = []
        for rec in referenced:
            entry = {"sha256": rec["sha256"], "cited_by": rec["cited_by"], "present": rec["present"]}
            if not rec["present"]:
                # WHY it is not carried, because the two reasons are
                # different evidence: not_found says the artifact was
                # looked for and is not there; eacces says the look
                # itself did not happen and the absence proves nothing.
                entry["reason"] = rec["reason"]
            if rec["present"]:
                # Named by the CITED digest, not by the bytes' own hash: the
                # verifier looks the citation up and recomputes, so altered
                # bytes grade FAILED instead of disappearing into ABSENT.
                rel = "artifacts/" + rec["sha256"]
                if rec["sha256"] in body_store:
                    raise ExportError(
                        f"referenced artifact {rec['sha256']} collides with a carried body of the same "
                        f"digest; refusing to overwrite evidence with evidence"
                    )
                digest = write_bytes(os.path.join(out_dir, rel), read_referenced_bytes(rec))
                written.append((rel, digest))
                entry["path"] = rel
            manifest["referenced_artifacts"].append(entry)
    if witness_url:
        os.makedirs(os.path.join(out_dir, "witness"), exist_ok=False)
        manifest_witness = {
            "witness_url": witness_url,
            "witness_key_id": (witness_sth or {}).get("witness_key_id", ""),
            "sth": "witness/sth.json",
            "tree_size": witness_tree_size,
            "sessions": [],
        }
        if witness_sth is not None:
            digest = write_json(os.path.join(out_dir, "witness/sth.json"), witness_sth)
            written.append(("witness/sth.json", digest))
        taken_w = set()
        for row in witness_rows:
            entry = {"session_id": row["session_id"], "present": row["present"]}
            if row["present"]:
                name = session_file_name(row["session_id"], taken_w)[: -len(".json")] + ".proof.json"
                rel = "witness/" + name
                digest = write_json(os.path.join(out_dir, rel), row["proof"])
                written.append((rel, digest))
                entry["path"] = rel
            else:
                # WHY nothing is carried. A head the witness has never seen is
                # not_submitted and is a fact about the evidence; unreachable
                # and lookup_failed are facts about this export run, and the
                # verifier must not read either as the first.
                entry["reason"] = row["reason"]
            manifest_witness["sessions"].append(entry)
        manifest["witness"] = manifest_witness
    if redacted:
        import docket_mask

        # Outside the canonical bytes by construction: the manifest is not
        # hashed into any chain, and nothing in a session file mentions this.
        manifest["redaction"] = {
            "policy": docket_mask.policy_name(),
            "entries_withheld": len(withheld),
            "withheld": [withheld[h] for h in sorted(withheld)],
        }
    digest = write_json(os.path.join(out_dir, "manifest.json"), manifest)
    written.insert(0, ("manifest.json", digest))

    # Summary.
    print(f"exported {len(chains)} session(s) from {db_path} -> {out_dir}")
    if witness_url:
        carried = sum(1 for r in witness_rows if r["present"])
        print(f"  witness: {witness_url}, tree_size {witness_tree_size}; {carried} of {len(witness_rows)} "
              f"session head(s) carried a proof")
        for n in witness_notes:
            print(f"    {n}")
        for r in witness_rows:
            if not r["present"]:
                print(f"    {r['session_id']}: {r['reason']} — {r.get('detail', '')}")
    d1 = "present" if present["chain_sig"] else "absent"
    if key_entries is None:
        print(f"  D-1 signature columns: {d1}; keys.json: not produced (no public keys live in the database)")
    else:
        ids = ", ".join(e["key_id"] for e in key_entries)
        print(f"  D-1 signature columns: {d1}; keys.json: {len(key_entries)} public key(s): {ids}")
    for chain in chains:
        head = chain.get("head")
        head_txt = f"head last_sequence={head['last_sequence']}" if head else "NO HEAD ROW"
        signed = sum(1 for e in chain["entries"] if "signature" in e)
        hmacs = sum(1 for e in chain["entries"] if "chain_hmac" in e)
        print(
            f"  {chain['session_id']}: {len(chain['entries'])} entries "
            f"({hmacs} with chain_hmac, {signed} with signature), {head_txt}"
        )
        if artifacts:
            with_body, hash_only = body_coverage[chain["session_id"]]
            line = f"    bodies: {with_body}/{len(chain['entries'])} entries have carried bodies"
            if hash_only:
                line += f"; hash-only sequences: {', '.join(str(s) for s in hash_only)}"
            print(line)
    if artifacts:
        print(f"  artifact bodies carried: {len(body_store)} distinct artifact_hash file(s) under artifacts/")
    if referenced_dirs:
        present = sum(1 for r in referenced if r["present"])
        blocked = sum(1 for r in referenced if r["reason"] == REASON_EACCES)
        missing = len(referenced) - present - blocked
        print(
            f"  referenced artifacts: {len(referenced)} cited by the carried camera records; "
            f"{present} carried, {missing} not found, {blocked} INACCESSIBLE (listed present=false)"
        )
        if blocked:
            print(
                "  INACCESSIBLE means a search directory or file could not be read, so those "
                "artifacts were never looked at — their absence from this bundle is not evidence "
                "that they are absent. virp-verify grades them UNVERIFIABLE, not ABSENT."
            )
        print(
            "  carried VERBATIM under the digest the record cites, unchecked here — virp-verify "
            "recomputes them as referenced_artifact_binding, and a missing one grades ABSENT"
        )
        for rec in referenced:
            if not rec["present"]:
                c = rec["cited_by"][0]
                label = "INACCESSIBLE" if rec["reason"] == REASON_EACCES else "NOT FOUND   "
                print(f"    {label}  {rec['sha256']}  cited by seq {c['segment_seq']} {c['field']}")
    if redacted:
        import docket_mask

        total = len(body_store) + len(withheld)
        print(
            f"  redaction: policy {docket_mask.policy_name()}; {len(withheld)} of {total} distinct "
            f"bodies withheld (exported hash-only), {sum(w['bytes'] for w in withheld.values())} bytes "
            f"left behind"
        )
        print(
            "  the withheld entries keep their artifact_hash and their place in the chain; "
            "virp-verify grades them exactly as it grades any hash-only entry"
        )
    print("files written (sha256):")
    for rel, digest in written:
        print(f"  {digest}  {rel}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="export_bundle.py",
        description="Export a Docket evidence bundle (directory) from a VIRP chain database snapshot. "
        "Exports only; virp-verify judges.",
    )
    p.add_argument("--db", required=True, help="path to the chain database SNAPSHOT (opened read-only, immutable)")
    p.add_argument("--out", help="bundle directory to create (must not exist)")
    p.add_argument("--sessions", nargs="+", metavar="ID", help="session id(s) to export")
    p.add_argument("--all-sessions", action="store_true", help="export every session in the database")
    p.add_argument("--seal", help="path to a virp-seal/1 JSON document to copy into the bundle verbatim")
    p.add_argument(
        "--seal-sig",
        help="detached minisign signature (.minisig) over the --seal document, copied into the bundle "
        "verbatim; the signature may travel in-band, the seal PUBLIC key never does (virp-verify "
        "takes it out of band via --seal-key)",
    )
    p.add_argument(
        "--keys",
        nargs="+",
        metavar="PUBFILE",
        help="chain-signing PUBLIC key file(s) (raw 64-hex, or JSON with public_key_hex) to write into "
        "keys.json; key_id is derived from the key bytes (sha256-raw-16), output is deterministic, and "
        "a file carrying secret/seed material is refused",
    )
    p.add_argument(
        "--artifacts",
        action="store_true",
        help="also carry artifact BODIES (raw bytes from the artifacts table) so the verifier can grade "
        "artifact binding and a reader can see what happened; without it the bundle is hash-only, as before",
    )
    p.add_argument(
        "--redacted",
        action="store_true",
        help="withhold every body the docket-mask-v1 policy would mask: those entries export hash-only, "
        "their bytes never leave, and the manifest records how many and which. Requires --artifacts. "
        "Nothing is modified — omission at export, never rewriting; every artifact_hash still commits "
        "to the original body and no verdict moves",
    )
    p.add_argument(
        "--referenced-artifacts",
        action="append",
        metavar="DIR",
        help="directory to search for the files the camera records CITE by digest — the segment video "
        "(segment_sha256) and the validator output (sensor_signature.validator_output_sha256). "
        "Repeatable. Both layouts virp_camera.py audit --artifact-dir reads are searched: the "
        "capture-host outbox (<camera>.<seq>.<segment_sha256>.<ext>) and content-addressed "
        "(<digest>.<ext>). Found files are carried under artifacts/<cited digest> VERBATIM and "
        "unchecked — virp-verify recomputes them. A cited artifact that is not found is listed "
        "present=false, never omitted. Requires --artifacts",
    )
    p.add_argument(
        "--witness",
        metavar="URL",
        help="witness base URL. For every exported session head, carry the witness's current signed tree "
             "head and an inclusion proof for that head's leaf. The leaf_index comes from the receipt the "
             "node-side submitter wrote (see --witness-receipts); the witness API has no route from a "
             "leaf's identity to its index. THE ONLY FLAG THAT USES THE NETWORK. A head the witness has "
             "never seen is recorded present=false / not_submitted; nothing here can fail the export.",
    )
    p.add_argument(
        "--witness-receipts",
        metavar="DIR",
        help="where the node-side submitter's <head>.witness.json receipts live "
             f"(default {WITNESS_RECEIPTS_DEFAULT}). Read-only; matched by leaf identity, never by file name.",
    )
    p.add_argument("--list-sessions", action="store_true", help="list session ids in the database and exit")
    args = p.parse_args(argv)

    try:
        if args.list_sessions:
            conn = open_readonly(args.db)
            try:
                discover_schema(conn)
                rows = list_sessions(conn)
            finally:
                conn.close()
            print(f"{len(rows)} session(s) in {args.db}:")
            for sid, n, has_head in rows:
                print(f"  {n:>7} entries  {'head' if has_head else 'NO HEAD':>7}  {sid}")
            return 0
        if not args.out:
            p.error("--out is required (unless --list-sessions)")
        if bool(args.sessions) == bool(args.all_sessions):
            p.error("give exactly one of --sessions <id>... or --all-sessions")
        return run_export(
            args.db, args.out, args.sessions or [], args.seal, args.all_sessions, args.artifacts, args.keys,
            args.seal_sig, args.redacted, args.referenced_artifacts, args.witness,
            args.witness_receipts,
        )
    except ExportError as e:
        print(f"export_bundle.py: error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
