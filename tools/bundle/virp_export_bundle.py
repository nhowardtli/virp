#!/usr/bin/env python3
"""
virp_export_bundle.py — export a chain database as a Docket evidence
bundle (docket-bundle/0.1).

Why this exists here: the bundle FORMAT is Docket's (see
~/docket/DESIGN.md §2), but producing one is the producer's job, and no
exporter existed on this side. Nothing in the Docket tree is read or
written by this script beyond the format it conforms to.

What it does NOT do, on purpose:
  - It does not verify anything. Every hash it writes is copied from the
    database, and the VERIFIER recomputes them. An exporter that "checked
    as it went" would be marking its own homework.
  - It does not sign. Signatures are copied verbatim from the columns the
    daemon wrote (chain_sig / head_sig); this script holds no key.
  - It does not invent a head. A session with no chain_heads row is
    exported without one and the verifier grades head_commitment ABSENT,
    which is the honest state rather than a head reconstructed by the
    thing being audited.

Artifact bodies are carried one file per distinct artifact_hash, named
by that hash. The label is a CLAIM: the verifier recomputes sha256 over
the bytes. Strict reading rejects a carried body no entry references, so
only referenced bodies are written.

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import sqlite3
import sys
import time

class InconsistentSnapshot(RuntimeError):
    """The entries and the head disagree about where the chain ends.

    Found by verifying a bundle exported from a LIVE chain: entries and
    heads were read in two separate queries, the daemon appended between
    them, and the exported head named a sequence the exported entries did
    not contain. virp-verify then reported head_commitment FAILED -- a
    healthy chain producing a failing bundle, with the blame landing on
    the chain rather than on the tool that sliced it.

    An exporter must be consistent or refuse. Writing a bundle it knows
    disagrees with itself would be manufacturing evidence of a defect
    that does not exist."""


BUNDLE_VERSION = "docket-bundle/0.1"
CHAIN_FORMAT = "v1"

# The twelve canonical fields, in the order src/virp_chain.c hashes them.
# Mirrors report/verify.py:canonical_json.
def canonical_json(e):
    return (
        '{"artifact_hash":"%s",'
        '"artifact_hash_alg":"%s",'
        '"artifact_id":"%s",'
        '"artifact_schema_version":"%s",'
        '"artifact_type":"%s",'
        '"monotonic_ns":%d,'
        '"previous_entry_hash":"%s",'
        '"sequence":%d,'
        '"session_id":"%s",'
        '"signer_node_id":%d,'
        '"signer_org_id":"%s",'
        '"timestamp_ns":%d}'
    ) % (e["artifact_hash"], e["artifact_hash_alg"], e["artifact_id"],
         e["artifact_schema_version"], e["artifact_type"], e["monotonic_ns"],
         e["previous_entry_hash"], e["sequence"], e["session_id"],
         e["signer_node_id"], e["signer_org_id"], e["timestamp_ns"])


def safe_name(session_id):
    """A session id is operator data; it must not choose a path. Every
    component outside [A-Za-z0-9._-] is replaced, and a digest of the
    ORIGINAL is appended so two ids cannot collide onto one file."""
    slug = re.sub(r'[^A-Za-z0-9._-]', '_', session_id)[:60]
    return "%s-%s" % (slug, hashlib.sha256(session_id.encode()).hexdigest()[:8])


def has_column(conn, table, col):
    return any(r[1] == col for r in
               conn.execute("PRAGMA table_info(%s)" % table).fetchall())


def export(db_path, out_dir, producer, retries=3):
    """Export, retrying on a racing writer, refusing if it cannot get a
    consistent slice."""
    last_err = None
    for _ in range(max(1, retries)):
        try:
            return _export_once(db_path, out_dir, producer)
        except InconsistentSnapshot as e:
            last_err = e
            time.sleep(0.75)
    raise last_err


def _export_once(db_path, out_dir, producer):
    conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    # One transaction for entries AND heads. Without this the two reads
    # can straddle an append.
    conn.execute("BEGIN DEFERRED")
    ent_sig = has_column(conn, "chain_entries", "chain_sig")
    head_sig = has_column(conn, "chain_heads", "head_sig")

    cols = ("session_id, sequence, chain_entry_hash, previous_entry_hash, "
            "timestamp_ns, monotonic_ns, artifact_type, artifact_id, "
            "artifact_hash, artifact_hash_alg, artifact_schema_version, "
            "signer_node_id, signer_org_id, chain_hmac")
    if ent_sig:
        cols += ", chain_sig, chain_sig_key_id"
    rows = conn.execute(
        "SELECT %s FROM chain_entries ORDER BY session_id, sequence" % cols
    ).fetchall()

    sessions = {}
    for r in rows:
        e = {
            "session_id": r[0], "sequence": r[1], "chain_entry_hash": r[2],
            "previous_entry_hash": r[3], "timestamp_ns": r[4],
            "monotonic_ns": r[5], "artifact_type": r[6], "artifact_id": r[7],
            "artifact_hash": r[8], "artifact_hash_alg": r[9],
            "artifact_schema_version": r[10], "signer_node_id": r[11],
            "signer_org_id": r[12],
        }
        entry = dict(e)
        if r[13]:
            entry["chain_hmac"] = r[13]
        entry["canonical_utf8"] = canonical_json(e)
        if ent_sig and r[14]:
            entry["signature"] = {
                "signature_scheme": "ed25519-detached-v1",
                "signing_key_id": r[15],
                "signature_hex": r[14],
            }
        sessions.setdefault(r[0], []).append(entry)

    heads = {}
    hcols = "session_id, last_sequence, last_entry_hash, head_hmac"
    if head_sig:
        hcols += ", head_sig, head_sig_key_id"
    for hr in conn.execute("SELECT %s FROM chain_heads" % hcols).fetchall():
        h = {"session_id": hr[0], "last_sequence": hr[1],
             "last_entry_hash": hr[2]}
        if hr[3]:
            h["head_hmac"] = hr[3]
        if head_sig and hr[4]:
            h["signature"] = {"signature_scheme": "ed25519-detached-v1",
                              "signing_key_id": hr[5],
                              "signature_hex": hr[4]}
        heads[hr[0]] = h

    # Only bodies an entry actually references may be carried; strict
    # reading rejects unattested content.
    # The head must not name a sequence the entries do not contain.
    for sid, h in heads.items():
        entries = sessions.get(sid) or []
        if not entries:
            continue
        last = max(e["sequence"] for e in entries)
        if int(h.get("last_sequence", -1)) > last:
            conn.close()
            raise InconsistentSnapshot(
                "session %r: head names last_sequence %s but the exported "
                "entries stop at %s -- a writer appended during the read"
                % (sid, h.get("last_sequence"), last))

    referenced = {e["artifact_hash"] for es in sessions.values() for e in es}
    bodies = {}
    for ah, content in conn.execute(
            "SELECT artifact_hash, artifact_content FROM artifacts").fetchall():
        if ah in referenced and ah not in bodies and content is not None:
            bodies[ah] = content
    conn.close()

    os.makedirs(os.path.join(out_dir, "sessions"), exist_ok=True)
    os.makedirs(os.path.join(out_dir, "artifacts"), exist_ok=True)

    manifest_sessions = []
    for sid, entries in sorted(sessions.items()):
        name = safe_name(sid)
        rel = "sessions/%s.json" % name
        doc = {"session_id": sid, "entries": entries}
        if sid in heads:
            doc["head"] = heads[sid]
        with open(os.path.join(out_dir, rel), "w") as f:
            json.dump(doc, f, indent=1, sort_keys=True)
            f.write("\n")
        manifest_sessions.append({"session_id": sid, "path": rel})

    manifest_artifacts = []
    for ah, content in sorted(bodies.items()):
        rel = "artifacts/%s" % ah
        raw = content.encode() if isinstance(content, str) else content
        with open(os.path.join(out_dir, rel), "wb") as f:
            f.write(raw)
        manifest_artifacts.append({"artifact_hash": ah, "path": rel})

    manifest = {
        "docket_bundle_version": BUNDLE_VERSION,
        "chain_format": CHAIN_FORMAT,
        "producer": producer,
        "created_at": datetime.datetime.now(
            datetime.timezone.utc).replace(microsecond=0).isoformat().replace(
                "+00:00", "Z"),
        "sessions": manifest_sessions,
        "artifacts": manifest_artifacts,
    }
    with open(os.path.join(out_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1, sort_keys=True)
        f.write("\n")

    return {"sessions": len(manifest_sessions),
            "entries": sum(len(v) for v in sessions.values()),
            "artifacts": len(manifest_artifacts),
            "entry_signatures": ent_sig, "head_signatures": head_sig}


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Export a VIRP chain database as a Docket evidence bundle")
    p.add_argument("--db", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--producer", default="virp-export-bundle (lab)")
    a = p.parse_args(argv)
    r = export(a.db, a.out, a.producer)
    print("bundle written to %s" % a.out)
    for k, v in sorted(r.items()):
        print("  %-18s %s" % (k, v))
    return 0


if __name__ == "__main__":
    sys.exit(main())
