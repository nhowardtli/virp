#!/usr/bin/env python3
"""
Test: every fed_outcome cites an observation body that is actually stored.

A fed_outcome artifact is the federation bridge's claim about what it put
to the gate and what came back. Its `observation_sha256` field is the only
pointer from that claim to the signed evidence — the SHA-256 of the raw
observation wire message, which the bridge appends separately under
artifact_id `ncfed-obs-<correlation[:32]>`.

The pointer is only worth anything if it resolves. A fed_outcome whose
observation_sha256 names a hash absent from `artifacts` is an unbacked
claim: the chain records "this ran and here is the proof" while the proof
is not retrievable. That reads as evidence and is not.

Regression pinned here (found 2026-08-16): commit cbdc5d24 ("Item 8"
per-uid action allowlist) narrowed a restricted principal's chain_append
to fed_request/fed_outcome. uid 993 (virp-netclaw) is such a principal, so
its middle append — the `observation` body itself — began returning
VIRP_ERR_ACTION_FORBIDDEN while the fed_outcome citing it kept landing.
Every federated read from 2026-08-11 17:44 UTC onward therefore carries a
dangling pointer. The daemon logged each refusal; nothing downstream
noticed, because nothing checked that the cited body resolves.

This test is that check. It is a data-integrity assertion over the live
chain, not a unit test of a function: it self-skips when no chain database
is present, so it is safe on a build host.

TWO CITATIONS (2026-09-03). An outcome is backed by an observation
(`observation_sha256`) or, when the exchange died before an observation
existed, by a `fed_error` body (`error_sha256`) that says why. The
question this file asks is unchanged and now asked of both: does the
cited body resolve, and does it resolve to the RIGHT TYPE. The extra
rule for the error-backed form is that it may never claim execution —
"it ran" is a claim only signed evidence can carry.

    VIRP_CHAIN_DB   path to chain.db (default /var/lib/virp/chain.db)
    VIRP_FED_SINCE  only audit outcomes completed on/after this ISO date
                    (default: audit everything in the chain)
"""

import json
import os
import sqlite3
import sys
import unittest

DEFAULT_DB = "/var/lib/virp/chain.db"

# The observation artifact types a fed_outcome may legitimately cite. Kept in
# lockstep with report/verify.py:OBSERVATION_TYPES, the chain layer
# (src/virp_chain.c: artifact_type IN ('observation','fed_observation')) and
# this file's own load_committed_observation_hashes(). "fed_observation" is the
# federation bridge's name for a signed observation (2026-08-16); a fed_outcome
# from the ncfed bridge cites one by design (tests/test_onode.c appends the
# cited body as 'fed_observation' under artifact_id ncfed-obs-*).
OBSERVATION_TYPES = frozenset(("observation", "fed_observation"))

# The type an `error_sha256` citation must resolve to. Deliberately its own
# set: a fed_error carries no signature and claims none, so it may back an
# outcome that says a command did NOT run and nothing else. Mirrors
# src/virp_chain.c (artifact_type = 'fed_error') and the daemon's GATE 4.
ERROR_TYPES = frozenset(("fed_error",))

# artifact_hash field name -> the types it may resolve to.
CITATIONS = {"observation_sha256": OBSERVATION_TYPES,
             "error_sha256": ERROR_TYPES}


def citation_of(body):
    """(field, hash) for the ONE citation this outcome carries.

    (None, None) when there is no usable citation — absent, malformed, or
    BOTH present, which is not extra evidence but an outcome that cannot
    be graded. The daemon refuses all three at GATE 4; this audit reads
    the same rule off the stored bodies."""
    found = []
    for field in CITATIONS:
        h = body.get(field)
        if isinstance(h, str) and len(h) == 64:
            found.append((field, h))
    return found[0] if len(found) == 1 else (None, None)


def chain_db_path():
    return os.environ.get("VIRP_CHAIN_DB", DEFAULT_DB)


def open_chain_ro(path):
    """Open the chain read-only. An audit never writes to what it audits."""
    return sqlite3.connect("file:%s?mode=ro" % path, uri=True)


def load_fed_outcomes(conn, since=None):
    """Return [(rowid, parsed_body)] for every fed_outcome artifact."""
    cur = conn.execute(
        "SELECT id, artifact_content FROM artifacts "
        "WHERE artifact_type = 'fed_outcome' ORDER BY created_at_ns"
    )
    out = []
    for rowid, content in cur:
        try:
            body = json.loads(content)
        except (ValueError, TypeError):
            # A fed_outcome that is not JSON is its own defect; report it
            # as a malformed row rather than silently dropping it.
            out.append((rowid, None))
            continue
        if since and (body.get("completed_at") or "") < since:
            continue
        out.append((rowid, body))
    return out


def load_artifact_hashes(conn):
    """Every artifact_hash in the table, as a set.

    One scan into memory rather than a correlated subquery per outcome:
    `artifacts` is indexed on artifact_id only, so a per-row lookup by
    hash is a full scan each time (~100k rows) and the audit does not
    finish. Bodies are keyed by (artifact_id, artifact_hash), so the same
    id may legitimately carry several hashes — membership is the question,
    not uniqueness.
    """
    return {h for (h,) in conn.execute("SELECT artifact_hash FROM artifacts")}


def load_hash_types(conn):
    """artifact_hash -> set of artifact_types stored under it."""
    types = {}
    for h, t in conn.execute("SELECT artifact_hash, artifact_type FROM artifacts"):
        types.setdefault(h, set()).add(t)
    return types


def load_committed_observation_hashes(conn):
    """Every artifact_hash an OBSERVATION chain ENTRY commits to, as a set.

    Distinct from load_artifact_hashes(): that reads the `artifacts` table
    (bodies retained); this reads `chain_entries` (appends accepted). An
    oversized observation — a GREEN output past the daemon's 8192-byte
    inline field — is chained commitment-only: the entry lands and commits
    to the hash, but no body row is stored. Such an observation is still IN
    the chain, so a fed_outcome that cites it is BACKED even though the body
    is not retrievable (the reader grades that entry UNVERIFIABLE, not PASS).
    This mirrors the daemon's fed_outcome gate (virp_chain_entry_commits_to).
    """
    return load_committed_hashes(conn, OBSERVATION_TYPES)


def load_committed_hashes(conn, types):
    """Every artifact_hash a chain ENTRY of one of `types` commits to."""
    placeholders = ",".join("?" * len(types))
    return {h for (h,) in conn.execute(
        "SELECT artifact_hash FROM chain_entries "
        "WHERE artifact_type IN (%s)" % placeholders,
        tuple(sorted(types)))}


class TestFedOutcomeObservationResolves(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = chain_db_path()
        if not os.path.exists(path):
            raise unittest.SkipTest(
                "no chain database at %s — nothing to audit" % path)
        cls.conn = open_chain_ro(path)
        cls.since = os.environ.get("VIRP_FED_SINCE") or None
        cls.outcomes = load_fed_outcomes(cls.conn, cls.since)
        cls.hashes = load_artifact_hashes(cls.conn)
        cls.committed = {
            "observation_sha256": load_committed_hashes(cls.conn,
                                                        OBSERVATION_TYPES),
            "error_sha256": load_committed_hashes(cls.conn, ERROR_TYPES),
        }
        cls.hash_types = load_hash_types(cls.conn)

    @classmethod
    def tearDownClass(cls):
        conn = getattr(cls, "conn", None)
        if conn is not None:
            conn.close()

    def test_every_outcome_body_is_json(self):
        bad = [rowid for rowid, body in self.outcomes if body is None]
        self.assertEqual(bad, [], "fed_outcome rows whose body is not JSON: %r" % bad)

    def test_every_outcome_carries_exactly_one_citation(self):
        """The pointer field must be present, well-formed, and singular.

        Both citations at once is refused as hard as neither: an outcome
        that names signed evidence AND an account of why there is none
        cannot be graded, and a reader would have to guess which half to
        believe."""
        missing = []
        for rowid, body in self.outcomes:
            if body is None:
                continue
            field, _ = citation_of(body)
            if field is None:
                missing.append((rowid, body.get("completed_at"),
                                {f: body.get(f) for f in CITATIONS
                                 if f in body}))
        self.assertEqual(
            missing, [],
            "fed_outcome rows with no single usable citation "
            "(observation_sha256 or error_sha256):\n" +
            "\n".join("  id=%s completed=%s fields=%r" % m for m in missing))

    def test_every_cited_body_resolves(self):
        """THE assertion: the cited body must be BACKED by the chain —
        either its bytes are retrievable from artifacts, OR an entry of
        the citing field's type commits to the hash (an oversized,
        commitment-only observation, whose body was legitimately not
        retained). Only a hash that NEITHER stores a body NOR is
        committed by such an entry is a dangling pointer — evidence the
        chain cannot produce."""
        dangling = []
        for rowid, body in self.outcomes:
            if body is None:
                continue
            field, h = citation_of(body)
            if field is None:
                continue          # covered by the previous test
            if h not in self.hashes and h not in self.committed[field]:
                dangling.append((
                    body.get("completed_at"), body.get("device"),
                    body.get("command"), field, h))

        if dangling:
            lines = ["%d of %d fed_outcome artifacts cite a body that is "
                     "NEITHER stored NOR committed by an entry of the type "
                     "the citation requires." %
                     (len(dangling), len(self.outcomes)),
                     "The chain claims evidence it cannot produce.",
                     "First 10:"]
            for completed, device, command, field, h in dangling[:10]:
                lines.append("  %s  %-24s %-40s %s=%s"
                             % (completed, device, str(command)[:40],
                                field, h))
            lines.append("Check the daemon log for POLICY REFUSAL on "
                         "chain_append artifact_type 'observation' / "
                         "'fed_observation' / 'fed_error'.")
            lines.append("")
            lines.append(
                "NOTE ON HISTORY: entries written before the 2026-08-16 fix "
                "cannot be repaired. The chain is append-only and the bodies "
                "were never stored, so those 54 rows stay unbacked forever — "
                "that is the honest record, not a bug to edit away. To audit "
                "only what the fixed daemon wrote, set VIRP_FED_SINCE to the "
                "date the fix was deployed; leave it unset to see the whole "
                "history including the damage.")
            self.fail("\n".join(lines))

    def test_cited_hash_names_the_right_type(self):
        """A resolving pointer must resolve to the type its FIELD NAME
        promises, not to some other artifact that happens to share the
        hash. `observation_sha256` must name an observation type;
        `error_sha256` must name a fed_error. Swapping them would let an
        unsigned body stand in for signed evidence, which is the whole
        thing GATE 3 and GATE 4 exist to prevent."""
        wrong = []
        for rowid, body in self.outcomes:
            if body is None:
                continue
            field, h = citation_of(body)
            if field is None or h not in self.hash_types:
                continue          # absent is the previous test's failure
            if not (CITATIONS[field] & self.hash_types[h]):
                wrong.append((body.get("completed_at"), field, h,
                              sorted(self.hash_types[h])))
        self.assertEqual(
            wrong, [],
            "a citation resolves to the wrong artifact type:\n" +
            "\n".join("  %s %s=%s -> %r" % w for w in wrong))

    def test_error_backed_outcomes_never_claim_execution(self):
        """An outcome backed only by a fed_error may report that a command
        did NOT run and why. It may not report that one did.

        The bridge holds no key and can never produce signed evidence.
        Without this rule it could write executed:true into the chain
        backed by nothing but its own account of a failure, and a reader
        joining outcomes to observations would see a completed command
        with no observation — indistinguishable from a retention gap.
        The daemon refuses this at GATE 4; this is the same rule read
        back off the live chain."""
        claiming = []
        for rowid, body in self.outcomes:
            if body is None:
                continue
            field, h = citation_of(body)
            if field != "error_sha256":
                continue
            if body.get("executed") or body.get("outcome") == "executed":
                claiming.append((body.get("completed_at"),
                                 body.get("device"), body.get("command"),
                                 body.get("outcome"), body.get("executed")))
        self.assertEqual(
            claiming, [],
            "error-backed fed_outcome claims a command executed:\n" +
            "\n".join("  %s %s %r outcome=%r executed=%r" % c
                       for c in claiming))


def main():
    path = chain_db_path()
    print("=== fed_outcome -> observation pointer audit ===")
    print("chain: %s" % path)
    if not os.path.exists(path):
        print("  *** SKIPPING: no chain database at %s" % path)
        print("  *** federated observation pointers are NOT covered in this run.")
        return 0
    suite = unittest.TestLoader().loadTestsFromTestCase(
        TestFedOutcomeObservationResolves)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
