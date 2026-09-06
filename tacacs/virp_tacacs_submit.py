#!/usr/bin/env python3
"""
virp_tacacs_submit.py — ship tac_plus-ng decisions to 313 as evidence.

WHY THIS EXISTS. tac_plus-ng writes its decisions to local files on the
box that makes them. A server that both decides and stores its own
record of deciding can be made to forget: anyone who can write
/var/log/tacacs can rewrite history, and the only copy is on the machine
with the motive. This ships each line to a chain on 313, which 215 does
not control, so a decision that happened is recorded somewhere 215
cannot reach.

It is a SUBMITTER, not a mover: the local file is still the primary
record and is never truncated or rotated by this process.

FAIL-CLOSED ON LOSS. The offset advances only after the gate confirms
the append. A refused or unreachable append leaves the offset where it
was and the line is retried; it is never skipped. A decision that
reached nobody must not look like one that was stored.

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import argparse
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from virp_tacacs_recv import (canonical_bytes, chain_append_evidence,
                              producer_key_id, producer_load_sk,
                              producer_sign, ARTIFACT_LIMIT)

SCHEMA = "tacacs_decision/1"

# The visible columns tac_plus-ng emits, after our ${msgid} append.
# Column 1 is "TIMESTAMP nas" because the timestamp prefix is not
# tab-separated from the device address.
AUTHZ_FIELDS = ("user", "port", "client", "profile", "result",
                "service", "cmd", "msgid")
ACCESS_FIELDS = ("user", "port", "client", "action", "msgid")


def split_line(line):
    """tac_plus-ng separates with TAB; field 0 carries 'timestamp nas'."""
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 2:
        return None
    head = parts[0].rsplit(" ", 1)
    if len(head) != 2:
        return None
    ts, nas = head[0], head[1]
    return ts, nas, parts[1:]


def parse_line(line, kind):
    """Return a dict, or None if the line is not parseable.

    An unparseable line is NOT silently dropped by the caller — see
    submit_line, which ships it with parse='FAILED' and the raw text, on
    the same principle the receiver uses: a record we could not read is
    still evidence that something arrived."""
    got = split_line(line)
    if not got:
        return None
    ts, nas, rest = got
    names = AUTHZ_FIELDS if kind == "authz" else ACCESS_FIELDS
    rec = {"timestamp": ts, "device_addr": nas}
    for i, name in enumerate(names):
        rec[name] = rest[i] if i < len(rest) else None
    return rec


def classify_refusal(rec, allowed_sources):
    """Tag a source refusal that the raw log cannot express.

    tac_plus-ng emits AUTHC-FAIL-ACL for an authentication denied by the
    source acl -- that IS a distinct token and is preserved as-is. But on
    the AUTHORIZATION path it emits only the generic AUTHZ-FAIL, with no
    reason vocabulary and no script-settable variable to carry one. So a
    source refusal and a command refusal are indistinguishable there.

    This recomputes the source test from the client address and records
    the verdict explicitly. It is DERIVED, not observed: the field is
    named source_refused_derived so a reader never mistakes it for
    something tac_plus-ng said."""
    client = rec.get("client")
    result = (rec.get("result") or "").lower()
    msgid = rec.get("msgid") or ""
    if msgid == "AUTHC-FAIL-ACL":
        return True, "tac_plus-ng"        # observed, not derived
    if result == "deny" and client is not None:
        return (client not in allowed_sources), "derived"
    return False, "n/a"


def build_body(rec, kind, node, key_id, allowed_sources):
    refused, basis = classify_refusal(rec, allowed_sources)
    body = {
        "schema": SCHEMA,
        "submitter_node": node,
        # PRESENT HERE DELIBERATELY. tacacs_accounting/1 carries
        # producer_sig with NO key id, so a record cannot say which key
        # signed it. That was survivable with one producer; this is a
        # SECOND producer on the same node and the same chain, so the
        # ambiguity would start to bite immediately.
        "producer_key_id": key_id,
        "decision_kind": kind,
        "source_refused_derived": refused,
        "source_refused_basis": basis,
    }
    body.update({k: v for k, v in rec.items()})
    return body


def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(path, state):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def submit_line(line, kind, cfg, sk, key_id, sock_path):
    """Returns (ok, detail). ok=False means the caller MUST NOT advance."""
    rec = parse_line(line, kind)
    if rec is None:
        rec = {"parse": "FAILED", "raw": line.rstrip("\n")[:512]}
    body_nosig = build_body(rec, kind, cfg["submitter_node"], key_id,
                            set(cfg.get("allowed_operator_sources", [])))
    body_bytes, _ = producer_sign(sk, body_nosig)
    if len(body_bytes) >= ARTIFACT_LIMIT:
        return False, "body %d >= limit %d" % (len(body_bytes), ARTIFACT_LIMIT)
    artifact_id = "tacacs-decision:%s:%s" % (
        kind, hashlib.sha256(body_bytes).hexdigest()[:24])
    return chain_append_evidence(cfg["session_id"], artifact_id,
                                 body_bytes, sock_path)
