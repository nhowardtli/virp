#!/usr/bin/env python3
"""
virp_tacacs_reconcile.py — reconcile TACACS+ receipts against gate
records. LAB ONLY.

Reads `tacacs_accounting/1` receipts and `gate_execution/1` records from
a chain database and states WHAT THE RECEIPTS APPEAR TO CORRESPOND TO,
as a `tacacs_reconciliation/1` record.

THE ONE INVARIANT: this program never modifies, re-signs, supersedes or
annotates a receipt. A receipt is final at receipt. Reconciliation is a
NEW record that CITES receipts by (session_id, sequence) plus their
raw_body_sha256, so a cited receipt can be located and confirmed to be
the one that was reconciled. Running this twice produces two
reconciliation records over the same receipts and changes no receipt.
The chain is opened READ-ONLY here; the only write is the new record,
submitted through the ordinary chain_append path.

A reconciliation verdict is a CLAIM, not a cryptographic verdict.
Docket renders it BESIDE the PASS/FAIL/UNCHECKED/UNVERIFIABLE ladder and
never inside it — see docs/TACACS-ACCOUNTING.md §5.

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from virp_tacacs_recv import (ARTIFACT_TYPE, canonical_bytes,
                              chain_append_evidence, producer_load_sk,
                              producer_sign)

SCHEMA = "tacacs_reconciliation/1"
ACCT_SCHEMA = "tacacs_accounting/1"

# The command-reassembly rules this reconciler knows, BY NAME. The name
# goes into the record, because reassembly is an interpretation and a
# reader is entitled to see which one ran.
REASSEMBLY_CISCO = "cisco_cmd_cmdarg_space_join_drop_cr"
REASSEMBLY_UNRECOGNIZED = "UNRECOGNIZED"

VERDICTS = ("MATCHED", "START_WITHOUT_STOP", "STOP_WITHOUT_START",
            "UNGOVERNED", "UNREPORTED", "AMBIGUOUS")
COVERAGE = ("RECEIVER_UP", "RECEIVER_DOWN", "INTERRUPTED",
            "RECEIVER_UNKNOWN")


# ── reading, strictly read-only ────────────────────────────────────────

def read_chain(db_path):
    """(receipts, gate_executions). Read-only URI; this program has no
    write path to the chain other than its own append."""
    conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    try:
        rows = conn.execute(
            "SELECT e.session_id, e.sequence, e.artifact_id, "
            "       e.artifact_type, e.timestamp_ns, a.artifact_content "
            "FROM chain_entries e JOIN artifacts a "
            "  ON a.artifact_hash = e.artifact_hash "
            " AND a.artifact_id = e.artifact_id "
            "ORDER BY e.session_id, e.sequence").fetchall()
    finally:
        conn.close()

    receipts, gates = [], []
    for session_id, seq, aid, atype, ts, content in rows:
        try:
            body = json.loads(content)
        except (ValueError, TypeError):
            continue
        if not isinstance(body, dict):
            continue
        schema = body.get("schema")
        if atype == ARTIFACT_TYPE and schema == ACCT_SCHEMA:
            receipts.append({"session_id": session_id, "sequence": seq,
                             "artifact_id": aid, "timestamp_ns": ts,
                             "body": body})
        elif schema == "gate_execution/1":
            gates.append({"session_id": session_id, "sequence": seq,
                          "artifact_id": aid, "timestamp_ns": ts,
                          "body": body})
    return receipts, gates


def read_ledger(path):
    """The receiver's own up/down ledger. Returns a list of (start_ns,
    stop_ns_or_None) windows in which the listener was up.

    A missing or unreadable ledger yields [] — which makes every
    coverage answer RECEIVER_UNKNOWN, never RECEIVER_UP. Absence of
    evidence about the listener is not evidence the listener was up."""
    windows = []
    if not path or not os.path.exists(path):
        return windows
    open_start = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("event") == "LISTEN_START":
                if open_start is not None:
                    # Previous window never closed: the listener died
                    # without writing LISTEN_STOP (SIGKILL, crash, power).
                    # Close it at this restart. The exact stop instant is
                    # unknown, but the RESTART is certain, so a span
                    # crossing it grades INTERRUPTED rather than borrowing
                    # continuity nobody observed.
                    windows.append((open_start, rec.get("utc_ns")))
                open_start = rec.get("utc_ns")
            elif rec.get("event") == "LISTEN_STOP" and open_start is not None:
                windows.append((open_start, rec.get("utc_ns")))
                open_start = None
    if open_start is not None:
        windows.append((open_start, None))   # still listening
    return windows


def _covers(windows, t_ns):
    for start, stop in windows:
        if start is None:
            continue
        if t_ns >= start and (stop is None or t_ns <= stop):
            return True
    return False


def coverage_for(windows, t_ns):
    """Point coverage. RECEIVER_UP only when a window demonstrably
    covers t_ns; absence of a ledger is never RECEIVER_UP."""
    if not windows:
        return "RECEIVER_UNKNOWN"
    return "RECEIVER_UP" if _covers(windows, t_ns) else "RECEIVER_DOWN"


def coverage_for_span(windows, t0_ns, t1_ns):
    """Coverage across the whole interval a claim depends on, plus the
    ledger events that justify the answer.

    Returns (coverage, evidence). Four states, deliberately distinct:

      RECEIVER_UP       every instant of [t0,t1] falls inside a listening
                        window.
      INTERRUPTED       the interval STARTS inside a listening window and
                        the receiver then stopped and/or restarted inside
                        it. This is the shape of "the listener was killed
                        mid-session": the START was received, the STOP
                        could not be.
      RECEIVER_DOWN     no part of the interval was covered.
      RECEIVER_UNKNOWN  no ledger covers it. Absence of evidence about
                        the listener is NOT evidence the listener was up.

    Why this matters, and why it is not a verdict: a missing STOP graded
    START_WITHOUT_STOP with coverage RECEIVER_UP is a gap the receiver
    cannot explain -- device loss, emulator loss, or a device that never
    sent it. The same gap with coverage INTERRUPTED has a cause the
    receiver can EVIDENCE from its own ledger. The two must never be
    collapsed, because one of them is a fault in the evidence path and
    the other is a fault somewhere nobody has looked yet.

    The evidence is the ledger boundary timestamps themselves, so a
    reader checks the claim rather than trusting it.
    """
    if not windows:
        return "RECEIVER_UNKNOWN", []
    if t1_ns < t0_ns:
        t0_ns, t1_ns = t1_ns, t0_ns

    # Every listening boundary strictly inside the interval is a moment
    # the receiver's availability changed while the claim was pending.
    boundaries = []
    for start, stop in windows:
        if start is not None and t0_ns < start <= t1_ns:
            boundaries.append({"event": "LISTEN_START", "utc_ns": start})
        if stop is not None and t0_ns <= stop < t1_ns:
            boundaries.append({"event": "LISTEN_STOP", "utc_ns": stop})
    boundaries.sort(key=lambda b: b["utc_ns"])

    start_covered = _covers(windows, t0_ns)
    end_covered = _covers(windows, t1_ns)

    if start_covered and end_covered and not boundaries:
        return "RECEIVER_UP", []
    if boundaries:
        return "INTERRUPTED", boundaries
    if not start_covered and not end_covered:
        return "RECEIVER_DOWN", []
    # Covered at exactly one end with no boundary inside: the interval
    # runs off the end of the ledger. Not UP, and not a demonstrated
    # outage either.
    return "RECEIVER_UNKNOWN", []


# ── interpretation, all of it named ────────────────────────────────────

def reassemble_command(args):
    """(command, rule_name).

    Cisco delivers a command as cmd=<verb> followed by repeated
    cmd-arg=<token>, with a trailing cmd-arg=<cr>. Joining those is an
    INTERPRETATION; the rule that ran is named in the record so a reader
    can see what "the command" meant on this run.

    An argument list with no cmd= is not guessed at: it returns
    (None, UNRECOGNIZED) and the caller must not claim a match on it.
    """
    verb = None
    tokens = []
    for a in args:
        if a.startswith("cmd="):
            if verb is None:
                verb = a[4:]
        elif a.startswith("cmd-arg="):
            tokens.append(a[8:])
    if verb is None:
        return None, REASSEMBLY_UNRECOGNIZED
    while tokens and tokens[-1] == "<cr>":
        tokens.pop()
    parts = [verb] + tokens
    return " ".join(p for p in parts if p != ""), REASSEMBLY_CISCO


def _task_id(body):
    idx = body.get("args_index") or {}
    return idx.get("task_id")


def _flags(body):
    return set(body.get("acct_flags") or [])


def record_class(body):
    """"command" or "session".

    MEASURED on Cisco IOS 15.2(4)M7: `aaa accounting commands 15 ...
    start-stop` emits a SINGLE STOP record per command. There is no START.
    `start-stop` governs EXEC/session accounting, where both records do
    appear; for COMMAND accounting one STOP is the whole, complete record.

    This distinction is load-bearing. Without it every accounted command
    grades STOP_WITHOUT_START, which would report a platform's normal and
    correct behaviour as a missing-evidence defect on every row -- crying
    wolf so consistently that a real missing STOP would be invisible.

    A command record is identified by carrying a `cmd` argument; a session
    record does not. Both are shell service records, so `service=` alone
    cannot separate them.
    """
    idx = body.get("args_index") or {}
    if idx.get("cmd") is not None:
        return "command"
    for a in (body.get("args") or []):
        if a.startswith("cmd="):
            return "command"
    return "session"


def reconcile(receipts, gates, windows, match_window_ms, horizon_ns=None):
    """Pair receipts with gate_executions and grade. Returns the list of
    per-item claims. Nothing here writes anything."""
    window_ns = match_window_ms * 1_000_000
    items = []
    matched_gate_keys = set()

    # The horizon closes an interval whose STOP never arrived. Without it a
    # START_WITHOUT_STOP would be graded at a single instant and a receiver
    # outage AFTER the START -- exactly the case worth catching -- would be
    # invisible. Default: the last receipt this run observed.
    if horizon_ns is None:
        _t = [r["body"].get("recv_utc_ns") or r["timestamp_ns"]
              for r in receipts]
        horizon_ns = max(_t) if _t else 0

    # Group receipts by (client_identity or source_addr, task_id). task_id
    # is the device's own correlator for one accounting session and is the
    # only join key TACACS+ offers between a START and its STOP.
    groups = {}
    for r in receipts:
        b = r["body"]
        key = (b.get("client_identity") or b.get("source_addr"),
               _task_id(b))
        groups.setdefault(key, []).append(r)

    for (device, task_id), members in sorted(
            groups.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
        members.sort(key=lambda r: r["body"].get("recv_utc_ns") or 0)
        starts = [r for r in members if "START" in _flags(r["body"])]
        stops = [r for r in members if "STOP" in _flags(r["body"])]

        cites = [{"session_id": r["session_id"],
                  "sequence": r["sequence"],
                  "raw_body_sha256": r["body"].get("raw_body_sha256"),
                  "acct_flags": r["body"].get("acct_flags")}
                 for r in members]

        ref = members[0]
        rb = ref["body"]
        command, rule = reassemble_command(rb.get("args") or [])
        t_ns = rb.get("recv_utc_ns") or ref["timestamp_ns"]
        last_ns = (members[-1]["body"].get("recv_utc_ns")
                   or members[-1]["timestamp_ns"])

        # Pair completeness first: it is a fact about the receipts alone
        # and does not depend on any gate record existing.
        # A pair that never closed stays open to the horizon; a closed
        # pair is judged only over its own span.
        klass = record_class(rb)
        span_end = horizon_ns if not stops else last_ns
        cov, cov_evidence = coverage_for_span(windows, t_ns, span_end)

        # Pair rules apply to SESSION records. For command accounting a
        # lone STOP is the complete record (see record_class); grading it
        # STOP_WITHOUT_START would report normal platform behaviour as a
        # defect on every row, and a real missing STOP would then be
        # invisible in the noise.
        if klass == "command":
            if stops:
                verdict, detail = None, ""
            else:
                verdict, detail = ("START_WITHOUT_STOP",
                                   "command record with no STOP")
        elif starts and not stops:
            verdict, detail = "START_WITHOUT_STOP", "no STOP for this task_id"
        elif stops and not starts:
            verdict, detail = "STOP_WITHOUT_START", "no START for this task_id"
        else:
            verdict, detail = None, ""

        # Candidate gate records: same device, same reassembled command
        # bytes, inside the window.
        candidates = []
        if command is not None:
            for g in gates:
                gb = g["body"]
                if gb.get("device") != device:
                    continue
                if gb.get("command") != command:
                    continue
                if abs((g["timestamp_ns"] or 0) - t_ns) > window_ns:
                    continue
                candidates.append(g)

        if command is None:
            gate_verdict = "UNGOVERNED"
            gate_cite = None
            detail = (detail + "; " if detail else "") + \
                "command not reassemblable under any known rule"
        elif len(candidates) == 1:
            gate_verdict = "MATCHED"
            g = candidates[0]
            gate_cite = {"session_id": g["session_id"],
                         "sequence": g["sequence"],
                         "artifact_id": g["artifact_id"]}
            matched_gate_keys.add((g["session_id"], g["sequence"]))
        elif len(candidates) > 1:
            gate_verdict = "AMBIGUOUS"
            gate_cite = [{"session_id": g["session_id"],
                          "sequence": g["sequence"],
                          "artifact_id": g["artifact_id"]}
                         for g in candidates]
            detail = (detail + "; " if detail else "") + \
                ("%d gate_execution candidates satisfied the match rule; "
                 "none chosen" % len(candidates))
        else:
            gate_verdict = "UNGOVERNED"
            gate_cite = None

        # A pair defect and a governance verdict are two different facts.
        # The pair defect wins the headline because it is a statement
        # about the receipts themselves, and the governance reading is
        # carried alongside rather than overwriting it.
        final = verdict or gate_verdict

        items.append({
            "verdict": final,
            "record_class": klass,
            "gate_correspondence": gate_verdict,
            "device": device,
            "task_id": task_id,
            "command": command,
            "command_reassembly": rule,
            "coverage": cov,
            "coverage_evidence": cov_evidence,
            "coverage_span_ns": [t_ns, span_end],
            "receipt_cites": cites,
            "gate_cite": gate_cite,
            "detail": detail,
        })

    # Gate records nobody accounted for. Only gate_executions inside the
    # observed receipt time span are considered: a gate record from
    # before this receiver ever listened is not evidence a device failed
    # to report, and grading it UNREPORTED would manufacture a fault.
    if receipts:
        times = [r["body"].get("recv_utc_ns") or r["timestamp_ns"]
                 for r in receipts]
        lo, hi = min(times) - window_ns, max(times) + window_ns
        for g in gates:
            if (g["session_id"], g["sequence"]) in matched_gate_keys:
                continue
            ts = g["timestamp_ns"] or 0
            if not (lo <= ts <= hi):
                continue
            items.append({
                "verdict": "UNREPORTED",
                "record_class": None,
                "gate_correspondence": "UNREPORTED",
                "device": g["body"].get("device"),
                "task_id": None,
                "command": g["body"].get("command"),
                "command_reassembly": None,
                "coverage": coverage_for(windows, ts),
                "coverage_evidence": [],
                "coverage_span_ns": [ts, ts],
                "receipt_cites": [],
                "gate_cite": {"session_id": g["session_id"],
                              "sequence": g["sequence"],
                              "artifact_id": g["artifact_id"]},
                "detail": "gate_execution with no corresponding accounting",
            })
    return items


def build_record(items, match_window_ms, db_path, ledger_path, windows):
    tally = {v: 0 for v in VERDICTS}
    cov = {c: 0 for c in COVERAGE}
    for it in items:
        tally[it["verdict"]] = tally.get(it["verdict"], 0) + 1
        cov[it["coverage"]] = cov.get(it["coverage"], 0) + 1
    return {
        "schema": SCHEMA,
        "reconciled_utc_ns": time.time_ns(),
        "match_rule": {
            "match_window_ms": match_window_ms,
            "command_comparison": "exact_bytes",
            "join_key": "client_identity_or_source_addr + args_index.task_id",
            "known_reassembly_rules": [REASSEMBLY_CISCO],
        },
        "source": {
            "chain_db_sha256": _file_sha256(db_path),
            "ledger_path_present": bool(windows),
            "ledger_windows": len(windows),
        },
        "tally": tally,
        "coverage_tally": cov,
        "items": items,
        "presentation": (
            "CLAIM, not a cryptographic verdict. Render beside the "
            "PASS/FAIL/UNCHECKED/UNVERIFIABLE ladder, never inside it. "
            "This record cites receipts and never modifies them."),
    }


def _file_sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Reconcile TACACS+ receipts against gate records "
                    "(lab only). Never modifies a receipt.")
    p.add_argument("--db", required=True, help="chain database (read-only)")
    p.add_argument("--ledger", help="receiver LISTEN_START/STOP ledger")
    p.add_argument("--match-window-ms", type=int, default=15000)
    p.add_argument("--out", help="write the record JSON here")
    p.add_argument("--submit", action="store_true",
                   help="append the record to the chain")
    p.add_argument("--producer-key")
    p.add_argument("--onode-socket", default="/run/virp/onode.sock")
    p.add_argument("--chain-session", default="tacacs-reconcile")
    args = p.parse_args(argv)

    receipts, gates = read_chain(args.db)
    windows = read_ledger(args.ledger)
    items = reconcile(receipts, gates, windows, args.match_window_ms)
    rec = build_record(items, args.match_window_ms, args.db,
                       args.ledger, windows)

    print("receipts: %d   gate_executions: %d   items: %d"
          % (len(receipts), len(gates), len(items)))
    print("tally: %s" % json.dumps(rec["tally"], sort_keys=True))
    print("coverage: %s" % json.dumps(rec["coverage_tally"], sort_keys=True))

    if args.out:
        with open(args.out, "w") as f:
            json.dump(rec, f, indent=1, sort_keys=True)
            f.write("\n")
        print("wrote %s" % args.out)

    if args.submit:
        if not args.producer_key:
            raise SystemExit("--submit needs --producer-key")
        sk = producer_load_sk(args.producer_key)
        body_bytes, _ = producer_sign(sk, rec)
        aid = "tacacs-reconcile:%d:%s" % (
            rec["reconciled_utc_ns"],
            hashlib.sha256(body_bytes).hexdigest()[:16])
        ok, detail = chain_append_evidence(args.chain_session, aid,
                                           body_bytes, args.onode_socket)
        if not ok:
            raise SystemExit("reconciliation NOT chained: %s" % detail)
        print("chained as %s (%d bytes)" % (aid, len(body_bytes)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
