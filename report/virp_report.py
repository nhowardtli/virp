#!/usr/bin/env python3
"""
virp report — consumer-side PDF report generator for a VIRP trust chain.

Reads a chain database read-only (without disturbing a running daemon) and
renders a PDF that is a PROJECTION OF RE-VERIFIED EVIDENCE. Every hash and
signature printed here was recomputed from the chain at render time; nothing
is copied from a stored value and presented as if it had been checked.

Where a check fails, the failure is printed in place, in red, at the point in
the report where the entry would otherwise have appeared. Nothing is dropped
to keep the report tidy. Where a check CANNOT be run because the chain never
retained the evidence, that is stated as UNVERIFIABLE and explained, and is
never counted as a pass.

Usage:
    virp report --db <path> --out <file.pdf>
                [--session <id>] [--since <ts>] [--until <ts>]

Pure Python: stdlib + reportlab. No compiled extensions beyond what reportlab
optionally ships, no system packages, and no network access of any kind.

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import argparse
import datetime
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import chain_read  # noqa: E402
import verify  # noqa: E402

from reportlab.lib import colors  # noqa: E402
from reportlab.lib.enums import TA_LEFT  # noqa: E402
from reportlab.lib.pagesizes import landscape, letter  # noqa: E402
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # noqa: E402
from reportlab.lib.units import inch  # noqa: E402
from reportlab.platypus import (  # noqa: E402
    KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
    TableStyle)

DEFAULT_OKEY = "/etc/virp/keys/onode.key"
DEFAULT_CHAIN_KEY = "/etc/virp/keys/chain.key"
DEFAULT_NODE_IDENTITY = "/etc/virp/autopilot-node.json"

# Verdict → colour. UNVERIFIABLE is amber, never green: it is not a pass.
# V2-SESSION is blue-violet — deliberately NEITHER the green of a verified
# pass NOR the red/amber of failure and retention loss: it marks a frame
# whose deployed version cannot be verified at rest by design, with its
# own corroboration verdicts alongside.
VERDICT_COLOR = {
    verify.PASS: colors.HexColor("#0b6b2f"),
    verify.FAIL: colors.HexColor("#b00020"),
    verify.UNCHECKED: colors.HexColor("#5a5a5a"),
    verify.UNVERIFIABLE: colors.HexColor("#8a5a00"),
    verify.V2_SESSION: colors.HexColor("#3f3fae"),
    verify.NOT_APPLICABLE: colors.HexColor("#8a8a8a"),
}

def vhex(verdict):
    """'#rrggbb' for a verdict, for use in Paragraph <font color=...> markup."""
    return "#" + VERDICT_COLOR[verdict].hexval()[2:].rjust(6, "0")[-6:]


FAIL_BG = colors.HexColor("#ffe3e6")
UNVERIFIABLE_BG = colors.HexColor("#fff4e0")
V2_BG = colors.HexColor("#eceafb")
HEAD_BG = colors.HexColor("#e8eaed")


# ── time helpers ──────────────────────────────────────────────────────────

def ns_to_utc(ns):
    """Nanosecond wall clock → ISO-8601 UTC, second resolution."""
    if ns is None:
        return "-"
    return datetime.datetime.fromtimestamp(
        ns / 1e9, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp(text):
    """Accept an ISO-8601 date/datetime or an epoch value, return epoch ns.

    Bare integers are interpreted by magnitude: seconds, milliseconds,
    microseconds or nanoseconds, so an operator can paste a chain
    timestamp_ns straight from the database without converting it.
    """
    text = text.strip()
    if not text:
        raise ValueError("empty timestamp")
    if text.isdigit():
        value = int(text)
        if value < 10 ** 11:          # seconds
            return value * 10 ** 9
        if value < 10 ** 14:          # milliseconds
            return value * 10 ** 6
        if value < 10 ** 17:          # microseconds
            return value * 10 ** 3
        return value                  # nanoseconds
    iso = text.replace("Z", "+00:00")
    dt = datetime.datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return int(dt.timestamp() * 10 ** 9)


def trunc(text, width):
    """Shorten for table display, marking that we did so."""
    if text is None:
        return "-"
    text = str(text)
    return text if len(text) <= width else text[:width - 1] + "…"


def esc(text):
    """Escape text for reportlab's mini-XML Paragraph markup.

    Required for any CALLER-SUPPLIED string — device command text in
    particular. reportlab parses Paragraph content as markup, so a
    blocked command containing '<', '>' or '&' (e.g. a redirect, or
    'a && b') would corrupt the tag stream or raise mid-render. Applied
    wherever command/reason text reaches a Paragraph."""
    if text is None:
        return "-"
    return (str(text).replace("&", "&amp;")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;"))


# ── evidence loading ──────────────────────────────────────────────────────

def load_evidence(reader, session=None, since_ns=None, until_ns=None):
    """Pull the selected chain entries plus every artifact body they name."""
    sql = ("SELECT " + ",".join(verify.ENTRY_COLUMNS) +
           " FROM chain_entries WHERE 1=1")
    params = []
    if session:
        sql += " AND session_id = ?"
        params.append(session)
    if since_ns is not None:
        sql += " AND timestamp_ns >= ?"
        params.append(since_ns)
    if until_ns is not None:
        sql += " AND timestamp_ns <= ?"
        params.append(until_ns)
    sql += " ORDER BY session_id, sequence"

    entries = [dict(r) for r in reader.conn.execute(sql, params)]
    # Keyed by (artifact_id, artifact_hash) — the pair the entry commits
    # to and the artifacts table is keyed by. An id-only key silently
    # keeps one body per colliding id and grades every sibling entry
    # against it: on 2026-08-16 that misreported 50 healthy federation
    # entries (the bridge's re-serialized retries) as FAILED.
    artifacts = {(r["artifact_id"], r["artifact_hash"]): r["artifact_content"]
                 for r in reader.conn.execute(
                     "SELECT artifact_id, artifact_hash, artifact_content "
                     "FROM artifacts")}
    return entries, artifacts


def load_heads(reader):
    """Load the signed per-session head records, or None when the database
    predates the chain_heads table (2026-08-01). None vs {} matters:
    None means chain length is structurally unverifiable (legacy DB);
    an empty/partial dict means the table exists and a missing session
    row is a tampering signal."""
    try:
        return {r["session_id"]: dict(r) for r in reader.conn.execute(
            "SELECT session_id, last_sequence, last_entry_hash, head_hmac "
            "FROM chain_heads")}
    except sqlite3.OperationalError:
        return None


def collect_journal_hello_acks(unit="virp-onode"):
    """Gather SESSION_HELLO_ACK session ids from the daemon journal, for
    corroborating v2 (session-key-signed) observations.

    Returns {"session_ids": set, "since_ns": int|None}, or None when the
    journal is unreadable here (not the daemon host, no privilege, no
    systemd) — the verifier then reports the corroboration UNCHECKED
    rather than inventing a verdict. This is the report's only subprocess
    and it is local-machine-only; the no-network property holds.
    """
    import re
    import subprocess
    try:
        out = subprocess.run(
            ["journalctl", "-u", unit, "-o", "short-unix", "--no-pager",
             "--grep", "SESSION_HELLO_ACK sent"],
            capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    sids = set(re.findall(rb"session_id=([0-9a-f]{32})", out.stdout))
    sids = {s.decode() for s in sids}

    # Earliest covered moment: the first line of the unit's journal. If a
    # v2 frame predates this, its HELLO_ACK may simply have rotated out —
    # corroboration is then UNCHECKED, not FAIL.
    since_ns = None
    try:
        head = subprocess.run(
            ["sh", "-c",
             "journalctl -u %s -o short-unix --no-pager | head -n 1" % unit],
            capture_output=True, timeout=120)
        tok = head.stdout.split(None, 1)
        if tok:
            since_ns = int(float(tok[0]) * 1e9)
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return {"session_ids": sids, "since_ns": since_ns}


def load_node_identity(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def artifact_json(v):
    """Parse an artifact body as JSON, or None."""
    if not v.artifact_content or v.artifact_content.startswith("base64:"):
        return None
    try:
        return json.loads(v.artifact_content)
    except ValueError:
        return None


def entry_device(v):
    """Best available device name for an entry.

    Observations name the device in their artifact_id; proposals, approvals
    and outcomes carry it in the artifact JSON; gate rejections encode it in
    the session_id as 'gate-enforce:<device>'. Falling back through all three
    keeps the device column populated instead of showing '-' for every row
    that is not an observation.
    """
    if v.device:
        return v.device
    body = artifact_json(v)
    if body and body.get("device"):
        return str(body["device"])
    session = v.entry["session_id"] or ""
    for prefix in ("gate-enforce:", "approval:"):
        if session.startswith(prefix):
            return session[len(prefix):]
    return "-"


def entry_tier(v):
    """Best available tier for an entry.

    Observations carry the tier in the signed header, so it is evidence.
    Proposals carry it in the artifact JSON. Everything else has none.
    """
    if v.header:
        return v.header["tier_name"]
    body = artifact_json(v)
    if body and "tier" in body:
        return str(body["tier"])
    return "-"


# ── approval lifecycle reconstruction ─────────────────────────────────────

def proposal_id_of(artifact_id):
    """'proposal:<pid>' / 'approval:<pid>' / 'outcome:<pid>' → <pid>."""
    if artifact_id and ":" in artifact_id:
        return artifact_id.split(":", 1)[1]
    return None


def build_lifecycles(verifications):
    """Reconstruct every propose → approve → apply → outcome cluster.

    Keyed by proposal_id, which all three artifact types carry. Returns a
    list of dicts sorted by the proposal's timestamp.

    Note on 'apply': the chain has no distinct 'apply' artifact type. The
    apply step is what produces the outcome record, so an outcome present
    means an apply occurred; the executed command's own output is a separate
    signed observation. That mapping is stated in the report rather than
    invented as a fourth row.
    """
    clusters = {}
    for v in verifications:
        atype = v.entry["artifact_type"]
        if atype not in ("proposal", "approval", "outcome"):
            continue
        pid = proposal_id_of(v.entry["artifact_id"])
        if pid is None:
            continue
        c = clusters.setdefault(pid, {"proposal_id": pid, "proposal": None,
                                      "approvals": [], "outcomes": []})
        if atype == "proposal":
            c["proposal"] = v
        elif atype == "approval":
            c["approvals"].append(v)
        else:
            c["outcomes"].append(v)

    out = []
    for pid, c in clusters.items():
        body = artifact_json(c["proposal"]) if c["proposal"] else None
        c["body"] = body or {}
        c["device"] = (body or {}).get("device", "-")
        c["command"] = (body or {}).get("command", "-")
        c["tier"] = (body or {}).get("tier", "-")
        c["ts_ns"] = c["proposal"].entry["timestamp_ns"] if c["proposal"] else 0

        flags = []
        # Single-use is enforced by the daemon's consumed.list, which is NOT
        # in the chain. What the chain can show is a proposal that produced
        # more than one outcome, or collected more than one approval — either
        # is a single-use violation visible from here.
        if len(c["outcomes"]) > 1:
            flags.append(("SINGLE-USE VIOLATION",
                          "%d outcomes recorded for one proposal; an approval "
                          "is single-use and must yield at most one apply"
                          % len(c["outcomes"])))
        if len(c["approvals"]) > 1:
            flags.append(("SINGLE-USE VIOLATION",
                          "%d approvals recorded for one proposal"
                          % len(c["approvals"])))
        if c["approvals"] and not c["outcomes"]:
            flags.append(("APPROVED, NO OUTCOME",
                          "the proposal was approved but no outcome was ever "
                          "recorded; the apply either never ran or did not "
                          "reach the chain"))
        if not c["approvals"] and not c["outcomes"]:
            flags.append(("NO OUTCOME",
                          "proposal was filed and never approved or applied "
                          "(expected for a gate-blocked command that no "
                          "operator approved)"))
        if c["proposal"] is None:
            flags.append(("ORPHAN",
                          "approval and/or outcome present with no proposal "
                          "entry in the selected range"))
        c["flags"] = flags
        out.append(c)

    out.sort(key=lambda x: x["ts_ns"])
    return out


# ── exceptions ────────────────────────────────────────────────────────────

def collect_exceptions(verifications):
    """Gather every refusal, block, disagreement and peer outage on record."""
    red = []
    gate = []
    disagreements = []
    outages = []

    for v in verifications:
        atype = v.entry["artifact_type"]
        tier = entry_tier(v)

        if atype == "gate_rejection":
            gate.append(v)
        if tier == "RED":
            red.append(v)

        body = artifact_json(v)
        if body and atype.startswith("comparator"):
            if body.get("disagreements"):
                disagreements.append((v, body))
            if body.get("peer_live") is False:
                outages.append((v, body))

    return {"red": red, "gate": gate,
            "disagreements": disagreements, "outages": outages}


# ── rendering ─────────────────────────────────────────────────────────────

def styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle(
        "Mono", parent=ss["BodyText"], fontName="Courier", fontSize=7.2,
        leading=8.6, alignment=TA_LEFT))
    ss.add(ParagraphStyle(
        "MonoSmall", parent=ss["BodyText"], fontName="Courier", fontSize=6.4,
        leading=7.6))
    ss.add(ParagraphStyle(
        "Bad", parent=ss["BodyText"], fontName="Courier-Bold", fontSize=7.2,
        leading=8.6, textColor=VERDICT_COLOR[verify.FAIL]))
    ss.add(ParagraphStyle(
        "Warn", parent=ss["BodyText"], fontName="Courier", fontSize=7.0,
        leading=8.4, textColor=VERDICT_COLOR[verify.UNVERIFIABLE]))
    ss.add(ParagraphStyle(
        "H2x", parent=ss["Heading2"], spaceBefore=14, spaceAfter=6))
    ss.add(ParagraphStyle(
        "H3x", parent=ss["Heading3"], spaceBefore=9, spaceAfter=4,
        fontSize=9.5))
    ss.add(ParagraphStyle(
        "Note", parent=ss["BodyText"], fontSize=8.2, leading=10.4))
    return ss


def kv_table(rows, ss, widths=(2.0 * inch, 8.3 * inch)):
    data = [[Paragraph("<b>%s</b>" % k, ss["Note"]),
             Paragraph(v, ss["Mono"])] for k, v in rows]
    t = Table(data, colWidths=widths, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor("#d0d0d0")),
    ]))
    return t


def verdict_para(verdict, ss):
    return Paragraph(
        '<font color="%s"><b>%s</b></font>'
        % (vhex(verdict), verdict), ss["Mono"])


def section_header(story, ss, ctx, args, summary, entries):
    story.append(Paragraph("VIRP Chain Evidence Report", ss["Title"]))
    story.append(Paragraph(
        "A projection of re-verified chain evidence. Every hash, link and "
        "signature below was recomputed from the database at render time.",
        ss["Note"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("1. Report header", ss["H2x"]))

    ts = [e["timestamp_ns"] for e in entries]
    rng = ("%s  →  %s" % (ns_to_utc(min(ts)), ns_to_utc(max(ts)))
           if ts else "no entries in range")

    filters = []
    if args.session:
        filters.append("session=%s" % args.session)
    if args.since:
        filters.append("since=%s" % args.since)
    if args.until:
        filters.append("until=%s" % args.until)

    rows = [
        ("Node identity", ctx["node_name"]),
        ("Signer", "signer_node_id=%s  signer_org_id=%s" % (
            ", ".join(str(x) for x in sorted(
                {e["signer_node_id"] for e in entries})) or "-",
            ", ".join(sorted({e["signer_org_id"] for e in entries})) or "-")),
        ("O-Key fingerprint", ctx["okey_fp"]),
        ("Chain-key fingerprint", ctx["chain_key_fp"]),
        ("Chain database", ctx["db_path"]),
        ("Read method", "%s" % ctx["read_method"]),
        ("Entries in report", "%d  (of %d in the database)"
         % (len(entries), ctx["total_entries"])),
        ("Sessions in report", str(summary["sessions"])),
        ("Time range (entries)", rng),
        ("Filters applied", ", ".join(filters) if filters else "none"),
        ("Report generated", ctx["generated"]),
        ("Generator", ctx["generator"]),
    ]
    story.append(kv_table(rows, ss))


def section_integrity(story, ss, summary, verifications):
    story.append(Paragraph("2. Integrity summary", ss["H2x"]))

    total = summary["entries"]
    obs = summary["observations"]

    def line(label, tally, denom):
        parts = []
        for verdict in (verify.PASS, verify.FAIL, verify.UNVERIFIABLE,
                        verify.V2_SESSION, verify.UNCHECKED):
            n = tally.get(verdict, 0)
            if n:
                parts.append('<font color="%s">%s %d</font>'
                             % (vhex(verdict),
                                verdict.lower(), n))
        return [Paragraph("<b>%s</b>" % label, ss["Note"]),
                Paragraph("%d checked — %s"
                          % (denom, ", ".join(parts) if parts else "none"),
                          ss["Mono"])]

    data = [
        line("Entry hash recompute", summary["entry_hash"], total),
        line("Hash-link continuity", summary["link"], total),
        line("Chain HMAC (K_chain)", summary["chain_hmac"], total),
        line("Artifact→entry binding", summary["artifact_bind"], total),
        line("Observation HMAC (O-Key)", summary["obs_hmac"], obs),
        line("Session head (chain length)", summary["heads"]["tally"],
             summary["sessions"]),
    ]
    if summary["obs_v2"]:
        data.append(line("V2 session-id journal corroboration",
                         summary["v2_journal"], summary["obs_v2"]))
    t = Table(data, colWidths=(2.3 * inch, 8.0 * inch), hAlign="LEFT")
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor("#d0d0d0")),
    ]))
    story.append(t)
    story.append(Spacer(1, 8))

    failed = summary["failed_entries"]
    broken = summary["first_broken_link"]

    if failed:
        head_note = ""
        if any(getattr(v, "is_head", False) for v in failed):
            head_note = (" Session-head failures are session-level "
                         "verdicts (the signed chain-length commitment) "
                         "and appear in this table only.")
        story.append(Paragraph(
            '<font color="%s"><b>%d ENTR%s FAILED VERIFICATION.</b></font> '
            "Each is reproduced in full at its position in the session "
            "breakdown below; none has been omitted.%s"
            % (vhex(verify.FAIL), len(failed),
               "Y" if len(failed) == 1 else "IES", head_note), ss["Note"]))
        story.append(Spacer(1, 4))
        rows = [[Paragraph("<b>%s</b>" % h, ss["MonoSmall"]) for h in
                 ("session", "seq", "check", "detail")]]
        for v in failed:
            for name, detail in v.failures:
                rows.append([
                    Paragraph(trunc(v.entry["session_id"], 34), ss["MonoSmall"]),
                    Paragraph(str(v.entry["sequence"]), ss["MonoSmall"]),
                    Paragraph(name, ss["Bad"]),
                    Paragraph(trunc(detail, 150), ss["MonoSmall"])])
        t = Table(rows, colWidths=(2.2 * inch, 0.5 * inch, 1.3 * inch,
                                   6.3 * inch), hAlign="LEFT", repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
            ("BACKGROUND", (0, 1), (-1, -1), FAIL_BG),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c0c0c0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)
    else:
        unverifiable = summary.get("unverifiable_entries", [])
        if unverifiable:
            story.append(Paragraph(
                '<font color="%s"><b>No entry failed verification.</b></font> '
                "Every check that could be run, passed — but "
                '<font color="%s"><b>%d entr%s could not be verified</b></font> '
                "(commitment-only: the evidence needed was never retained). "
                "These are graded UNVERIFIABLE, never PASS; see the "
                "per-session breakdown and the retention-limits summary."
                % (vhex(verify.PASS), vhex(verify.UNVERIFIABLE),
                   len(unverifiable),
                   "y" if len(unverifiable) == 1 else "ies"), ss["Note"]))
        else:
            story.append(Paragraph(
                '<font color="%s"><b>No entry failed verification.</b></font> '
                "Every check that could be run, passed."
                % vhex(verify.PASS), ss["Note"]))

    story.append(Spacer(1, 6))
    if broken is not None:
        story.append(Paragraph(
            '<font color="%s"><b>FIRST BROKEN LINK:</b> session %s, sequence '
            "%d — %s</font>"
            % (vhex(verify.FAIL),
               broken.entry["session_id"], broken.entry["sequence"],
               broken.link_detail), ss["Note"]))
    else:
        story.append(Paragraph(
            "Hash-link continuity: unbroken across every session in this "
            "report. Each entry's previous_entry_hash equals the recomputed "
            "hash of its predecessor, and each sequence 0 matches "
            "sha256(\"VIRP_CHAIN_GENESIS:\" + session_id).", ss["Note"]))

    reasons = summary["retention_reasons"]
    if reasons:
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            "<b>Checks that could not be run (UNVERIFIABLE)</b> — these "
            "are limits of what the chain retained, not verification "
            "failures, and are never counted as passes:", ss["Note"]))
        rows = [[Paragraph("<b>entries</b>", ss["MonoSmall"]),
                 Paragraph("<b>reason</b>", ss["MonoSmall"])]]
        for reason, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
            rows.append([Paragraph(str(n), ss["MonoSmall"]),
                         Paragraph(reason, ss["MonoSmall"])])
        t = Table(rows, colWidths=(0.7 * inch, 9.6 * inch), hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
            ("BACKGROUND", (0, 1), (-1, -1), UNVERIFIABLE_BG),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c0c0c0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)

    v2_frames = [v for v in verifications
                 if v.obs_hmac == verify.V2_SESSION]
    if v2_frames:
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            '<font color="%s"><b>%d V2 SESSION-SIGNED OBSERVATION%s.</b>'
            "</font> Each is a version-2 frame signed with a per-session "
            "key (HKDF of the O-Key and the handshake transcript). The "
            "transcript is not retained past the session, so at-rest "
            "cryptographic verification of these signatures is <b>not "
            "possible with available material — a property of the "
            "deployed version, not a verification failure</b>. What CAN "
            "be checked is corroborated below and in the session tables: "
            "the header session id against the daemon journal's "
            "SESSION_HELLO_ACK record, sha256 of the stored bytes against "
            "the entry's own artifact_hash, and the entry's hash-chain "
            "linkage. A mismatch on any of those IS a failure and is "
            "reported as one."
            % (vhex(verify.V2_SESSION), len(v2_frames),
               "" if len(v2_frames) == 1 else "S"), ss["Note"]))
        story.append(Spacer(1, 4))
        rows = [[Paragraph("<b>%s</b>" % h, ss["MonoSmall"]) for h in
                 ("session", "seq", "signed (UTC)", "v2 session id",
                  "journal", "binding", "linkage")]]
        for v in v2_frames:
            hdr = v.header or {}
            linkage = (verify.PASS
                       if verify.FAIL not in (v.entry_hash, v.link,
                                              v.chain_hmac)
                       else verify.FAIL)
            rows.append([
                Paragraph(trunc(v.entry["session_id"], 30), ss["MonoSmall"]),
                Paragraph(str(v.entry["sequence"]), ss["MonoSmall"]),
                Paragraph(ns_to_utc(hdr.get("timestamp_ns")), ss["MonoSmall"]),
                Paragraph(trunc(hdr.get("session_id", "-"), 34),
                          ss["MonoSmall"]),
                verdict_para(v.v2_journal, ss),
                verdict_para(v.artifact_bind, ss),
                verdict_para(linkage, ss)])
        t = Table(rows, colWidths=(2.0 * inch, 0.4 * inch, 1.35 * inch,
                                   2.4 * inch, 1.35 * inch, 1.35 * inch,
                                   1.35 * inch),
                  hAlign="LEFT", repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
            ("BACKGROUND", (0, 1), (-1, -1), V2_BG),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c0c0c0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)


def section_sessions(story, ss, verifications):
    # No page break here: section 2's length varies, and forcing one leaves a
    # near-empty page whenever its last table happens to spill.
    story.append(Spacer(1, 12))
    story.append(Paragraph("3. Session breakdown", ss["H2x"]))
    story.append(Paragraph(
        "Entries in chain order within each session. ENTRY HASH and PREV are "
        "the first 16 hex of the recomputed 64-hex values. A row that failed "
        "any check is highlighted and followed by the failure detail in "
        "place.", ss["Note"]))

    by_session = {}
    for v in verifications:
        by_session.setdefault(v.entry["session_id"], []).append(v)

    header = ("seq", "type", "tier", "device", "timestamp (UTC)",
              "artifact id", "entry hash", "prev", "checks")
    widths = (0.4, 0.95, 0.72, 1.35, 1.35, 2.05, 1.0, 1.0, 1.5)

    for session_id in sorted(by_session):
        rows_v = sorted(by_session[session_id],
                        key=lambda x: x["entry"]["sequence"]
                        if isinstance(x, dict) else x.entry["sequence"])
        story.append(Paragraph(
            "%s <font size=8>(%d entries)</font>"
            % (session_id, len(rows_v)), ss["H3x"]))

        data = [[Paragraph("<b>%s</b>" % h, ss["MonoSmall"]) for h in header]]
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c8c8c8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]

        for v in rows_v:
            e = v.entry
            checks = []
            for label, verdict in (("h", v.entry_hash), ("l", v.link),
                                   ("m", v.chain_hmac),
                                   ("b", v.artifact_bind),
                                   ("o", v.obs_hmac),
                                   ("j", v.v2_journal)):
                if verdict == verify.NOT_APPLICABLE:
                    continue
                mark = {verify.PASS: "✓", verify.FAIL: "✗",
                        verify.UNVERIFIABLE: "?",
                        verify.V2_SESSION: "◈",
                        verify.UNCHECKED: "·"}[verdict]
                checks.append('<font color="%s">%s%s</font>'
                              % (vhex(verdict),
                                 label, mark))
            data.append([
                Paragraph(str(e["sequence"]), ss["MonoSmall"]),
                Paragraph(trunc(e["artifact_type"], 15), ss["MonoSmall"]),
                Paragraph(entry_tier(v), ss["MonoSmall"]),
                Paragraph(trunc(entry_device(v), 22), ss["MonoSmall"]),
                Paragraph(ns_to_utc(e["timestamp_ns"]), ss["MonoSmall"]),
                Paragraph(trunc(e["artifact_id"], 34), ss["MonoSmall"]),
                Paragraph(e["chain_entry_hash"][:16], ss["MonoSmall"]),
                Paragraph(e["previous_entry_hash"][:16], ss["MonoSmall"]),
                Paragraph(" ".join(checks), ss["MonoSmall"]),
            ])
            idx = len(data) - 1
            if not v.ok:
                style.append(("BACKGROUND", (0, idx), (-1, idx), FAIL_BG))

            # Failures are reported in place, immediately under the row they
            # belong to, so a reader scanning the session cannot miss them.
            for name, detail in v.failures:
                data.append([
                    Paragraph("", ss["MonoSmall"]),
                    Paragraph("<b>FAILED</b>", ss["Bad"]),
                    Paragraph("%s: %s" % (name, detail), ss["Bad"]),
                    "", "", "", "", "", ""])
                fidx = len(data) - 1
                style.append(("BACKGROUND", (0, fidx), (-1, fidx), FAIL_BG))
                style.append(("SPAN", (2, fidx), (-1, fidx)))

        t = Table(data, colWidths=[w * inch for w in widths],
                  hAlign="LEFT", repeatRows=1)
        t.setStyle(TableStyle(style))
        story.append(t)
        story.append(Spacer(1, 6))

    story.append(Paragraph(
        "Check legend: h=entry hash, l=hash link, m=chain HMAC, "
        "b=artifact binding, o=observation HMAC, j=v2 session-id journal "
        "corroboration (v2 frames only). "
        "✓ pass, ✗ fail, ? unverifiable (evidence not retained), "
        "◈ v2 session-signed (at-rest verification impossible by design "
        "of the deployed version — see the V2 stanza in section 2), "
        "· unchecked (key or journal not supplied).", ss["Note"]))


def section_lifecycles(story, ss, lifecycles):
    story.append(PageBreak())
    story.append(Paragraph("4. Approval lifecycles", ss["H2x"]))
    if not lifecycles:
        story.append(Paragraph(
            "No proposal, approval or outcome entries in the selected range.",
            ss["Note"]))
        return

    story.append(Paragraph(
        "Every propose → approve → apply → outcome cluster in "
        "the range, keyed by proposal_id. The chain records no distinct "
        "'apply' artifact: the apply step is what produces the outcome "
        "record, so a present outcome is the evidence that an apply ran, and "
        "the executed command's output is a separate signed observation.",
        ss["Note"]))
    story.append(Spacer(1, 6))

    for c in lifecycles:
        block = []
        block.append(Paragraph(
            "proposal_id %s — %s <font size=8>(%s)</font>"
            % (c["proposal_id"], c["device"], c["tier"]), ss["H3x"]))

        rows = []
        if c["proposal"]:
            p = c["proposal"]
            rows.append(("PROPOSE", ns_to_utc(p.entry["timestamp_ns"]),
                         "command: %s<br/>proposer: %s<br/>"
                         "command_hash: %s<br/>entry: %s"
                         % (trunc(c["command"], 110),
                            c["body"].get("proposer", "-"),
                            trunc(c["body"].get("command_hash", "-"), 64),
                            p.entry["chain_entry_hash"][:16]),
                         p))
        for a in c["approvals"]:
            b = artifact_json(a) or {}
            rows.append((
                "APPROVE", ns_to_utc(a.entry["timestamp_ns"]),
                "operator: %s<br/>approver_key_id: %s<br/>ttl: %ss<br/>"
                "entry: %s"
                % (b.get("operator", "-"), b.get("approver_key_id", "-"),
                   b.get("ttl_seconds", "-"),
                   a.entry["chain_entry_hash"][:16]), a))
        for o in c["outcomes"]:
            b = artifact_json(o) or {}
            ok = b.get("success")
            rows.append((
                "APPLY/OUTCOME", ns_to_utc(o.entry["timestamp_ns"]),
                "result: <b>%s</b><br/>proposal_entry_hash: %s<br/>"
                "approval_entry_hash: %s<br/>entry: %s"
                % ("SUCCESS" if ok else "FAILURE",
                   trunc(b.get("proposal_entry_hash", "-"), 40),
                   trunc(b.get("approval_entry_hash", "-"), 40),
                   o.entry["chain_entry_hash"][:16]), o))

        data = [[Paragraph("<b>%s</b>" % h, ss["MonoSmall"]) for h in
                 ("stage", "timestamp (UTC)", "detail", "verification")]]
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c8c8c8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
        for stage, ts, detail, v in rows:
            data.append([
                Paragraph("<b>%s</b>" % stage, ss["MonoSmall"]),
                Paragraph(ts, ss["MonoSmall"]),
                Paragraph(detail, ss["MonoSmall"]),
                verdict_para(v.rollup, ss)])
            if not v.ok:
                style.append(("BACKGROUND", (0, len(data) - 1),
                              (-1, len(data) - 1), FAIL_BG))

        t = Table(data, colWidths=(1.1 * inch, 1.35 * inch, 6.3 * inch,
                                   1.55 * inch), hAlign="LEFT")
        t.setStyle(TableStyle(style))
        block.append(t)

        for label, detail in c["flags"]:
            severe = "VIOLATION" in label or label == "APPROVED, NO OUTCOME"
            block.append(Spacer(1, 2))
            block.append(Paragraph(
                '<font color="%s"><b>%s</b> — %s</font>'
                % (vhex(verify.FAIL if severe
                                 else verify.UNVERIFIABLE),
                   label, detail), ss["Note"]))
        block.append(Spacer(1, 8))
        story.append(KeepTogether(block))

    story.append(Paragraph(
        "Single-use note: the authoritative replay store is the daemon's "
        "consumed.list, which is not part of the chain. The violations "
        "flagged here are those visible from chain evidence alone — a "
        "proposal that collected more than one approval, or yielded more "
        "than one outcome.", ss["Note"]))


def section_exceptions(story, ss, ex):
    story.append(PageBreak())
    story.append(Paragraph("5. Exceptions", ss["H2x"]))
    story.append(Paragraph(
        "Every refusal, block, disagreement and peer outage on record in the "
        "selected range.", ss["Note"]))

    # ── gate blocks / RED rejections ──
    story.append(Paragraph(
        "5.1 Gate blocks and RED rejections (%d gate blocks, %d RED-tier "
        "entries)" % (len(ex["gate"]), len(ex["red"])), ss["H3x"]))

    if ex["gate"]:
        # Reason RETENTION (2026-07-30): gate_rejection entries now carry a
        # structured reason body (schema gate_rejection/1) committed to by
        # artifact_hash, so the reason is shown from the chain itself rather
        # than only as a commitment hash. Entries written before that change
        # have no body and are rendered as such — never silently blank.
        rows = [[Paragraph("<b>%s</b>" % h, ss["MonoSmall"]) for h in
                 ("session / device", "seq", "timestamp (UTC)",
                  "tier / max", "reason (from chain body)", "binding")]]
        legacy = 0
        for v in ex["gate"]:
            e = v.entry
            body = artifact_json(v) or {}
            if body:
                tiers = "%s > %s" % (body.get("classified_tier", "?"),
                                     body.get("gate_max_tier", "?"))
                reason = body.get("matched_rule") or body.get("message") or ""
                cmd = body.get("command")
                if cmd:
                    reason = "%s<br/><font size=6>command: %s</font>" % (
                        esc(trunc(reason, 150)), esc(trunc(cmd, 110)))
                else:
                    reason = esc(trunc(reason, 150))
            else:
                legacy += 1
                tiers = "—"
                reason = ('<i>no body retained — commitment only: %s</i>'
                          % e["artifact_hash"][:32])
            rows.append([
                Paragraph(trunc(e["session_id"], 34), ss["MonoSmall"]),
                Paragraph(str(e["sequence"]), ss["MonoSmall"]),
                Paragraph(ns_to_utc(e["timestamp_ns"]), ss["MonoSmall"]),
                Paragraph(tiers, ss["MonoSmall"]),
                Paragraph(reason, ss["MonoSmall"]),
                Paragraph(vhex(v.artifact_bind), ss["MonoSmall"])])
        t = Table(rows, colWidths=(1.9 * inch, 0.35 * inch, 1.3 * inch,
                                   1.15 * inch, 4.6 * inch, 1.0 * inch),
                  hAlign="LEFT", repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c8c8c8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)
        story.append(Spacer(1, 3))
        if legacy:
            story.append(Paragraph(
                '<font color="%s"><b>%d of these gate blocks predate '
                "gate-reason retention</b></font> (daemon change of "
                "2026-07-30) and stored no body, so for those rows the chain "
                "retains only sha256(reason): given the reason text from the "
                "daemon journal you can confirm it matches, but the text "
                "cannot be reconstructed from the chain. Rows showing a "
                "reason were verified against the entry's own commitment."
                % (vhex(verify.UNVERIFIABLE), legacy), ss["Note"]))
        else:
            story.append(Paragraph(
                "Every gate block above shows its reason as retained in the "
                "chain body, bound to the entry by "
                "artifact_hash = sha256(body) and covered by the entry's "
                "chain HMAC. The body is a structured object (schema "
                "gate_rejection/1: device, driver, command, classified tier, "
                "gate max tier, matched rule, message); the same message text "
                "is the payload of the O-Key-signed ERROR observation "
                "returned to the caller, so chain and observation agree by "
                "construction.", ss["Note"]))
    else:
        story.append(Paragraph("No gate blocks in range.", ss["Note"]))

    if ex["red"]:
        story.append(Spacer(1, 5))
        rows = [[Paragraph("<b>%s</b>" % h, ss["MonoSmall"]) for h in
                 ("session", "seq", "type", "device", "timestamp (UTC)",
                  "detail")]]
        for v in ex["red"]:
            e = v.entry
            body = artifact_json(v) or {}
            detail = body.get("command") or (
                v.payload["command"] if v.payload else "-")
            rows.append([
                Paragraph(trunc(e["session_id"], 30), ss["MonoSmall"]),
                Paragraph(str(e["sequence"]), ss["MonoSmall"]),
                Paragraph(trunc(e["artifact_type"], 15), ss["MonoSmall"]),
                Paragraph(trunc(entry_device(v), 22), ss["MonoSmall"]),
                Paragraph(ns_to_utc(e["timestamp_ns"]), ss["MonoSmall"]),
                Paragraph(esc(trunc(detail, 90)), ss["MonoSmall"])])
        t = Table(rows, colWidths=(1.9 * inch, 0.4 * inch, 1.0 * inch,
                                   1.4 * inch, 1.35 * inch, 4.25 * inch),
                  hAlign="LEFT", repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c8c8c8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)

    # ── comparator disagreements ──
    story.append(Paragraph(
        "5.2 Comparator disagreements (%d records)"
        % len(ex["disagreements"]), ss["H3x"]))
    if ex["disagreements"]:
        rows = [[Paragraph("<b>%s</b>" % h, ss["MonoSmall"]) for h in
                 ("timestamp (UTC)", "peers", "target", "local", "peer",
                  "check")]]
        for v, body in ex["disagreements"]:
            for d in body.get("disagreements", []):
                rows.append([
                    Paragraph(ns_to_utc(v.entry["timestamp_ns"]),
                              ss["MonoSmall"]),
                    Paragraph("%s ↔ %s" % (body.get("node", "-"),
                                                body.get("peer", "-")),
                              ss["MonoSmall"]),
                    Paragraph(str(d.get("target", "-")), ss["MonoSmall"]),
                    Paragraph(str(d.get("local", "-")), ss["MonoSmall"]),
                    Paragraph(str(d.get("peer", "-")), ss["MonoSmall"]),
                    Paragraph(str(d.get("check", "-")), ss["MonoSmall"])])
        t = Table(rows, colWidths=(1.35 * inch, 1.9 * inch, 1.6 * inch,
                                   0.8 * inch, 0.8 * inch, 3.85 * inch),
                  hAlign="LEFT", repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c8c8c8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)
        story.append(Spacer(1, 3))
        story.append(Paragraph(
            "A null on either side is counted as a disagreement by design: "
            "silence between two observers is not consensus.", ss["Note"]))
    else:
        story.append(Paragraph("No comparator disagreements in range.",
                               ss["Note"]))

    # ── peer outages ──
    story.append(Paragraph("5.3 Peer outage records (%d)"
                           % len(ex["outages"]), ss["H3x"]))
    if ex["outages"]:
        rows = [[Paragraph("<b>%s</b>" % h, ss["MonoSmall"]) for h in
                 ("timestamp (UTC)", "peer", "peer_live", "peer chain head",
                  "signed reason / note")]]
        for v, body in ex["outages"]:
            head = body.get("peer_chain_head") or {}
            rows.append([
                Paragraph(ns_to_utc(v.entry["timestamp_ns"]), ss["MonoSmall"]),
                Paragraph(str(body.get("peer", "-")), ss["MonoSmall"]),
                Paragraph("FALSE", ss["Bad"]),
                Paragraph(trunc(str(head.get("entry_hash", "-")), 24),
                          ss["MonoSmall"]),
                Paragraph(trunc(body.get("verification_note", "-"), 150),
                          ss["MonoSmall"])])
        t = Table(rows, colWidths=(1.35 * inch, 1.3 * inch, 0.8 * inch,
                                   1.8 * inch, 5.05 * inch),
                  hAlign="LEFT", repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c8c8c8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No peer outage records in range.", ss["Note"]))


def section_limitations(story, ss, ctx, summary):
    story.append(PageBreak())
    story.append(Paragraph("6. Limitations of this report", ss["H2x"]))
    story.append(Paragraph(
        "Stated plainly, because a report that hides its own boundaries is "
        "worse than no report.", ss["Note"]))
    story.append(Spacer(1, 6))

    items = []

    items.append((
        "This report verifies THIS node's chain only. It does not "
        "cross-verify any peer.",
        "Observations are signed with HMAC-SHA256 under this node's own "
        "O-Key (fingerprint %s). HMAC is symmetric: verifying it proves only "
        "that a holder of THIS key signed the bytes. VIRP has no asymmetric "
        "observation signing, no peer public-key registry and no foreign-"
        "chain import, so a peer's signature cannot be checked here and is "
        "not checked anywhere in this document. Where a peer appears — "
        "comparator verdicts, peer chain heads, peer liveness — the "
        "claim is only “this node observed and signed that the peer "
        "reported X at time T”, never “the peer's signature was "
        "verified”." % ctx["okey_fp"]))

    items.append((
        "Peer chain-head hashes are 16-hex-character prefixes, not full "
        "64-character hashes.",
        "The peer head is collected through `virp chain tail`, which prints "
        "entry hashes truncated to 16 hex characters. Any peer_chain_head "
        "value in section 5 is therefore a prefix of the real hash. 16 hex "
        "characters is 64 bits: strong enough that an accidental collision "
        "is implausible, but it is a prefix comparison, not a full hash "
        "comparison. Entry hashes for THIS node's own chain are computed "
        "here at full 64 hex and only abbreviated for display."))

    items.append((
        "Read method: %s." % ctx["read_method"],
        ctx["read_caveat"]))

    reasons = summary["retention_reasons"]
    if reasons:
        detail = ("Some checks could not be run at all because the chain does "
                  "not retain the evidence they need. These are counted as "
                  "UNVERIFIABLE in section 2 and never as passes:<br/>")
        for reason, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
            detail += "<br/>• <b>%d entries</b> — %s" % (n, reason)
        items.append(("Not everything in the chain can be re-verified from "
                      "the chain.", detail))

    items.append((
        "Absence of evidence is not evidence of absence.",
        "This report describes what is IN the chain. A command that never "
        "reached the daemon, an action taken outside VIRP, or an entry that "
        "was never written leaves no trace here. The hash chain makes "
        "undetected MODIFICATION of recorded entries hard; it does not make "
        "unrecorded activity visible. Truncation of the chain's tail is also "
        "not detectable from the chain alone."))

    items.append((
        "The chain HMAC and the observation HMAC share a trust root with the "
        "daemon.",
        "Both K_chain and the O-Key are readable by the daemon's user on this "
        "host. An adversary with that access could rewrite entries and "
        "recompute every hash and HMAC in this report, and the result would "
        "verify clean. This report detects tampering by someone WITHOUT the "
        "keys; it is not evidence against the key holder."))

    items.append((
        "The chain is linked per session, not globally.",
        "previous_entry_hash links an entry to its predecessor within the "
        "same session_id, and sequence restarts at 0 for each session. There "
        "is no single global ordering, so continuity is verified per session "
        "and this report makes no claim about ordering ACROSS sessions "
        "beyond the wall-clock timestamps, which are daemon-supplied."))

    if ctx["filtered"]:
        items.append((
            "This is a filtered view.",
            "A --session/--since/--until filter was applied, so this report "
            "covers %d of the %d entries in the database. Where a filter cuts "
            "a session mid-chain, the first entry shown has no in-range "
            "predecessor and its link is reported UNCHECKED rather than "
            "assumed good."
            % (summary["entries"], ctx["total_entries"])))

    data = []
    for i, (title, detail) in enumerate(items, 1):
        data.append([Paragraph("<b>%d.</b>" % i, ss["Note"]),
                     Paragraph("<b>%s</b><br/><br/>%s" % (title, detail),
                               ss["Note"])])
    t = Table(data, colWidths=(0.35 * inch, 9.95 * inch), hAlign="LEFT")
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor("#d0d0d0")),
    ]))
    story.append(t)


def _footer(canvas, doc, ctx):
    canvas.saveState()
    canvas.setFont("Courier", 7)
    canvas.setFillColor(colors.HexColor("#666666"))
    canvas.drawString(0.5 * inch, 0.35 * inch,
                      "VIRP chain evidence report — %s — %s"
                      % (ctx["node_name"], ctx["generated"]))
    canvas.drawRightString(letter[1] - 0.5 * inch, 0.35 * inch,
                           "page %d" % doc.page)
    canvas.restoreState()


def render_pdf(out_path, ctx, entries, verifications, summary, args):
    doc = SimpleDocTemplate(
        out_path, pagesize=landscape(letter),
        leftMargin=0.5 * inch, rightMargin=0.5 * inch,
        topMargin=0.5 * inch, bottomMargin=0.6 * inch,
        title="VIRP Chain Evidence Report — %s" % ctx["node_name"],
        author="virp report", subject="Re-verified VIRP chain evidence")

    ss = styles()
    story = []
    section_header(story, ss, ctx, args, summary, entries)
    section_integrity(story, ss, summary, verifications)
    section_sessions(story, ss, verifications)
    section_lifecycles(story, ss, build_lifecycles(verifications))
    section_exceptions(story, ss, collect_exceptions(verifications))
    section_limitations(story, ss, ctx, summary)

    draw = lambda c, d: _footer(c, d, ctx)  # noqa: E731
    doc.build(story, onFirstPage=draw, onLaterPages=draw)


# ── CLI ───────────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="virp report",
        description="Generate a PDF report of re-verified VIRP chain "
                    "evidence. Reads the chain read-only and never writes "
                    "to it. Makes no network connections.")
    p.add_argument("--db", required=True, help="path to chain.db")
    p.add_argument("--out", required=True, help="output PDF path")
    p.add_argument("--session", help="restrict to one session_id")
    p.add_argument("--since", help="lower bound on entry timestamp "
                                   "(ISO-8601 or epoch)")
    p.add_argument("--until", help="upper bound on entry timestamp "
                                   "(ISO-8601 or epoch)")
    p.add_argument("--okey", default=DEFAULT_OKEY,
                   help="O-Key for observation HMAC verification "
                        "(default: %s)" % DEFAULT_OKEY)
    p.add_argument("--chain-key", default=DEFAULT_CHAIN_KEY,
                   help="chain key for entry HMAC verification "
                        "(default: %s)" % DEFAULT_CHAIN_KEY)
    p.add_argument("--node-identity", default=DEFAULT_NODE_IDENTITY,
                   help="JSON file naming this node")
    p.add_argument("--journal-unit", default="virp-onode",
                   help="systemd unit whose journal supplies HELLO_ACK "
                        "session ids for v2 corroboration "
                        "(default: virp-onode)")
    p.add_argument("--no-journal", action="store_true",
                   help="skip journal corroboration of v2 frames; their "
                        "session ids are then reported UNCHECKED")
    p.add_argument("--allow-immutable", action="store_true",
                   help="permit the unsafe immutable=1 read as a last "
                        "resort; it can silently omit un-checkpointed WAL "
                        "entries and stamps a loud caveat on the report")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    since_ns = parse_timestamp(args.since) if args.since else None
    until_ns = parse_timestamp(args.until) if args.until else None
    if since_ns is not None and until_ns is not None and since_ns > until_ns:
        print("virp report: --since is after --until", file=sys.stderr)
        return 2

    # Keys are optional. A missing key downgrades the relevant check to
    # UNCHECKED and is reported; it is never silently treated as a pass.
    okey = chain_key = None
    okey_fp = "unavailable — observation HMACs NOT verified"
    chain_fp = "unavailable — chain HMACs NOT verified"
    try:
        okey = verify.load_key(args.okey)
        okey_fp = verify.key_fingerprint(okey)
    except (OSError, ValueError) as exc:
        print("virp report: O-Key unavailable (%s); observation signatures "
              "will be reported UNCHECKED" % exc, file=sys.stderr)
    try:
        chain_key = verify.load_key(args.chain_key)
        chain_fp = verify.key_fingerprint(chain_key)
    except (OSError, ValueError) as exc:
        print("virp report: chain key unavailable (%s); chain HMACs will be "
              "reported UNCHECKED" % exc, file=sys.stderr)

    try:
        reader = chain_read.open_chain(
            args.db, allow_immutable=args.allow_immutable)
    except chain_read.ChainReadError as exc:
        print("virp report: %s" % exc, file=sys.stderr)
        return 1

    with reader:
        total = reader.conn.execute(
            "SELECT count(*) FROM chain_entries").fetchone()[0]
        entries, artifacts = load_evidence(
            reader, args.session, since_ns, until_ns)
        heads = load_heads(reader)
        v2_journal = (None if args.no_journal
                      else collect_journal_hello_acks(args.journal_unit))
        if v2_journal is None and not args.no_journal:
            print("virp report: daemon journal unreadable here; v2 session "
                  "corroboration will be reported UNCHECKED", file=sys.stderr)
        verifications, summary = verify.verify_chain(
            entries, artifacts, okey=okey, chain_key=chain_key,
            heads=heads, selection_complete=since_ns is None and until_ns is None,
            v2_journal=v2_journal)

        identity = load_node_identity(args.node_identity)
        ctx = {
            "node_name": identity.get("node") or "(node identity unknown)",
            "okey_fp": okey_fp,
            "chain_key_fp": chain_fp,
            "db_path": os.path.abspath(args.db),
            "read_method": reader.method,
            "read_caveat": reader.caveat,
            "total_entries": total,
            "generated": datetime.datetime.now(
                datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "generator": "virp report (reportlab %s, python %d.%d.%d)"
                         % (__import__("reportlab").Version,
                            *sys.version_info[:3]),
            "filtered": bool(args.session or args.since or args.until),
        }

        if not entries:
            print("virp report: no chain entries matched the filters",
                  file=sys.stderr)

        render_pdf(args.out, ctx, entries, verifications, summary, args)

    failed = len(summary["failed_entries"])
    print("virp report: wrote %s" % args.out)
    print("  read method     : %s" % ctx["read_method"])
    print("  entries         : %d (of %d in database)"
          % (summary["entries"], total))
    print("  entry hash      : %s" % _fmt(summary["entry_hash"]))
    print("  hash links      : %s" % _fmt(summary["link"]))
    print("  chain HMAC      : %s" % _fmt(summary["chain_hmac"]))
    print("  artifact binding: %s" % _fmt(summary["artifact_bind"]))
    print("  observation HMAC: %s" % _fmt(summary["obs_hmac"]))
    if summary["obs_v2"]:
        jt = {k: v for k, v in summary["v2_journal"].items()
              if k != verify.NOT_APPLICABLE}
        print("  v2 session obs  : %d (at-rest unverifiable by design; "
              "journal corroboration: %s)"
              % (summary["obs_v2"], _fmt(jt)))
    if failed:
        print("  FAILED ENTRIES  : %d" % failed)
    # Exit 1 on any verification failure so a caller can gate on it. The PDF
    # is still written — a report of a broken chain is exactly when you most
    # need the report.
    return 1 if failed else 0


def _fmt(tally):
    return ", ".join("%s=%d" % (k.lower(), v)
                     for k, v in tally.items() if v)


if __name__ == "__main__":
    sys.exit(main())
