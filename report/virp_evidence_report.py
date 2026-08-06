#!/usr/bin/env python3
"""
virp evidence-report — control-mapped PDF over collected compliance evidence.

Reads the chain database READ-ONLY and renders the evidence collected by
autopilot/virp_evidence.py, organised BY CONTROL. For each control it
prints every evidence item mapped to it, the exact command that produced
the evidence (the collection method), the signed result, and an honest
per-item caveat saying what that read does and does not prove.

Like `virp report`, this is A PROJECTION OF RE-VERIFIED EVIDENCE: every
hash, link and signature printed here is recomputed from the chain at
render time by the same report/verify.py the chain report uses. Nothing
is copied from a stored value and shown as if it had been checked. Where
a check fails it is printed in place, in red. Where a check CANNOT be run
because the chain never retained the evidence, that is stated as
UNVERIFIABLE and never counted as a pass.

This tool runs as a KEY HOLDER (it needs the O-Key and chain key to
verify). That is the deliberate division of labour: the collector is a
least-privilege identity that holds no keys and only stores signed bytes;
verification happens here, afterwards, by someone who can actually check.

Usage:
    virp-evidence-report --db <path> --out <file.pdf>
                         [--session evidence:YYYY-MM-DD]

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import argparse
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import chain_read  # noqa: E402
import verify  # noqa: E402
import virp_report as vr  # noqa: E402  (shared helpers: styles, esc, kv_table)

from reportlab.lib import colors  # noqa: E402
from reportlab.lib.pagesizes import landscape, letter  # noqa: E402
from reportlab.lib.units import inch  # noqa: E402
from reportlab.platypus import (  # noqa: E402
    KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
    TableStyle, XPreformatted)

EVIDENCE_TYPE = "evidence_item"
SESSION_PREFIX = "evidence:"

# How much device output to render per result. The full signed bytes stay
# in the chain and their sha256 is printed, so truncation is visible and
# never silent.
OUTPUT_DISPLAY_MAX = 2200

GAP_BG = colors.HexColor("#fff4e0")
UNMAPPED_BG = colors.HexColor("#eef2ff")


# ── model ────────────────────────────────────────────────────────────────

def latest_evidence_session(reader):
    """Most recent session_id beginning 'evidence:', or None."""
    row = reader.conn.execute(
        "SELECT session_id FROM chain_entries WHERE session_id LIKE ? "
        "ORDER BY session_id DESC LIMIT 1", (SESSION_PREFIX + "%",)).fetchone()
    return row[0] if row else None


def build_model(verifications):
    """Group re-verified entries into a control-organised model.

    Returns (controls, unmapped, stats) where `controls` is a list of
    dicts sorted by control_id, each holding the items mapped to it, and
    `unmapped` holds items with no operator-supplied mapping. Evidence is
    NEVER dropped: an item whose body will not parse still lands in
    stats["unparsable"] and is reported.
    """
    by_artifact = {v.entry["artifact_id"]: v for v in verifications}

    results = []
    unparsable = []
    for v in verifications:
        if v.entry["artifact_type"] != EVIDENCE_TYPE:
            continue
        body = vr.artifact_json(v)
        if not isinstance(body, dict) or not body.get("item"):
            unparsable.append(v)
            continue
        obs_id = body.get("observation")
        results.append({
            "body": body,
            "record": v,                      # the evidence_item entry
            "obs": by_artifact.get(obs_id),   # the signed observation entry
            "obs_id": obs_id,
        })

    # Group: control_id -> item name -> [results]
    buckets = {}
    unmapped = {}
    for r in results:
        body = r["body"]
        ctl = body.get("control") if body.get("mapping_status") == "mapped" \
            else None
        target = buckets if ctl else unmapped
        if ctl:
            key = ctl.get("control_id") or "(no id)"
            entry = target.setdefault(key, {
                "control_id": key,
                "control_description": ctl.get("control_description") or "",
                "framework": ctl.get("framework") or "",
                "items": {},
            })
        else:
            key = "(unmapped)"
            entry = target.setdefault(key, {"items": {}})
        item = entry["items"].setdefault(body["item"], {
            "name": body["item"],
            "title": body.get("title") or body["item"],
            "command": body.get("collection_method") or "",
            "proves": body.get("proves") or "",
            "does_not_prove": body.get("does_not_prove") or "",
            "evidence_gap": body.get("evidence_gap"),
            "results": [],
        })
        item["results"].append(r)

    for group in list(buckets.values()) + list(unmapped.values()):
        for item in group["items"].values():
            item["results"].sort(
                key=lambda x: (x["body"].get("device") or "",
                               x["body"].get("ts") or ""))

    controls = sorted(buckets.values(), key=lambda c: c["control_id"])
    unmapped_items = []
    for group in unmapped.values():
        unmapped_items.extend(
            sorted(group["items"].values(), key=lambda i: i["name"]))

    devices = sorted({r["body"].get("device") for r in results
                      if r["body"].get("device")})
    item_names = sorted({r["body"]["item"] for r in results})
    runs = sorted({r["body"].get("ts") for r in results if r["body"].get("ts")})

    stats = {
        "evidence_records": len(results),
        "unparsable_records": len(unparsable),
        "controls": len(controls),
        # Two distinct quantities, both reported: how many distinct ITEMS
        # lack a mapping, and how many collected RECORDS those account for
        # (one per device per collection). Printing only one invites the
        # reader to quote the wrong number.
        "unmapped_items": len(unmapped_items),
        "unmapped_records": sum(len(i["results"]) for i in unmapped_items),
        "devices": devices,
        "items": item_names,
        "collection_timestamps": runs,
        "gaps": sorted({i["name"] for g in buckets.values()
                        for i in g["items"].values() if i["evidence_gap"]}
                       | {i["name"] for i in unmapped_items
                          if i["evidence_gap"]}),
        "status_counts": _count(results, lambda r: r["body"].get(
            "collection_status") or "unknown"),
        "observations_linked": sum(1 for r in results if r["obs"] is not None),
        "observations_missing": sum(1 for r in results if r["obs"] is None),
    }
    return controls, unmapped_items, stats, unparsable


def _count(rows, key):
    out = {}
    for r in rows:
        k = key(r)
        out[k] = out.get(k, 0) + 1
    return out


def provenance_of(controls, unmapped):
    """Mapping-file provenance as recorded AT COLLECTION TIME, read back
    out of the chain-bound bodies. Returns a sorted list of distinct
    (items_source, items_sha256, controls_source, controls_sha256,
    framework) tuples — more than one means the item set or the mapping
    changed inside the reported window, which the report states."""
    seen = set()
    for group in controls + [{"items": {i["name"]: i}} for i in unmapped]:
        for item in group["items"].values():
            for r in item["results"]:
                b = r["body"]
                seen.add((b.get("items_source") or "-",
                          b.get("items_sha256") or "-",
                          b.get("controls_source") or "-",
                          b.get("controls_sha256") or "-",
                          (b.get("control") or {}).get("framework")
                          or b.get("framework") or "-"))
    return sorted(seen)


def signed_output(r):
    """The device output as re-derived FROM THE SIGNED BYTES at render
    time — not from the collector's stored copy. Returns (text, note)."""
    v = r["obs"]
    if v is None:
        return None, ("the signed observation this record names (%s) is not "
                      "in the reported range" % (r["obs_id"] or "unnamed"))
    if v.artifact_raw is None:
        return None, ("the chain retained no signed body for %s"
                      % r["obs_id"])
    payload = verify.parse_observation_payload(v.artifact_raw)
    if payload is None:
        return None, "the stored observation could not be parsed"
    return payload["output"], ""


# ── rendering ────────────────────────────────────────────────────────────

def section_header(story, ss, ctx, stats, prov):
    story.append(Paragraph("VIRP Compliance Evidence Report", ss["Title"]))
    story.append(Paragraph(
        "Read-only evidence, collected through the VIRP gate and organised "
        "by control. Every hash and signature below was recomputed from the "
        "chain at render time. The control mapping is <b>operator-supplied "
        "and is not asserted by this tool</b>.", ss["Note"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("1. Report header", ss["H2x"]))

    frameworks = sorted({p[4] for p in prov})
    rows = [
        ("Node identity", ctx["node_name"]),
        ("Framework (operator-supplied)",
         vr.esc(", ".join(frameworks) or "-")),
        ("Chain session", vr.esc(ctx["session"])),
        ("Devices covered", vr.esc(", ".join(stats["devices"]) or "-")),
        ("Evidence items", vr.esc(", ".join(stats["items"]) or "-")),
        ("Controls reported", "%d mapped, %d item(s) unmapped (%d record(s))"
         % (stats["controls"], stats["unmapped_items"],
            stats["unmapped_records"])),
        ("Evidence records", str(stats["evidence_records"])),
        ("Collection timestamps", vr.esc(
            "%s  →  %s" % (stats["collection_timestamps"][0],
                           stats["collection_timestamps"][-1])
            if stats["collection_timestamps"] else "-")),
        ("O-Key fingerprint", ctx["okey_fp"]),
        ("Chain-key fingerprint", ctx["chain_key_fp"]),
        ("Chain database", vr.esc(ctx["db_path"])),
        ("Read method", vr.esc(ctx["read_method"])),
        ("Report generated", ctx["generated"]),
        ("Generator", vr.esc(ctx["generator"])),
    ]
    story.append(vr.kv_table(rows, ss))

    story.append(Paragraph("1.1 Mapping provenance (as recorded at "
                           "collection time)", ss["H3x"]))
    story.append(Paragraph(
        "The item set and control mapping are data files an operator edits. "
        "Each collected record carries the path and SHA-256 of the files it "
        "was produced from, committed to by the chain entry — so this report "
        "names exactly the mapping that produced it and cannot be "
        "retroactively re-pointed at a different one.", ss["Note"]))
    data = [[Paragraph("<b>%s</b>" % h, ss["Note"]) for h in
             ("Item set", "sha256", "Control mapping", "sha256", "Framework")]]
    for p in prov:
        data.append([Paragraph(vr.esc(p[0]), ss["MonoSmall"]),
                     Paragraph(p[1][:16], ss["MonoSmall"]),
                     Paragraph(vr.esc(p[2]), ss["MonoSmall"]),
                     Paragraph(p[3][:16], ss["MonoSmall"]),
                     Paragraph(vr.esc(p[4]), ss["MonoSmall"])])
    t = Table(data, colWidths=(3.0 * inch, 1.2 * inch, 3.0 * inch,
                               1.2 * inch, 1.5 * inch), hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), vr.HEAD_BG),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d0d0d0")),
    ]))
    story.append(t)
    if len(prov) > 1:
        story.append(Paragraph(
            "<b>Note:</b> more than one item-set or mapping revision appears "
            "in this window — the data files changed between collections. "
            "Each record above is bound to the revision it was collected "
            "under.", ss["Warn"]))


def section_integrity(story, ss, summary, stats):
    story.append(Paragraph("2. Integrity summary (recomputed at render "
                           "time)", ss["H2x"]))

    def line(label, tally):
        parts = []
        for verdict in (verify.PASS, verify.FAIL, verify.UNVERIFIABLE,
                        verify.UNCHECKED, verify.NOT_APPLICABLE):
            n = tally.get(verdict, 0)
            if n:
                parts.append('<font color="%s">%s %d</font>'
                             % (vr.vhex(verdict), verdict, n))
        return (label, " &nbsp; ".join(parts) or "-")

    rows = [
        ("Chain entries verified", str(summary["entries"])),
        ("Evidence records", str(stats["evidence_records"])),
        ("Signed observations linked", "%d (%d record(s) name an "
         "observation outside this range)"
         % (stats["observations_linked"], stats["observations_missing"])),
        line("Entry hash", summary["entry_hash"]),
        line("Hash-link continuity", summary["link"]),
        line("Chain HMAC", summary["chain_hmac"]),
        line("Artifact binding", summary["artifact_bind"]),
        line("Observation HMAC", summary["obs_hmac"]),
        line("Session head (chain length)", summary["heads"]["tally"]),
        ("Collection status", " &nbsp; ".join(
            "%s %d" % (k, v)
            for k, v in sorted(stats["status_counts"].items())) or "-"),
    ]
    story.append(vr.kv_table(rows, ss))
    failed = len(summary["failed_entries"])
    if failed:
        story.append(Paragraph(
            "<b>%d entr%s failed verification.</b> Failures are printed in "
            "place, in red, on the control they belong to. Nothing was "
            "dropped to keep this report tidy."
            % (failed, "y" if failed == 1 else "ies"), ss["Bad"]))
    # Head failures are session-level, so no control row carries them —
    # print each one here where the verdict tally is.
    for sid, (verdict, detail) in sorted(
            summary["heads"]["per_session"].items()):
        if verdict == verify.FAIL:
            story.append(Paragraph(
                "<b>SESSION HEAD FAILED:</b> %s — %s"
                % (sid, detail), ss["Bad"]))
    if not failed:
        story.append(Paragraph(
            "Every check that could be run passed. UNVERIFIABLE, where it "
            "appears, is a retention limit of the chain format and is never "
            "counted as a pass — see the limitations section.", ss["Note"]))


def _verdict_row(v, ss):
    """Compact per-entry verdict strip."""
    cells = []
    for label, verdict in (("entry", v.entry_hash), ("link", v.link),
                           ("chain-hmac", v.chain_hmac),
                           ("artifact", v.artifact_bind),
                           ("obs-hmac", v.obs_hmac)):
        cells.append('%s <font color="%s"><b>%s</b></font>'
                     % (label, vr.vhex(verdict), verdict))
    return Paragraph(" &nbsp;|&nbsp; ".join(cells), ss["MonoSmall"])


def render_result(story, ss, r):
    """One device's collected result for one item."""
    body = r["body"]
    device = body.get("device") or "-"
    status = body.get("collection_status") or "unknown"

    rows = [[Paragraph("<b>Device</b>", ss["Note"]),
             Paragraph(vr.esc(device), ss["Mono"]),
             Paragraph("<b>Collected</b>", ss["Note"]),
             Paragraph(vr.esc(body.get("ts") or "-"), ss["Mono"]),
             Paragraph("<b>Tier</b>", ss["Note"]),
             Paragraph(vr.esc(body.get("tier") or "-"), ss["Mono"])]]
    t = Table(rows, colWidths=(0.7 * inch, 2.6 * inch, 0.8 * inch,
                               1.7 * inch, 0.5 * inch, 0.9 * inch),
              hAlign="LEFT")
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                           ("TOPPADDING", (0, 0), (-1, -1), 2)]))
    story.append(t)

    # Verification verdicts for the record and its signed observation.
    story.append(Paragraph("<b>evidence record</b> %s"
                           % vr.esc(r["record"].entry["artifact_id"]),
                           ss["MonoSmall"]))
    story.append(_verdict_row(r["record"], ss))
    if r["obs"] is not None:
        story.append(Paragraph("<b>signed observation</b> %s"
                               % vr.esc(r["obs_id"]), ss["MonoSmall"]))
        story.append(_verdict_row(r["obs"], ss))

    for v in (r["record"], r["obs"]):
        if v is None:
            continue
        for name, detail in v.failures:
            story.append(Paragraph("FAILED %s: %s"
                                   % (name, vr.esc(detail)), ss["Bad"]))
        for verdict, detail in ((v.artifact_bind, v.artifact_bind_detail),
                                (v.obs_hmac, v.obs_hmac_detail)):
            if verdict == verify.UNVERIFIABLE and detail:
                story.append(Paragraph("UNVERIFIABLE: %s" % vr.esc(detail),
                                       ss["Warn"]))

    if status != "ok":
        story.append(Paragraph(
            "<b>COLLECTION STATUS %s</b> — %s"
            % (status.upper(), vr.esc(body.get("collection_note") or "")),
            ss["Warn"]))

    text, note = signed_output(r)
    if text is None:
        story.append(Paragraph("Signed result unavailable: %s" % vr.esc(note),
                               ss["Warn"]))
        return
    raw_len = len(text.encode())
    shown = text
    if len(shown) > OUTPUT_DISPLAY_MAX:
        shown = shown[:OUTPUT_DISPLAY_MAX]
        trunc_note = ("  [display truncated at %d of %d bytes — the full "
                      "signed bytes remain in the chain]"
                      % (OUTPUT_DISPLAY_MAX, raw_len))
    else:
        trunc_note = ""
    story.append(Paragraph("<b>Signed result</b> (%d bytes, sha256 %s)"
                           % (raw_len,
                              (body.get("output_sha256") or "")[:16]),
                           ss["Note"]))
    story.append(XPreformatted(vr.esc(shown.rstrip() or "(empty)"),
                               ss["MonoSmall"]))
    if trunc_note:
        story.append(Paragraph(vr.esc(trunc_note.strip()), ss["Warn"]))
    story.append(Spacer(1, 5))


def render_item(story, ss, item):
    story.append(Paragraph("%s <font size=8>(%s)</font>"
                           % (vr.esc(item["title"]), vr.esc(item["name"])),
                           ss["H3x"]))
    story.append(vr.kv_table(
        [("Collection method", "<b>%s</b>" % vr.esc(item["command"])),
         ("Results", "%d device result(s)" % len(item["results"]))], ss,
        widths=(1.6 * inch, 8.7 * inch)))

    if item["evidence_gap"]:
        gap = Table([[Paragraph(
            "<b>EVIDENCE GAP — this control is NOT evidenced by this "
            "item.</b> %s" % vr.esc(item["evidence_gap"]), ss["Note"])]],
            colWidths=(10.3 * inch,), hAlign="LEFT")
        gap.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), GAP_BG),
            ("BOX", (0, 0), (-1, -1), 0.5,
             vr.VERDICT_COLOR[verify.UNVERIFIABLE]),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
        story.append(gap)
        story.append(Spacer(1, 4))

    for r in item["results"]:
        render_result(story, ss, r)

    # The caveat sits AFTER the evidence, where a reader has just seen the
    # output and is most likely to over-read it.
    cav = Table([
        [Paragraph("<b>What this read proves</b>", ss["Note"]),
         Paragraph(vr.esc(item["proves"]) or "-", ss["Note"])],
        [Paragraph("<b>What it does NOT prove</b>", ss["Note"]),
         Paragraph(vr.esc(item["does_not_prove"]) or "-", ss["Note"])],
    ], colWidths=(1.6 * inch, 8.7 * inch), hAlign="LEFT")
    cav.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), vr.HEAD_BG),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d0d0d0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    story.append(cav)
    story.append(Spacer(1, 8))


def section_controls(story, ss, controls):
    story.append(PageBreak())
    story.append(Paragraph("3. Evidence by control", ss["H2x"]))
    if not controls:
        story.append(Paragraph(
            "No mapped controls in this range. Any collected items appear "
            "under section 4.", ss["Warn"]))
        return
    story.append(Paragraph(
        "Each control below lists the evidence items an operator mapped to "
        "it. The control identifiers and descriptions come from the mapping "
        "file named in section 1.1 — this tool does not assert them.",
        ss["Note"]))

    for c in controls:
        story.append(Spacer(1, 6))
        head = Table([[Paragraph(
            "<b>%s</b> &nbsp; %s <font size=7>[%s]</font>"
            % (vr.esc(c["control_id"]), vr.esc(c["control_description"]),
               vr.esc(c["framework"])), ss["Note"])]],
            colWidths=(10.3 * inch,), hAlign="LEFT")
        head.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), vr.HEAD_BG),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#9aa0a6")),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        story.append(head)
        for item in sorted(c["items"].values(), key=lambda i: i["name"]):
            render_item(story, ss, item)


def section_unmapped(story, ss, unmapped):
    story.append(PageBreak())
    story.append(Paragraph("4. Unmapped evidence items", ss["H2x"]))
    if not unmapped:
        story.append(Paragraph(
            "Every collected item is mapped to a control in the mapping file "
            "named in section 1.1.", ss["Note"]))
        return
    box = Table([[Paragraph(
        "<b>%d item(s) below were collected, signed and chain-registered "
        "exactly like every other item, but no operator has mapped them to "
        "a control yet.</b> They are reported here rather than dropped: a "
        "missing mapping is an operator to-do, never a reason to lose "
        "evidence. Add them to the control mapping file to move them into "
        "section 3." % len(unmapped), ss["Note"])]],
        colWidths=(10.3 * inch,), hAlign="LEFT")
    box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), UNMAPPED_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#5566cc")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    story.append(box)
    for item in unmapped:
        render_item(story, ss, item)


def section_gaps(story, ss, controls, unmapped, stats):
    story.append(PageBreak())
    story.append(Paragraph("5. Declared evidence gaps", ss["H2x"]))
    gaps = []
    for c in controls:
        for item in c["items"].values():
            if item["evidence_gap"]:
                gaps.append((c["control_id"], item))
    for item in unmapped:
        if item["evidence_gap"]:
            gaps.append(("(unmapped)", item))
    if not gaps:
        story.append(Paragraph(
            "No item in this report declares a structural evidence gap. That "
            "is not a statement that the control set is fully evidenced — "
            "only that no collected item declared itself unable to evidence "
            "its control.", ss["Note"]))
        return
    story.append(Paragraph(
        "These items were collected and signed, but the item set itself "
        "declares that the read CANNOT evidence its control. They are listed "
        "here so a reader cannot mistake a signed-but-uninformative result "
        "for a satisfied control.", ss["Note"]))
    for control_id, item in gaps:
        story.append(Paragraph(
            "<b>%s — %s</b> (%s)" % (vr.esc(control_id),
                                     vr.esc(item["title"]),
                                     vr.esc(item["command"])), ss["Note"]))
        story.append(Paragraph(vr.esc(item["evidence_gap"]), ss["Warn"]))
        story.append(Spacer(1, 4))


def section_limitations(story, ss, ctx, stats, summary, unmapped):
    story.append(PageBreak())
    story.append(Paragraph("6. Limitations", ss["H2x"]))
    story.append(Paragraph(
        "Read this section before drawing any compliance conclusion from "
        "the pages above.", ss["Note"]))

    def para(title, text):
        story.append(Paragraph("<b>%s</b>" % title, ss["Note"]))
        story.append(Paragraph(text, ss["Note"]))
        story.append(Spacer(1, 5))

    para("This is a read-only, point-in-time snapshot.",
         "Every item here is a single read taken at the timestamp shown "
         "beside it. It evidences the device's state at that instant and "
         "says nothing about any other moment — not before, not after, and "
         "not continuously. A device that was compliant at collection time "
         "and changed a minute later would produce exactly this report. "
         "Nothing here was written to any device: the collector submits "
         "GREEN reads only and holds no ability to change anything.")

    para("The control mapping is operator-supplied, not tool-asserted.",
         "The control identifiers, descriptions and framework name on these "
         "pages come from a data file an operator wrote (named with its "
         "SHA-256 in section 1.1). This tool does not know, check or claim "
         "that a given read satisfies a given control — it renders the "
         "mapping it was given. A wrong or wishful mapping produces a "
         "wrong-but-well-formed report. The per-item &quot;what this does "
         "NOT prove&quot; caveats are the counterweight and are part of the "
         "evidence, not decoration.")

    para("HMAC is not a digital signature.",
         "VIRP observations and chain entries are authenticated with "
         "symmetric HMAC-SHA256, not asymmetric signatures. Anyone holding "
         "the key can both produce and verify a valid MAC, so these results "
         "prove that the holder of the O-Key produced them and that they "
         "have not been altered since — they do NOT provide "
         "non-repudiation, and they do not let a third party who lacks the "
         "key verify anything independently. This report was generated by a "
         "key holder. Treat it as an internal integrity record, not as "
         "third-party-verifiable attestation.")

    para("The collector cannot verify its own evidence.",
         "The collecting identity holds no keys by design, so it stored "
         "signed bytes without checking them. Every verdict in this report "
         "was computed here, at render time, by a key holder. That "
         "separation is the point, but it means the collector could not "
         "have detected a bad signature at collection time.")

    if unmapped:
        para("Unmapped items.",
             "%d evidence item(s) in this report have no control mapping and "
             "appear in section 4: %s. They were collected and signed "
             "identically to mapped items; only the mapping is missing."
             % (len(unmapped),
                vr.esc(", ".join(sorted(i["name"] for i in unmapped)))))
    else:
        para("Unmapped items.",
             "None — every collected item in this report is mapped to a "
             "control. Items lacking a mapping are never dropped; they would "
             "appear in section 4.")

    if stats["gaps"]:
        para("Declared evidence gaps.",
             "%d item(s) declare that they cannot evidence their control at "
             "all (%s); see section 5. The corresponding controls should be "
             "treated as UNEVIDENCED by this report."
             % (len(stats["gaps"]), vr.esc(", ".join(stats["gaps"]))))

    bad_status = {k: v for k, v in stats["status_counts"].items()
                  if k != "ok"}
    if bad_status:
        para("Results that observed nothing.",
             "%s. The device answered, and the answer is validly signed, but "
             "its content evidences nothing — a command the device did not "
             "recognise, or an empty reply. These are flagged in place and "
             "must not be read as satisfied controls."
             % vr.esc(", ".join("%d result(s) with status %s" % (v, k)
                                for k, v in sorted(bad_status.items()))))

    para("Coverage of this report.",
         "This report covers chain session <b>%s</b> only, and within it "
         "only the %d evidence record(s) listed. Evidence collected into "
         "another session, or outside the reported range, is not represented "
         "here and its absence is not evidence of anything."
         % (vr.esc(ctx["session"]), stats["evidence_records"]))

    if ctx.get("read_caveat"):
        para("Chain read method.", vr.esc(ctx["read_caveat"]))

    if stats["unparsable_records"]:
        para("Unparsable records.",
             "%d evidence record(s) in this session could not be parsed as "
             "evidence bodies and are therefore not rendered under any "
             "control. They are counted here rather than ignored."
             % stats["unparsable_records"])


def _footer(canvas, doc, ctx):
    canvas.saveState()
    canvas.setFont("Courier", 7)
    canvas.setFillColor(colors.HexColor("#666666"))
    canvas.drawString(0.5 * inch, 0.35 * inch,
                      "VIRP compliance evidence report — %s — %s — control "
                      "mapping is operator-supplied"
                      % (ctx["node_name"], ctx["generated"]))
    canvas.drawRightString(letter[1] - 0.5 * inch, 0.35 * inch,
                           "page %d" % doc.page)
    canvas.restoreState()


def render_pdf(out_path, ctx, controls, unmapped, stats, summary, unparsable):
    ss = vr.styles()
    doc = SimpleDocTemplate(
        out_path, pagesize=landscape(letter),
        leftMargin=0.5 * inch, rightMargin=0.5 * inch,
        topMargin=0.5 * inch, bottomMargin=0.6 * inch,
        title="VIRP Compliance Evidence Report",
        author="virp-evidence-report")
    story = []
    prov = provenance_of(controls, unmapped)
    section_header(story, ss, ctx, stats, prov)
    section_integrity(story, ss, summary, stats)
    section_controls(story, ss, controls)
    section_unmapped(story, ss, unmapped)
    section_gaps(story, ss, controls, unmapped, stats)
    section_limitations(story, ss, ctx, stats, summary, unmapped)
    draw = lambda c, d: _footer(c, d, ctx)  # noqa: E731
    doc.build(story, onFirstPage=draw, onLaterPages=draw)


# ── CLI ──────────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="virp-evidence-report",
        description="Render collected VIRP compliance evidence as a "
                    "control-mapped PDF. Reads the chain read-only and "
                    "never writes to it. Makes no network connections.")
    p.add_argument("--db", required=True, help="path to chain.db")
    p.add_argument("--out", required=True, help="output PDF path")
    p.add_argument("--session",
                   help="evidence session id (default: the most recent "
                        "session beginning 'evidence:')")
    p.add_argument("--okey", default=vr.DEFAULT_OKEY,
                   help="O-Key for observation HMAC verification")
    p.add_argument("--chain-key", default=vr.DEFAULT_CHAIN_KEY,
                   help="chain key for entry HMAC verification")
    p.add_argument("--node-identity", default=vr.DEFAULT_NODE_IDENTITY,
                   help="JSON file naming this node")
    p.add_argument("--allow-immutable", action="store_true",
                   help="permit the unsafe immutable=1 read as a last resort")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    okey = chain_key = None
    okey_fp = "unavailable — observation HMACs NOT verified"
    chain_fp = "unavailable — chain HMACs NOT verified"
    try:
        okey = verify.load_key(args.okey)
        okey_fp = verify.key_fingerprint(okey)
    except (OSError, ValueError) as exc:
        print("virp-evidence-report: O-Key unavailable (%s); observation "
              "signatures will be reported UNCHECKED" % exc, file=sys.stderr)
    try:
        chain_key = verify.load_key(args.chain_key)
        chain_fp = verify.key_fingerprint(chain_key)
    except (OSError, ValueError) as exc:
        print("virp-evidence-report: chain key unavailable (%s); chain HMACs "
              "will be reported UNCHECKED" % exc, file=sys.stderr)

    try:
        reader = chain_read.open_chain(
            args.db, allow_immutable=args.allow_immutable)
    except chain_read.ChainReadError as exc:
        print("virp-evidence-report: %s" % exc, file=sys.stderr)
        return 1

    with reader:
        session = args.session or latest_evidence_session(reader)
        if not session:
            print("virp-evidence-report: no evidence session found in %s "
                  "(expected a session_id beginning %r)"
                  % (args.db, SESSION_PREFIX), file=sys.stderr)
            return 1

        # Select the WHOLE session so hash-link continuity is actually
        # verifiable: filtering to evidence rows alone would manufacture
        # sequence gaps and report a healthy chain as broken.
        entries, artifacts = vr.load_evidence(reader, session, None, None)
        if not entries:
            print("virp-evidence-report: session %r has no entries" % session,
                  file=sys.stderr)
            return 1
        heads = vr.load_heads(reader)
        verifications, summary = verify.verify_chain(
            entries, artifacts, okey=okey, chain_key=chain_key,
            heads=heads, selection_complete=True)

        controls, unmapped, stats, unparsable = build_model(verifications)

        identity = vr.load_node_identity(args.node_identity)
        ctx = {
            "node_name": identity.get("node") or "(node identity unknown)",
            "okey_fp": okey_fp,
            "chain_key_fp": chain_fp,
            "db_path": os.path.abspath(args.db),
            "read_method": reader.method,
            "read_caveat": reader.caveat,
            "session": session,
            "generated": datetime.datetime.now(
                datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "generator": "virp-evidence-report (reportlab %s, python "
                         "%d.%d.%d)" % (__import__("reportlab").Version,
                                        *sys.version_info[:3]),
        }
        if not stats["evidence_records"]:
            print("virp-evidence-report: session %r contains no %s entries"
                  % (session, EVIDENCE_TYPE), file=sys.stderr)

        render_pdf(args.out, ctx, controls, unmapped, stats, summary,
                   unparsable)

    failed = len(summary["failed_entries"])
    print("virp-evidence-report: wrote %s" % args.out)
    print("  session          : %s" % session)
    print("  chain entries    : %d" % summary["entries"])
    print("  evidence records : %d" % stats["evidence_records"])
    print("  controls         : %d" % stats["controls"])
    print("  unmapped items   : %d (%d record(s))"
          % (stats["unmapped_items"], stats["unmapped_records"]))
    print("  devices          : %d" % len(stats["devices"]))
    print("  evidence gaps    : %d" % len(stats["gaps"]))
    print("  entry hash       : %s" % vr._fmt(summary["entry_hash"]))
    print("  hash links       : %s" % vr._fmt(summary["link"]))
    print("  chain HMAC       : %s" % vr._fmt(summary["chain_hmac"]))
    print("  artifact binding : %s" % vr._fmt(summary["artifact_bind"]))
    print("  observation HMAC : %s" % vr._fmt(summary["obs_hmac"]))
    print("  collection status: %s"
          % ", ".join("%s=%d" % kv
                      for kv in sorted(stats["status_counts"].items())))
    if failed:
        print("  FAILED ENTRIES   : %d" % failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
