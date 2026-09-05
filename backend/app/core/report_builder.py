"""ReportLab PDF report builder.

PS-required structure per device report:
  1. Device identification (hostname, vendor, OS, audit timestamp)
  2. Executive summary (pass/fail counts, compliance %, top 3 critical)
  3. Findings table: Rule ID | Title | Severity | Status | Source
  4. Remediation appendix: exact CLI per failed rule
  5. Footer disclaimer (advisory-only)
"""

from __future__ import annotations

import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.core.remediation import ADVISORY_NOTICE
from app.core.rule_engine import SEVERITY_ORDER

NAVY = colors.HexColor("#0F172A")
INK = colors.HexColor("#0A0A0A")
MUTED = colors.HexColor("#6B7280")
CRIMSON = colors.HexColor("#DC2626")
AMBER = colors.HexColor("#D97706")
GREEN = colors.HexColor("#16A34A")
HAIRLINE = colors.HexColor("#E5E7EB")

SEVERITY_COLORS = {"critical": CRIMSON, "high": CRIMSON, "medium": AMBER, "low": MUTED}
STATUS_COLORS = {"pass": GREEN, "fail": CRIMSON, "error": AMBER, "not_applicable": MUTED}


def _styles():
    ss = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("cf-title", parent=ss["Title"], fontName="Helvetica-Bold", fontSize=20, textColor=NAVY, spaceAfter=2),
        "subtitle": ParagraphStyle("cf-sub", parent=ss["Normal"], fontName="Helvetica", fontSize=9, textColor=MUTED),
        "h2": ParagraphStyle("cf-h2", parent=ss["Heading2"], fontName="Helvetica-Bold", fontSize=13, textColor=INK, spaceBefore=14, spaceAfter=6),
        "body": ParagraphStyle("cf-body", parent=ss["Normal"], fontSize=9, leading=12, textColor=INK),
        "mono": ParagraphStyle("cf-mono", parent=ss["Normal"], fontName="Courier", fontSize=8.5, leading=11, textColor=INK, backColor=colors.HexColor("#F3F4F6"), borderPadding=6),
        "small": ParagraphStyle("cf-small", parent=ss["Normal"], fontSize=7.5, textColor=MUTED),
    }


def _safe(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>")


def build_pdf(
    device: dict,
    summary: dict,
    findings: list[dict],
    unparsed_count: int = 0,
    ai_confirmed_categories: list[str] | None = None,
) -> bytes:
    buf = io.BytesIO()
    st = _styles()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, title=f"ComplianceForge Report - {device.get('hostname') or device.get('device_id')}",
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=18 * mm,
        author="ComplianceForge",
    )
    story: list = []

    # 1 — device identification
    story.append(Paragraph("ComplianceForge", st["subtitle"]))
    story.append(Paragraph("Network Security Compliance Audit Report", st["title"]))
    story.append(Spacer(1, 6))
    ident = [
        ["Hostname", device.get("hostname") or "n/a"],
        ["Device ID", device.get("device_id") or "n/a"],
        ["Vendor", device.get("vendor_label") or device.get("vendor") or "n/a"],
        ["OS Version", device.get("os_version") or "n/a"],
        ["Model", device.get("model") or "n/a"],
        ["Audit Timestamp", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
    ]
    t = Table([[Paragraph(f"<b>{k}</b>", st["body"]), Paragraph(_safe(str(v)), st["body"])] for k, v in ident], colWidths=[38 * mm, 118 * mm])
    t.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#FAFAFA")]),
        ("GRID", (0, 0), (-1, -1), 0.5, HAIRLINE),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)

    # 2 — executive summary
    story.append(Paragraph("Executive Summary", st["h2"]))
    pct = summary.get("compliance_pct", 0)
    passes, fails = summary.get("pass_count", 0), summary.get("fail_count", 0)
    total = summary.get("total_rules", 0)
    summary_line = f"Compliance Score: <b>{pct}%</b> &nbsp;|&nbsp; {passes} PASS / {fails} FAIL / {total} rules evaluated"
    if unparsed_count:
        summary_line += f" &nbsp;|&nbsp; {unparsed_count} unrecognized line(s) routed to Training Queue"
    story.append(Paragraph(summary_line, st["body"]))
    story.append(Spacer(1, 4))
    top = summary.get("top_critical_findings") or []
    if top:
        items = "".join(f"<li><b>{f['rule_id']}</b> — {_safe(f['title'])}</li>" for f in top)
        story.append(Paragraph("Top critical findings:", st["body"]))
        story.append(Paragraph(items, st["body"]))

    # 3 — findings table
    story.append(Paragraph("Findings", st["h2"]))
    header = [Paragraph(f"<b>{h}</b>", st["body"]) for h in ["Rule ID", "Title", "Severity", "Status", "Source"]]
    rows = [header]
    sev_rank = SEVERITY_ORDER
    for f in sorted(findings, key=lambda x: (sev_rank.get(x["severity"], 99), x["status"] != "fail")):
        source_label = "AI-confirmed mapping" if f.get("source") == "ai_suggested_human_confirmed" else "Built-in rule"
        rows.append(
            [
                Paragraph(f["rule_id"], st["body"]),
                Paragraph(_safe(f["title"]), st["body"]),
                Paragraph(f["severity"].upper(), st["body"]),
                Paragraph(f["status"].upper(), st["body"]),
                Paragraph(source_label, st["body"]),
            ]
        )
    t = Table(rows, colWidths=[26 * mm, 72 * mm, 18 * mm, 18 * mm, 30 * mm], repeatRows=1)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.5, HAIRLINE),
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ]
    # color status cells
    sorted_findings = sorted(findings, key=lambda x: (sev_rank.get(x["severity"], 99), x["status"] != "fail"))
    for i, f in enumerate(sorted_findings, start=1):
        col = STATUS_COLORS.get(f["status"], INK)
        style.append(("TEXTCOLOR", (3, i), (3, i), col))
        style.append(("FONTNAME", (3, i), (3, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(style))
    story.append(t)

    # 4 — remediation appendix
    failed = [f for f in findings if f["status"] == "fail" and f.get("remediation")]
    story.append(Paragraph("Remediation Appendix", st["h2"]))
    story.append(Paragraph(
        "Exact CLI per failed rule, in vendor-native syntax. AI-suggested mappings that a human "
        "confirmed are marked with their source.", st["body"]
    ))
    story.append(Spacer(1, 6))
    if not failed:
        story.append(Paragraph("No failed rules — no remediation required.", st["body"]))
    for f in failed:
        source_tag = " [source: AI-suggested + human-confirmed mapping]" if f.get("source") == "ai_suggested_human_confirmed" else ""
        story.append(Paragraph(f"<b>{f['rule_id']}</b> — {_safe(f['title'])}{source_tag}", st["body"]))
        story.append(Spacer(1, 2))
        story.append(Paragraph(_safe(f["remediation"]), st["mono"]))
        story.append(Spacer(1, 6))

    # 5 — footer disclaimer
    story.append(Spacer(1, 10))
    story.append(Paragraph(f"<b>Disclaimer:</b> {_safe(ADVISORY_NOTICE)}", st["small"]))

    def _footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 10 * mm, f"ComplianceForge — advisory-only remediation. Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc_.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
