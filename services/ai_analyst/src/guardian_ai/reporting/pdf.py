"""Render a professional PDF report via reportlab (pure-python, no system libraries)."""

from __future__ import annotations

import io

from guardian_core.finding_explain import explain_finding
from guardian_core.redaction import scrub_text
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def _x(v) -> str:  # noqa: ANN001 - escape dynamic text for reportlab's mini-markup
    from xml.sax.saxutils import escape  # noqa: PLC0415
    return escape(str(v if v is not None else ""))


_SEV_COLOR = {
    "critical": colors.HexColor("#b00020"),
    "high": colors.HexColor("#d9534f"),
    "medium": colors.HexColor("#f0ad4e"),
    "low": colors.HexColor("#5bc0de"),
    "info": colors.HexColor("#777777"),
}


def render_pdf(report, findings: list, *, truncation_note: str = "") -> bytes:  # noqa: ANN001
    """`truncation_note` is non-empty when the caller could not fit every finding (WP-G2).

    Printed immediately under the title, because a PDF is the artefact most likely to be read
    without the context that produced it.
    """
    summary = report.summary or {}
    counts = summary.get("severity_counts", {})
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title="Security Assessment Report")
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Security Assessment Report", styles["Title"]))
    story.append(Paragraph(report.title or "", styles["Heading3"]))
    if truncation_note:
        story.append(Paragraph(f"<b>Partial report.</b> {truncation_note}", styles["Normal"]))
    story.append(Spacer(1, 6 * mm))

    story.append(Paragraph("Executive Summary", styles["Heading1"]))
    story.append(
        Paragraph(
            f"Security score: <b>{summary.get('security_score', 'n/a')}/100</b> "
            f"({summary.get('posture', '')})",
            styles["Normal"],
        )
    )
    story.append(
        Paragraph(
            " &nbsp; ".join(
                f"{s}: {counts.get(s, 0)}" for s in ("critical", "high", "medium", "low", "info")
            ),
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(summary.get("recommendation", ""), styles["Normal"]))
    story.append(Spacer(1, 6 * mm))

    story.append(Paragraph("Findings", styles["Heading1"]))
    data = [["Severity", "Risk", "Title", "Standards"]]
    ordered = sorted(findings, key=lambda x: -x.risk_score)
    for f in ordered:
        data.append(
            [
                f.severity.upper(),
                str(f.risk_score),
                Paragraph(f.title, styles["BodyText"]),
                f"{f.cwe_id or ''} {f.owasp_ref or ''}".strip(),
            ]
        )
    if len(data) == 1:
        data.append(["—", "—", "No findings", "—"])

    table = Table(data, colWidths=[22 * mm, 14 * mm, 95 * mm, 30 * mm], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a1a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for i, f in enumerate(ordered, start=1):
        style.append(("TEXTCOLOR", (0, i), (0, i), _SEV_COLOR.get(f.severity, colors.black)))
    table.setStyle(TableStyle(style))
    story.append(table)

    # Per-finding detail leads with the same plain-language explanation the console and the HTML
    # report show — one source (guardian_core.finding_explain), so the artefacts never disagree.
    if ordered:
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph("Finding details", styles["Heading1"]))
        for f in ordered:
            ex = explain_finding(f)
            standards = " · ".join(x for x in (f.cwe_id, f.owasp_ref) if x)
            evidence = scrub_text(str((f.evidence or {}).get("match")
                                      or (f.evidence or {}).get("summary") or ""))[0]
            story.append(Paragraph(
                f"<b>{_x(f.severity.upper())}</b> — {_x(f.title)} "
                f"<font color='#777'>· risk {f.risk_score}</font>", styles["Heading3"]))
            story.append(Paragraph(f"<b>What this means.</b> {_x(ex.what_it_means)}",
                                   styles["Normal"]))
            story.append(Paragraph(f"<b>Why it matters.</b> {_x(ex.why_it_matters)}",
                                   styles["Normal"]))
            story.append(Paragraph(f"<b>What to do.</b> {_x(ex.what_to_do)}", styles["Normal"]))
            tech = standards or "no standard mapping"
            if ex.where:
                tech += f" · {ex.where}"
            story.append(Paragraph(f"<font size=8 color='#555'>Technical: {_x(tech)}"
                                   + (f" · Evidence: {_x(evidence)}" if evidence else "")
                                   + "</font>", styles["Normal"]))
            story.append(Spacer(1, 3 * mm))

    story.append(Spacer(1, 8 * mm))
    story.append(
        Paragraph(
            "Generated by Security Guardian Platform. Severities and risk scores are produced by a "
            "deterministic risk engine; narrative is AI-assisted and human-reviewed.",
            styles["Italic"],
        )
    )

    doc.build(story)
    return buf.getvalue()
