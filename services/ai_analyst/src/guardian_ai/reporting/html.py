"""Render a professional HTML security report from a report + its findings.

The report is the artifact that leaves the platform: emailed to an auditor, attached to a board
pack, forwarded to a prospect. Two consequences shape this module.

Evidence is scrubbed on the way in (WP-F2's redactor). The engines redact at write time, but a
report is the worst place for the one value they missed, and it is the copy nobody can recall.

The compliance table prints `not assessed` as its own column rather than folding it into a pass
rate, because a 100% pass over 20% coverage is the number that misleads an auditor.
"""

from __future__ import annotations

import html

from guardian_core.finding_explain import explain_finding
from guardian_core.redaction import scrub_text

_SEV_COLOR = {
    "critical": "#b00020",
    "high": "#d9534f",
    "medium": "#f0ad4e",
    "low": "#5bc0de",
    "info": "#777",
}


def _esc(v) -> str:  # noqa: ANN001
    return html.escape(str(v if v is not None else ""))


_STATUS_STYLE = {
    "failing": "background:#b00020;color:#fff",
    "passing": "background:#2e7d32;color:#fff",
    "not_assessed": "background:#666;color:#fff",
}


def _compliance_table(coverage) -> str:  # noqa: ANN001
    """The control table, with `not assessed` given equal billing.

    Collapsing it into "passing" would be the single most misleading thing this product could
    print: it would tell an auditor a control was verified when nothing looked at it.
    """
    if not isinstance(coverage, dict) or not coverage.get("frameworks"):
        return ""
    blocks = []
    for framework in coverage["frameworks"]:
        counts = framework.get("counts", {})
        rows = "".join(
            f"<tr><td><code>{_esc(control['id'])}</code></td>"
            f"<td>{_esc(control['title'])}</td>"
            f"<td><span style=\"{_STATUS_STYLE.get(control['status'], '')};"
            f"padding:2px 6px;border-radius:3px\">"
            f"{_esc(control['status'].replace('_', ' '))}</span></td>"
            f"<td>{_esc(control['rationale'])}</td></tr>"
            for control in framework.get("controls", [])
        )
        blocks.append(
            f"<h3>{_esc(framework['framework'])}</h3>"
            f"<p>{counts.get('failing', 0)} failing · {counts.get('passing', 0)} passing · "
            f"{counts.get('not_assessed', 0)} not assessed — "
            f"<strong>{framework.get('coverage', 0)}% of controls were assessed</strong> by "
            f"{_esc(', '.join(framework.get('engines_assessed', [])) or 'no engine')}</p>"
            f"<table><thead><tr><th>Control</th><th>Title</th><th>Status</th>"
            f"<th>Basis</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    return ("<h2>Control Coverage</h2>"
            f"<p style=\"color:#777\">{_esc(coverage.get('disclaimer', ''))}</p>"
            + "".join(blocks))


def _truncation_banner(note: str) -> str:
    if not note:
        return ""
    return (
        "<p style=\"background:#fff4e5;border-left:4px solid #f0ad4e;padding:10px;"
        "margin:12px 0\"><strong>Partial report.</strong> " + _esc(note) + "</p>"
    )


def render_html(report, findings: list, *, truncation_note: str = "") -> str:  # noqa: ANN001
    """`truncation_note` is non-empty when the caller could not fit every finding (WP-G2).

    It is rendered at the top rather than the bottom: a reader who stops after the summary
    must not come away believing they saw the whole assessment.
    """
    summary = report.summary or {}
    counts = summary.get("severity_counts", {})
    score = summary.get("security_score", "n/a")
    posture = summary.get("posture", "")

    # Findings are rendered as sections that lead with the same plain-language explanation the
    # console shows — what it means / why it matters / what to do — followed by the technical facts.
    # One source (guardian_core.finding_explain), so the report and the screen never disagree.
    blocks = []
    for f in sorted(findings, key=lambda x: -x.risk_score):
        color = _SEV_COLOR.get(f.severity, "#777")
        ex = explain_finding(f)
        raw_evidence = ((f.evidence or {}).get("match")
                        or (f.evidence or {}).get("summary") or "")
        evidence = _esc(scrub_text(str(raw_evidence))[0])
        standards = " · ".join(filter(None, [f.cwe_id, f.owasp_ref]))
        sev = f"<span style='color:{color};font-weight:700'>{_esc(f.severity.upper())}</span>"
        blocks.append(
            f"<section class='finding'>"
            f"<h3>{sev} &nbsp;{_esc(f.title)} <small style='color:#777'>· risk "
            f"{f.risk_score}</small></h3>"
            f"<div class='explain'>"
            f"<h4>What this means</h4><p>{_esc(ex.what_it_means)}</p>"
            f"<h4>Why it matters</h4><p>{_esc(ex.why_it_matters)}</p>"
            f"<h4>What to do</h4><p>{_esc(ex.what_to_do)}</p>"
            f"</div>"
            f"<p class='tech'><strong>Technical details:</strong> "
            f"{_esc(standards) or 'no standard mapping'}"
            f"{(' · ' + _esc(ex.where)) if ex.where else ''}</p>"
            + (f"<p class='tech'><strong>Evidence:</strong> <code>{evidence}</code></p>"
               if evidence else "")
            + "</section>"
        )

    badges = " ".join(
        f"<span style='background:{_SEV_COLOR[s]};color:#fff;padding:2px 8px;"
        f"border-radius:10px;margin-right:6px'>{s}: {counts.get(s, 0)}</span>"
        for s in ("critical", "high", "medium", "low", "info")
    )
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Security Assessment Report</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:40px;color:#1a1a1a}}
 h1{{border-bottom:3px solid #1a1a1a;padding-bottom:8px}}
 .score{{font-size:48px;font-weight:700}}
 table{{border-collapse:collapse;width:100%;margin-top:16px;font-size:13px}}
 th,td{{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}}
 th{{background:#f4f4f4}}
 code{{background:#f6f6f6;padding:1px 4px}}
 .finding{{border:1px solid #ddd;border-radius:6px;padding:14px 18px;margin:14px 0}}
 .finding h3{{margin:0 0 6px;font-size:16px}}
 .explain h4{{margin:10px 0 2px;font-size:11px;letter-spacing:.06em;text-transform:uppercase;
   color:#b00020}}
 .explain p{{margin:0 0 4px}}
 .tech{{color:#555;font-size:12px;margin:6px 0 0}}
</style></head><body>
<h1>Security Assessment Report</h1>
{_truncation_banner(truncation_note)}
<p><strong>{_esc(report.title)}</strong> — status: {_esc(report.status)}</p>
<h2>Executive Summary</h2>
<p class="score">{_esc(score)}/100 <small>({_esc(posture)})</small></p>
<p>{badges}</p>
<p>{_esc(summary.get("recommendation", ""))}</p>
{_compliance_table(summary.get("compliance"))}
<h2>Findings</h2>
{"".join(blocks) or "<p>No findings.</p>"}
<p style="margin-top:24px;color:#777;font-size:12px">
Generated by Security Guardian Platform. Severities and risk scores are produced by a deterministic
risk engine; narrative is AI-assisted and human-reviewed.</p>
</body></html>"""
