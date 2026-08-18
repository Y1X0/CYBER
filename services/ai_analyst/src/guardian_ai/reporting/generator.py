"""Assemble a report's sections and summary from findings + the AI executive summary."""

from __future__ import annotations

from guardian_core import compliance
from guardian_db.models import Finding, ReportSection, ScanEngineRun
from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian_ai.analyst import executive_summary
from guardian_ai.providers.base import LLMProvider


def _engines_completed(session: Session, scan_id) -> set[str]:  # noqa: ANN001
    """Which engines actually finished for this scan.

    The compliance assessment needs this and nothing else can substitute for it: a control whose
    engine never ran is `not_assessed`, and calling it `passing` because no finding mentioned it
    manufactures an assurance nobody earned.
    """
    if scan_id is None:
        return set()
    return {
        run.engine for run in session.execute(
            select(ScanEngineRun).where(ScanEngineRun.scan_id == scan_id)
        ).scalars() if run.status == "completed"
    }


def _compliance_refs(findings: list) -> list[compliance.FindingRef]:  # noqa: ANN001
    return [
        compliance.FindingRef(
            id=str(f.id), severity=f.severity, title=f.title, category=f.category or "",
            cwe_id=f.cwe_id, rule=str((f.location or {}).get("rule") or ""), status=f.status,
        )
        for f in findings
    ]


def _findings_for(session: Session, scan_id) -> list:  # noqa: ANN001
    rows = session.execute(select(Finding).where(Finding.scan_id == scan_id)).scalars().all()
    return sorted(rows, key=lambda f: -f.risk_score)


def generate_report_content(session: Session, report, provider: LLMProvider) -> dict:  # noqa: ANN001
    """(Re)build the report's sections + summary. Returns the executive-summary dict."""
    findings = _findings_for(session, report.scan_id)
    exec_summary = executive_summary(session, findings, provider)

    # Clear any prior sections (idempotent regeneration).
    for old in session.execute(
        select(ReportSection).where(ReportSection.report_id == report.id)
    ).scalars():
        session.delete(old)
    session.flush()

    session.add(
        ReportSection(
            report_id=report.id,
            kind="executive",
            title="Executive Summary",
            body=exec_summary.get("summary", ""),
            ordering=0,
        )
    )
    remediation_lines = [
        f"- [{f.severity.upper()}] {f.title}: "
        + (
            (f.remediation or {}).get("summary")
            if isinstance(f.remediation, dict)
            else None or "Follow referenced CWE/OWASP guidance and re-scan to verify."
        )
        for f in findings
    ]
    session.add(
        ReportSection(
            report_id=report.id,
            kind="remediation",
            title="Remediation Plan",
            body="\n".join(remediation_lines) or "No remediation items.",
            ordering=2,
        )
    )
    # Compliance coverage. Every framework is assessed against the engines that completed, so a
    # control nothing looked at is reported as not assessed rather than as passing.
    engines = _engines_completed(session, report.scan_id)
    refs = _compliance_refs(findings)
    assessments = [compliance.assess(f, refs, engines_completed=engines)
                   for f in compliance.FRAMEWORKS]
    coverage = compliance.summarize(assessments)
    session.add(
        ReportSection(
            report_id=report.id,
            kind="compliance",
            title="Control Coverage",
            body="\n".join(
                f"{block['framework']}: {block['counts']['failing']} failing, "
                f"{block['counts']['passing']} passing, "
                f"{block['counts']['not_assessed']} not assessed "
                f"({block['coverage']}% of controls assessed)"
                for block in coverage["frameworks"]
            ) + "\n\n" + coverage["disclaimer"],
            ordering=4,
        )
    )

    standards = sorted(
        {f.owasp_ref for f in findings if f.owasp_ref} | {f.cwe_id for f in findings if f.cwe_id}
    )
    session.add(
        ReportSection(
            report_id=report.id,
            kind="standards",
            title="Standards Coverage",
            body=", ".join(standards) or "n/a",
            ordering=3,
        )
    )

    report.summary = {
        "security_score": exec_summary.get("security_score"),
        "posture": exec_summary.get("posture"),
        "severity_counts": exec_summary.get("severity_counts"),
        "total_findings": len(findings),
        "recommendation": exec_summary.get("recommendation"),
        "top_risks": exec_summary.get("top_risks", []),
        "compliance": coverage,
    }
    return exec_summary
