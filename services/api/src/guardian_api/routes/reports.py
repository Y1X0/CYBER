"""Reports API — the human-governed deliverable (doc 07 §6).

Lifecycle: draft → in_review → approved → published (with rejected/revoked). Approval requires an
independent reviewer; a report is not customer-visible until published. Every transition is audited
and recorded in `report_approvals`.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from guardian_ai.providers import get_provider
from guardian_ai.reporting import generate_report_content, render_html, render_pdf
from guardian_common.logging import get_logger
from guardian_core import quota
from guardian_db.audit import record_audit
from guardian_db.models import Finding, Report, ReportApproval, Scan
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from guardian_api.deps import (
    Identity,
    client_ip,
    get_current_identity,
    get_db,
    require_reviewer,
    require_staff_write,
)
from guardian_api.pagination import apply_cursor, order_newest_first, page_request, paginate
from guardian_api.schemas import ReportAction, ReportCreate, ReportOut

log = get_logger("guardian.api.reports")

router = APIRouter()


def _build_summary(db: Session, scan: Scan) -> dict:
    """Counts and the five worst findings, computed in the database (WP-G2).

    This used to load every finding of the scan to count them and sort five out — the whole result
    set in memory to produce eleven numbers. The counts are a `GROUP BY` and the top five are an
    `ORDER BY ... LIMIT 5`, which is what an index is for.
    """
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total = 0
    for severity, count in db.execute(
        select(Finding.severity, func.count())
        .where(Finding.scan_id == scan.id)
        .group_by(Finding.severity)
    ).all():
        counts[severity] = int(count)
        total += int(count)

    top = db.execute(
        select(Finding.title, Finding.severity, Finding.risk_score)
        .where(Finding.scan_id == scan.id)
        .order_by(Finding.risk_score.desc(), Finding.id)
        .limit(5)
    ).all()
    return {
        "total_findings": total,
        "severity_counts": counts,
        "top_risks": [
            {"title": row.title, "severity": row.severity, "risk_score": row.risk_score}
            for row in top
        ],
    }


def _get_owned(db: Session, report_id: uuid.UUID, identity: Identity) -> Report:
    report = (
        db.query(Report)
        .filter(Report.id == report_id, Report.tenant_id == identity.tenant_id)
        .first()
    )
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    return report


@router.post("", response_model=ReportOut, status_code=201)
def create_report(
    body: ReportCreate,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> ReportOut:
    scan = (
        db.query(Scan).filter(Scan.id == body.scan_id, Scan.tenant_id == identity.tenant_id).first()
    )
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    report = Report(
        tenant_id=identity.tenant_id,
        customer_id=scan.customer_id,
        scan_id=scan.id,
        title=body.title or f"Security Assessment — scan {scan.id}",
        status="draft",
        summary=_build_summary(db, scan),
    )
    db.add(report)
    db.flush()
    record_audit(
        db,
        action="report.create",
        tenant_id=identity.tenant_id,
        customer_id=scan.customer_id,
        actor_id=identity.user.id,
        entity_type="report",
        entity_id=str(report.id),
        ip=ip,
    )
    db.commit()
    return ReportOut.model_validate(report, from_attributes=True)


def _transition(
    db: Session,
    report: Report,
    identity: Identity,
    *,
    expected: set[str],
    new_status: str,
    decision: str,
    notes: str,
    ip: str | None,
) -> Report:
    if report.status not in expected:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"cannot {decision} a report in '{report.status}' state (expected {sorted(expected)})",
        )
    report.status = new_status
    db.add(
        ReportApproval(
            report_id=report.id, actor_id=identity.user.id, decision=decision, notes=notes
        )
    )
    record_audit(
        db,
        action=f"report.{decision}",
        tenant_id=identity.tenant_id,
        customer_id=report.customer_id,
        actor_id=identity.user.id,
        entity_type="report",
        entity_id=str(report.id),
        ip=ip,
        metadata={"status": new_status},
    )
    db.commit()
    return report


@router.post("/{report_id}/generate", response_model=ReportOut)
def generate_report(
    report_id: uuid.UUID,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> ReportOut:
    """Build the report's sections + summary from findings and the AI executive summary."""
    report = _get_owned(db, report_id, identity)
    generate_report_content(db, report, get_provider())
    record_audit(
        db,
        action="report.generate",
        tenant_id=identity.tenant_id,
        customer_id=report.customer_id,
        actor_id=identity.user.id,
        entity_type="report",
        entity_id=str(report.id),
        ip=ip,
    )
    db.commit()
    return ReportOut.model_validate(report, from_attributes=True)


@router.get("/{report_id}/export")
def export_report(
    report_id: uuid.UUID,
    format: str = "pdf",  # noqa: A002 - query param name
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> Response:
    """Export a report as PDF (default) or HTML. Portal contacts get published reports only."""
    report = _get_owned(db, report_id, identity)
    if not identity.is_staff and (
        report.customer_id != identity.portal_customer_id or report.status != "published"
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    # Bounded, and the document says so (WP-G2). Rendering every finding of a 50,000-finding scan
    # is a memory event and a PDF nobody opens; rendering the first few thousand *without saying so*
    # is worse, because the reader cannot tell "nothing else was found" from "nothing else fitted".
    ceiling = identity.limits.max_report_findings
    total = db.execute(
        select(func.count()).select_from(Finding).where(Finding.scan_id == report.scan_id)
    ).scalar_one()
    findings = db.execute(
        select(Finding).where(Finding.scan_id == report.scan_id)
        .order_by(Finding.risk_score.desc(), Finding.id)
        .limit(ceiling)
    ).scalars().all()
    note = quota.truncation_note(shown=len(findings), total=int(total))
    if note:
        response_headers = {"X-Findings-Truncated": "true"}
        log.warning("report_findings_truncated", report=str(report.id),
                    shown=len(findings), total=int(total))
    else:
        response_headers = {}

    if format == "html":
        return Response(content=render_html(report, findings, truncation_note=note),
                        media_type="text/html", headers=response_headers)
    if format == "pdf":
        return Response(
            content=render_pdf(report, findings, truncation_note=note),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="report-{report.id}.pdf"',
                     **response_headers},
        )
    raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "format must be pdf or html")


@router.post("/{report_id}/submit", response_model=ReportOut)
def submit_report(
    report_id: uuid.UUID,
    body: ReportAction,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> ReportOut:
    report = _get_owned(db, report_id, identity)
    _transition(
        db,
        report,
        identity,
        expected={"draft", "rejected"},
        new_status="in_review",
        decision="submit",
        notes=body.notes,
        ip=ip,
    )
    return ReportOut.model_validate(report, from_attributes=True)


@router.post("/{report_id}/approve", response_model=ReportOut)
def approve_report(
    report_id: uuid.UUID,
    body: ReportAction,
    request: Request,
    identity: Identity = Depends(require_reviewer),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> ReportOut:
    report = _get_owned(db, report_id, identity)
    _transition(
        db,
        report,
        identity,
        expected={"in_review"},
        new_status="approved",
        decision="approve",
        notes=body.notes,
        ip=ip,
    )
    return ReportOut.model_validate(report, from_attributes=True)


@router.post("/{report_id}/reject", response_model=ReportOut)
def reject_report(
    report_id: uuid.UUID,
    body: ReportAction,
    request: Request,
    identity: Identity = Depends(require_reviewer),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> ReportOut:
    report = _get_owned(db, report_id, identity)
    _transition(
        db,
        report,
        identity,
        expected={"in_review"},
        new_status="rejected",
        decision="reject",
        notes=body.notes,
        ip=ip,
    )
    return ReportOut.model_validate(report, from_attributes=True)


@router.post("/{report_id}/publish", response_model=ReportOut)
def publish_report(
    report_id: uuid.UUID,
    body: ReportAction,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> ReportOut:
    report = _get_owned(db, report_id, identity)
    _transition(
        db,
        report,
        identity,
        expected={"approved"},
        new_status="published",
        decision="publish",
        notes=body.notes,
        ip=ip,
    )
    return ReportOut.model_validate(report, from_attributes=True)


@router.get("", response_model=list[ReportOut])
def list_reports(
    response: Response,
    limit: int | None = None,
    cursor: str | None = None,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> list[ReportOut]:
    size, after = page_request(limit, cursor, maximum=identity.limits.max_page_size)
    q = db.query(Report).filter(Report.tenant_id == identity.tenant_id)
    if not identity.is_staff:
        # Portal contacts only ever see published reports for their own customer.
        q = q.filter(
            Report.customer_id == identity.portal_customer_id, Report.status == "published"
        )
    rows = order_newest_first(apply_cursor(q, Report, after), Report).limit(size + 1).all()
    return [ReportOut.model_validate(r, from_attributes=True)
            for r in paginate(response, rows, size)]


@router.get("/{report_id}", response_model=ReportOut)
def get_report(
    report_id: uuid.UUID,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> ReportOut:
    report = _get_owned(db, report_id, identity)
    if not identity.is_staff and (
        report.customer_id != identity.portal_customer_id or report.status != "published"
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    return ReportOut.model_validate(report, from_attributes=True)
