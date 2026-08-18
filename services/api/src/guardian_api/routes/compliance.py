"""Control coverage across frameworks (WP-F4).

Answers "where do we stand against SOC 2 / ISO 27001 / PCI DSS", from findings and — critically —
from **which engines actually ran**. A control nothing looked at is reported as `not_assessed`, and
that distinction is the entire value of the endpoint: a pass rate that quietly counts unexamined
controls as passing is the number that misleads an auditor.

Read-only, tenant-scoped, and staff-only by default; a portal contact sees their own customer.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from guardian_core import compliance
from guardian_db.models import Finding, Scan, ScanEngineRun
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, get_current_identity, get_db

router = APIRouter()

# Findings a human has dismissed do not count against a control; findings a human has confirmed do.
_COUNTED_STATUSES = ("open", "triaged", "confirmed", "accepted_risk")


class ControlOut(BaseModel):
    id: str
    title: str
    description: str
    status: str
    rationale: str
    findings: list[dict] = []


class FrameworkOut(BaseModel):
    framework: str
    counts: dict[str, int]
    coverage: int
    engines_assessed: list[str] = []
    controls: list[ControlOut] = []


class ComplianceOut(BaseModel):
    frameworks: list[FrameworkOut] = []
    overall_coverage: int = 0
    disclaimer: str = ""


@router.get("", response_model=ComplianceOut)
def get_compliance(
    customer_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    framework: str | None = Query(default=None, max_length=20),
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> ComplianceOut:
    if framework and framework not in compliance.FRAMEWORKS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"unknown framework: {framework}; known: {', '.join(compliance.FRAMEWORKS)}",
        )

    findings_query = select(Finding).where(
        Finding.tenant_id == identity.tenant_id,
        Finding.status.in_(_COUNTED_STATUSES),
    )
    scans_query = select(Scan.id).where(Scan.tenant_id == identity.tenant_id)

    if not identity.is_staff:
        findings_query = findings_query.where(Finding.customer_id == identity.portal_customer_id)
        scans_query = scans_query.where(Scan.customer_id == identity.portal_customer_id)
    if customer_id:
        findings_query = findings_query.where(Finding.customer_id == customer_id)
        scans_query = scans_query.where(Scan.customer_id == customer_id)
    if scan_id:
        findings_query = findings_query.where(Finding.scan_id == scan_id)
        scans_query = scans_query.where(Scan.id == scan_id)

    findings = [
        compliance.FindingRef(
            id=str(row.id), severity=row.severity, title=row.title, category=row.category or "",
            cwe_id=row.cwe_id, rule=str((row.location or {}).get("rule") or ""), status=row.status,
        )
        for row in db.execute(findings_query.limit(5000)).scalars()
    ]

    # Only engines that *completed* count as having assessed anything. A degraded or failed run
    # produces fewer findings and would otherwise be indistinguishable from a clean one.
    scan_ids = list(db.execute(scans_query.limit(2000)).scalars())
    engines: set[str] = set()
    if scan_ids:
        engines = {
            run.engine for run in db.execute(
                select(ScanEngineRun).where(ScanEngineRun.scan_id.in_(scan_ids))
            ).scalars() if run.status == "completed"
        }

    frameworks = [framework] if framework else list(compliance.FRAMEWORKS)
    assessments = [compliance.assess(name, findings, engines_completed=engines)
                   for name in frameworks]
    return ComplianceOut.model_validate(compliance.summarize(assessments))
