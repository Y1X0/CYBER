"""Customer security dashboard summary — score, severity mix, recent scans."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from guardian_ai.security_score import security_score
from guardian_db.models import Finding, Scan
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, get_current_identity, get_db
from guardian_api.schemas import DashboardResponse, ScanOut

router = APIRouter()


@router.get("", response_model=DashboardResponse)
def dashboard(
    customer_id: uuid.UUID | None = None,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> DashboardResponse:
    fq = db.query(Finding).filter(Finding.tenant_id == identity.tenant_id)
    sq = db.query(Scan).filter(Scan.tenant_id == identity.tenant_id)
    if not identity.is_staff:
        fq = fq.filter(Finding.customer_id == identity.portal_customer_id)
        sq = sq.filter(Scan.customer_id == identity.portal_customer_id)
    elif customer_id is not None:
        fq = fq.filter(Finding.customer_id == customer_id)
        sq = sq.filter(Scan.customer_id == customer_id)

    findings = fq.limit(5000).all()
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    recent = sq.order_by(Scan.created_at.desc()).limit(10).all()

    return DashboardResponse(
        security_score=security_score(findings),
        severity_counts=counts,
        total_findings=len(findings),
        recent_scans=[ScanOut.model_validate(s, from_attributes=True) for s in recent],
    )
