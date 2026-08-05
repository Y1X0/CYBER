"""Findings API: read (tenant-scoped) and human-pentester triage."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from guardian_db.audit import record_audit
from guardian_db.models import Finding, FindingEvent
from sqlalchemy.orm import Session

from guardian_api.deps import (
    Identity,
    client_ip,
    get_current_identity,
    get_db,
    require_staff_write,
)
from guardian_api.schemas import FindingOut, FindingTriage

router = APIRouter()

# Sort key so critical/high surface first in list views.
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@router.get("", response_model=list[FindingOut])
def list_findings(
    scan_id: uuid.UUID | None = Query(default=None),
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low|info)$"),
    status_filter: str | None = Query(default=None, alias="status"),
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> list[FindingOut]:
    q = db.query(Finding).filter(Finding.tenant_id == identity.tenant_id)
    if not identity.is_staff:
        q = q.filter(Finding.customer_id == identity.portal_customer_id)
    if scan_id is not None:
        q = q.filter(Finding.scan_id == scan_id)
    if severity is not None:
        q = q.filter(Finding.severity == severity)
    if status_filter is not None:
        q = q.filter(Finding.status == status_filter)
    rows = q.limit(1000).all()
    rows.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), -f.risk_score))
    return [FindingOut.model_validate(r, from_attributes=True) for r in rows]


@router.patch("/{finding_id}", response_model=FindingOut)
def triage_finding(
    finding_id: uuid.UUID,
    body: FindingTriage,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> FindingOut:
    """Pentester triage: change status and/or override severity, with an audited justification.

    A severity override or a move to false_positive/accepted_risk records who did it and why —
    every transition is captured in `finding_events` and the audit log (doc 07 §6, §7).
    """
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id, Finding.tenant_id == identity.tenant_id)
        .first()
    )
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")

    # A severity override or risk-acceptance must be justified.
    justified = bool(body.note.strip())
    if (
        body.severity_override or body.status in {"false_positive", "accepted_risk"}
    ) and not justified:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "a justification note is required for severity overrides and risk decisions",
        )

    if body.status and body.status != finding.status:
        db.add(
            FindingEvent(
                finding_id=finding.id,
                actor_id=identity.user.id,
                from_status=finding.status,
                to_status=body.status,
                note=body.note,
            )
        )
        finding.status = body.status

    if body.severity_override and body.severity_override != finding.severity:
        record_audit(
            db,
            action="finding.severity_override",
            tenant_id=identity.tenant_id,
            customer_id=finding.customer_id,
            actor_id=identity.user.id,
            entity_type="finding",
            entity_id=str(finding.id),
            ip=ip,
            metadata={"from": finding.severity, "to": body.severity_override, "note": body.note},
        )
        finding.severity = body.severity_override
        finding.source = "manual"  # a human has adjudicated this finding

    finding.reviewed_by = identity.user.id
    record_audit(
        db,
        action="finding.triage",
        tenant_id=identity.tenant_id,
        customer_id=finding.customer_id,
        actor_id=identity.user.id,
        entity_type="finding",
        entity_id=str(finding.id),
        ip=ip,
        metadata={"status": finding.status},
    )
    db.commit()
    return FindingOut.model_validate(finding, from_attributes=True)
