"""Read findings for a scan (tenant-scoped), ordered by severity."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from guardian_db.models import Finding
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, get_current_identity, get_db
from guardian_api.schemas import FindingOut

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
    rows.sort(key=lambda f: _SEV_ORDER.get(f.severity, 9))
    return [FindingOut.model_validate(r, from_attributes=True) for r in rows]
