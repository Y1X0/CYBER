"""Scan lifecycle: create (enqueue) → get → list. Tenant-scoped throughout."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from guardian_core.enums import EngineKey, ScanStatus
from guardian_core.policy import evaluate_gate
from guardian_db.audit import record_audit
from guardian_db.models import Asset, Finding, Policy, Scan
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, client_ip, get_current_identity, get_db, require_staff_write
from guardian_api.publisher import enqueue_analysis, enqueue_scan
from guardian_api.schemas import ScanCreate, ScanOut

router = APIRouter()

_VALID_ENGINES = {e.value for e in EngineKey}


@router.post("", response_model=ScanOut, status_code=202)
def create_scan(
    body: ScanCreate,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> ScanOut:
    asset = db.get(Asset, body.asset_id)
    if asset is None or asset.tenant_id != identity.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")

    unknown = set(body.engines) - _VALID_ENGINES
    if unknown:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, f"unknown engines: {sorted(unknown)}"
        )

    scan = Scan(
        tenant_id=identity.tenant_id,
        customer_id=asset.customer_id,
        asset_id=asset.id,
        trigger=body.trigger,
        ref=body.ref,
        status=ScanStatus.QUEUED.value,
        requested_engines=body.engines,
        stats={},
        created_by=identity.user.id,
    )
    db.add(scan)
    db.flush()
    record_audit(
        db,
        action="scan.create",
        tenant_id=identity.tenant_id,
        customer_id=asset.customer_id,
        actor_id=identity.user.id,
        entity_type="scan",
        entity_id=str(scan.id),
        ip=ip,
        metadata={"engines": body.engines},
    )
    db.commit()

    enqueue_scan(str(scan.id))
    return ScanOut.model_validate(scan, from_attributes=True)


def _scoped_query(db: Session, identity: Identity):  # noqa: ANN202
    q = db.query(Scan).filter(Scan.tenant_id == identity.tenant_id)
    if not identity.is_staff:
        q = q.filter(Scan.customer_id == identity.portal_customer_id)
    return q


@router.get("", response_model=list[ScanOut])
def list_scans(
    asset_id: uuid.UUID | None = None,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> list[ScanOut]:
    q = _scoped_query(db, identity)
    if asset_id is not None:
        q = q.filter(Scan.asset_id == asset_id)
    rows = q.order_by(Scan.created_at.desc()).limit(200).all()
    return [ScanOut.model_validate(r, from_attributes=True) for r in rows]


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: uuid.UUID,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> ScanOut:
    scan = _scoped_query(db, identity).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return ScanOut.model_validate(scan, from_attributes=True)


@router.post("/{scan_id}/analyze", status_code=202)
def analyze_scan(
    scan_id: uuid.UUID,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> dict:
    """Enqueue AI analysis (grounded explanation + remediation) for a scan's findings."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.tenant_id == identity.tenant_id).first()
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    record_audit(
        db,
        action="scan.analyze.request",
        tenant_id=identity.tenant_id,
        customer_id=scan.customer_id,
        actor_id=identity.user.id,
        entity_type="scan",
        entity_id=str(scan.id),
        ip=ip,
    )
    db.commit()
    enqueue_analysis(str(scan.id))
    return {"scan_id": str(scan.id), "status": "analysis_queued"}


@router.get("/{scan_id}/gate")
def scan_gate(
    scan_id: uuid.UUID,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> dict:
    """Evaluate the deployment gate for a scan (used by CI/CD to block on high-risk findings)."""
    scan = _scoped_query(db, identity).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")

    # Project-scoped policy, else tenant default, else the built-in DEFAULT_RULES.
    policy = (
        db.query(Policy)
        .filter(Policy.organization_id == identity.tenant_id, Policy.enabled.is_(True))
        .order_by(Policy.created_at.desc())
        .first()
    )
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    result = evaluate_gate(findings, policy.rules if policy else None)
    return {
        "scan_id": str(scan.id),
        "passed": result.passed,
        "blocking_count": len(result.blocking),
        "blocking": result.blocking,
    }
