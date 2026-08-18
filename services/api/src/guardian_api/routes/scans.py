"""Scan lifecycle: create (enqueue) → get → list. Tenant-scoped throughout."""

from __future__ import annotations

import uuid
from functools import lru_cache

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from guardian_common.metrics import REGISTRY
from guardian_core import quota
from guardian_core.enums import ScanStatus
from guardian_core.policy import evaluate_gate
from guardian_db.audit import record_audit
from guardian_db.models import Asset, Finding, Policy, Scan
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, client_ip, get_current_identity, get_db, require_staff_write
from guardian_api.pagination import apply_cursor, order_newest_first, page_request, paginate
from guardian_api.publisher import enqueue_analysis, enqueue_scan
from guardian_api.schemas import ScanCreate, ScanOut

router = APIRouter()


@lru_cache
def _registered_engine_keys() -> frozenset[str]:
    # Entry-point names are the engine keys by convention (see pyproject scanner_plugins group).
    from importlib.metadata import entry_points

    return frozenset(ep.name for ep in entry_points(group="guardian.scanner_plugins"))


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

    # Validate against actually-registered engines (entry-point names == engine keys), not the core
    # enum — a third-party engine registered via entry points is requestable without editing core,
    # and the API stays decoupled from the worker package (reads installed metadata only).
    unknown = set(body.engines) - _registered_engine_keys()
    if unknown:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, f"unknown engines: {sorted(unknown)}"
        )

    # Admission control (WP-G2). The queue is shared, and nothing bounded how much of it one tenant
    # could take: WP-H3 caps concurrent scans per *asset* in the worker, which stops one host being
    # hammered and does nothing about ten thousand scans of ten thousand assets. Counted rather than
    # rate-limited, because what matters is work in flight, not requests per minute.
    active = db.execute(
        select(func.count()).select_from(Scan).where(
            Scan.tenant_id == identity.tenant_id,
            Scan.status.in_((ScanStatus.QUEUED.value, ScanStatus.RUNNING.value)),
        )
    ).scalar_one()
    admission = quota.admit_scan(active=int(active), limit=identity.limits.concurrent_scans)
    if not admission.allowed:
        REGISTRY.inc("guardian_scan_admission_refused_total", {})
        record_audit(
            db, action="scan.refused_quota", tenant_id=identity.tenant_id,
            customer_id=asset.customer_id, actor_id=identity.user.id, entity_type="asset",
            entity_id=str(asset.id), ip=ip,
            # The reason, not just the refusal: "try again later" with no cause is a support ticket.
            metadata={"reason": admission.reason, "active": int(active),
                      "limit": identity.limits.concurrent_scans},
        )
        db.commit()
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, admission.reason,
            headers={"Retry-After": str(admission.retry_after)},
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
    response: Response,
    asset_id: uuid.UUID | None = None,
    limit: int | None = None,
    cursor: str | None = None,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> list[ScanOut]:
    """One page of scans, newest first.

    The old hard `LIMIT 200` was not a page: there was no way to reach scan 201, and no way to tell
    that it existed (WP-G2).
    """
    size, after = page_request(limit, cursor, maximum=identity.limits.max_page_size)
    q = _scoped_query(db, identity)
    if asset_id is not None:
        q = q.filter(Scan.asset_id == asset_id)
    rows = order_newest_first(apply_cursor(q, Scan, after), Scan).limit(size + 1).all()
    return [ScanOut.model_validate(r, from_attributes=True)
            for r in paginate(response, rows, size)]


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
