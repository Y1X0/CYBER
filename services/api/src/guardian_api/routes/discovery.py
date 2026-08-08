"""Discovery run lifecycle (Phase 6C.1) — the Control-Plane trigger for EASM/active discovery.

Creates a tenant-scoped discovery run and enqueues it onto the `recon` queue; the execution plane
(worker) runs the pipeline (6B/6C). This route NEVER opens a socket — it only orchestrates. Active
targets in `seeds` are still gated by the authorization table in the worker; this endpoint grants no
authorization by itself.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from guardian_db.audit import record_audit
from guardian_db.models import Customer, DiscoveryRun, DiscoveryScope
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, client_ip, get_current_identity, get_db, require_staff_write
from guardian_api.publisher import enqueue_discovery
from guardian_api.schemas import DiscoveryRunCreate, DiscoveryRunOut

router = APIRouter()


@router.post("/runs", response_model=DiscoveryRunOut, status_code=202)
def create_discovery_run(
    body: DiscoveryRunCreate,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> DiscoveryRunOut:
    customer = db.get(Customer, body.customer_id)
    if customer is None or customer.tenant_id != identity.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "customer not found")

    # A scope carries the enabled providers (empty → default passive dns/ct in the worker).
    scope = DiscoveryScope(
        tenant_id=identity.tenant_id, customer_id=customer.id, name="run scope",
        seeds=body.seeds, providers=body.providers,
    )
    db.add(scope)
    db.flush()
    run = DiscoveryRun(
        tenant_id=identity.tenant_id, customer_id=customer.id, scope_id=scope.id,
        status="queued", trigger=body.trigger, seeds=body.seeds, stats={},
    )
    db.add(run)
    db.flush()
    record_audit(
        db, action="discovery.run.create", tenant_id=identity.tenant_id,
        customer_id=customer.id, actor_id=identity.user.id, entity_type="discovery_run",
        entity_id=str(run.id), ip=ip, metadata={"providers": body.providers},
    )
    db.commit()

    enqueue_discovery(str(run.id))
    return DiscoveryRunOut.model_validate(run, from_attributes=True)


def _scoped(db: Session, identity: Identity):  # noqa: ANN202
    q = db.query(DiscoveryRun).filter(DiscoveryRun.tenant_id == identity.tenant_id)
    if not identity.is_staff:
        q = q.filter(DiscoveryRun.customer_id == identity.portal_customer_id)
    return q


@router.get("/runs", response_model=list[DiscoveryRunOut])
def list_discovery_runs(
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> list[DiscoveryRunOut]:
    rows = _scoped(db, identity).order_by(DiscoveryRun.created_at.desc()).limit(200).all()
    return [DiscoveryRunOut.model_validate(r, from_attributes=True) for r in rows]


@router.get("/runs/{run_id}", response_model=DiscoveryRunOut)
def get_discovery_run(
    run_id: uuid.UUID,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> DiscoveryRunOut:
    run = _scoped(db, identity).filter(DiscoveryRun.id == run_id).first()
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "discovery run not found")
    return DiscoveryRunOut.model_validate(run, from_attributes=True)
