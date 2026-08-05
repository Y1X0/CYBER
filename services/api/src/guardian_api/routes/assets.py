"""Asset inventory management, scoped to tenant + customer."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from guardian_common.crypto import encrypt_json
from guardian_db.audit import record_audit
from guardian_db.models import Asset, Customer
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, client_ip, get_current_identity, get_db, require_staff_write
from guardian_api.schemas import AssetCreate, AssetOut

router = APIRouter()


def _assert_customer_in_tenant(
    db: Session, customer_id: uuid.UUID, tenant_id: uuid.UUID
) -> Customer:
    customer = db.get(Customer, customer_id)
    if customer is None or customer.tenant_id != tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "customer not found")
    return customer


@router.post("", response_model=AssetOut, status_code=201)
def create_asset(
    body: AssetCreate,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> AssetOut:
    _assert_customer_in_tenant(db, body.customer_id, identity.tenant_id)
    asset = Asset(
        tenant_id=identity.tenant_id,
        customer_id=body.customer_id,
        name=body.name,
        kind=body.kind,
        identifier=body.identifier,
        exposure=body.exposure,
        config=body.config,
        # Credentials are encrypted at rest; the plaintext never touches the DB, logs, or audit.
        secret_ref=encrypt_json(body.secret) if body.secret else None,
    )
    db.add(asset)
    db.flush()
    record_audit(
        db,
        action="asset.create",
        tenant_id=identity.tenant_id,
        customer_id=body.customer_id,
        actor_id=identity.user.id,
        entity_type="asset",
        entity_id=str(asset.id),
        ip=ip,
        metadata={"kind": body.kind},
    )
    db.commit()
    return AssetOut.model_validate(asset, from_attributes=True)


@router.get("", response_model=list[AssetOut])
def list_assets(
    customer_id: uuid.UUID | None = None,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> list[AssetOut]:
    q = db.query(Asset).filter(Asset.tenant_id == identity.tenant_id)
    if not identity.is_staff:
        q = q.filter(Asset.customer_id == identity.portal_customer_id)
    elif customer_id is not None:
        q = q.filter(Asset.customer_id == customer_id)
    rows = q.order_by(Asset.created_at.desc()).all()
    return [AssetOut.model_validate(r, from_attributes=True) for r in rows]
