"""Asset inventory management, scoped to tenant + customer."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from guardian_common.crypto import encrypt_json
from guardian_db.audit import record_audit
from guardian_db.models import Asset, Customer
from guardian_db.session import set_tenant
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, client_ip, get_current_identity, get_db, require_staff_write
from guardian_api.pagination import apply_cursor, order_newest_first, page_request, paginate
from guardian_api.schemas import AssetCreate, AssetOut

router = APIRouter()


def _assert_customer_in_tenant(
    db: Session, customer_id: uuid.UUID, tenant_id: uuid.UUID
) -> Customer:
    customer = db.get(Customer, customer_id)
    if customer is None or customer.tenant_id != tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "customer not found")
    return customer


def _existing_asset(db: Session, tenant_id: uuid.UUID, body: AssetCreate) -> Asset | None:
    """The asset that would collide with `body` on uq_asset_identity (tenant, customer, kind,
    identifier), or None. Tenant scoping is redundant with RLS but explicit."""
    return db.execute(
        select(Asset).where(
            Asset.tenant_id == tenant_id,
            Asset.customer_id == body.customer_id,
            Asset.kind == body.kind,
            Asset.identifier == body.identifier,
        )
    ).scalar_one_or_none()


def _asset_exists_409(existing: Asset | None) -> HTTPException:
    """A clean 409 that names the existing asset, so a caller can scan it instead of dead-ending.
    A target you already have is the same target, not a server error."""
    return HTTPException(
        status.HTTP_409_CONFLICT,
        detail={
            "code": "asset_exists",
            "message": "an asset with this identifier already exists for this customer",
            "asset_id": str(existing.id) if existing is not None else None,
        },
    )


@router.post("", response_model=AssetOut, status_code=201)
def create_asset(
    body: AssetCreate,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> AssetOut:
    _assert_customer_in_tenant(db, body.customer_id, identity.tenant_id)
    # A duplicate identifier used to raise the raw uq_asset_identity IntegrityError as a 500, which
    # dead-ended the New Scan flow whenever the target already existed. Pre-check and return a clean
    # 409 naming the existing asset (the caller scans that one instead); a concurrent create that
    # slips past the pre-check is caught on flush and mapped to the same 409.
    existing = _existing_asset(db, identity.tenant_id, body)
    if existing is not None:
        raise _asset_exists_409(existing)
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
    try:
        db.flush()
    except IntegrityError:
        # Lost a race with a concurrent create. Rollback clears the transaction-local RLS tenant
        # GUC, so re-bind it before looking the winner up, then return the same clean 409.
        db.rollback()
        set_tenant(db, identity.tenant_id)
        raise _asset_exists_409(_existing_asset(db, identity.tenant_id, body)) from None
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
    response: Response,
    customer_id: uuid.UUID | None = None,
    limit: int | None = None,
    cursor: str | None = None,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> list[AssetOut]:
    """One page of assets, newest first.

    This returned the whole inventory (WP-G2). Discovery is designed to find things, so an estate
    of 200,000 assets is a success, not an anomaly — and it was being built into a single JSON
    array in memory on every request.
    """
    size, after = page_request(limit, cursor, maximum=identity.limits.max_page_size)
    q = db.query(Asset).filter(Asset.tenant_id == identity.tenant_id)
    if not identity.is_staff:
        q = q.filter(Asset.customer_id == identity.portal_customer_id)
    elif customer_id is not None:
        q = q.filter(Asset.customer_id == customer_id)
    rows = order_newest_first(apply_cursor(q, Asset, after), Asset).limit(size + 1).all()
    return [AssetOut.model_validate(r, from_attributes=True)
            for r in paginate(response, rows, size)]
