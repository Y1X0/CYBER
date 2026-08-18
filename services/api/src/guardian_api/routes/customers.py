"""Customer management (staff). Portal contacts see only their own customer."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from guardian_db.audit import record_audit
from guardian_db.models import Customer
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, client_ip, get_current_identity, get_db, require_staff_write
from guardian_api.pagination import apply_cursor, order_newest_first, page_request, paginate
from guardian_api.schemas import CustomerCreate, CustomerOut

router = APIRouter()


@router.post("", response_model=CustomerOut, status_code=201)
def create_customer(
    body: CustomerCreate,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> CustomerOut:
    customer = Customer(tenant_id=identity.tenant_id, name=body.name, criticality=body.criticality)
    db.add(customer)
    db.flush()
    record_audit(
        db,
        action="customer.create",
        tenant_id=identity.tenant_id,
        customer_id=customer.id,
        actor_id=identity.user.id,
        entity_type="customer",
        entity_id=str(customer.id),
        ip=ip,
        metadata={"name": body.name},
    )
    db.commit()
    return CustomerOut.model_validate(customer, from_attributes=True)


@router.get("", response_model=list[CustomerOut])
def list_customers(
    response: Response,
    limit: int | None = None,
    cursor: str | None = None,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> list[CustomerOut]:
    size, after = page_request(limit, cursor, maximum=identity.limits.max_page_size)
    q = db.query(Customer).filter(Customer.tenant_id == identity.tenant_id)
    if not identity.is_staff:  # portal contact: restrict to own customer
        q = q.filter(Customer.id == identity.portal_customer_id)
    rows = order_newest_first(apply_cursor(q, Customer, after), Customer).limit(size + 1).all()
    return [CustomerOut.model_validate(r, from_attributes=True)
            for r in paginate(response, rows, size)]
