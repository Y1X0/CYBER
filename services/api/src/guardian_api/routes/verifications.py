"""Domain ownership verification (WP-F1).

The onboarding step that makes active scanning defensible. A customer asks to prove a domain, gets
a token and instructions, publishes it, and asks Guardian to check. Only a successful check creates
the `Authorization` that the active engines require.

The API deliberately does not perform the lookup itself. Checking means reaching a customer-supplied
domain over DNS and HTTPS, which is outbound network work with an SSRF surface, and the API is the
one process in this system that holds every tenant's session. It queues the check for the worker,
which already runs that kind of request behind an egress guard.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from guardian_core.ownership import InvalidDomain, instructions, normalize_domain
from guardian_db.audit import record_audit
from guardian_db.models import Authorization, Customer, DomainVerification
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, client_ip, get_current_identity, get_db, require_staff_write

router = APIRouter()

_METHODS = {"dns_txt", "http_file"}


class VerificationCreate(BaseModel):
    customer_id: uuid.UUID
    domain: str = Field(min_length=3, max_length=253)
    method: str = Field(default="dns_txt", pattern="^(dns_txt|http_file)$")


class VerificationOut(BaseModel):
    id: uuid.UUID
    customer_id: uuid.UUID
    domain: str
    method: str
    status: str
    attempts: int
    last_error: str | None = None
    expires_at: str | None = None
    verified_at: str | None = None
    authorization_id: uuid.UUID | None = None
    # What the customer must publish. Returned on create and on read, because a challenge nobody
    # can re-read is one they have to start over.
    instructions: dict | None = None


def _out(record: DomainVerification, *, with_instructions: bool = True) -> VerificationOut:
    return VerificationOut(
        id=record.id,
        customer_id=record.customer_id,
        domain=record.domain,
        method=record.method,
        status=record.status,
        attempts=record.attempts,
        last_error=record.last_error,
        expires_at=record.expires_at.isoformat() if record.expires_at else None,
        verified_at=record.verified_at.isoformat() if record.verified_at else None,
        authorization_id=record.authorization_id,
        instructions=(
            instructions(record.domain, record.method, record.token)
            if with_instructions and record.status == "pending" else None
        ),
    )


def _customer(db: Session, customer_id: uuid.UUID, tenant_id: uuid.UUID) -> Customer:
    customer = db.get(Customer, customer_id)
    if customer is None or customer.tenant_id != tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "customer not found")
    return customer


@router.post("", response_model=VerificationOut, status_code=201)
def create_verification(
    body: VerificationCreate,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> VerificationOut:
    """Issue an ownership challenge for a domain."""
    _customer(db, body.customer_id, identity.tenant_id)
    try:
        domain = normalize_domain(body.domain)
    except InvalidDomain as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    from guardian_scanner.ownership import create_verification as issue

    record = issue(
        db, tenant_id=identity.tenant_id, customer_id=body.customer_id,
        domain=domain, method=body.method, created_by=identity.user.id,
    )
    record_audit(
        db, action="verification.created", tenant_id=identity.tenant_id,
        customer_id=body.customer_id, actor_id=identity.user.id,
        entity_type="domain_verification", entity_id=str(record.id),
        metadata={"domain": domain, "method": body.method}, ip=ip,
    )
    db.commit()
    del request
    return _out(record)


@router.get("", response_model=list[VerificationOut])
def list_verifications(
    customer_id: uuid.UUID | None = None,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> list[VerificationOut]:
    query = select(DomainVerification).where(
        DomainVerification.tenant_id == identity.tenant_id
    ).order_by(DomainVerification.created_at.desc()).limit(200)
    if customer_id:
        query = query.where(DomainVerification.customer_id == customer_id)
    return [_out(record) for record in db.execute(query).scalars()]


@router.get("/{verification_id}", response_model=VerificationOut)
def get_verification(
    verification_id: uuid.UUID,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> VerificationOut:
    record = db.get(DomainVerification, verification_id)
    if record is None or record.tenant_id != identity.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "verification not found")
    return _out(record)


@router.post("/{verification_id}/check", response_model=VerificationOut)
def request_check(
    verification_id: uuid.UUID,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> VerificationOut:
    """Ask the worker to look for the published proof."""
    record = db.get(DomainVerification, verification_id)
    if record is None or record.tenant_id != identity.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "verification not found")
    if record.status == "verified":
        return _out(record, with_instructions=False)

    from guardian_scanner.celery_app import celery_app

    # Queued before the audit row is committed on purpose: the worker reads the verification, not
    # the audit trail, and a queue failure must surface as an error to the caller rather than as a
    # committed "check requested" for a check nobody will run.
    celery_app.send_task("guardian.check_domain_verification", args=[str(record.id)])
    record_audit(
        db, action="verification.check_requested", tenant_id=identity.tenant_id,
        customer_id=record.customer_id, actor_id=identity.user.id,
        entity_type="domain_verification", entity_id=str(record.id),
        metadata={"domain": record.domain}, ip=ip,
    )
    db.commit()
    del request
    return _out(record)


@router.delete("/{verification_id}", status_code=204)
def revoke_verification(
    verification_id: uuid.UUID,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> None:
    """Withdraw a verification, and the authorization it granted.

    Revoking the proof must revoke the permission. Leaving an authorization standing after its
    evidence has been withdrawn is how a scan keeps running against a domain the customer no longer
    claims.
    """
    record = db.get(DomainVerification, verification_id)
    if record is None or record.tenant_id != identity.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "verification not found")

    import datetime as dt

    now = dt.datetime.now(dt.UTC)
    record.status = "revoked"
    if record.authorization_id:
        authorization = db.get(Authorization, record.authorization_id)
        if authorization is not None and authorization.revoked_at is None:
            authorization.revoked_at = now
    record_audit(
        db, action="verification.revoked", tenant_id=identity.tenant_id,
        customer_id=record.customer_id, actor_id=identity.user.id,
        entity_type="domain_verification", entity_id=str(record.id),
        metadata={"domain": record.domain}, ip=ip,
    )
    db.commit()
    del request
