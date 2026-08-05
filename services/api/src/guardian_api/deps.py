"""Request dependencies: DB session, authenticated identity, and RBAC context.

Tenant scoping is enforced here: every authenticated request resolves a `tenant_id`, and route
handlers filter all queries by it (application-level isolation; RLS is a Phase-5 hardening).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import dataclass

import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from guardian_common.config import get_settings
from guardian_common.security import decode_access_token
from guardian_core.enums import StaffRole
from guardian_db.models import CustomerContact, TenantMembership, User
from guardian_db.session import get_session
from sqlalchemy.orm import Session

_bearer = HTTPBearer(auto_error=True)

# Staff roles permitted to perform write operations in Phase 1.
_WRITE_ROLES = {
    StaffRole.OWNER.value,
    StaffRole.ADMIN.value,
    StaffRole.PENTESTER.value,
    StaffRole.ANALYST.value,
}


def get_db() -> Iterator[Session]:
    session = get_session()
    try:
        yield session
    finally:
        session.close()


@dataclass
class Identity:
    user: User
    tenant_id: uuid.UUID
    staff_role: str | None  # set when the principal is internal staff
    portal_customer_id: uuid.UUID | None  # set when the principal is an external contact

    @property
    def is_staff(self) -> bool:
        return self.staff_role is not None

    def can_write(self) -> bool:
        return self.staff_role in _WRITE_ROLES


def get_current_identity(
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
    x_tenant_id: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Identity:
    settings = get_settings()
    try:
        payload = decode_access_token(
            creds.credentials, secret=settings.jwt_secret, algorithms=[settings.jwt_algorithm]
        )
        user_id = uuid.UUID(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token") from None

    user = db.get(User, user_id)
    if user is None or user.status != "active":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found or inactive")

    # Resolve staff membership (optionally disambiguated by X-Tenant-Id when multi-tenant staff).
    memberships = db.query(TenantMembership).filter(TenantMembership.user_id == user_id).all()
    if memberships:
        chosen = memberships[0]
        if x_tenant_id:
            match = next((m for m in memberships if str(m.tenant_id) == x_tenant_id), None)
            if match is None:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "not a member of that tenant")
            chosen = match
        return Identity(
            user=user, tenant_id=chosen.tenant_id, staff_role=chosen.role, portal_customer_id=None
        )

    # Otherwise resolve external portal contact.
    contact = db.query(CustomerContact).filter(CustomerContact.user_id == user_id).first()
    if contact is not None:
        from guardian_db.models import Customer

        customer = db.get(Customer, contact.customer_id)
        if customer is None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "customer not found")
        return Identity(
            user=user,
            tenant_id=customer.tenant_id,
            staff_role=None,
            portal_customer_id=contact.customer_id,
        )

    raise HTTPException(status.HTTP_403_FORBIDDEN, "no tenant membership or portal access")


def require_staff_write(identity: Identity = Depends(get_current_identity)) -> Identity:
    if not identity.can_write():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role for this action")
    return identity


def client_ip(x_forwarded_for: str | None = Header(default=None)) -> str | None:
    return x_forwarded_for.split(",")[0].strip() if x_forwarded_for else None
