"""Request dependencies: DB session, authenticated identity, and RBAC context.

Tenant scoping is defense-in-depth: every authenticated request resolves a `tenant_id`, route
handlers filter queries by it (application level), and — underneath — the request runs on an
RLS-enforced app session bound to that tenant via `set_tenant`, so Postgres itself rejects any
cross-tenant read or write even if a handler forgets to filter.
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
from guardian_db.session import get_app_session, get_session, reset_tenant, set_tenant
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
    # RLS-enforced app session; the tenant GUC is set by get_current_identity and cleared here.
    session = get_app_session()
    try:
        yield session
    finally:
        try:
            reset_tenant(session)
        except Exception:  # noqa: BLE001, S110 - connection may already be broken; closing is enough
            pass
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

    # Identity bootstrap runs on a privileged (admin) session: these lookups precede knowing the
    # tenant, so they must not be filtered by RLS. Data queries afterward use the RLS-bound `db`.
    boot = get_session()
    try:
        user = boot.get(User, user_id)
        if user is None or user.status != "active":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found or inactive")
        boot.expunge(user)

        memberships = boot.query(TenantMembership).filter(TenantMembership.user_id == user_id).all()
        identity: Identity | None = None
        if memberships:
            chosen = memberships[0]
            if x_tenant_id:
                match = next((m for m in memberships if str(m.tenant_id) == x_tenant_id), None)
                if match is None:
                    raise HTTPException(status.HTTP_403_FORBIDDEN, "not a member of that tenant")
                chosen = match
            identity = Identity(user=user, tenant_id=chosen.tenant_id, staff_role=chosen.role,
                                portal_customer_id=None)
        else:
            contact = (
                boot.query(CustomerContact).filter(CustomerContact.user_id == user_id).first()
            )
            if contact is not None:
                from guardian_db.models import Customer

                customer = boot.get(Customer, contact.customer_id)
                if customer is None:
                    raise HTTPException(status.HTTP_403_FORBIDDEN, "customer not found")
                identity = Identity(user=user, tenant_id=customer.tenant_id, staff_role=None,
                                    portal_customer_id=contact.customer_id)
    finally:
        boot.close()

    if identity is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "no tenant membership or portal access")

    # Bind the request session to this tenant so RLS filters every subsequent query.
    set_tenant(db, identity.tenant_id)
    return identity


def require_staff_write(identity: Identity = Depends(get_current_identity)) -> Identity:
    if not identity.can_write():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role for this action")
    return identity


# Roles allowed to approve/reject a report (independent QA gate, doc 07 §6).
_REVIEW_ROLES = {StaffRole.REVIEWER.value, StaffRole.ADMIN.value, StaffRole.OWNER.value}


def require_reviewer(identity: Identity = Depends(get_current_identity)) -> Identity:
    if identity.staff_role not in _REVIEW_ROLES:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "report approval requires a reviewer/admin/owner role"
        )
    return identity


def client_ip(x_forwarded_for: str | None = Header(default=None)) -> str | None:
    return x_forwarded_for.split(",")[0].strip() if x_forwarded_for else None
