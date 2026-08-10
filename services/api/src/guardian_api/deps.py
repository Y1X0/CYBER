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
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from guardian_common.config import get_settings
from guardian_common.security import decode_access_token
from guardian_core.enums import StaffRole
from guardian_db.models import User
from guardian_db.session import get_app_session, reset_tenant, set_tenant
from sqlalchemy import text
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

    # Bootstrap runs on the same RLS app session — no second (owner) connection. `users` is a global
    # table (no RLS), and membership/portal lookups use SECURITY DEFINER functions scoped to this
    # JWT-verified user id, so RLS is honored without needing a tenant bound yet.
    user = db.get(User, user_id)
    if user is None or user.status != "active":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found or inactive")

    identity: Identity | None = None
    memberships = db.execute(
        text("SELECT tenant_id, role FROM auth_memberships(:u)"), {"u": str(user_id)}
    ).all()
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
        portal = db.execute(
            text("SELECT customer_id, tenant_id, role FROM auth_portal(:u)"), {"u": str(user_id)}
        ).first()
        if portal is not None:
            identity = Identity(user=user, tenant_id=portal.tenant_id, staff_role=None,
                                portal_customer_id=portal.customer_id)

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


def client_ip(request: Request) -> str | None:
    """Client IP for audit + rate limiting, from a TRUSTED source (P1-①).

    X-Forwarded-For is client-spoofable. By default (GUARDIAN_TRUSTED_PROXY_COUNT=0) we use the
    socket peer and IGNORE the header — an attacker cannot change their bucket by setting XFF. When
    the app sits behind N trusted proxies that append XFF, set the count to N: the real client is
    the entry just before those N trusted hops. An attacker can only PREPEND entries (to the left of
    that position), so the selected IP cannot be forged. A header shorter than expected falls back
    to the peer (fail-safe, never to an attacker-controlled value)."""
    peer = request.client.host if request.client else None
    n = get_settings().trusted_proxy_count
    if n <= 0:
        return peer
    xff = request.headers.get("x-forwarded-for")
    if not xff:
        return peer
    parts = [p.strip() for p in xff.split(",") if p.strip()]
    return parts[-(n + 1)] if len(parts) >= n + 1 else peer
