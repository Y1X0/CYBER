"""Request dependencies: DB session, authenticated identity, and RBAC context.

Tenant scoping is defense-in-depth: every authenticated request resolves a `tenant_id`, route
handlers filter queries by it (application level), and — underneath — the request runs on an
RLS-enforced app session bound to that tenant via `set_tenant`, so Postgres itself rejects any
cross-tenant read or write even if a handler forgets to filter.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterator
from dataclasses import dataclass

import jwt
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from guardian_common.config import get_settings
from guardian_common.security import decode_access_token
from guardian_core import apikeys
from guardian_core.enums import StaffRole
from guardian_db.models import ApiKey, User
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
    # Set when the caller authenticated with an API key rather than as a person (WP-G1). A key's
    # scopes are the ceiling on what it may do, whatever role it borrows.
    api_key: ApiKey | None = None
    scopes: tuple[str, ...] = ()

    @property
    def is_machine(self) -> bool:
        return self.api_key is not None

    @property
    def is_staff(self) -> bool:
        return self.staff_role is not None

    def can_write(self) -> bool:
        return self.staff_role in _WRITE_ROLES


def _api_key_identity(token: str, db: Session) -> Identity | None:
    """Authenticate an API key, or None when the value is not one.

    Returning None rather than raising for a non-key lets the JWT path try it; every *failure of a
    real key* raises, so a revoked or expired key is never quietly treated as an anonymous caller.
    """
    settings = get_settings()
    try:
        key_id = apikeys.parse(token)
    except apikeys.InvalidKey:
        return None

    # Looked up by id, then one constant-time digest comparison. No table scan, and no timing
    # signal from comparing the secret.
    record = db.execute(
        text("SELECT id, tenant_id, name, key_hash, scopes, expires_at, revoked_at "
             "FROM api_keys WHERE id = :id"),
        {"id": _key_uuid(key_id)},
    ).first()
    if record is None or not apikeys.verify(token, record.key_hash,
                                            pepper=settings.apikey_pepper):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid API key")
    if record.revoked_at is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "this API key has been revoked")
    now = dt.datetime.now(dt.UTC)
    if record.expires_at is not None and record.expires_at <= now:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "this API key has expired")

    key = db.get(ApiKey, record.id)
    if key is not None:
        key.last_used_at = now
        db.commit()

    identity = Identity(
        user=_MachineUser(str(record.name), record.id), tenant_id=record.tenant_id,
        # A key is not a person and holds no staff role: what it may do comes from its scopes and
        # nothing else. Borrowing a role would give it whatever that role gains later.
        staff_role=None, portal_customer_id=None, api_key=key,
        scopes=tuple(record.scopes or ()),
    )
    set_tenant(db, identity.tenant_id)
    return identity


def _key_uuid(key_id: str) -> uuid.UUID:
    """The key id (16 hex chars) as the row's UUID: it is the first half, zero-padded."""
    return uuid.UUID(key_id.ljust(32, "0"))


class _MachineUser:
    """Stands in for `Identity.user` when the caller is a key.

    Audit records want an actor; a key is not a user row, so this carries the key's name and id
    without pretending a person did it — `actor_id` stays the key's id and shows up as such.
    """

    def __init__(self, name: str, key_id: uuid.UUID) -> None:
        self.id = key_id
        self.name = f"api-key:{name}"
        self.email = ""
        self.status = "active"


def get_current_identity(
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
    x_tenant_id: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Identity:
    settings = get_settings()

    # An API key is presented in the same Authorization header. Its distinctive prefix means the
    # two schemes never have to guess about each other.
    machine = _api_key_identity(creds.credentials, db)
    if machine is not None:
        return machine

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
    if identity.is_machine:
        # A key never inherits a staff role. Endpoints a key may use declare a scope with
        # `require_scope`; anything that only checks for a human role refuses it, which is the safe
        # default for every endpoint written before keys existed.
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "this endpoint requires a human staff role; API keys are limited to scoped endpoints",
        )
    if not identity.can_write():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role for this action")
    return identity


def require_scope(scope: str):  # noqa: ANN201 - FastAPI dependency factory
    """Require a scope for API-key callers; humans are governed by their role as before.

    Written this way round deliberately: adding key support to an endpoint is an explicit act, and
    an endpoint nobody has thought about stays closed to machines.
    """

    def dependency(identity: Identity = Depends(get_current_identity)) -> Identity:
        if identity.is_machine and not apikeys.allows(identity.scopes, scope):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"this API key does not carry the {scope!r} scope",
            )
        return identity

    return dependency


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
