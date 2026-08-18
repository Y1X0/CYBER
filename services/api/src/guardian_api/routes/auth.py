"""Authentication: sign-up, login (password → JWT) and current-identity introspection."""

from __future__ import annotations

import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from guardian_common.config import get_settings
from guardian_common.logging import get_logger
from guardian_common.security import (
    create_access_token,
    hash_password,
    verify_dummy,
    verify_password,
)
from guardian_db.audit import record_audit
from guardian_db.models import Customer, Tenant, TenantMembership, User
from guardian_db.session import set_tenant
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, client_ip, get_current_identity, get_db
from guardian_api.ratelimit import login_limiter
from guardian_api.schemas import LoginRequest, MeResponse, TokenResponse

log = get_logger("guardian.api.auth")

router = APIRouter()

# A password that survives an offline attempt on a stolen hash. Argon2id does the work; this only
# stops the shortest guesses, and length is the parameter that actually matters.
MIN_PASSWORD_LENGTH = 12


class SignupRequest(BaseModel):
    """What a new customer supplies to exist.

    `organization` becomes the tenant, and `company` (optional) becomes their first customer record
    — the thing assets and scans hang off. Both are collected here because an organization with no
    customer cannot onboard an asset, and making somebody discover that later is a dead end.
    """

    email: EmailStr
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=200)
    name: str = Field(default="", max_length=200)
    organization: str = Field(min_length=2, max_length=200)
    company: str = Field(default="", max_length=200)


class SignupResponse(TokenResponse):
    tenant_id: str
    customer_id: str


def _slug(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return base[:100] or "org"


@router.post("/signup", response_model=SignupResponse, status_code=201)
def signup(
    body: SignupRequest,
    request: Request,
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> SignupResponse:
    """Create an organization and its first owner.

    Until this existed a tenant could only be created by running `guardian_api.seed` or by writing
    to the database by hand, so there was no way for a customer to start — the product had no front
    door. It creates exactly three rows (tenant, user, owner membership) plus the first customer
    record, and grants nothing beyond them: no authorization, no verified domain, no ability to scan
    anything. Everything that lets Guardian touch a system still has to be earned afterwards.

    Rate-limited on the same limiter as login, because an unbounded tenant-creation endpoint is a
    way to fill a database from one laptop.
    """
    settings = get_settings()
    if not settings.self_serve_signup:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "self-service sign-up is disabled on this deployment; an operator provisions tenants",
        )

    limiter = login_limiter()
    ok_ip, retry = limiter.hit(f"signup:{ip or 'unknown'}")
    if not ok_ip:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many sign-up attempts",
                            headers={"Retry-After": str(int(retry) + 1)})

    email = body.email.lower()
    if db.query(User).filter(User.email == email).first() is not None:
        # Deliberately the same shape as any other refusal, and deliberately not "that address is
        # already registered" — sign-up is unauthenticated, and a distinct answer here turns it
        # into an account-enumeration oracle.
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "that address cannot be used to create an organization")

    # The tenant's identity is chosen here, before anything is written, because this request is the
    # one case where the row being inserted *is* the tenant. `get_db` hands out an RLS-enforced
    # session and the policies on `tenants`, `tenant_memberships` and `customers` check the row
    # against `app.current_tenant`; with nothing bound, PostgreSQL refuses the insert outright.
    # Binding first is also the tighter answer: for the length of this transaction sign-up can only
    # write rows belonging to the organization it is creating, and the binding is transaction-local
    # so it is gone by the time the connection returns to the pool.
    tenant_id = uuid.uuid4()
    set_tenant(db, tenant_id)

    # Slug uniqueness is enforced by the database, not by a pre-flight query: under RLS this session
    # cannot see another tenant's row, so a check here would always find the slug free and then fail
    # on the unique index. One retry with a suffix, then give up rather than loop.
    base = _slug(body.organization)
    tenant: Tenant | None = None
    for slug in (base, f"{base}-{uuid.uuid4().hex[:6]}"):
        savepoint = db.begin_nested()
        candidate = Tenant(id=tenant_id, name=body.organization, slug=slug, mode="saas")
        db.add(candidate)
        try:
            db.flush()
        except IntegrityError:
            # The savepoint rollback also evicts the pending instance; nothing to expunge.
            savepoint.rollback()
            continue
        savepoint.commit()
        tenant = candidate
        break
    if tenant is None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "that organization name could not be registered; try another")

    user = User(email=email, name=body.name or email.split("@")[0],
                password_hash=hash_password(body.password), status="active")
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        # The address was taken between the check above and here. Same non-enumerating answer.
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "that address cannot be used to create an organization") from exc
    db.add(TenantMembership(user_id=user.id, tenant_id=tenant.id, role="owner"))
    customer = Customer(tenant_id=tenant.id, name=body.company or body.organization,
                        criticality="high")
    db.add(customer)
    db.flush()

    record_audit(db, action="auth.signup", tenant_id=tenant.id, customer_id=customer.id,
                 actor_id=user.id, entity_type="tenant", entity_id=str(tenant.id), ip=ip,
                 metadata={"organization": body.organization})
    db.commit()
    log.info("tenant_created", tenant=str(tenant.id), slug=slug)

    token = create_access_token(subject=str(user.id), secret=settings.jwt_secret,
                                algorithm=settings.jwt_algorithm,
                                ttl_minutes=settings.access_token_ttl_minutes)
    del request
    return SignupResponse(access_token=token,
                          expires_in=settings.access_token_ttl_minutes * 60,
                          tenant_id=str(tenant.id), customer_id=str(customer.id))


@router.post("/login", response_model=TokenResponse)
def login(
    body: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> TokenResponse:
    # Rate limit BEFORE the Argon2 verify (P1-γ): bounds guessing + CPU-exhaustion from one source.
    # Keyed by IP and by account; the 429 is identical whether or not the account exists (no
    # user-enumeration signal). Counting every attempt is fine — interactive logins stay well under.
    limiter = login_limiter()
    email = body.email.lower()
    ok_ip, retry_ip = limiter.hit(f"ip:{ip or 'unknown'}")
    ok_acct, retry_acct = limiter.hit(f"acct:{email}")
    if not (ok_ip and ok_acct):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "too many login attempts",
            headers={"Retry-After": str(int(max(retry_ip, retry_acct)) + 1)},
        )

    user = db.query(User).filter(User.email == email).first()
    # Constant-ish response regardless of which factor failed (avoid user enumeration).
    # When the user is unknown, still run one Argon2 verification so the response time does
    # not reveal whether the email exists (timing oracle).
    if user is None or not user.password_hash:
        verify_dummy(body.password)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    if user.status != "active":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "account disabled")

    settings = get_settings()
    token = create_access_token(
        subject=str(user.id),
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        ttl_minutes=settings.access_token_ttl_minutes,
    )
    record_audit(
        db, action="auth.login", actor_id=user.id, entity_type="user", entity_id=str(user.id), ip=ip
    )
    db.commit()
    return TokenResponse(access_token=token, expires_in=settings.access_token_ttl_minutes * 60)


@router.get("/me", response_model=MeResponse)
def me(identity: Identity = Depends(get_current_identity)) -> MeResponse:
    return MeResponse(
        id=identity.user.id,
        email=identity.user.email,
        name=identity.user.name,
        tenant_id=identity.tenant_id,
        staff_role=identity.staff_role,
        portal_customer_id=identity.portal_customer_id,
    )
