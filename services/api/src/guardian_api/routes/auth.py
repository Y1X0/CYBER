"""Authentication: sign-up, login (password → JWT) and current-identity introspection."""

from __future__ import annotations

import datetime as dt
import hashlib
import re
import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from guardian_common.config import get_settings
from guardian_common.logging import get_logger
from guardian_common.metrics import REGISTRY
from guardian_common.security import (
    create_access_token,
    hash_password,
    verify_dummy,
    verify_password,
)
from guardian_db.audit import record_audit
from guardian_db.models import (
    Customer,
    PasswordResetToken,
    Tenant,
    TenantMembership,
    User,
)
from guardian_db.session import set_tenant
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from guardian_api.deps import (
    Identity,
    get_current_identity,
    get_db,
    require_owner,
    resolve_client_ip,
)
from guardian_api.ratelimit import (
    argon2_verification_slot,
    client_bucket_key,
    login_limiter,
    per_client_limiting_enabled,
    record_failed_login,
    record_untrusted_signup,
)
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

    # Sign-up is rate-limited PER CLIENT, on the same trusted-IP basis as login: key on the resolved
    # client IP only when it is trustworthy (a configured hop count that resolved to a valid client,
    # or a local/dev direct connection). Behind a shared proxy with the count unset, or on a short/
    # malformed X-Forwarded-For, the IP is untrusted — keying a shared value there would let one
    # source block EVERYONE's sign-up, so those are counted and alerted on instead of blocked.
    limiter = login_limiter()
    ip, ip_trusted = resolve_client_ip(request)
    signup_key: str | None = None
    if per_client_limiting_enabled(settings) and ip_trusted:
        bucket = client_bucket_key(ip)
        if bucket is not None:
            signup_key = f"signup:{bucket}"
    if signup_key is not None:
        ok_ip, retry = limiter.hit(signup_key, fail_closed=True)
        if not ok_ip:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many sign-up attempts",
                                headers={"Retry-After": str(int(retry) + 1)})
    else:
        record_untrusted_signup()  # alert-only; never blocks

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
                                ttl_minutes=settings.access_token_ttl_minutes,
                                claims={"tv": user.token_version or 0})
    del request
    return SignupResponse(access_token=token,
                          expires_in=settings.access_token_ttl_minutes * 60,
                          tenant_id=str(tenant.id), customer_id=str(customer.id))


@router.post("/login", response_model=TokenResponse)
def login(
    body: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    # Abuse controls, in priority order (P1-γ). No BLOCK is ever keyed on a value that many users
    # share, so no request pattern from one client can deny login to another who has the correct
    # password:
    #   * a per-CLIENT bucket counts FAILED logins from one resolved client IP and refuses a client
    #     over the limit BEFORE spending an Argon2 slot — bounding password spraying (one password
    #     across many emails). It is keyed on the client IP ONLY when that IP is TRUSTWORTHY (a
    #     configured proxy hop count that resolved to a valid client, or a local/dev direct
    #     connection); a short/malformed X-Forwarded-For, or a shared proxy with the count unset, is
    #     never keyed on — so it can never lock everyone out on one shared IP.
    #   * the per-ACCOUNT bucket bounds brute force against one account (and only that account);
    #   * an Argon2 concurrency limiter bounds CPU exhaustion by shedding excess load with a 503;
    #   * a failed-login breaker only ALERTS (metric + log), it never blocks.
    # Auth keys fail CLOSED under a saturated limiter table (Issue 4). `ip` is also kept for audit.
    settings = get_settings()
    limiter = login_limiter()
    email = body.email.lower()
    per_client_ceiling = settings.login_failed_per_client_per_minute
    ip, ip_trusted = resolve_client_ip(request)
    client_key: str | None = None
    if per_client_limiting_enabled(settings):
        bucket = client_bucket_key(ip) if ip_trusted else None
        if bucket is None:
            # No trustworthy client IP (untrusted XFF position, or missing/unparseable): skip the
            # per-client bucket for this request rather than key on a shared placeholder that would
            # lock such requests out of each other. The account bucket still applies. Surfaced as a
            # metric so a misconfigured hop count is visible.
            REGISTRY.inc("guardian_login_client_ip_unresolved_total")
        else:
            client_key = f"client:{bucket}"

    # Refuse an already-blocked client up front (peek — recorded only on failure below).
    if client_key is not None:
        ok_client, retry_client = limiter.check(
            client_key, max_hits=per_client_ceiling, fail_closed=True)
        if not ok_client:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "too many failed login attempts from this client",
                headers={"Retry-After": str(int(retry_client) + 1)},
            )

    ok_acct, retry_acct = limiter.hit(f"acct:{email}", fail_closed=True)
    if not ok_acct:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "too many login attempts",
            headers={"Retry-After": str(int(retry_acct) + 1)},
        )

    user = db.query(User).filter(User.email == email).first()
    # Constant-ish response regardless of which factor failed (avoid user enumeration). When the
    # user is unknown, still run one Argon2 verification so the response time does not reveal
    # whether the email exists (timing oracle). Both verifications run under the concurrency slot.
    with argon2_verification_slot() as slot:
        if not slot:
            # The process is saturated with in-flight verifications: shed THIS request with a
            # retryable 503 rather than block anyone out or queue unboundedly.
            REGISTRY.inc("guardian_login_argon2_shed_total")
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "authentication is busy, please retry",
                headers={"Retry-After": "1"},
            )
        if user is None or not user.password_hash:
            verify_dummy(body.password)
            password_ok = False
        else:
            password_ok = verify_password(body.password, user.password_hash)

    if not password_ok:
        # Record the failure against the client bucket (spraying control) and the alert breaker.
        if client_key is not None:
            limiter.hit(client_key, max_hits=per_client_ceiling, fail_closed=True)
        record_failed_login()  # alert-only; never blocks
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    if user.status != "active":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "account disabled")

    token = create_access_token(
        subject=str(user.id),
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        ttl_minutes=settings.access_token_ttl_minutes,
        claims={"tv": user.token_version},
    )
    record_audit(
        db, action="auth.login", actor_id=user.id, entity_type="user", entity_id=str(user.id), ip=ip
    )
    db.commit()
    return TokenResponse(access_token=token, expires_in=settings.access_token_ttl_minutes * 60)


class ProxyDiagnostic(BaseModel):
    """What an owner needs to confirm GUARDIAN_TRUSTED_PROXY_COUNT — and nothing that identifies a
    client. Each trusted proxy APPENDS the peer it received from, so with N trusted hops the real
    client is `X-Forwarded-For[-N]`. `xff_entry_count` is how many entries arrived. `socket_peer` is
    the direct TCP peer (your load balancer), included so the topology is unambiguous. `guidance`
    states the rule: send a request that carries NO client-supplied X-Forwarded-For (e.g. from a
    trusted network path) and set the count to the resulting `xff_entry_count`."""

    xff_entry_count: int
    socket_peer: str | None
    trusted_proxy_count_configured: int
    resolved_client_ip_source: str
    guidance: str


@router.get("/proxy-diagnostic", response_model=ProxyDiagnostic)
def proxy_diagnostic(
    request: Request,
    identity: Identity = Depends(require_owner),
) -> ProxyDiagnostic:
    """OWNER-only. Report ONLY the X-Forwarded-For hop COUNT and the socket peer so the
    trusted-proxy count can be confirmed against the live edge. The XFF entry VALUES (client IPs)
    are never returned or logged — only their count."""
    settings = get_settings()
    xff = request.headers.get("x-forwarded-for", "")
    count = len([p for p in xff.split(",") if p.strip()])
    n = settings.trusted_proxy_count
    source = "socket_peer (XFF ignored)" if n <= 0 else f"XFF[-{n}] (trusted_proxy_count={n})"
    return ProxyDiagnostic(
        xff_entry_count=count,
        socket_peer=request.client.host if request.client else None,
        trusted_proxy_count_configured=n,
        resolved_client_ip_source=source,
        guidance=(
            "Each trusted proxy appends one X-Forwarded-For entry, so the client is XFF[-N]. Make "
            "this request WITHOUT a client-supplied X-Forwarded-For header (so every entry present "
            f"was added by your infrastructure): the correct GUARDIAN_TRUSTED_PROXY_COUNT then "
            f"equals xff_entry_count, i.e. {count}."
        ),
    )


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


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> Response:
    """Revoke every access token this user currently holds.

    Access tokens are stateless bearer tokens, so "log out" cannot mean deleting a server session —
    there is none. Instead it bumps the user's token_version, which is embedded in every token as
    `tv`; on the next request each outstanding token fails the `tv` check in get_current_identity
    and is rejected as revoked. This closes the window where a token stolen before logout stays
    valid until its natural expiry.
    """
    user = db.get(User, identity.user.id)
    user.token_version += 1
    record_audit(db, action="auth.logout", actor_id=user.id, tenant_id=identity.tenant_id,
                 entity_type="user", entity_id=str(user.id))
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── Password reset (Item 6) ──────────────────────────────────────────────────────────────────────
class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    # A urlsafe token of 32 bytes is 43 chars; bound generously and cheaply reject nonsense.
    token: str = Field(min_length=20, max_length=512)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=200)


def _hash_reset_token(raw: str) -> str:
    """SHA-256 hex of a reset token. Only this is stored — never the raw token."""
    return hashlib.sha256(raw.encode()).hexdigest()


def _reset_rate_limited(keys: list[str], settings) -> float | None:  # noqa: ANN001
    """Fail-closed per-key rate limit for the reset endpoints. Returns Retry-After secs if over."""
    limiter = login_limiter()
    ceiling = settings.password_reset_per_minute
    for key in keys:
        ok, retry = limiter.hit(key, max_hits=ceiling, fail_closed=True)
        if not ok:
            return retry
    return None


def _deliver_reset_token(user: User, raw_token: str, settings) -> None:  # noqa: ANN001
    """Deliver a reset token to the user.

    There is no email provider wired into this repo yet, so this is the single delivery seam a
    deployment overrides to send the reset link by email. It NEVER logs the raw token outside
    local/dev (a token in a production log is a credential in a log). In local/dev it logs the token
    so the flow is usable without email infrastructure.
    """
    if settings.is_local_or_dev:
        log.info("password_reset_token_dev_only", user_id=str(user.id), reset_token=raw_token)
    else:
        # Production: record that a reset was requested, WITHOUT the token. A real deployment wires
        # an email sender here. Until then the token is delivered by no channel in production.
        log.info("password_reset_requested", user_id=str(user.id))


@router.post("/password-reset/request", status_code=status.HTTP_202_ACCEPTED)
def request_password_reset(
    body: PasswordResetRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    """Begin a password reset. ALWAYS returns 202 — the response never reveals whether the email is
    registered (no account enumeration). If it is a real, active account, a single-use token
    (hashed at rest, 30-minute expiry) is created and delivered out of band."""
    settings = get_settings()
    email = body.email.lower()
    ip, _ = resolve_client_ip(request)
    # Rate-limit per email (bounds targeting one inbox) and per client IP (bounds a spraying src).
    keys = [f"pwreset-req:{email}"]
    bucket = client_bucket_key(ip)
    if bucket is not None:
        keys.append(f"pwreset-ip:{bucket}")
    retry = _reset_rate_limited(keys, settings)
    if retry is not None:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many reset requests",
                            headers={"Retry-After": str(int(retry) + 1)})

    user = db.query(User).filter(User.email == email).first()
    if user is not None and user.status == "active":
        raw = secrets.token_urlsafe(32)
        expires = dt.datetime.now(dt.UTC) + dt.timedelta(
            minutes=settings.password_reset_ttl_minutes)
        db.add(PasswordResetToken(user_id=user.id, token_hash=_hash_reset_token(raw),
                                  expires_at=expires))
        record_audit(db, action="auth.password_reset.requested", actor_id=user.id,
                     entity_type="user", entity_id=str(user.id), ip=ip)
        db.commit()
        _deliver_reset_token(user, raw, settings)
    # Uniform answer whether or not the account exists.
    return {"status": "if the account exists, a reset link has been sent"}


@router.post("/password-reset/confirm", status_code=status.HTTP_204_NO_CONTENT)
def confirm_password_reset(
    body: PasswordResetConfirm,
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    """Complete a password reset with a valid, unused, unexpired token. Sets the new password and
    bumps token_version so every existing session is revoked (Item 1). The token — and every other
    outstanding reset token for the user — is consumed, so it cannot be replayed."""
    settings = get_settings()
    ip, _ = resolve_client_ip(request)
    # Rate-limit confirmation per client IP to slow token guessing (the token itself is 256-bit).
    bucket = client_bucket_key(ip)
    if bucket is not None:
        retry = _reset_rate_limited([f"pwreset-confirm:{bucket}"], settings)
        if retry is not None:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many attempts",
                                headers={"Retry-After": str(int(retry) + 1)})

    now = dt.datetime.now(dt.UTC)
    token_hash = _hash_reset_token(body.token)
    row = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_hash == token_hash,
        PasswordResetToken.used_at.is_(None),
        PasswordResetToken.expires_at > now,
    ).first()
    if row is None:
        # One generic error for unknown / used / expired — never reveal which.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired reset token")
    user = db.get(User, row.user_id)
    if user is None or user.status != "active":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired reset token")

    user.password_hash = hash_password(body.new_password)
    user.token_version += 1     # revoke every access token issued before the reset
    # Consume this token AND any other outstanding token for the user, so none can be replayed.
    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.used_at.is_(None),
    ).update({PasswordResetToken.used_at: now})
    record_audit(db, action="auth.password_reset.completed", actor_id=user.id,
                 entity_type="user", entity_id=str(user.id), ip=ip)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
