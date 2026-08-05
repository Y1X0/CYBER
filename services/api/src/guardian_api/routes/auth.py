"""Authentication: login (password → JWT) and current-identity introspection."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from guardian_common.config import get_settings
from guardian_common.security import create_access_token, verify_password
from guardian_db.audit import record_audit
from guardian_db.models import User
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, client_ip, get_current_identity, get_db
from guardian_api.schemas import LoginRequest, MeResponse, TokenResponse

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
def login(
    body: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> TokenResponse:
    user = db.query(User).filter(User.email == body.email.lower()).first()
    # Constant-ish response regardless of which factor failed (avoid user enumeration).
    if (
        user is None
        or not user.password_hash
        or not verify_password(body.password, user.password_hash)
    ):
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
