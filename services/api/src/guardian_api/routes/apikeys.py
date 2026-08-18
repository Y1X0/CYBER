"""API key management (WP-G1).

`api_keys` has been a table since the first schema with no way to create a key and no way to
authenticate with one, so the only credential that has ever worked is a person's password. A CI
pipeline that wants to fail a build on a critical finding has had no way in.

Three properties, all of them tested:

* **the secret is returned exactly once.** There is no endpoint that reveals it again, because a
  key you can re-read is a key that lives in whatever read it — a log, a browser cache, a support
  ticket. Losing it means issuing a new one, which is the correct cost.
* **least privilege by default.** A key with no scopes can do nothing; there is no implicit "all",
  and `assets:write` is deliberately not in the CI preset, so a leaked build key cannot point the
  scanner at a target nobody authorized.
* **only an owner or admin manages keys**, and every issue and revocation is audited with the key's
  id — never any part of its secret.
"""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from guardian_common.config import get_settings
from guardian_core import apikeys
from guardian_core.enums import StaffRole
from guardian_db.audit import record_audit
from guardian_db.models import ApiKey
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, client_ip, get_current_identity, get_db

router = APIRouter()

_MANAGE_ROLES = {StaffRole.OWNER.value, StaffRole.ADMIN.value}
MAX_TTL_DAYS = 365
DEFAULT_TTL_DAYS = 90


def _require_manager(identity: Identity = Depends(get_current_identity)) -> Identity:
    """Managing keys is an owner/admin action, and never a key's own action.

    A key that can mint keys is a key that can escalate itself past its own scopes and outlive its
    own revocation.
    """
    if identity.is_machine:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "API keys cannot manage API keys")
    if identity.staff_role not in _MANAGE_ROLES:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "managing API keys requires an owner or admin role")
    return identity


class KeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scopes: list[str] = Field(default_factory=list)
    ttl_days: int = Field(default=DEFAULT_TTL_DAYS, ge=1, le=MAX_TTL_DAYS)


class KeyOut(BaseModel):
    id: uuid.UUID
    name: str
    scopes: list[str]
    expires_at: str | None = None
    last_used_at: str | None = None
    revoked_at: str | None = None
    created_at: str | None = None


class KeyCreated(KeyOut):
    # Present on creation and never again. There is no endpoint that can return it a second time.
    token: str
    note: str = (
        "Store this now: Guardian keeps only a peppered digest and cannot show the key again."
    )


def _out(key: ApiKey) -> KeyOut:
    return KeyOut(
        id=key.id, name=key.name, scopes=list(key.scopes or []),
        expires_at=key.expires_at.isoformat() if key.expires_at else None,
        last_used_at=key.last_used_at.isoformat() if key.last_used_at else None,
        revoked_at=key.revoked_at.isoformat() if key.revoked_at else None,
        created_at=key.created_at.isoformat() if key.created_at else None,
    )


@router.get("/scopes", response_model=dict)
def list_scopes(identity: Identity = Depends(get_current_identity)) -> dict:
    """The scopes that exist, and the presets worth starting from."""
    del identity
    return {
        "scopes": list(apikeys.ALL_SCOPES),
        "presets": {
            "ci": list(apikeys.CI_SCOPES),
            "read_only": list(apikeys.READ_ONLY_SCOPES),
        },
        "note": ("A key with no scopes can do nothing. `assets:write` is deliberately absent from "
                 "the CI preset: a leaked build key must not be able to point the scanner at a "
                 "target nobody authorized."),
    }


@router.post("", response_model=KeyCreated, status_code=201)
def create_key(
    body: KeyCreate,
    request: Request,
    identity: Identity = Depends(_require_manager),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> KeyCreated:
    settings = get_settings()
    scopes = apikeys.normalize_scopes(body.scopes)
    unknown = sorted(set(body.scopes) - set(scopes))
    if unknown:
        # Refused rather than dropped: a key carrying a scope that looks authoritative in an audit
        # and grants nothing is the worst of both.
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"unknown scope(s): {', '.join(unknown)}")

    issued = apikeys.mint(pepper=settings.apikey_pepper)
    now = dt.datetime.now(dt.UTC)
    key = ApiKey(
        # The row id *is* the key id, so authentication is one lookup rather than a table scan.
        id=uuid.UUID(issued.key_id.ljust(32, "0")),
        tenant_id=identity.tenant_id,
        name=body.name,
        key_hash=issued.digest,
        scopes=list(scopes),
        expires_at=now + dt.timedelta(days=body.ttl_days),
    )
    db.add(key)
    db.flush()
    record_audit(
        db, action="apikey.created", tenant_id=identity.tenant_id, customer_id=None,
        actor_id=identity.user.id, entity_type="api_key", entity_id=str(key.id), ip=ip,
        # The id and the scopes, never any part of the secret.
        metadata={"name": body.name, "scopes": list(scopes), "ttl_days": body.ttl_days},
    )
    db.commit()
    del request
    return KeyCreated(**_out(key).model_dump(), token=issued.token)


@router.get("", response_model=list[KeyOut])
def list_keys(
    identity: Identity = Depends(_require_manager),
    db: Session = Depends(get_db),
) -> list[KeyOut]:
    rows = db.execute(
        select(ApiKey).where(ApiKey.tenant_id == identity.tenant_id)
        .order_by(ApiKey.created_at.desc()).limit(200)
    ).scalars()
    return [_out(row) for row in rows]


@router.delete("/{key_id}", status_code=204)
def revoke_key(
    key_id: uuid.UUID,
    request: Request,
    identity: Identity = Depends(_require_manager),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> None:
    """Revoke immediately. Revocation is checked on every request, not cached."""
    key = db.get(ApiKey, key_id)
    if key is None or key.tenant_id != identity.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found")
    if key.revoked_at is None:
        key.revoked_at = dt.datetime.now(dt.UTC)
    record_audit(
        db, action="apikey.revoked", tenant_id=identity.tenant_id, customer_id=None,
        actor_id=identity.user.id, entity_type="api_key", entity_id=str(key.id), ip=ip,
        metadata={"name": key.name},
    )
    db.commit()
    del request
