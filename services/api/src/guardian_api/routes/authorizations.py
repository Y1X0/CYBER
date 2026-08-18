"""What the customer has authorized Guardian to do, and to what (WP-P0).

Until now no route created an `Authorization`. The only way one came into existence was a passing
ownership check, which meant an operator running a managed engagement had nowhere to record the
consent they had actually been given — and a customer had no way to see, in one place, what they
had authorized.

The security property this endpoint must not break, stated plainly:

**Recording consent is not the same as proving control.** A row in our database saying "I authorize
you to scan example.com" is a claim by whoever was logged in. It is adequate for the artifact plane
— a customer handing over their own repository is consenting to something they demonstrably possess
— and it is *not* adequate for sending packets at a host, because the person typing it may not own
that host. So:

* `written_consent` may be recorded here freely. `guardian_core.authorization` places it in
  `ARTIFACT_METHODS` and not in `NETWORK_METHODS`, so it authorizes scanning an artifact the
  customer supplied and authorizes no network activity whatsoever.
* `active_recon` — which *does* permit sending packets — is accepted only for a domain this tenant
  has already **verified**, by publishing the DNS record WP-F1 issued. The ownership proof stays
  the gate; this endpoint records the scope and the responsible identity on top of it.

That is why there is no "authorize everything" button, and why the UI says so.
"""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from guardian_core import authorization as authz
from guardian_core.ownership import normalize_domain
from guardian_db.audit import record_audit
from guardian_db.models import Asset, Authorization, Customer, DomainVerification, User
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian_api.deps import (
    Identity,
    client_ip,
    get_current_identity,
    get_db,
    require_staff_write,
)
from guardian_api.pagination import apply_cursor, order_newest_first, page_request, paginate

router = APIRouter()

# What a customer may record here. `ownership_verified` is deliberately absent: it is issued by the
# verification flow when a proof passes, and nothing else may mint one.
RECORDABLE = ("written_consent", "active_recon")

MAX_VALIDITY_DAYS = 365


class AuthorizationCreate(BaseModel):
    customer_id: uuid.UUID
    method: str = Field(pattern="^(written_consent|active_recon)$")
    scope: str = Field(min_length=3, max_length=200)
    asset_id: uuid.UUID | None = None
    domains: list[str] = Field(default_factory=list, max_length=50)
    validity_days: int = Field(default=90, ge=1, le=MAX_VALIDITY_DAYS)
    # The person's own statement, recorded verbatim. An authorization whose basis nobody wrote down
    # is one nobody can defend afterwards.
    reference: str = Field(default="", max_length=500)


class AuthorizationOut(BaseModel):
    id: uuid.UUID
    customer_id: uuid.UUID
    asset_id: uuid.UUID | None
    method: str
    scope: str
    targets: list[dict]
    permits_network: bool
    permits_artifact: bool
    state: str
    valid_from: str | None
    valid_until: str | None
    revoked_at: str | None
    authorized_by: str
    created_at: str


def _state(row: Authorization, now: dt.datetime) -> str:
    if row.revoked_at is not None:
        return "revoked"
    if row.valid_until is not None and _aware(row.valid_until) <= now:
        return "expired"
    if row.valid_from is not None and _aware(row.valid_from) > now:
        return "pending"
    return "active"


def _aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


def _out(row: Authorization, actor: str, now: dt.datetime) -> AuthorizationOut:
    return AuthorizationOut(
        id=row.id, customer_id=row.customer_id, asset_id=row.asset_id, method=row.method,
        scope=row.scope or "", targets=list(row.authorized_targets or []),
        # Spelled out per row rather than inferred by the reader: the difference between these two
        # is the difference between reading a file and sending packets at somebody's server.
        permits_network=row.method in authz.NETWORK_METHODS,
        permits_artifact=row.method in authz.ARTIFACT_METHODS,
        state=_state(row, now),
        valid_from=row.valid_from.isoformat() if row.valid_from else None,
        valid_until=row.valid_until.isoformat() if row.valid_until else None,
        revoked_at=row.revoked_at.isoformat() if row.revoked_at else None,
        authorized_by=actor, created_at=row.created_at.isoformat(),
    )


def _actors(db: Session, rows: list[Authorization]) -> dict:
    ids = {row.authorized_by for row in rows if row.authorized_by}
    if not ids:
        return {}
    return {u.id: (u.email or u.name or str(u.id))
            for u in db.execute(select(User).where(User.id.in_(ids))).scalars()}


def _verified_domains(db: Session, tenant_id: uuid.UUID, customer_id: uuid.UUID) -> set[str]:
    """Domains this customer has actually proved they control."""
    rows = db.execute(
        select(DomainVerification).where(
            DomainVerification.tenant_id == tenant_id,
            DomainVerification.customer_id == customer_id,
            DomainVerification.status == "verified",
        ).limit(500)
    ).scalars()
    now = dt.datetime.now(dt.UTC)
    return {row.domain.lower() for row in rows
            if row.expires_at is None or _aware(row.expires_at) > now}


@router.get("/methods", response_model=dict)
def describe_methods(identity: Identity = Depends(get_current_identity)) -> dict:
    """What each method actually permits, in the customer's words.

    Served from the same constants the gate evaluates, so the explanation cannot drift away from
    the behaviour it describes.
    """
    del identity
    return {
        "methods": [
            {
                "method": "written_consent",
                "label": "Written consent (artifact scanning)",
                "permits_network": False,
                "permits_artifact": True,
                "summary": "Lets Guardian scan material you supply — a repository, a container "
                           "image, an infrastructure template, an OpenAPI document. Guardian will "
                           "not send a single packet at a running system on this basis.",
                "requires": "nothing beyond your confirmation, because you are handing us the "
                            "material yourself",
            },
            {
                "method": "active_recon",
                "label": "Active testing (network scanning)",
                "permits_network": True,
                "permits_artifact": True,
                "summary": "Lets Guardian connect to your running systems: port and service "
                           "discovery, dynamic web testing, API testing.",
                "requires": "a domain you have already verified. Consent recorded in a form is a "
                            "claim; the DNS record is the proof, and active testing needs the "
                            "proof.",
            },
        ],
        "note": "Verifying a domain proves you control it. It does not by itself authorize every "
                "kind of scan — the authorization below records what you asked for, over which "
                "scope, and for how long.",
    }


@router.post("", response_model=AuthorizationOut, status_code=201)
def create_authorization(
    body: AuthorizationCreate,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> AuthorizationOut:
    """Record an authorization. See the module docstring for what this may and may not grant."""
    customer = db.get(Customer, body.customer_id)
    if customer is None or customer.tenant_id != identity.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "customer not found")

    if body.asset_id is not None:
        asset = db.get(Asset, body.asset_id)
        if asset is None or asset.tenant_id != identity.tenant_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")

    targets: list[dict] = []
    for raw in body.domains:
        try:
            targets.append({"type": "domain", "value": normalize_domain(raw)})
        except Exception as exc:  # noqa: BLE001 - the reason is the useful part
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"{raw!r} is not a domain: {exc}") from exc

    if body.asset_id is None and not targets:
        # An authorization with neither an asset nor a target grants nothing, and the gate reads it
        # that way. Refusing here means the customer finds out now rather than when a scan is
        # skipped for no visible reason.
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "an authorization must name an asset or at least one domain; one that names neither "
            "authorizes nothing",
        )

    if body.method == "active_recon":
        verified = _verified_domains(db, identity.tenant_id, body.customer_id)
        unproved = [t["value"] for t in targets
                    if not any(t["value"] == d or t["value"].endswith("." + d) for d in verified)]
        if unproved or not targets:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "active testing requires a verified domain. "
                + (f"These are not verified for this customer: {', '.join(unproved)}. "
                   if unproved else "No domain was named. ")
                + "Verify the domain first — recorded consent is a claim, and sending packets at a "
                  "host needs proof of control, not a claim.",
            )

    now = dt.datetime.now(dt.UTC)
    row = Authorization(
        tenant_id=identity.tenant_id, customer_id=body.customer_id, asset_id=body.asset_id,
        scope=body.scope, authorized_targets=targets, method=body.method,
        authorized_by=identity.user.id, valid_from=now,
        valid_until=now + dt.timedelta(days=body.validity_days),
    )
    db.add(row)
    db.flush()
    record_audit(
        db, action="authorization.recorded", tenant_id=identity.tenant_id,
        customer_id=body.customer_id, actor_id=identity.user.id, entity_type="authorization",
        entity_id=str(row.id), ip=ip,
        metadata={"method": body.method, "scope": body.scope,
                  "targets": [t["value"] for t in targets], "asset_id": str(body.asset_id or ""),
                  "reference": body.reference[:200], "validity_days": body.validity_days},
    )
    db.commit()
    del request
    return _out(row, identity.user.email or str(identity.user.id), now)


@router.get("", response_model=list[AuthorizationOut])
def list_authorizations(
    response: Response,
    customer_id: uuid.UUID | None = None,
    limit: int | None = None,
    cursor: str | None = None,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> list[AuthorizationOut]:
    """Everything this tenant has authorized, with its state.

    The answer to "what am I allowing Guardian to do?", in one list.
    """
    size, after = page_request(limit, cursor, maximum=identity.limits.max_page_size)
    query = db.query(Authorization).filter(Authorization.tenant_id == identity.tenant_id)
    if not identity.is_staff:
        query = query.filter(Authorization.customer_id == identity.portal_customer_id)
    elif customer_id is not None:
        query = query.filter(Authorization.customer_id == customer_id)

    rows = order_newest_first(
        apply_cursor(query, Authorization, after), Authorization).limit(size + 1).all()
    page = paginate(response, rows, size)
    actors = _actors(db, page)
    now = dt.datetime.now(dt.UTC)
    return [_out(row, actors.get(row.authorized_by, "unknown"), now) for row in page]


@router.delete("/{authorization_id}", status_code=204)
def revoke_authorization(
    authorization_id: uuid.UUID,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> None:
    """Withdraw an authorization. Effective on the next gate evaluation, which is every scan."""
    row = db.get(Authorization, authorization_id)
    if row is None or row.tenant_id != identity.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "authorization not found")
    if row.revoked_at is None:
        row.revoked_at = dt.datetime.now(dt.UTC)
    record_audit(
        db, action="authorization.revoked", tenant_id=identity.tenant_id,
        customer_id=row.customer_id, actor_id=identity.user.id, entity_type="authorization",
        entity_id=str(row.id), ip=ip, metadata={"method": row.method},
    )
    db.commit()
    del request
