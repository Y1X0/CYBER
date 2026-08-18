"""Managing outbound webhooks (WP-G3).

A customer registers where they want to be told and what about. Two things are load-bearing:

* **the signing secret is shown once.** There is no endpoint that returns it again, on the same
  reasoning as WP-G1's API keys — a secret you can re-read lives in whatever read it.
* **the destination is validated before it is stored.** `https` only, no inline credentials, no
  loopback. That is the cheap half of the SSRF defence; the sender still pins to a validated public
  address at connect time, because a hostname that resolves privately looks exactly like one that
  does not until it is resolved.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from guardian_core import webhooks as wh
from guardian_db.audit import record_audit
from guardian_db.models import WebhookDelivery, WebhookEndpoint
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

router = APIRouter()


class EndpointCreate(BaseModel):
    url: str = Field(min_length=8, max_length=2000)
    events: list[str] = Field(default_factory=list)
    description: str = Field(default="", max_length=200)
    customer_id: uuid.UUID | None = None


class EndpointOut(BaseModel):
    id: uuid.UUID
    url: str
    description: str
    events: list[str]
    enabled: bool
    disabled_reason: str | None = None
    consecutive_failures: int
    last_success_at: str | None = None


class EndpointCreated(EndpointOut):
    secret: str
    note: str = (
        "Store this now: it signs every delivery and Guardian will not show it again. Verify "
        "`X-Guardian-Signature` over `<timestamp>.<body>` and reject anything older than five "
        "minutes — a signature alone only proves the payload came from Guardian at some point."
    )


def _out(row: WebhookEndpoint) -> EndpointOut:
    return EndpointOut(
        id=row.id, url=row.url, description=row.description, events=list(row.events or []),
        enabled=row.enabled, disabled_reason=row.disabled_reason,
        consecutive_failures=row.consecutive_failures,
        last_success_at=row.last_success_at.isoformat() if row.last_success_at else None,
    )


@router.get("/events", response_model=dict)
def list_events(identity: Identity = Depends(get_current_identity)) -> dict:
    del identity
    return {"events": list(wh.EVENTS),
            "note": "An endpoint subscribed to nothing receives nothing — subscribing to "
                    "everything is an explicit choice, not the effect of leaving the field blank."}


@router.post("", response_model=EndpointCreated, status_code=201)
def create_endpoint(
    body: EndpointCreate,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> EndpointCreated:
    try:
        url = wh.validate_url(body.url)
    except wh.InvalidWebhookUrl as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    unknown = sorted(set(body.events) - set(wh.EVENTS))
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"unknown event(s): {', '.join(unknown)}")

    secret = wh.new_secret()
    endpoint = WebhookEndpoint(
        tenant_id=identity.tenant_id, customer_id=body.customer_id, url=url,
        description=body.description, events=sorted(set(body.events)), secret=secret,
        created_by=identity.user.id,
    )
    db.add(endpoint)
    db.flush()
    record_audit(
        db, action="webhook.created", tenant_id=identity.tenant_id,
        customer_id=body.customer_id, actor_id=identity.user.id, entity_type="webhook_endpoint",
        entity_id=str(endpoint.id), ip=ip,
        # The destination and the events, never the secret.
        metadata={"url": url, "events": list(endpoint.events)},
    )
    db.commit()
    del request
    return EndpointCreated(**_out(endpoint).model_dump(), secret=secret)


@router.get("", response_model=list[EndpointOut])
def list_endpoints(
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> list[EndpointOut]:
    rows = db.execute(
        select(WebhookEndpoint).where(WebhookEndpoint.tenant_id == identity.tenant_id)
        .order_by(WebhookEndpoint.created_at.desc()).limit(200)
    ).scalars()
    return [_out(row) for row in rows]


@router.get("/{endpoint_id}/deliveries", response_model=list[dict])
def list_deliveries(
    endpoint_id: uuid.UUID,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> list[dict]:
    """What was actually sent, and what came back.

    The record that settles "we never got the alert" — including the exact bytes that were signed,
    because without them "the signature did not verify" has no resolution.
    """
    endpoint = db.get(WebhookEndpoint, endpoint_id)
    if endpoint is None or endpoint.tenant_id != identity.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "webhook endpoint not found")
    rows = db.execute(
        select(WebhookDelivery).where(WebhookDelivery.endpoint_id == endpoint_id)
        .order_by(WebhookDelivery.created_at.desc()).limit(100)
    ).scalars()
    return [
        {"id": str(row.id), "event": row.event_type, "status": row.status,
         "attempts": row.attempts, "response_status": row.response_status,
         "error": row.error, "payload": row.payload,
         "delivered_at": row.delivered_at.isoformat() if row.delivered_at else None,
         "next_attempt_at": (row.next_attempt_at.isoformat()
                             if row.next_attempt_at else None)}
        for row in rows
    ]


@router.delete("/{endpoint_id}", status_code=204)
def delete_endpoint(
    endpoint_id: uuid.UUID,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> None:
    endpoint = db.get(WebhookEndpoint, endpoint_id)
    if endpoint is None or endpoint.tenant_id != identity.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "webhook endpoint not found")
    endpoint.enabled = False
    record_audit(
        db, action="webhook.deleted", tenant_id=identity.tenant_id,
        customer_id=endpoint.customer_id, actor_id=identity.user.id,
        entity_type="webhook_endpoint", entity_id=str(endpoint.id), ip=ip,
        metadata={"url": endpoint.url},
    )
    db.commit()
    del request
