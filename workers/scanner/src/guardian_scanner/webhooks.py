"""Sending a webhook (WP-G3).

The destination is an address a customer typed into a form, so the outbound request gets the same
egress discipline as every other customer-supplied target in this platform: pinned to a validated
public address at connect time, no redirects followed, and a bounded body read.

Redirects matter more here than anywhere else in the codebase. A customer's endpoint that answers
`302 Location: http://169.254.169.254/latest/meta-data/` would, if followed, have Guardian fetch its
own cloud credentials and — because a webhook sends a *signed* request — do it with a header the
receiver can prove came from Guardian. Redirects are refused rather than followed.

Delivery is recorded whatever happens, including the bytes that were signed. "The signature did not
verify" is otherwise an unresolvable support conversation.
"""

from __future__ import annotations

import datetime as dt
import uuid

from guardian_common.logging import get_logger
from guardian_core import webhooks as wh
from guardian_db.models import WebhookDelivery, WebhookEndpoint
from guardian_db.session import session_scope
from sqlalchemy import select

from guardian_scanner.celery_app import celery_app

log = get_logger("guardian.webhooks")

REQUEST_TIMEOUT = 10.0
# An endpoint that has failed this many times in a row is disabled. A dead endpoint that is retried
# forever is a slow outbound flood at somebody who is not listening.
MAX_CONSECUTIVE_FAILURES = 20


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def enqueue(session, *, tenant_id, event_type: str, data: dict,  # noqa: ANN001
            customer_id=None, now: dt.datetime | None = None) -> list[uuid.UUID]:
    """Queue one event for every endpoint that asked for it.

    Returns the delivery ids. Callers do not wait on them: a customer's slow endpoint must never
    hold up a scan, which is the reason this is a queue rather than a call.
    """
    if event_type not in wh.EVENTS:
        raise ValueError(f"unknown webhook event: {event_type}")
    now = now or _now()

    endpoints = list(session.execute(
        select(WebhookEndpoint).where(
            WebhookEndpoint.tenant_id == tenant_id,
            WebhookEndpoint.enabled.is_(True),
        )
    ).scalars())

    payload, redacted = wh.sanitize(data)
    if redacted:
        # A credential in an event payload means something upstream put it there. Masked here and
        # logged, on the same reasoning as the findings boundary (WP-F2).
        log.warning("webhook_payload_redacted", event_type=event_type,
                        patterns=sorted(set(redacted)))

    created: list[uuid.UUID] = []
    for endpoint in endpoints:
        if event_type not in (endpoint.events or []):
            continue
        if endpoint.customer_id and customer_id and endpoint.customer_id != customer_id:
            continue
        event = wh.Event(
            id=uuid.uuid4().hex, type=event_type, occurred_at=now,
            tenant_id=str(tenant_id), customer_id=str(customer_id) if customer_id else None,
            data=payload,
        )
        delivery = WebhookDelivery(
            tenant_id=tenant_id, endpoint_id=endpoint.id, event_type=event_type,
            event_id=event.id, status="pending", next_attempt_at=now,
            payload=event.body()[:wh.MAX_BODY_BYTES],
        )
        session.add(delivery)
        session.flush()
        created.append(delivery.id)
    return created


def _transport():  # noqa: ANN202
    """A POST that never follows a redirect and never leaves a validated public address."""
    import httpx  # noqa: PLC0415

    from guardian_scanner.engines.dast_engine import _pinned_egress  # noqa: PLC0415

    def post(url: str, body: str, headers: dict) -> tuple[int, str]:
        try:
            with _pinned_egress(), httpx.Client(
                follow_redirects=False, timeout=REQUEST_TIMEOUT
            ) as client:
                response = client.post(url, content=body.encode(), headers=headers)
        except Exception as exc:  # noqa: BLE001 - a connection failure is a delivery failure
            return 0, f"{type(exc).__name__}: {exc}"[:500]
        if 300 <= response.status_code < 400:
            # Not followed. A customer endpoint answering `302 Location: 169.254.169.254` would
            # otherwise have Guardian fetch its own metadata, carrying a signature the receiver can
            # prove came from Guardian.
            return response.status_code, (
                f"refused to follow a redirect to {response.headers.get('location', '')[:200]}"
            )
        return response.status_code, response.text[:500]

    return post


@celery_app.task(name="guardian.deliver_webhook")
def deliver_webhook(delivery_id: str, *, _post=None) -> dict:  # noqa: ANN001
    """Attempt one delivery, and schedule the next attempt if it is worth making."""
    post = _post or _transport()
    with session_scope() as session:
        delivery = session.get(WebhookDelivery, uuid.UUID(delivery_id))
        if delivery is None:
            return {"status": "unknown"}
        if delivery.status == "delivered":
            return {"status": "delivered"}
        endpoint = session.get(WebhookEndpoint, delivery.endpoint_id)
        if endpoint is None or not endpoint.enabled:
            delivery.status = "dropped"
            delivery.error = "the endpoint was removed or disabled before delivery"
            return {"status": "dropped"}

        now = _now()
        delivery.attempts += 1
        timestamp = int(now.timestamp())
        signature = wh.sign(delivery.payload, secret=endpoint.secret, timestamp=timestamp)
        event = wh.Event(id=delivery.event_id, type=delivery.event_type, occurred_at=now,
                         tenant_id=str(delivery.tenant_id))
        status, detail = post(
            endpoint.url, delivery.payload,
            wh.headers(event, signature=signature, delivery_id=str(delivery.id)),
        )
        delivery.response_status = status

        if 200 <= status < 300:
            delivery.status = "delivered"
            delivery.delivered_at = now
            delivery.error = None
            delivery.next_attempt_at = None
            endpoint.consecutive_failures = 0
            endpoint.last_success_at = now
            log.info("webhook_delivered", endpoint=str(endpoint.id),
                     event_type=delivery.event_type, attempts=delivery.attempts)
            return {"status": "delivered", "attempts": delivery.attempts}

        delivery.error = detail
        endpoint.consecutive_failures += 1
        if wh.should_retry(status, attempt=delivery.attempts):
            delivery.status = "pending"
            delivery.next_attempt_at = now + dt.timedelta(
                seconds=wh.retry_delay(delivery.attempts))
        else:
            delivery.status = "failed"
            delivery.next_attempt_at = None

        if endpoint.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
            # A dead endpoint retried forever is a slow outbound flood at somebody not listening.
            endpoint.enabled = False
            endpoint.disabled_at = now
            endpoint.disabled_reason = (
                f"disabled after {endpoint.consecutive_failures} consecutive failures; the last "
                f"was HTTP {status}: {detail[:120]}"
            )
            log.warning("webhook_endpoint_disabled", endpoint=str(endpoint.id),
                        failures=endpoint.consecutive_failures)

        log.info("webhook_delivery_failed", endpoint=str(endpoint.id), status=status,
                 attempts=delivery.attempts, retrying=delivery.status == "pending")
        return {"status": delivery.status, "attempts": delivery.attempts,
                "response_status": status}


@celery_app.task(name="guardian.sweep_webhook_deliveries")
def sweep_webhook_deliveries(limit: int = 100) -> dict:
    """Re-attempt deliveries whose backoff has elapsed."""
    now = _now()
    with session_scope() as session:
        due = list(session.execute(
            select(WebhookDelivery)
            .where(WebhookDelivery.status == "pending",
                   WebhookDelivery.next_attempt_at.isnot(None),
                   WebhookDelivery.next_attempt_at <= now)
            .limit(limit)
        ).scalars())
        ids = [str(row.id) for row in due]
    for delivery_id in ids:
        deliver_webhook.apply_async(args=[delivery_id])
    return {"dispatched": len(ids)}


__all__ = ["deliver_webhook", "enqueue", "sweep_webhook_deliveries"]
