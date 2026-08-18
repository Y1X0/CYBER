"""Recovering work the broker lost (WP-P1).

`POST /scans` answers **202 Accepted**. That is a promise, and until this existed the platform could
break it silently and permanently: a Redis restart without persistence drops the queue, the scan row
stays `queued` for ever, and no amount of healthy worker brings it back. The customer was told
"scans are processed in order" about a scan that would never be processed. Measured, not assumed —
see `docs/PILOT_RUN.md` §4c.

The whole difficulty is telling **lost** from **waiting**, because re-sending a message that is
merely queued behind other work means two workers running one scan.

Two facts make that decidable, and neither is a guess:

1. **`run_scan` claims its scan atomically.** Its first database write moves `queued → running`, and
   that transition is a conditional `UPDATE` that exactly one caller can win. So a scan still
   sitting at `queued` has definitely not begun executing — whatever the broker holds — and a
   duplicate delivery is a no-op rather than a collision.
2. **The broker can be read.** Celery's Redis transport keeps pending messages in a list per queue
   and delivered-but-unacknowledged ones in the `unacked` hash. A scan whose message appears in
   neither is not going to be delivered by anybody.

So: `queued`, older than the grace period, and absent from the broker ⇒ the message is gone, nothing
is executing it, and re-sending is safe. Anything else is left alone.

The failure direction is deliberate. If the broker cannot be read, or the queue is too long to
enumerate, this recovers **nothing** — "I could not look" must never be read as "nothing is there",
which is the same rule the scanners follow about empty results.
"""

from __future__ import annotations

import base64
import datetime as dt
import json

from guardian_common.config import get_settings
from guardian_common.logging import get_logger
from guardian_core.enums import ScanStatus
from guardian_db.audit import record_audit
from guardian_db.models import Scan
from guardian_db.session import session_scope
from sqlalchemy import select

from guardian_scanner.celery_app import celery_app

log = get_logger("guardian.recovery")

# How long a scan may sit at `queued` before it is a candidate. Comfortably above `task_time_limit`
# (1800s), so a scan waiting behind a long-running one is never mistaken for a lost one even if the
# broker read is unavailable for a while.
STRANDED_AFTER_SECONDS = 2400

# Bounds. A sweep is a background job on a shared queue, not a place to enumerate an unbounded
# backlog: past the message cap the broker is reported unreadable rather than partially read.
MAX_CANDIDATES = 200
MAX_BROKER_MESSAGES = 5000

# The queues a `run_scan` message can be waiting on. Kept explicit rather than discovered, because
# a queue this does not know about would be read as "the message is gone".
SCAN_QUEUES = ("default",)

_RECOVERABLE_TASKS = ("guardian.run_scan",)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


def _scan_id_of(envelope: dict) -> str | None:
    """The scan id inside a Celery message envelope, or None if this is not a scan task.

    Anything unparseable raises, and `visible_scan_ids` turns that into "unknown". A message we
    cannot read is a scan we cannot rule out, and skipping it quietly would make a live scan look
    stranded.
    """
    headers = envelope.get("headers") or {}
    if headers.get("task") not in _RECOVERABLE_TASKS:
        return None
    args = json.loads(base64.b64decode(envelope["body"]))[0]
    return str(args[0]) if args else None


def visible_scan_ids(client=None) -> set[str] | None:  # noqa: ANN001
    """Scan ids the broker still holds — pending in a queue, or delivered and unacknowledged.

    Returns `None` when the answer cannot be established: broker unreachable, a queue longer than
    `MAX_BROKER_MESSAGES`, or a message that will not parse. `None` and `set()` mean opposite
    things here and the caller must not conflate them.
    """
    if client is None:
        try:
            import redis  # noqa: PLC0415 - optional at import time; required only for a sweep

            client = redis.Redis.from_url(get_settings().redis_url)
        except Exception as exc:  # noqa: BLE001 - any failure to reach the broker is "unknown"
            log.warning("recovery_broker_unreachable", error=str(exc)[:200])
            return None

    seen: set[str] = set()
    try:
        for queue in SCAN_QUEUES:
            depth = client.llen(queue)
            if depth > MAX_BROKER_MESSAGES:
                log.warning("recovery_queue_too_long", queue=queue, depth=int(depth))
                return None
            for raw in client.lrange(queue, 0, MAX_BROKER_MESSAGES):
                scan_id = _scan_id_of(json.loads(raw))
                if scan_id:
                    seen.add(scan_id)
        # Delivered to a worker and not yet acknowledged. With `task_acks_late` this is precisely
        # the set being executed right now, and re-sending any of it would double-run a scan.
        for raw in client.hvals("unacked") or ():
            payload = json.loads(raw)
            envelope = payload[0] if isinstance(payload, list) and payload else payload
            scan_id = _scan_id_of(envelope)
            if scan_id:
                seen.add(scan_id)
    except Exception as exc:  # noqa: BLE001 - an unreadable broker is unknown, never empty
        log.warning("recovery_broker_unreadable", error=str(exc)[:200])
        return None
    return seen


def stranded_scan_ids(session, *, now: dt.datetime | None = None) -> list[Scan]:  # noqa: ANN001
    """Scans that have been sitting at `queued` longer than anything should."""
    now = now or _now()
    cutoff = now - dt.timedelta(seconds=STRANDED_AFTER_SECONDS)
    return list(session.execute(
        select(Scan)
        .where(Scan.status == ScanStatus.QUEUED.value, Scan.created_at <= cutoff)
        .order_by(Scan.created_at.asc())
        .limit(MAX_CANDIDATES)
    ).scalars())


@celery_app.task(name="guardian.sweep_stranded_scans")
def sweep_stranded_scans() -> dict:
    """Re-send scans the broker lost. Idempotent, and silent when it cannot be sure."""
    stats = {"candidates": 0, "requeued": 0, "waiting": 0, "skipped_unknown_broker": 0}

    with session_scope() as session:
        candidates = stranded_scan_ids(session)
        stats["candidates"] = len(candidates)
        if not candidates:
            return stats

        visible = visible_scan_ids()
        if visible is None:
            # Fail closed: without a reliable view of the broker, re-sending risks running a scan
            # twice, and that is worse than recovering it late.
            stats["skipped_unknown_broker"] = len(candidates)
            log.warning("recovery_skipped_broker_unknown", candidates=len(candidates))
            return stats

        now = _now()
        requeue: list[tuple[str, str, str | None, int]] = []
        for scan in candidates:
            if str(scan.id) in visible:
                stats["waiting"] += 1
                continue
            waited = int((now - _aware(scan.created_at)).total_seconds())
            record_audit(
                session, action="scan.requeued", tenant_id=scan.tenant_id,
                customer_id=scan.customer_id, entity_type="scan", entity_id=str(scan.id),
                metadata={"reason": "the broker no longer holds this scan's message",
                          "waited_seconds": waited, "status": scan.status},
            )
            requeue.append((str(scan.id), str(scan.tenant_id),
                            str(scan.customer_id) if scan.customer_id else None, waited))
            stats["requeued"] += 1

    # Dispatched after the audit commits. A message sent for a scan whose audit row was rolled back
    # would be a recovery nobody can account for.
    for scan_id, tenant_id, _customer_id, waited in requeue:
        celery_app.send_task("guardian.run_scan", args=[scan_id])
        log.info("scan_requeued", scan_id=scan_id, tenant_id=tenant_id, waited_seconds=waited)

    if stats["requeued"]:
        log.warning("recovery_requeued_scans", **stats)
    return stats


__all__ = [
    "MAX_BROKER_MESSAGES",
    "MAX_CANDIDATES",
    "STRANDED_AFTER_SECONDS",
    "stranded_scan_ids",
    "sweep_stranded_scans",
    "visible_scan_ids",
]
