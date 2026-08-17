"""The sweep that turns schedules into queued work (WP-A3).

Celery beat fires one task on a fixed cadence; that task reads the `schedules` table and enqueues
whatever is due. Beat's own static schedule is deliberately not used for tenant work — it cannot be
edited through the API, cannot express per-customer cadence, and would put every tenant's timing in
one shared config file.

Two properties matter more than the mechanics:

**A missed window must not stampede.** If the worker was down for six hours, a schedule due every
hour is not six runs behind — it is one run late. `next_run_at` advances from *now*, not by
repeatedly adding the interval, so an outage costs the customer one scan rather than delivering six
at once and six times the bill.

**A schedule that cannot succeed must stop.** Consecutive failures disable it. A target that was
deleted, an authorization that lapsed, a repository that no longer exists — retrying those forever
burns worker time and bills for work that cannot complete.
"""

from __future__ import annotations

import datetime as dt
import uuid

from guardian_common.logging import get_logger
from guardian_core.enums import ScanStatus
from guardian_db.models import Asset, Schedule
from guardian_db.session import session_scope
from sqlalchemy import select

from guardian_scanner.celery_app import celery_app

log = get_logger("guardian.scheduling")

# After this many consecutive failures a schedule is disabled and needs a human to re-enable it.
MAX_CONSECUTIVE_FAILURES = 5
# A schedule more than this far past due was missed during an outage rather than merely delayed.
MISSED_WINDOW_SECONDS = 3600


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _advance(schedule: Schedule, now: dt.datetime) -> dt.datetime:
    """The next due time.

    Always relative to now, never `next_run_at + interval` accumulated forward. The second form
    fires every missed window in a burst the moment a worker returns, which is how a scheduler
    turns an outage into a self-inflicted denial of service against the customer's own systems.
    """
    return now + dt.timedelta(seconds=max(300, int(schedule.interval_seconds)))


@celery_app.task(name="guardian.sweep_schedules")
def sweep_schedules(limit: int = 200) -> dict:
    """Enqueue every schedule that is due. Idempotent: claiming advances `next_run_at` first."""
    now = _now()
    enqueued, failed, disabled = 0, 0, 0

    with session_scope() as session:
        due = session.execute(
            select(Schedule)
            .where(Schedule.enabled.is_(True), Schedule.next_run_at <= now)
            .order_by(Schedule.next_run_at)
            .limit(limit)
            .with_for_update(skip_locked=True)   # two beat instances must not double-enqueue
        ).scalars().all()

        for schedule in due:
            late = (now - schedule.next_run_at).total_seconds()
            # Claim the slot BEFORE enqueuing. A crash between the two costs one skipped run; the
            # reverse order costs an unbounded number of duplicate scans.
            schedule.next_run_at = _advance(schedule, now)
            schedule.last_run_at = now

            try:
                _dispatch(session, schedule)
                schedule.last_status = "queued"
                schedule.consecutive_failures = 0
                enqueued += 1
                if late > MISSED_WINDOW_SECONDS:
                    log.warning("schedule_missed_window", schedule_id=str(schedule.id),
                                late_seconds=int(late),
                                note="running once, not once per missed interval")
            except Exception as exc:  # noqa: BLE001 - one bad schedule must not stop the sweep
                schedule.last_status = "failed"
                schedule.consecutive_failures += 1
                failed += 1
                log.error("schedule_dispatch_failed", schedule_id=str(schedule.id),
                          tenant_id=str(schedule.tenant_id), error=type(exc).__name__,
                          detail=str(exc)[:200],
                          failures=schedule.consecutive_failures)
                if schedule.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    schedule.enabled = False
                    disabled += 1
                    log.error("schedule_disabled", schedule_id=str(schedule.id),
                              reason="consecutive failures — target or authorization may be gone")

    result = {"due": len(due), "enqueued": enqueued, "failed": failed, "disabled": disabled}
    log.info("schedule_sweep_complete", **result)
    return result


def _dispatch(session, schedule: Schedule) -> None:  # noqa: ANN001
    """Create the work row and publish it. Raises if the schedule's target no longer resolves."""
    from guardian_db.models import DiscoveryRun, Scan  # noqa: PLC0415

    if schedule.kind == "scan":
        if schedule.target_id is None:
            raise ValueError("scan schedule has no asset")
        asset = session.get(Asset, schedule.target_id)
        if asset is None or asset.tenant_id != schedule.tenant_id:
            # Cross-tenant would be a serious bug rather than a missing row, so both are refused
            # here and the failure counter will disable the schedule if it persists.
            raise ValueError("scan schedule target is missing or not in this tenant")
        engines = list(schedule.settings.get("engines") or ["secrets", "sast", "sca"])
        scan = Scan(
            tenant_id=schedule.tenant_id, customer_id=asset.customer_id, asset_id=asset.id,
            trigger="schedule", status=ScanStatus.QUEUED.value,
            requested_engines=engines, stats={},
        )
        session.add(scan)
        session.flush()
        _publish("guardian.run_scan", str(scan.id))

    elif schedule.kind == "discovery":
        run = DiscoveryRun(
            tenant_id=schedule.tenant_id, customer_id=schedule.customer_id,
            scope_id=schedule.target_id, status="queued", trigger="schedule",
            seeds=dict(schedule.settings.get("seeds") or {}),
        )
        session.add(run)
        session.flush()
        _publish("guardian.run_discovery", str(run.id))

    else:
        raise ValueError(f"unknown schedule kind: {schedule.kind!r}")


def _publish(task_name: str, row_id: str) -> None:
    """Send by name so the scheduler does not import the task modules it triggers."""
    celery_app.send_task(task_name, args=[row_id])


def upsert_schedule(session, *, tenant_id, kind: str, interval_seconds: int,  # noqa: ANN001
                    target_id=None, customer_id=None, settings=None,
                    enabled: bool = True) -> Schedule:
    """Create or update one schedule.

    Upsert rather than insert because re-registering an existing schedule should change its cadence,
    not double the customer's scan volume and their bill.
    """
    tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(str(tenant_id))
    existing = session.execute(
        select(Schedule).where(
            Schedule.tenant_id == tenant_uuid,
            Schedule.kind == kind,
            Schedule.target_id == target_id,
        )
    ).scalars().first()

    if existing is not None:
        existing.interval_seconds = interval_seconds
        existing.enabled = enabled
        existing.consecutive_failures = 0     # an explicit edit is a fresh start
        if settings is not None:
            existing.settings = settings
        return existing

    schedule = Schedule(
        tenant_id=tenant_uuid, customer_id=customer_id, kind=kind, target_id=target_id,
        interval_seconds=interval_seconds, enabled=enabled,
        settings=settings or {}, next_run_at=_now(),
    )
    session.add(schedule)
    session.flush()
    return schedule
