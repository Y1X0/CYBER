"""Request metrics and the security SLOs (WP-G4).

Two halves, and the second is the reason the package exists.

The first is ordinary: request rate, latency and status by route. Labelled by the route *template*
(`/api/v1/findings/{finding_id}`) rather than the path, because a label whose cardinality grows with
the number of findings is a label that eventually takes the monitoring system down with it.

The second is the part a generic dashboard never gives you: whether the *security function* is
working. A platform like this fails quietly. Feeds stop syncing and every scan still reports
"completed" — with an increasingly out-of-date idea of what a vulnerability is. Engines start
failing and the finding count goes down, which looks like progress. Scans get stuck `running` and
nobody notices because nothing errored.

So the SLOs are about silence: how old the intelligence is, how many engine runs failed, how many
scans never finished, how much of the remediation backlog is past its own deadline. Each is
reported with an explicit `unknown` state when there is no data to judge from — because "no scans
have run" is not "everything is healthy", and a dashboard that renders it green is worse than no
dashboard.
"""

from __future__ import annotations

import datetime as dt
import time
from dataclasses import dataclass

from guardian_common.metrics import REGISTRY
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

# Thresholds. Visible, and deliberately conservative — an operator who disagrees should be changing
# a number they can see.
FEED_STALE_HOURS = 48
ENGINE_FAILURE_BUDGET = 0.05      # 5% of engine runs in the window
SCAN_STUCK_HOURS = 6
OVERDUE_BUDGET = 0.10             # 10% of active remediation items
# How long the scanner may go without finishing anything *while work is waiting* before that is
# treated as "it has stopped" rather than "it is busy". Chosen well above the longest engine
# timeout (task_time_limit is 1800s) so a single slow scan never trips it.
SCANNER_STALL_MINUTES = 45
WINDOW_HOURS = 24

HEALTHY = "healthy"
DEGRADED = "degraded"
UNKNOWN = "unknown"


class MetricsMiddleware(BaseHTTPMiddleware):
    """Count and time every request, including the ones that raise."""

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001, ANN201
        started = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            # In `finally` so an exception is still counted: the requests that fail are the ones
            # worth graphing, and an unhandled error would otherwise be invisible in the rate.
            template = _template(request)
            labels = {"method": request.method, "route": template, "status": str(status_code)}
            REGISTRY.inc("guardian_http_requests_total", labels)
            REGISTRY.observe(
                "guardian_http_request_seconds", time.perf_counter() - started,
                {"method": request.method, "route": template},
            )
            if status_code == 401:
                REGISTRY.inc("guardian_auth_failures_total", {"route": template})
            elif status_code == 403:
                REGISTRY.inc("guardian_authorization_denied_total", {"route": template})


def _template(request: Request) -> str:
    """The route as a bounded label: `/api/v1/findings/{finding_id}`.

    Built by substituting the matched path parameters back out of the concrete path rather than
    reading `route.path`, which on a nested router is the sub-router's fragment (`/{finding_id}`)
    and collides across routers. A label whose cardinality grows with the number of findings is a
    label that eventually takes the monitoring system down with it.
    """
    path = request.scope.get("path") or "/"
    params = request.scope.get("path_params") or {}
    if not params:
        return path if request.scope.get("route") is not None else "unmatched"
    for name, value in params.items():
        path = path.replace(str(value), "{" + name + "}")
    return path


@dataclass
class Slo:
    name: str
    status: str
    detail: str
    value: float | None = None
    threshold: float | None = None

    def as_dict(self) -> dict:
        return {"name": self.name, "status": self.status, "detail": self.detail,
                "value": self.value, "threshold": self.threshold}


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def evaluate_slos(session, *, now: dt.datetime | None = None) -> list[Slo]:  # noqa: ANN001
    """The security-function SLOs, across the whole deployment.

    Deliberately not tenant-scoped: this answers "is the platform doing its job", which is an
    operator's question, and the endpoint that serves it is operator-only for that reason.
    """
    from guardian_db.models import FeedState, RemediationItem, Scan, ScanEngineRun
    from sqlalchemy import func, select

    now = now or _now()
    window_start = now - dt.timedelta(hours=WINDOW_HOURS)
    results: list[Slo] = []

    # ── intelligence freshness ───────────────────────────────────────────────────────────────────
    rows = session.execute(select(FeedState.source, FeedState.last_success_at)).all()
    if not rows:
        results.append(Slo(
            "feed_freshness", UNKNOWN,
            "no feed has ever synced, so every vulnerability answer is based on whatever was "
            "seeded — this is not a healthy state, it is an unmeasured one",
        ))
    else:
        stale = []
        for source, last_success in rows:
            if last_success is None:
                stale.append(f"{source} (never)")
                continue
            age_hours = (now - _aware(last_success)).total_seconds() / 3600
            REGISTRY.set("guardian_feed_age_seconds", age_hours * 3600, {"feed": str(source)})
            if age_hours > FEED_STALE_HOURS:
                stale.append(f"{source} ({int(age_hours)}h)")
        results.append(Slo(
            "feed_freshness", DEGRADED if stale else HEALTHY,
            (f"{len(stale)} feed(s) older than {FEED_STALE_HOURS}h: {', '.join(stale)} — scans "
             "still complete, with an out-of-date idea of what a vulnerability is"
             if stale else f"every feed synced within {FEED_STALE_HOURS}h"),
            value=float(len(stale)), threshold=0.0,
        ))

    # ── engine health ────────────────────────────────────────────────────────────────────────────
    engine_rows = session.execute(
        select(ScanEngineRun.engine, ScanEngineRun.status, func.count())
        .join(Scan, Scan.id == ScanEngineRun.scan_id)
        .where(Scan.created_at >= window_start)
        .group_by(ScanEngineRun.engine, ScanEngineRun.status)
    ).all()
    total = sum(count for _, _, count in engine_rows)
    failed = sum(count for _, status_, count in engine_rows if status_ == "failed")
    if total == 0:
        results.append(Slo(
            "engine_success_rate", UNKNOWN,
            f"no engine ran in the last {WINDOW_HOURS}h — nothing was scanned, which is different "
            "from nothing being wrong",
        ))
    else:
        rate = failed / total
        results.append(Slo(
            "engine_success_rate", DEGRADED if rate > ENGINE_FAILURE_BUDGET else HEALTHY,
            (f"{failed} of {total} engine runs failed in the last {WINDOW_HOURS}h — a failed "
             "engine reports no findings, which looks exactly like a clean scan"
             if rate > ENGINE_FAILURE_BUDGET else
             f"{failed} of {total} engine runs failed in the last {WINDOW_HOURS}h"),
            value=round(rate, 4), threshold=ENGINE_FAILURE_BUDGET,
        ))

    # ── scans that never finished ────────────────────────────────────────────────────────────────
    cutoff = now - dt.timedelta(hours=SCAN_STUCK_HOURS)
    stuck = session.execute(
        select(func.count()).select_from(Scan)
        .where(Scan.status.in_(("queued", "running")), Scan.created_at < cutoff)
    ).scalar_one()
    results.append(Slo(
        "scan_completion", DEGRADED if stuck else HEALTHY,
        (f"{stuck} scan(s) have been queued or running for more than {SCAN_STUCK_HOURS}h — a scan "
         "that never finishes never reports, and nothing errored to say so"
         if stuck else f"no scan has been running longer than {SCAN_STUCK_HOURS}h"),
        value=float(stuck), threshold=0.0,
    ))

    # ── remediation backlog ──────────────────────────────────────────────────────────────────────
    active = session.execute(
        select(func.count()).select_from(RemediationItem)
        .where(RemediationItem.status.in_(("open", "in_progress", "reopened", "fixed")))
    ).scalar_one()
    overdue = session.execute(
        select(func.count()).select_from(RemediationItem)
        .where(RemediationItem.status.in_(("open", "in_progress", "reopened", "fixed")),
               RemediationItem.due_at < now)
    ).scalar_one()
    if active == 0:
        results.append(Slo("remediation_sla", UNKNOWN,
                           "no remediation item is open, so there is nothing to be late on"))
    else:
        ratio = overdue / active
        results.append(Slo(
            "remediation_sla", DEGRADED if ratio > OVERDUE_BUDGET else HEALTHY,
            f"{overdue} of {active} open remediation items are past their due date",
            value=round(ratio, 4), threshold=OVERDUE_BUDGET,
        ))

    # ── is the scanner executing at all? ─────────────────────────────────────────────────────────
    results.append(_scanner_liveness(session, now))

    # Publishing the execution gauges here means one authenticated SLO read refreshes what the
    # scrape will serve, so `/metrics` and `/health/slo` cannot disagree about the same database.
    collect_execution_metrics(session, now=now)

    for slo in results:
        REGISTRY.set("guardian_slo_healthy", 1.0 if slo.status == HEALTHY else 0.0,
                     {"slo": slo.name})
    return results


def collect_execution_metrics(session, *, now: dt.datetime | None = None) -> dict:  # noqa: ANN001
    """Publish scan-execution telemetry, read from the database at scrape time (RED-5).

    The worker and the API are different processes; an in-process counter incremented in the worker
    can never appear on the API's `/metrics`. Rather than add a second metrics system (a push
    gateway, a sidecar, a Redis counter set), this reads the state both processes already share and
    agree on. It is durable across restarts for the same reason — the numbers are the rows.

    Everything here is a gauge, deliberately. A count over a rolling window is not monotonic, and
    exporting one as a counter would make every `rate()` built on it wrong.
    """
    from guardian_db.models import Scan, ScanEngineRun
    from sqlalchemy import func, select

    now = now or _now()
    window_start = now - dt.timedelta(hours=WINDOW_HOURS)
    stats: dict = {"queue": {}, "scans": {}, "engine_runs": {}}

    # ── queue depth: instantaneous, not windowed ─────────────────────────────────────────────────
    for state in ("queued", "running"):
        depth = session.execute(
            select(func.count()).select_from(Scan).where(Scan.status == state)
        ).scalar_one()
        REGISTRY.set("guardian_scan_queue_depth", float(depth), {"state": state})
        stats["queue"][state] = int(depth)

    # ── scans started/completed/failed in the window ─────────────────────────────────────────────
    seen = {row[0]: int(row[1]) for row in session.execute(
        select(Scan.status, func.count()).where(Scan.created_at >= window_start)
        .group_by(Scan.status)
    ).all()}
    # Every status is published, including the ones with no rows: a series that disappears when the
    # count reaches zero is a series an alert cannot distinguish from a broken scrape.
    for state in ("queued", "running", "completed", "partial", "failed"):
        REGISTRY.set("guardian_scans_window", float(seen.get(state, 0)),
                     {"status": state, "window": f"{WINDOW_HOURS}h"})
        stats["scans"][state] = seen.get(state, 0)

    # ── engine execution and failure, per engine ─────────────────────────────────────────────────
    for engine, run_status, count in session.execute(
        select(ScanEngineRun.engine, ScanEngineRun.status, func.count())
        .join(Scan, Scan.id == ScanEngineRun.scan_id)
        .where(Scan.created_at >= window_start)
        .group_by(ScanEngineRun.engine, ScanEngineRun.status)
    ).all():
        REGISTRY.set("guardian_scan_engine_runs_window", float(count),
                     {"engine": str(engine), "status": str(run_status),
                      "window": f"{WINDOW_HOURS}h"})
        stats["engine_runs"][f"{engine}:{run_status}"] = int(count)

    # ── duration ─────────────────────────────────────────────────────────────────────────────────
    duration = func.extract("epoch", Scan.finished_at - Scan.started_at)
    row = session.execute(
        select(func.percentile_cont(0.5).within_group(duration.asc()),
               func.percentile_cont(0.95).within_group(duration.asc()),
               func.max(duration))
        .where(Scan.finished_at.isnot(None), Scan.started_at.isnot(None),
               Scan.created_at >= window_start)
    ).first()
    for label, value in zip(("p50", "p95", "max"), row or (None, None, None), strict=False):
        if value is not None:
            REGISTRY.set("guardian_scan_duration_seconds", float(value),
                         {"quantile": label, "window": f"{WINDOW_HOURS}h"})
            stats.setdefault("duration_seconds", {})[label] = round(float(value), 3)

    # ── liveness: the age of the newest finished scan ────────────────────────────────────────────
    newest = session.execute(
        select(func.max(Scan.finished_at)).where(Scan.finished_at.isnot(None))
    ).scalar()
    if newest is not None:
        age = (now - _aware(newest)).total_seconds()
        REGISTRY.set("guardian_scanner_last_completion_seconds", age, {})
        stats["last_completion_seconds"] = round(age, 1)
    return stats


def _scanner_liveness(session, now: dt.datetime) -> Slo:  # noqa: ANN001
    """Has the scanner stopped executing? (RED-5)

    The distinction that matters is between *idle* and *stalled*. A platform with nothing queued and
    nothing running is idle, and idle is not evidence of health — it reports `unknown`. A platform
    with work waiting and nothing finishing is stalled, and that is the alert: it is precisely the
    shape of "the worker died" and, until this existed, the shape a customer noticed first.
    """
    from guardian_db.models import Scan
    from sqlalchemy import func, select

    waiting = session.execute(
        select(func.count()).select_from(Scan).where(Scan.status.in_(("queued", "running")))
    ).scalar_one()
    newest = session.execute(
        select(func.max(Scan.finished_at)).where(Scan.finished_at.isnot(None))
    ).scalar()
    stall_seconds = SCANNER_STALL_MINUTES * 60
    idle_for = (now - _aware(newest)).total_seconds() if newest is not None else None

    if not waiting:
        return Slo("scanner_liveness", UNKNOWN,
                   "nothing is queued or running, so there is no evidence either way — an idle "
                   "scanner and a dead one look identical from here",
                   value=0.0, threshold=float(stall_seconds))
    if newest is None:
        # Nothing has ever finished. On a deployment that has been running for a while that means
        # the worker has never worked; on a brand-new one it means the first scan was submitted
        # moments ago and has not had time to finish. Those need opposite answers, and the age of
        # the oldest waiting scan is what separates them — without it, every new deployment told
        # its first customer that nothing was executing their scan while a healthy worker ran it.
        oldest = session.execute(
            select(func.min(Scan.created_at)).where(Scan.status.in_(("queued", "running")))
        ).scalar()
        waited = (now - _aware(oldest)).total_seconds() if oldest is not None else 0.0
        if waited <= stall_seconds:
            return Slo("scanner_liveness", UNKNOWN,
                       f"{waiting} scan(s) are waiting and none has finished yet — the oldest has "
                       f"been waiting {int(waited)}s, which is not yet long enough to tell a "
                       "working scanner from a missing one",
                       value=round(waited, 1), threshold=float(stall_seconds))
        return Slo("scanner_liveness", DEGRADED,
                   f"{waiting} scan(s) are waiting, the oldest for {int(waited // 60)} minutes, "
                   "and no scan has ever finished — the worker has either never run or cannot "
                   "reach the database",
                   value=round(waited, 1), threshold=float(stall_seconds))
    if idle_for is not None and idle_for > stall_seconds:
        return Slo("scanner_liveness", DEGRADED,
                   f"{waiting} scan(s) are waiting and nothing has finished for "
                   f"{int(idle_for // 60)} minutes — the scanner has stopped executing",
                   value=round(idle_for, 1), threshold=float(stall_seconds))
    return Slo("scanner_liveness", HEALTHY,
               f"{waiting} scan(s) in flight and the last one finished "
               f"{int((idle_for or 0) // 60)} minute(s) ago",
               value=round(idle_for or 0.0, 1), threshold=float(stall_seconds))


def _aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


def overall(slos: list[Slo]) -> str:
    """One word for the lot.

    `unknown` never collapses into `healthy`: an SLO nobody could evaluate is a question nobody
    answered, and rendering that green is how a dashboard lies quietly for a month.
    """
    if any(slo.status == DEGRADED for slo in slos):
        return DEGRADED
    if any(slo.status == UNKNOWN for slo in slos):
        return UNKNOWN
    return HEALTHY


__all__ = [
    "DEGRADED",
    "collect_execution_metrics",
    "HEALTHY",
    "UNKNOWN",
    "MetricsMiddleware",
    "Slo",
    "evaluate_slos",
    "overall",
]
