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

    for slo in results:
        REGISTRY.set("guardian_slo_healthy", 1.0 if slo.status == HEALTHY else 0.0,
                     {"slo": slo.name})
    return results


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
    "HEALTHY",
    "UNKNOWN",
    "MetricsMiddleware",
    "Slo",
    "evaluate_slos",
    "overall",
]
