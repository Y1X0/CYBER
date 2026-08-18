"""The security dashboard (WP-P0).

Every number here is a query. There is no sampling, no smoothing and no placeholder: if a value
cannot be computed it is absent or explicitly zero-with-a-reason, because a dashboard that invents
a plausible figure is worse than one that admits it has none — this is the screen a customer looks
at to decide whether they are safe.

Two trends are served, and both are honest about what they measure:

* **risk trend** is findings by the day they were *first seen*. It answers "what is arriving", which
  is a fact we hold. It is not "your risk score over time" — nobody recorded that daily, and
  reconstructing it from current state would be a guess presented as history.
* **exposure trend** is assets by the day they were first seen, split by exposure. Same reasoning:
  it is the growth of the attack surface, which is recorded, rather than a retrospective score.
"""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, Depends
from guardian_ai.security_score import security_score
from guardian_db.models import Asset, Finding, RemediationItem, Scan, ScanEngineRun
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, get_current_identity, get_db
from guardian_api.schemas import DashboardResponse, ScanOut

router = APIRouter()

TREND_DAYS = 30
OPEN_STATUSES = ("open", "triaged", "confirmed")


def _aware(value: dt.datetime | None) -> dt.datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


@router.get("", response_model=DashboardResponse)
def dashboard(
    customer_id: uuid.UUID | None = None,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> DashboardResponse:
    now = dt.datetime.now(dt.UTC)
    since = now - dt.timedelta(days=TREND_DAYS)

    def scoped(query, model):  # noqa: ANN001, ANN202
        query = query.filter(model.tenant_id == identity.tenant_id)
        if not identity.is_staff:
            return query.filter(model.customer_id == identity.portal_customer_id)
        if customer_id is not None:
            return query.filter(model.customer_id == customer_id)
        return query

    fq = scoped(db.query(Finding), Finding)
    sq = scoped(db.query(Scan), Scan)
    aq = scoped(db.query(Asset), Asset)
    rq = scoped(db.query(RemediationItem), RemediationItem)

    # ── findings ─────────────────────────────────────────────────────────────────────────────────
    findings = fq.limit(5000).all()
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    open_counts = dict(counts)
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        if f.status in OPEN_STATUSES:
            open_counts[f.severity] = open_counts.get(f.severity, 0) + 1
    open_total = sum(open_counts.values())

    # ── assets ───────────────────────────────────────────────────────────────────────────────────
    assets_total = aq.count()
    by_exposure: dict[str, int] = {}
    for exposure, count in scoped(
        db.query(Asset.exposure, func.count()), Asset
    ).group_by(Asset.exposure).all():
        by_exposure[str(exposure or "unknown")] = int(count)

    # ── scans ────────────────────────────────────────────────────────────────────────────────────
    scan_states: dict[str, int] = {}
    for state, count in scoped(db.query(Scan.status, func.count()), Scan).group_by(
        Scan.status
    ).all():
        scan_states[str(state)] = int(count)

    last_success = sq.filter(Scan.status.in_(("completed", "partial"))).order_by(
        Scan.finished_at.desc().nullslast()).first()

    # Engine runs that could not answer. These are the states that must never read as "clean", so
    # they are surfaced next to the finding counts rather than buried in a scan detail page.
    inconclusive = db.execute(
        select(ScanEngineRun.status, func.count())
        .join(Scan, Scan.id == ScanEngineRun.scan_id)
        .where(Scan.tenant_id == identity.tenant_id,
               ScanEngineRun.status.in_(("failed", "skipped", "deferred")),
               Scan.created_at >= since)
        .group_by(ScanEngineRun.status)
    ).all()

    # ── remediation ──────────────────────────────────────────────────────────────────────────────
    remediation: dict[str, int] = {}
    for state, count in scoped(
        db.query(RemediationItem.status, func.count()), RemediationItem
    ).group_by(RemediationItem.status).all():
        remediation[str(state)] = int(count)
    overdue = rq.filter(
        RemediationItem.status.in_(("open", "in_progress", "reopened", "fixed")),
        RemediationItem.due_at < now,
    ).count()

    # ── trends ───────────────────────────────────────────────────────────────────────────────────
    risk_trend = [
        {"day": str(day), "severity": str(severity), "count": int(count)}
        for day, severity, count in scoped(
            db.query(func.date(Finding.created_at), Finding.severity, func.count()), Finding
        ).filter(Finding.created_at >= since)
        .group_by(func.date(Finding.created_at), Finding.severity).all()
    ]
    exposure_trend = [
        {"day": str(day), "exposure": str(exposure or "unknown"), "count": int(count)}
        for day, exposure, count in scoped(
            db.query(func.date(Asset.created_at), Asset.exposure, func.count()), Asset
        ).filter(Asset.created_at >= since)
        .group_by(func.date(Asset.created_at), Asset.exposure).all()
    ]

    recent = sq.order_by(Scan.created_at.desc()).limit(10).all()

    return DashboardResponse(
        security_score=security_score(findings),
        severity_counts=counts,
        total_findings=len(findings),
        recent_scans=[ScanOut.model_validate(s, from_attributes=True) for s in recent],
        open_severity_counts=open_counts,
        open_findings=open_total,
        assets_total=assets_total,
        assets_by_exposure=by_exposure,
        scans_by_status=scan_states,
        scans_active=scan_states.get("queued", 0) + scan_states.get("running", 0),
        scans_completed=scan_states.get("completed", 0) + scan_states.get("partial", 0),
        last_successful_scan_at=(
            _aware(last_success.finished_at).isoformat()
            if last_success and last_success.finished_at else None
        ),
        engine_runs_unresolved={str(state): int(count) for state, count in inconclusive},
        remediation_by_status=remediation,
        remediation_overdue=overdue,
        risk_trend=risk_trend,
        exposure_trend=exposure_trend,
        trend_days=TREND_DAYS,
    )
