"""Security SLOs and the metrics endpoint (WP-G4).

A platform like this fails quietly. Feeds stop syncing and every scan still reports `completed`,
with a steadily more out-of-date idea of what a vulnerability is. Engines start failing and the
finding count goes *down*, which looks like progress. Scans get stuck `running` and nothing errors.

So the tests here are about a dashboard telling the truth in the cases where silence is the
symptom — and, above all, about `unknown` never being rendered as `healthy`.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


def _session():
    from guardian_db.session import session_scope

    return session_scope()


def _slos(**kwargs):
    from guardian_api.observability import evaluate_slos

    with _session() as db:
        return {slo.name: slo for slo in evaluate_slos(db, **kwargs)}


def _clear():
    """Each test owns the deployment-wide state these SLOs read.

    Scans are aged out of the window rather than deleted: other tests' findings reference them, and
    the SLO reads a 24-hour window, so shifting `created_at` back isolates this test without
    touching anything else's data.
    """
    import datetime as _dt

    from guardian_db.models import FeedState, RemediationItem, Scan
    from guardian_db.session import session_scope

    with session_scope() as db:
        db.query(FeedState).delete()
        db.query(RemediationItem).delete()
        old = _dt.datetime.now(_dt.UTC) - _dt.timedelta(days=30)
        for scan in db.query(Scan).all():
            scan.created_at = old
            if scan.status in ("queued", "running"):
                scan.status = "completed"


def _feed(source: str, *, hours_ago: float | None):
    from guardian_db.models import FeedState
    from guardian_db.session import session_scope

    with session_scope() as db:
        db.merge(FeedState(
            source=source,
            last_success_at=(None if hours_ago is None
                             else dt.datetime.now(dt.UTC) - dt.timedelta(hours=hours_ago)),
        ))


def _scan(*, status="completed", engine_statuses=(), age_hours=0.0):
    from guardian_db.models import (
        Asset,
        Customer,
        Scan,
        ScanEngineRun,
        Tenant,
    )
    from guardian_db.session import session_scope

    slug = f"g4-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        db.add(customer)
        db.flush()
        asset = Asset(tenant_id=tenant.id, customer_id=customer.id, name="a", kind="repo",
                      identifier=f"https://example.invalid/{slug}.git", config={})
        db.add(asset)
        db.flush()
        scan = Scan(tenant_id=tenant.id, customer_id=customer.id, asset_id=asset.id,
                    trigger="manual", status=status, requested_engines=["secrets"], stats={})
        db.add(scan)
        db.flush()
        if age_hours:
            scan.created_at = dt.datetime.now(dt.UTC) - dt.timedelta(hours=age_hours)
        for index, engine_status in enumerate(engine_statuses):
            db.add(ScanEngineRun(scan_id=scan.id, engine=f"engine{index}", status=engine_status))
        db.flush()
        return {"tenant": tenant.id, "scan": scan.id}


# ── the rule ──────────────────────────────────────────────────────────────────────────────────────
def test_no_data_is_unknown_and_never_healthy():
    """"Nothing has run" is not "everything is fine", and a dashboard that renders it green is how
    a platform lies quietly for a month."""
    from guardian_api.observability import UNKNOWN, overall

    _clear()
    slos = _slos()

    assert slos["feed_freshness"].status == UNKNOWN
    assert overall(list(slos.values())) != "healthy"


def test_unknown_never_collapses_into_healthy_in_the_overall_status():
    from guardian_api.observability import HEALTHY, UNKNOWN, Slo, overall

    assert overall([Slo("a", HEALTHY, ""), Slo("b", UNKNOWN, "")]) == UNKNOWN
    assert overall([Slo("a", HEALTHY, "")]) == HEALTHY


# ── the failures that look like silence ───────────────────────────────────────────────────────────
def test_a_stale_feed_is_degraded_even_though_every_scan_completes():
    from guardian_api.observability import DEGRADED, HEALTHY

    _clear()
    _feed("nvd", hours_ago=1)
    assert _slos()["feed_freshness"].status == HEALTHY

    _feed("kev", hours_ago=200)
    stale = _slos()["feed_freshness"]
    assert stale.status == DEGRADED
    assert "kev" in stale.detail
    assert "out-of-date" in stale.detail


def test_a_feed_that_never_synced_counts_as_stale():
    from guardian_api.observability import DEGRADED

    _clear()
    _feed("nvd", hours_ago=1)
    _feed("epss", hours_ago=None)
    assert _slos()["feed_freshness"].status == DEGRADED


def test_failing_engines_are_degraded_because_a_failed_engine_looks_like_a_clean_scan():
    from guardian_api.observability import DEGRADED, HEALTHY

    _clear()
    _scan(engine_statuses=["completed"] * 20)
    assert _slos()["engine_success_rate"].status == HEALTHY

    _scan(engine_statuses=["failed"] * 10)
    degraded = _slos()["engine_success_rate"]
    assert degraded.status == DEGRADED
    assert "looks exactly like a clean scan" in degraded.detail


def test_a_scan_stuck_running_is_reported_although_nothing_errored():
    from guardian_api.observability import DEGRADED, HEALTHY

    _clear()
    assert _slos()["scan_completion"].status == HEALTHY

    _scan(status="running", age_hours=48)
    stuck = _slos()["scan_completion"]
    assert stuck.status == DEGRADED
    assert "never reports" in stuck.detail


def test_a_recent_running_scan_is_not_reported_as_stuck():
    from guardian_api.observability import HEALTHY

    _clear()
    _scan(status="running", age_hours=0.1)
    assert _slos()["scan_completion"].status == HEALTHY


def test_an_overdue_backlog_is_degraded():
    from guardian_api.observability import DEGRADED
    from guardian_db.models import RemediationItem
    from guardian_db.session import session_scope

    _clear()
    ctx = _scan(engine_statuses=["completed"])
    with session_scope() as db:
        from guardian_db.models import Customer, Finding, Scan, ScanEngineRun

        scan = db.get(Scan, ctx["scan"])
        run = db.query(ScanEngineRun).filter(ScanEngineRun.scan_id == scan.id).first()
        customer = db.query(Customer).filter(Customer.tenant_id == ctx["tenant"]).first()
        finding = Finding(
            tenant_id=ctx["tenant"], customer_id=customer.id, scan_id=scan.id,
            engine_run_id=run.id, asset_id=scan.asset_id, fingerprint=uuid.uuid4().hex[:32],
            title="t", description="", category="secret", severity="high", risk_score=70,
            status="open", location={}, evidence={},
        )
        db.add(finding)
        db.flush()
        db.add(RemediationItem(
            tenant_id=ctx["tenant"], customer_id=customer.id, finding_id=finding.id,
            status="open", due_at=dt.datetime.now(dt.UTC) - dt.timedelta(days=5),
        ))

    assert _slos()["remediation_sla"].status == DEGRADED


# ── the endpoints ─────────────────────────────────────────────────────────────────────────────────
def _client_and_user():
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token
    from guardian_db.models import Tenant, TenantMembership, User
    from guardian_db.session import session_scope

    slug = f"g4u-{uuid.uuid4().hex[:8]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        user = User(email=f"{slug}@x.invalid", name="Operator", status="active")
        db.add(user)
        db.flush()
        db.add(TenantMembership(user_id=user.id, tenant_id=tenant.id, role="owner"))
        user_id = user.id

    settings = get_settings()
    token = create_access_token(subject=str(user_id), secret=settings.jwt_secret,
                                algorithm=settings.jwt_algorithm)
    return TestClient(app), {"Authorization": f"Bearer {token}"}


def test_the_slo_endpoint_reports_every_slo_with_its_reasoning():
    _clear()
    _feed("nvd", hours_ago=1)
    client, hdr = _client_and_user()

    body = client.get("/health/slo", headers=hdr).json()

    assert {slo["name"] for slo in body["slos"]} >= {
        "feed_freshness", "engine_success_rate", "scan_completion"}
    assert all(slo["detail"] for slo in body["slos"])
    assert "not `healthy`" in body["note"]


def test_the_slo_endpoint_requires_authentication():
    """The detail strings say precisely how the platform is failing."""
    client, _ = _client_and_user()
    assert client.get("/health/slo").status_code in (401, 403)


def test_metrics_are_closed_without_the_scrape_token():
    """An unset secret must never mean 'no authentication required'."""
    client, _ = _client_and_user()
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"X-Metrics-Token": "wrong"}).status_code == 401


def test_metrics_are_served_with_the_scrape_token(monkeypatch):
    from guardian_common.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "metrics_token", "scrape-me", raising=False)
    client, _ = _client_and_user()

    response = client.get("/metrics", headers={"X-Metrics-Token": "scrape-me"})

    assert response.status_code == 200
    assert "# TYPE guardian_http_requests_total counter" in response.text


def test_requests_are_counted_by_route_template_not_by_path(monkeypatch):
    """A label whose cardinality grows with the number of findings eventually takes the monitoring
    system down with it."""
    from guardian_common.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "metrics_token", "scrape-me", raising=False)
    client, hdr = _client_and_user()

    client.get(f"/api/v1/findings/{uuid.uuid4()}", headers=hdr)
    rendered = client.get("/metrics", headers={"X-Metrics-Token": "scrape-me"}).text

    assert "/api/v1/findings/{finding_id}" in rendered


def test_an_unauthenticated_request_is_counted_as_an_auth_failure(monkeypatch):
    from guardian_common.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "metrics_token", "scrape-me", raising=False)
    client, _ = _client_and_user()

    client.get("/api/v1/findings", headers={"Authorization": "Bearer nonsense"})
    rendered = client.get("/metrics", headers={"X-Metrics-Token": "scrape-me"}).text

    assert "guardian_auth_failures_total" in rendered
