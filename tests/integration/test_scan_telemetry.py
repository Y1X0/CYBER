"""Can an operator see the scanner working, or stopping? (audit RED-5)

`guardian_scan_engine_runs_total` was declared and never incremented, and the worker never imported
the metrics registry at all — it could not have helped if it had, because the worker is a different
process from the API that serves `/metrics`. So the one question an operator needs answered — is the
scanner executing? — had no answer anywhere in the exposition.

The repair reads the database at scrape time. These tests assert the numbers are real (they move
when scans move) and that the stall alert distinguishes *idle* from *dead*, which is the distinction
that decides whether anyone gets paged.

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


def _estate():
    from guardian_db.models import Asset, Customer, Tenant, TenantMembership, User
    from guardian_db.session import session_scope

    slug = f"tel-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        user = User(email=f"o-{slug}@x.invalid", name="Owner", status="active")
        db.add_all([customer, user])
        db.flush()
        db.add(TenantMembership(user_id=user.id, tenant_id=tenant.id, role="owner"))
        asset = Asset(tenant_id=tenant.id, customer_id=customer.id, name="app", kind="repo",
                      identifier=f"inline-{slug}", exposure="public",
                      config={"inline_content": {"a.py": 'K = "AKIA' + 'IOSFODNN7EXAMPLE"\n'}})
        db.add(asset)
        db.flush()
        return {"tenant": tenant.id, "customer": customer.id, "user": user.id,
                "asset": asset.id, "slug": slug}


def _scan(ctx, status="queued", *, run_it=False, started=None, finished=None):
    from guardian_db.models import Scan
    from guardian_db.session import session_scope
    from guardian_scanner.tasks import run_scan

    with session_scope() as db:
        scan = Scan(tenant_id=ctx["tenant"], customer_id=ctx["customer"], asset_id=ctx["asset"],
                    trigger="manual", status=status, requested_engines=["secrets"], stats={},
                    started_at=started, finished_at=finished)
        db.add(scan)
        db.flush()
        scan_id = str(scan.id)
    if run_it:
        run_scan(scan_id)
    return scan_id


def _metrics_text(ctx=None):
    from guardian_api.observability import collect_execution_metrics
    from guardian_common.metrics import REGISTRY
    from guardian_db.session import session_scope

    del ctx
    with session_scope() as db:
        collect_execution_metrics(db)
    return REGISTRY.render()


def _sample(text: str, name: str) -> list[str]:
    return [line for line in text.splitlines()
            if line.startswith(name + "{") or line.startswith(name + " ")]


# ── the metrics exist and are real ────────────────────────────────────────────────────────────────
def test_a_completed_scan_produces_execution_samples():
    """Before the repair, the exposition had a HELP line and no samples, forever."""
    ctx = _estate()
    _scan(ctx, run_it=True)

    text = _metrics_text()

    assert _sample(text, "guardian_scans_window"), "no scan counts exported"
    assert _sample(text, "guardian_scan_engine_runs_window"), "no engine-run counts exported"
    assert _sample(text, "guardian_scan_duration_seconds"), "no scan duration exported"
    assert _sample(text, "guardian_scanner_last_completion_seconds")


def test_engine_execution_and_failure_are_separately_visible():
    """"The scanner ran" and "the scanner ran and failed" must not be one number."""
    ctx = _estate()
    _scan(ctx, run_it=True)

    text = _metrics_text()
    runs = _sample(text, "guardian_scan_engine_runs_window")

    assert any('engine="secrets"' in line and 'status="completed"' in line for line in runs)
    # The label exists whether or not anything failed, so an alert can be written against it.
    assert all("window=" in line for line in runs)


def test_queue_depth_reflects_work_that_has_not_run():
    """The signal that work is accepted but not executing — the A1 situation exactly."""
    ctx = _estate()
    _scan(ctx, status="queued")

    text = _metrics_text()
    queued = _sample(text, "guardian_scan_queue_depth")
    line = next(x for x in queued if 'state="queued"' in x)

    assert float(line.rsplit(" ", 1)[1]) >= 1


def test_every_scan_status_is_exported_even_at_zero():
    """A series that vanishes at zero is one an alert cannot tell from a broken scrape."""
    _estate()
    text = _metrics_text()
    exported = " ".join(_sample(text, "guardian_scans_window"))

    for state in ("queued", "running", "completed", "partial", "failed"):
        assert f'status="{state}"' in exported


def test_the_metrics_endpoint_serves_the_database_numbers(monkeypatch):
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings

    ctx = _estate()
    _scan(ctx, run_it=True)
    token = "audit-scrape-token"
    monkeypatch.setattr(get_settings(), "metrics_token", token, raising=False)

    response = TestClient(app).get("/metrics", headers={"X-Metrics-Token": token})

    assert response.status_code == 200
    assert "guardian_scans_window" in response.text
    assert "guardian_scan_queue_depth" in response.text


def test_the_metrics_endpoint_is_still_closed_without_the_token():
    from fastapi.testclient import TestClient
    from guardian_api.main import app

    assert TestClient(app).get("/metrics").status_code == 401


# ── the alert: has the scanner stopped? ───────────────────────────────────────────────────────────
def _liveness(now=None):
    from guardian_api.observability import _scanner_liveness
    from guardian_db.session import session_scope

    now = now or dt.datetime.now(dt.UTC)
    with session_scope() as db:
        return _scanner_liveness(db, now)


def test_work_waiting_and_nothing_finishing_is_degraded():
    """The shape of "the worker died", and the alert that did not exist."""
    ctx = _estate()
    _scan(ctx, status="queued")

    # Far enough in the future that every finished scan in this shared database is stale.
    verdict = _liveness(dt.datetime.now(dt.UTC) + dt.timedelta(days=2))

    assert verdict.status == "degraded"
    assert "stopped executing" in verdict.detail or "never run" in verdict.detail


def test_a_scanner_that_is_merely_busy_is_healthy():
    ctx = _estate()
    _scan(ctx, run_it=True)   # something finished just now
    _scan(ctx, status="queued")

    verdict = _liveness()

    assert verdict.status == "healthy"


def test_an_idle_scanner_reports_unknown_not_healthy():
    """Nothing queued proves nothing. An idle scanner and a dead one look identical from here, and
    rendering that green is how a dashboard lies for a month."""
    from guardian_db.models import Scan
    from guardian_db.session import session_scope

    # Park the queue for the length of this assertion and put it back. Other tests' rows would
    # otherwise decide the verdict, and leaving them altered would decide theirs.
    with session_scope() as db:
        parked = [row.id for row in db.query(Scan).filter(
            Scan.status.in_(("queued", "running"))).all()]
        if parked:
            db.query(Scan).filter(Scan.id.in_(parked)).update(
                {"status": "completed"}, synchronize_session=False)
    try:
        verdict = _liveness()
    finally:
        with session_scope() as db:
            if parked:
                db.query(Scan).filter(Scan.id.in_(parked)).update(
                    {"status": "queued"}, synchronize_session=False)

    assert verdict.status == "unknown"
    assert "idle" in verdict.detail


def test_the_liveness_slo_is_part_of_the_slo_report():
    from guardian_api.observability import evaluate_slos
    from guardian_db.session import session_scope

    with session_scope() as db:
        names = {slo.name for slo in evaluate_slos(db)}

    assert "scanner_liveness" in names
