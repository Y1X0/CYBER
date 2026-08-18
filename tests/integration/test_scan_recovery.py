"""Recovering work the broker lost (WP-P1).

`POST /scans` answers 202 Accepted. The platform could break that promise silently and permanently:
a Redis restart without persistence drops the queue, the scan sits at `queued` for ever, and a
perfectly healthy worker has nothing to consume. Measured in `docs/PILOT_RUN.md` §4c.

Recovery is the easy half. The hard half is not re-sending a message that is merely *waiting*,
because that runs one scan on two workers. So most of this file is about the cases where recovery
must do **nothing**.

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

SECRET_CONTENT = 'AWS_SECRET = "AKIA' + 'IOSFODNN7EXAMPLE"\n'


def _estate():
    """A customer with an authorized, scannable asset."""
    from guardian_db.models import Asset, Authorization, Customer, Tenant, User
    from guardian_db.session import session_scope

    slug = f"rec-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        user = User(email=f"{slug}@example.com", name="U", status="active")
        db.add_all([customer, user])
        db.flush()
        asset = Asset(tenant_id=tenant.id, customer_id=customer.id, name="app", kind="repo",
                      identifier=f"inline-{slug}", exposure="public",
                      config={"inline_content": SECRET_CONTENT})
        db.add(asset)
        db.flush()
        now = dt.datetime.now(dt.UTC)
        db.add(Authorization(
            tenant_id=tenant.id, customer_id=customer.id, asset_id=asset.id, scope="test",
            authorized_targets=[], method="written_consent", authorized_by=user.id,
            valid_from=now - dt.timedelta(days=1), valid_until=now + dt.timedelta(days=30)))
        return {"tenant": tenant.id, "customer": customer.id, "asset": asset.id}


def _queue_scan(ctx, *, age_seconds: float = 0.0):
    """A queued scan, optionally backdated so it already qualifies as stranded."""
    from guardian_db.models import Scan
    from guardian_db.session import session_scope

    with session_scope() as db:
        scan = Scan(tenant_id=ctx["tenant"], customer_id=ctx["customer"], asset_id=ctx["asset"],
                    trigger="manual", status="queued", requested_engines=["secrets"], stats={})
        db.add(scan)
        db.flush()
        if age_seconds:
            scan.created_at = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=age_seconds)
        return scan.id


def _status(scan_id):
    from guardian_db.models import Scan
    from guardian_db.session import session_scope

    with session_scope() as db:
        return db.get(Scan, scan_id).status


def _findings(ctx):
    from guardian_db.models import Finding
    from guardian_db.session import session_scope

    with session_scope() as db:
        return db.query(Finding).filter(Finding.asset_id == ctx["asset"]).all()


def _is_candidate(scan_id) -> bool:
    """Whether the sweep considers this particular scan stranded.

    Asked per scan rather than by counting: the sweep is deployment-wide by design, like the SLOs,
    so anything else in the database is also a candidate and a global count would say nothing about
    the case under test.
    """
    from guardian_db.session import session_scope
    from guardian_scanner.recovery import stranded_scan_ids

    with session_scope() as db:
        return str(scan_id) in {str(s.id) for s in stranded_scan_ids(db)}


def _sweep(monkeypatch, visible):
    """Run the sweep with a known broker view, capturing what it re-sends."""
    from guardian_scanner import recovery

    sent: list[str] = []
    monkeypatch.setattr(recovery, "visible_scan_ids", lambda *a, **k: visible)
    monkeypatch.setattr(recovery.celery_app, "send_task",
                        lambda name, args=None, **k: sent.append(args[0]))
    stats = recovery.sweep_stranded_scans()
    return stats, sent


# ── the message is gone ───────────────────────────────────────────────────────────────────────────
def test_a_scan_whose_message_the_broker_lost_is_recovered(monkeypatch):
    """The defect this exists for: FLUSHDB, and the 202 the customer was given still means something."""
    ctx = _estate()
    scan_id = _queue_scan(ctx, age_seconds=3600)

    stats, sent = _sweep(monkeypatch, visible=set())          # the broker holds nothing

    assert str(scan_id) in sent, f"the lost scan was not re-sent; stats={stats}"
    assert stats["requeued"] >= 1


def test_the_requeue_is_recorded_with_its_reason(monkeypatch):
    """A scan that reappears with no explanation is a support ticket."""
    from guardian_db.models import AuditLog
    from guardian_db.session import session_scope

    ctx = _estate()
    scan_id = _queue_scan(ctx, age_seconds=3600)
    _sweep(monkeypatch, visible=set())

    with session_scope() as db:
        rows = db.query(AuditLog).filter(
            AuditLog.entity_id == str(scan_id), AuditLog.action == "scan.requeued").all()
    assert rows, "the scan was re-sent and nothing recorded why"
    meta = rows[0].meta if hasattr(rows[0], "meta") else rows[0].metadata_
    assert "broker" in str(meta)
    assert meta["waited_seconds"] >= 3600


def test_recovery_actually_completes_the_scan(monkeypatch):
    """End to end: lost, recovered, executed, findings persisted."""
    from guardian_scanner import recovery
    from guardian_scanner.tasks import run_scan

    ctx = _estate()
    scan_id = _queue_scan(ctx, age_seconds=3600)
    sent: list[str] = []
    monkeypatch.setattr(recovery, "visible_scan_ids", lambda *a, **k: set())
    monkeypatch.setattr(recovery.celery_app, "send_task",
                        lambda name, args=None, **k: sent.append(args[0]))
    recovery.sweep_stranded_scans()

    for delivered in sent:                                     # the worker consuming the re-send
        run_scan(delivered)

    assert _status(scan_id) in ("completed", "partial")
    assert _findings(ctx), "the recovered scan produced no finding"


# ── the cases where doing nothing is the whole job ────────────────────────────────────────────────
def test_a_scan_still_in_the_broker_is_left_alone(monkeypatch):
    """A deep backlog is not a lost message, and re-sending would run it twice."""
    ctx = _estate()
    scan_id = _queue_scan(ctx, age_seconds=3600)

    stats, sent = _sweep(monkeypatch, visible={str(scan_id)})   # still waiting its turn

    assert str(scan_id) not in sent
    assert stats["waiting"] >= 1


def test_a_recently_queued_scan_is_not_touched(monkeypatch):
    """Normal waiting. The grace period is what stops recovery fighting the queue."""
    ctx = _estate()
    scan_id = _queue_scan(ctx)                                 # queued just now

    assert not _is_candidate(scan_id)
    _stats, sent = _sweep(monkeypatch, visible=set())
    assert str(scan_id) not in sent


def test_a_running_scan_is_never_requeued(monkeypatch):
    """Something is executing it. Re-sending is the one thing that must not happen."""
    from guardian_db.models import Scan
    from guardian_db.session import session_scope

    ctx = _estate()
    scan_id = _queue_scan(ctx, age_seconds=3600)
    with session_scope() as db:
        db.get(Scan, scan_id).status = "running"

    assert not _is_candidate(scan_id)
    _stats, sent = _sweep(monkeypatch, visible=set())
    assert str(scan_id) not in sent


def test_an_unreadable_broker_recovers_nothing(monkeypatch):
    """"I could not look" must never be read as "nothing is there" — the same rule the scanners
    follow about empty results, applied to the queue."""
    ctx = _estate()
    scan_id = _queue_scan(ctx, age_seconds=3600)

    assert _is_candidate(scan_id), "the fixture did not produce a stranded scan"
    stats, sent = _sweep(monkeypatch, visible=None)             # broker unreachable

    assert sent == []
    assert stats["requeued"] == 0
    assert stats["skipped_unknown_broker"] >= 1


# ── idempotency: a duplicate delivery must be a no-op ─────────────────────────────────────────────
def test_a_duplicate_delivery_does_not_run_the_scan_twice():
    """The claim is atomic, so the second delivery finds nothing to do.

    Without it the second run reaches `ScanEngineRun` and collides on the unique constraint, which
    turns a harmless redelivery into a failed scan.
    """
    from guardian_db.models import ScanEngineRun
    from guardian_db.session import session_scope
    from guardian_scanner.tasks import run_scan

    ctx = _estate()
    scan_id = _queue_scan(ctx)

    first = run_scan(str(scan_id))
    second = run_scan(str(scan_id))                             # the same message, delivered again

    assert first["status"] in ("completed", "partial")
    assert second.get("claimed") is False, f"the second delivery re-ran the scan: {second}"
    assert _status(scan_id) in ("completed", "partial"), "a redelivery moved the scan off terminal"

    with session_scope() as db:
        runs = db.query(ScanEngineRun).filter(ScanEngineRun.scan_id == scan_id).all()
    assert len(runs) == 1, f"{len(runs)} engine runs for one engine — the redelivery ran it again"


def test_a_duplicate_delivery_does_not_duplicate_findings():
    ctx = _estate()
    scan_id = _queue_scan(ctx)

    run_count_before = len(_findings(ctx))
    from guardian_scanner.tasks import run_scan

    run_scan(str(scan_id))
    after_first = _findings(ctx)
    run_scan(str(scan_id))
    after_second = _findings(ctx)

    assert run_count_before == 0
    assert after_first, "the scan produced no finding"
    assert len(after_second) == len(after_first), "the redelivery filed duplicate findings"


# ── what the customer is told ─────────────────────────────────────────────────────────────────────
def test_queue_health_stops_promising_a_scan_will_be_processed_in_order():
    """It said "scans are processed in order" about one that never would be."""
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token
    from guardian_db.models import TenantMembership, User
    from guardian_db.session import session_scope
    from guardian_scanner.recovery import STRANDED_AFTER_SECONDS

    ctx = _estate()
    _queue_scan(ctx, age_seconds=STRANDED_AFTER_SECONDS + 600)
    with session_scope() as db:
        user = User(email=f"qh-{uuid.uuid4().hex[:8]}@example.com", name="U", status="active")
        db.add(user)
        db.flush()
        db.add(TenantMembership(user_id=user.id, tenant_id=ctx["tenant"], role="owner"))
        user_id = user.id

    settings = get_settings()
    token = create_access_token(subject=str(user_id), secret=settings.jwt_secret,
                                algorithm=settings.jwt_algorithm)
    body = TestClient(app).get("/api/v1/scans/queue-health",
                               headers={"Authorization": f"Bearer {token}"}).json()

    assert body["state"] in ("delayed", "stalled"), body
    assert "processed in order" not in body["detail"]
    if body["state"] == "delayed":
        assert "re-submits it automatically" in body["detail"]
