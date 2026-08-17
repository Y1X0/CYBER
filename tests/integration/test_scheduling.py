"""Recurring schedules and the sweep that enqueues them (WP-A3).

A subscription is sold on recurring work, so this is the machinery a customer actually pays for.
Two behaviours are worth more than the plumbing and are tested first:

  * a missed window produces ONE run, not one per interval the worker was down — the alternative
    turns an outage into a burst of scans against the customer's own systems, and a burst of
    charges;
  * a schedule that cannot succeed is disabled rather than retried forever against a target that
    no longer exists.

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


def _now():
    return dt.datetime.now(dt.UTC)


def _tenant_with_asset():
    from guardian_db.models import Asset, Customer, Tenant
    from guardian_db.session import session_scope

    marker = uuid.uuid4().hex[:8]
    with session_scope() as db:
        t = Tenant(name=f"sched-{marker}", slug=f"sched-{marker}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        a = Asset(tenant_id=t.id, customer_id=c.id, name=f"repo-{marker}", kind="repo",
                  identifier=f"https://example.invalid/{marker}.git", config={})
        db.add(a)
        db.flush()
        return str(t.id), str(c.id), str(a.id)


@pytest.fixture(autouse=True)
def _no_real_publish(monkeypatch):
    """The sweep must create rows and publish; the broker itself is not what these tests assert."""
    published: list[tuple[str, str]] = []
    monkeypatch.setattr("guardian_scanner.scheduling._publish",
                        lambda task, row_id: published.append((task, row_id)))
    return published


# ── the sweep enqueues due work ───────────────────────────────────────────────────────────────────
def test_due_scan_schedule_creates_a_queued_scan(_no_real_publish):
    from guardian_db.models import Scan
    from guardian_db.session import session_scope
    from guardian_scanner.scheduling import sweep_schedules, upsert_schedule

    tid, cid, aid = _tenant_with_asset()
    with session_scope() as db:
        upsert_schedule(db, tenant_id=tid, kind="scan", target_id=uuid.UUID(aid),
                        customer_id=uuid.UUID(cid), interval_seconds=3600,
                        settings={"engines": ["secrets"]})

    result = sweep_schedules()
    assert result["enqueued"] >= 1

    with session_scope() as db:
        scans = db.query(Scan).filter(Scan.tenant_id == uuid.UUID(tid)).all()
        assert len(scans) == 1
        assert scans[0].trigger == "schedule"
        assert scans[0].status == "queued"
        assert scans[0].requested_engines == ["secrets"]
    assert ("guardian.run_scan", str(scans[0].id)) in _no_real_publish


def test_schedule_not_yet_due_is_left_alone(_no_real_publish):
    from guardian_db.models import Scan, Schedule
    from guardian_db.session import session_scope
    from guardian_scanner.scheduling import sweep_schedules, upsert_schedule

    tid, cid, aid = _tenant_with_asset()
    with session_scope() as db:
        s = upsert_schedule(db, tenant_id=tid, kind="scan", target_id=uuid.UUID(aid),
                            customer_id=uuid.UUID(cid), interval_seconds=3600)
        s.next_run_at = _now() + dt.timedelta(hours=1)

    sweep_schedules()
    with session_scope() as db:
        assert db.query(Scan).filter(Scan.tenant_id == uuid.UUID(tid)).count() == 0
        assert db.query(Schedule).filter(Schedule.tenant_id == uuid.UUID(tid)).one().enabled


def test_disabled_schedule_is_skipped(_no_real_publish):
    from guardian_db.models import Scan
    from guardian_db.session import session_scope
    from guardian_scanner.scheduling import sweep_schedules, upsert_schedule

    tid, cid, aid = _tenant_with_asset()
    with session_scope() as db:
        upsert_schedule(db, tenant_id=tid, kind="scan", target_id=uuid.UUID(aid),
                        customer_id=uuid.UUID(cid), interval_seconds=3600, enabled=False)
    sweep_schedules()
    with session_scope() as db:
        assert db.query(Scan).filter(Scan.tenant_id == uuid.UUID(tid)).count() == 0


# ── the stampede property ─────────────────────────────────────────────────────────────────────────
def test_a_long_outage_produces_one_run_not_one_per_missed_interval(_no_real_publish):
    """Six hours down with an hourly schedule is one run late, not six runs behind.

    Accumulating `next_run_at + interval` would fire every missed window the moment the worker
    returned — a self-inflicted burst against the customer's systems, and six times the charge.
    """
    from guardian_db.models import Scan, Schedule
    from guardian_db.session import session_scope
    from guardian_scanner.scheduling import sweep_schedules, upsert_schedule

    tid, cid, aid = _tenant_with_asset()
    with session_scope() as db:
        s = upsert_schedule(db, tenant_id=tid, kind="scan", target_id=uuid.UUID(aid),
                            customer_id=uuid.UUID(cid), interval_seconds=3600)
        s.next_run_at = _now() - dt.timedelta(hours=6)

    sweep_schedules()
    with session_scope() as db:
        assert db.query(Scan).filter(Scan.tenant_id == uuid.UUID(tid)).count() == 1
        schedule = db.query(Schedule).filter(Schedule.tenant_id == uuid.UUID(tid)).one()
        # Next due is an hour from NOW, not five hours in the past.
        assert schedule.next_run_at > _now() + dt.timedelta(minutes=50)


def test_repeated_sweeps_do_not_duplicate_work(_no_real_publish):
    from guardian_db.models import Scan
    from guardian_db.session import session_scope
    from guardian_scanner.scheduling import sweep_schedules, upsert_schedule

    tid, cid, aid = _tenant_with_asset()
    with session_scope() as db:
        upsert_schedule(db, tenant_id=tid, kind="scan", target_id=uuid.UUID(aid),
                        customer_id=uuid.UUID(cid), interval_seconds=3600)
    sweep_schedules()
    sweep_schedules()
    sweep_schedules()
    with session_scope() as db:
        assert db.query(Scan).filter(Scan.tenant_id == uuid.UUID(tid)).count() == 1


# ── failure handling ──────────────────────────────────────────────────────────────────────────────
def test_a_schedule_whose_target_vanished_is_eventually_disabled(_no_real_publish):
    from guardian_db.models import Schedule
    from guardian_db.session import session_scope
    from guardian_scanner.scheduling import (
        MAX_CONSECUTIVE_FAILURES,
        sweep_schedules,
        upsert_schedule,
    )

    tid, cid, _aid = _tenant_with_asset()
    ghost = uuid.uuid4()
    with session_scope() as db:
        upsert_schedule(db, tenant_id=tid, kind="scan", target_id=ghost,
                        customer_id=uuid.UUID(cid), interval_seconds=300)

    for _ in range(MAX_CONSECUTIVE_FAILURES):
        with session_scope() as db:
            db.query(Schedule).filter(Schedule.tenant_id == uuid.UUID(tid)).one().next_run_at = _now()
        sweep_schedules()

    with session_scope() as db:
        schedule = db.query(Schedule).filter(Schedule.tenant_id == uuid.UUID(tid)).one()
        assert schedule.enabled is False
        assert schedule.last_status == "failed"


def test_one_failing_schedule_does_not_stop_the_sweep(_no_real_publish):
    from guardian_db.models import Scan
    from guardian_db.session import session_scope
    from guardian_scanner.scheduling import sweep_schedules, upsert_schedule

    bad_tid, bad_cid, _ = _tenant_with_asset()
    good_tid, good_cid, good_aid = _tenant_with_asset()
    with session_scope() as db:
        upsert_schedule(db, tenant_id=bad_tid, kind="scan", target_id=uuid.uuid4(),
                        customer_id=uuid.UUID(bad_cid), interval_seconds=300)
        upsert_schedule(db, tenant_id=good_tid, kind="scan", target_id=uuid.UUID(good_aid),
                        customer_id=uuid.UUID(good_cid), interval_seconds=300)

    result = sweep_schedules()
    assert result["failed"] >= 1
    assert result["enqueued"] >= 1
    with session_scope() as db:
        assert db.query(Scan).filter(Scan.tenant_id == uuid.UUID(good_tid)).count() == 1


def test_an_asset_from_another_tenant_is_refused(_no_real_publish):
    """A schedule must never reach across tenants, even by a mistyped id."""
    from guardian_db.models import Scan, Schedule
    from guardian_db.session import session_scope
    from guardian_scanner.scheduling import sweep_schedules, upsert_schedule

    _a_tid, _a_cid, a_asset = _tenant_with_asset()
    b_tid, b_cid, _b_asset = _tenant_with_asset()
    with session_scope() as db:
        upsert_schedule(db, tenant_id=b_tid, kind="scan", target_id=uuid.UUID(a_asset),
                        customer_id=uuid.UUID(b_cid), interval_seconds=300)

    sweep_schedules()
    with session_scope() as db:
        assert db.query(Scan).filter(Scan.tenant_id == uuid.UUID(b_tid)).count() == 0
        assert db.query(Schedule).filter(
            Schedule.tenant_id == uuid.UUID(b_tid)).one().last_status == "failed"


# ── discovery schedules ───────────────────────────────────────────────────────────────────────────
def test_discovery_schedule_creates_a_run(_no_real_publish):
    from guardian_db.models import DiscoveryRun
    from guardian_db.session import session_scope
    from guardian_scanner.scheduling import sweep_schedules, upsert_schedule

    tid, cid, _aid = _tenant_with_asset()
    with session_scope() as db:
        upsert_schedule(db, tenant_id=tid, kind="discovery", customer_id=uuid.UUID(cid),
                        interval_seconds=86400,
                        settings={"seeds": {"domains": ["example.com"]}})

    sweep_schedules()
    with session_scope() as db:
        runs = db.query(DiscoveryRun).filter(DiscoveryRun.tenant_id == uuid.UUID(tid)).all()
        assert len(runs) == 1
        assert runs[0].trigger == "schedule"
        assert runs[0].seeds == {"domains": ["example.com"]}


# ── upsert semantics ──────────────────────────────────────────────────────────────────────────────
def test_re_registering_updates_cadence_rather_than_doubling_it(_no_real_publish):
    """Registering the same schedule twice must not double a customer's scan volume — or bill."""
    from guardian_db.models import Schedule
    from guardian_db.session import session_scope
    from guardian_scanner.scheduling import upsert_schedule

    tid, cid, aid = _tenant_with_asset()
    with session_scope() as db:
        upsert_schedule(db, tenant_id=tid, kind="scan", target_id=uuid.UUID(aid),
                        customer_id=uuid.UUID(cid), interval_seconds=3600)
    with session_scope() as db:
        upsert_schedule(db, tenant_id=tid, kind="scan", target_id=uuid.UUID(aid),
                        customer_id=uuid.UUID(cid), interval_seconds=7200)
    with session_scope() as db:
        rows = db.query(Schedule).filter(Schedule.tenant_id == uuid.UUID(tid)).all()
        assert len(rows) == 1
        assert rows[0].interval_seconds == 7200
