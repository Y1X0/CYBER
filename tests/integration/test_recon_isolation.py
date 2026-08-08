"""Recon execution-plane isolation, end-to-end (Phase 6C.3). Gated by GUARDIAN_RUN_DB_TESTS=1.

Two properties through the *real* run_discovery path:
  * the runtime egress allowlist is bound to exactly the gate-cleared hosts while active providers
    run, and is cleared afterwards (no bleed into the next run/tenant);
  * tenant isolation (RLS) still holds for graph writes made on the recon path.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

_IP = "93.184.216.34"


def _setup(*, targets_auth, active_targets, providers):
    from guardian_db.models import (
        Authorization,
        Customer,
        DiscoveryRun,
        DiscoveryScope,
        Tenant,
        User,
    )
    from guardian_db.session import session_scope

    marker = uuid.uuid4().hex[:8]
    now = dt.datetime.now(dt.UTC)
    with session_scope() as db:
        t = Tenant(name=f"63-{marker}", slug=f"63-{marker}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        u = User(email=f"63-{marker}@x.com", name="U", password_hash="x", status="active")
        db.add(u)
        db.flush()
        db.add(Authorization(
            tenant_id=t.id, customer_id=c.id, asset_id=None, scope="active recon",
            authorized_targets=targets_auth, method="active_recon", authorized_by=u.id,
            valid_from=now - dt.timedelta(hours=1), valid_until=now + dt.timedelta(hours=1),
        ))
        scope = DiscoveryScope(tenant_id=t.id, customer_id=c.id, name="s",
                               seeds={}, providers=providers)
        db.add(scope)
        db.flush()
        run = DiscoveryRun(tenant_id=t.id, customer_id=c.id, scope_id=scope.id, status="queued",
                           trigger="manual", seeds={"active_targets": active_targets})
        db.add(run)
        db.flush()
        return str(t.id), str(run.id)


def test_egress_allowlist_bound_to_authorized_targets_and_cleared(monkeypatch):
    """During active providers the allowlist == the gate-cleared hosts; after the run it is None."""
    from guardian_scanner import egress
    from guardian_scanner.discovery import tasks

    captured: dict = {}

    class _SpyProvider:
        key = "spy"
        requires_authorization = True

        def collect(self, ctx):  # noqa: ANN001
            captured["allowlist"] = egress.current_allowlist()
            captured["authorized_targets"] = list(ctx.authorized_targets)
            return iter(())  # observe only; write nothing

    monkeypatch.setattr(tasks, "available_providers", lambda: {"spy": _SpyProvider()})

    assert egress.current_allowlist() is None
    tid, run_id = _setup(targets_auth=[{"type": "ip", "value": _IP}],
                         active_targets=[_IP], providers=["spy"])
    result = tasks.run_discovery.apply(args=[run_id]).get()

    assert result["status"] == "completed"
    assert captured["authorized_targets"] == [_IP]
    assert captured["allowlist"] == frozenset({_IP})  # bound to exactly the cleared host
    assert egress.current_allowlist() is None          # cleared after the run — no bleed


def test_recon_writes_are_tenant_isolated():
    """Graph nodes written on the recon path never cross tenants under RLS."""
    from guardian_db.session import get_app_session, set_tenant
    from guardian_scanner.discovery.tasks import run_discovery

    snap = {"service_scan": {_IP: {"443": {"port": 443, "tls": {"v": "1.3"}},
                                   "80": {"port": 80, "banner": "nginx"}}}}
    a_tid, a_run = _setup(targets_auth=[{"type": "ip", "value": _IP}],
                          active_targets=[_IP], providers=["service_scan"])
    b_tid, b_run = _setup(targets_auth=[{"type": "ip", "value": _IP}],
                          active_targets=[_IP], providers=["service_scan"])
    # inject the offline snapshot into each run so no live network is needed
    from guardian_db.models import DiscoveryRun
    from guardian_db.session import session_scope
    with session_scope() as db:
        for rid in (a_run, b_run):
            r = db.get(DiscoveryRun, uuid.UUID(rid))
            r.seeds = {**r.seeds, "settings": snap}

    run_discovery.apply(args=[a_run]).get()
    run_discovery.apply(args=[b_run]).get()

    s = get_app_session()
    try:
        row = s.execute(
            text("SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = current_user")
        ).one()
        if row.rolbypassrls or row.rolsuper:
            pytest.skip("app session is not RLS-enforced")
        set_tenant(s, a_tid)
        seen = s.execute(text("SELECT DISTINCT tenant_id::text FROM graph_nodes")).scalars().all()
        assert seen == [a_tid]  # tenant A never sees tenant B's recon-discovered nodes
    finally:
        s.close()
