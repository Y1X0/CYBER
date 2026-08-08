"""End-to-end active discovery (Phase 6C) — authorized, scope-checked, auditable service scan.

Proves the safety contract the CTO fixed: no network before authorization; authorization comes only
from a valid, tenant-owned DB record; the provider stays limited; and every property (dedup, TLS-change
provenance, cross-tenant isolation, RLS) holds. Gated by GUARDIAN_RUN_DB_TESTS=1.
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
_TLS_A = {"version": "TLSv1.3", "subject": "CN=example.com"}
_TLS_B = {"version": "TLSv1.3", "subject": "CN=new.example.com"}


def _snapshot(tls=_TLS_A):
    return {"service_scan": {_IP: {"443": {"port": 443, "tls": tls},
                                   "80": {"port": 80, "banner": "nginx"}}}}


def _setup(*, targets_auth, active_targets, snapshot=None, allow_live=False, valid=True):
    """Create tenant/customer/user + an active-recon authorization + a scope + a run. Returns ids."""
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
        t = Tenant(name=f"6c-{marker}", slug=f"6c-{marker}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        u = User(email=f"6c-{marker}@x.com", name="U", password_hash="x", status="active")
        db.add(u)
        db.flush()
        if targets_auth is not None:
            db.add(Authorization(
                tenant_id=t.id, customer_id=c.id, asset_id=None, scope="active recon",
                authorized_targets=targets_auth, method="active_recon", authorized_by=u.id,
                valid_from=now - dt.timedelta(hours=1),
                valid_until=now + (dt.timedelta(hours=1) if valid else dt.timedelta(hours=-1)),
            ))
        scope = DiscoveryScope(tenant_id=t.id, customer_id=c.id, name="s",
                               seeds={}, providers=["service_scan"])
        db.add(scope)
        db.flush()
        settings = dict(snapshot or {})
        if allow_live:
            settings["allow_live"] = True
        run = DiscoveryRun(tenant_id=t.id, customer_id=c.id, scope_id=scope.id, status="queued",
                           trigger="manual", seeds={"active_targets": active_targets,
                                                    "settings": settings})
        db.add(run)
        db.flush()
        return str(t.id), str(run.id)


def _events(tenant_id, type_):
    from guardian_db.models import DomainEvent
    from guardian_db.session import session_scope

    with session_scope() as db:
        return db.query(DomainEvent).filter(
            DomainEvent.tenant_id == uuid.UUID(tenant_id), DomainEvent.type == type_
        ).count()


def _service_nodes(tenant_id):
    from guardian_db.models import GraphNode
    from guardian_db.session import session_scope

    with session_scope() as db:
        return db.query(GraphNode).filter(
            GraphNode.tenant_id == uuid.UUID(tenant_id), GraphNode.node_type == "service"
        ).all()


def test_authorized_target_is_scanned():
    from guardian_scanner.discovery.tasks import run_discovery

    tid, run_id = _setup(targets_auth=[{"type": "ip", "value": _IP}],
                         active_targets=[_IP], snapshot=_snapshot())
    result = run_discovery.apply(args=[run_id]).get()
    assert result["status"] == "completed"

    nodes = {n.canonical_key: n for n in _service_nodes(tid)}
    assert f"{_IP}:443" in nodes
    assert nodes[f"{_IP}:443"].metadata_.get("tls") == _TLS_A
    from guardian_db.models import GraphEdge
    from guardian_db.session import session_scope
    with session_scope() as db:
        hosts = db.query(GraphEdge).filter(
            GraphEdge.tenant_id == uuid.UUID(tid), GraphEdge.relation == "hosts"
        ).count()
    assert hosts >= 1  # ip --hosts--> service


def test_unauthorized_target_blocked_before_any_network(monkeypatch):
    """The core guarantee: an unauthorized target never opens a socket, and the denial is audited.

    6C.2 note: the live network now runs via the protocol probes' sandbox call, so the tripwire moved
    to `sandbox.run_in_sandbox` — if the gate leaked, ANY live probe attempt raises here and fails
    the test. Stricter than before; same guarantee.
    """
    from guardian_scanner import sandbox
    from guardian_scanner.discovery.tasks import run_discovery

    def _boom(*_a, **_k):  # must never be reached for a blocked target
        raise AssertionError("NETWORK ATTEMPTED for an unauthorized target")

    monkeypatch.setattr(sandbox, "run_in_sandbox", _boom)

    # allow_live=True so that IF the gate leaked, a probe WOULD hit the sandbox and blow up.
    tid, run_id = _setup(targets_auth=[{"type": "ip", "value": _IP}],
                         active_targets=["10.0.0.5"], allow_live=True)  # 10.0.0.5 not authorized
    result = run_discovery.apply(args=[run_id]).get()  # must NOT raise

    assert result["status"] == "completed"
    assert _service_nodes(tid) == []                       # nothing scanned
    assert _events(tid, "discovery.target.blocked") == 1   # denial recorded in the event trail
    # And the audit log carries it too.
    from guardian_db.session import session_scope
    with session_scope() as db:
        audited = db.execute(text(
            "SELECT count(*) FROM audit_log WHERE tenant_id = :t "
            "AND action = 'discovery.target.blocked'"), {"t": tid}).scalar()
    assert audited == 1


def test_expired_authorization_blocks():
    from guardian_scanner.discovery.tasks import run_discovery

    tid, run_id = _setup(targets_auth=[{"type": "ip", "value": _IP}], active_targets=[_IP],
                         snapshot=_snapshot(), valid=False)  # authorization window in the past
    run_discovery.apply(args=[run_id]).get()
    assert _service_nodes(tid) == []
    assert _events(tid, "discovery.target.blocked") == 1


def test_out_of_scope_target_blocks():
    from guardian_scanner.discovery.tasks import run_discovery

    # Authorization covers example.com; the target is a different domain's IP.
    tid, run_id = _setup(targets_auth=[{"type": "domain", "value": "example.com"}],
                         active_targets=["8.8.8.8"], snapshot=_snapshot())
    run_discovery.apply(args=[run_id]).get()
    assert _service_nodes(tid) == []
    assert _events(tid, "discovery.target.blocked") == 1


def test_no_authorization_at_all_blocks():
    from guardian_scanner.discovery.tasks import run_discovery

    tid, run_id = _setup(targets_auth=None, active_targets=[_IP], snapshot=_snapshot())
    run_discovery.apply(args=[run_id]).get()
    assert _service_nodes(tid) == []
    assert _events(tid, "discovery.target.blocked") == 1


def test_duplicate_scan_no_duplicate_service_node():
    from guardian_db.models import Customer, DiscoveryRun, DiscoveryScope
    from guardian_db.session import session_scope
    from guardian_scanner.discovery.tasks import run_discovery

    tid, run_id = _setup(targets_auth=[{"type": "ip", "value": _IP}], active_targets=[_IP],
                         snapshot=_snapshot())
    run_discovery.apply(args=[run_id]).get()
    first = len(_service_nodes(tid))

    with session_scope() as db:
        c = db.query(Customer).filter(Customer.tenant_id == uuid.UUID(tid)).first()
        scope = db.query(DiscoveryScope).filter(DiscoveryScope.tenant_id == uuid.UUID(tid)).first()
        run2 = DiscoveryRun(tenant_id=uuid.UUID(tid), customer_id=c.id, scope_id=scope.id,
                            status="queued", trigger="manual",
                            seeds={"active_targets": [_IP], "settings": _snapshot()})
        db.add(run2)
        db.flush()
        run2_id = str(run2.id)
    run_discovery.apply(args=[run2_id]).get()
    assert len(_service_nodes(tid)) == first  # upsert, not duplicate


def test_tls_change_recorded_in_history():
    from guardian_db.models import Customer, DiscoveryRun, DiscoveryScope, NodeEvent
    from guardian_db.session import session_scope
    from guardian_scanner.discovery.tasks import run_discovery

    tid, run_id = _setup(targets_auth=[{"type": "ip", "value": _IP}], active_targets=[_IP],
                         snapshot=_snapshot(_TLS_A))
    run_discovery.apply(args=[run_id]).get()

    # Second run: same service, different certificate.
    with session_scope() as db:
        c = db.query(Customer).filter(Customer.tenant_id == uuid.UUID(tid)).first()
        scope = db.query(DiscoveryScope).filter(DiscoveryScope.tenant_id == uuid.UUID(tid)).first()
        run2 = DiscoveryRun(tenant_id=uuid.UUID(tid), customer_id=c.id, scope_id=scope.id,
                            status="queued", trigger="manual",
                            seeds={"active_targets": [_IP], "settings": _snapshot(_TLS_B)})
        db.add(run2)
        db.flush()
        run2_id = str(run2.id)
    run_discovery.apply(args=[run2_id]).get()

    with session_scope() as db:
        tls_events = db.query(NodeEvent).filter(
            NodeEvent.tenant_id == uuid.UUID(tid), NodeEvent.event_type == "tls_changed"
        ).count()
    assert tls_events >= 1  # the certificate change is in the node's history


def test_service_nodes_isolated_across_tenants():
    from guardian_db.session import get_app_session, set_tenant
    from guardian_scanner.discovery.tasks import run_discovery

    a_tid, a_run = _setup(targets_auth=[{"type": "ip", "value": _IP}], active_targets=[_IP],
                          snapshot=_snapshot())
    b_tid, b_run = _setup(targets_auth=[{"type": "ip", "value": _IP}], active_targets=[_IP],
                          snapshot=_snapshot())
    run_discovery.apply(args=[a_run]).get()
    run_discovery.apply(args=[b_run]).get()

    s = get_app_session()
    try:
        row = s.execute(text("SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = current_user")).one()
        if row.rolbypassrls or row.rolsuper:
            pytest.skip("app session is not RLS-enforced")
        set_tenant(s, a_tid)
        seen = s.execute(text("SELECT DISTINCT tenant_id::text FROM graph_nodes")).scalars().all()
        assert seen == [a_tid]  # tenant A never sees tenant B's discovered services
    finally:
        s.close()


def test_sandbox_timeout_is_contained(monkeypatch):
    """A probe that breaches the sandbox limits yields no result and never crashes the run.

    6C.2 note: sandbox-containment moved from the provider's private `_probe_one` into the protocol
    probe. The BEHAVIOR is unchanged (violation → None); only the call site moved, so the assertion
    now targets the probe directly.
    """
    from guardian_scanner import sandbox
    from guardian_scanner.discovery.protocols.tls_probe import TlsProbe

    def _raise(*_a, **_k):
        raise sandbox.SandboxViolation("bounded out")

    monkeypatch.setattr(sandbox, "run_in_sandbox", _raise)
    # allow_live with no snapshot → goes through the sandbox path, which raises → contained as None.
    assert TlsProbe().probe(_IP, 443, timeout=1, allow_live=True, snapshot=None) is None
