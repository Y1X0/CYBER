"""Discovery operationalization via the Control Plane (Phase 6C.1) — API → enqueue → worker → graph.

Proves discovery is runnable from the real system (not just direct calls in tests), stays tenant-
scoped (RLS) and write-gated, and that the 6C authorization gate is preserved through the API path.
Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


def _auth(role="admin"):
    """Create a tenant/customer/user(+membership) and return (client, headers, tenant_id, customer_id)."""
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token
    from guardian_db.models import Customer, Tenant, TenantMembership, User
    from guardian_db.session import session_scope

    marker = uuid.uuid4().hex[:8]
    with session_scope() as db:
        t = Tenant(name=f"op-{marker}", slug=f"op-{marker}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        u = User(email=f"op-{marker}@x.com", name="U", password_hash="x", status="active")
        db.add(u)
        db.flush()
        db.add(TenantMembership(user_id=u.id, tenant_id=t.id, role=role))
        tid, cid, uid = str(t.id), str(c.id), str(u.id)

    settings = get_settings()
    headers = {"Authorization": "Bearer " + create_access_token(
        subject=uid, secret=settings.jwt_secret, algorithm=settings.jwt_algorithm)}
    return TestClient(app), headers, tid, cid


def _run_inline(monkeypatch):
    """Make the route's enqueue execute the task synchronously (Control Plane → worker, in-process)."""
    import guardian_api.routes.discovery as dr
    from guardian_scanner.discovery.tasks import run_discovery

    monkeypatch.setattr(dr, "enqueue_discovery", lambda rid: run_discovery.apply(args=[rid]).get())


def test_create_run_via_api_runs_discovery_end_to_end(monkeypatch):
    from guardian_db.models import GraphNode
    from guardian_db.session import session_scope

    _run_inline(monkeypatch)
    client, headers, tid, cid = _auth()
    snap = {"ct": {"example.com": ["api.example.com"]},
            "dns": {"example.com": ["93.184.216.34"], "api.example.com": ["93.184.216.34"]}}
    resp = client.post("/api/v1/discovery/runs", headers=headers, json={
        "customer_id": cid, "providers": ["dns", "ct"],
        "seeds": {"domains": ["example.com", "api.example.com"], "settings": snap},
    })
    assert resp.status_code == 202, resp.text
    run_id = resp.json()["id"]

    got = client.get(f"/api/v1/discovery/runs/{run_id}", headers=headers)
    assert got.status_code == 200
    assert got.json()["status"] == "completed"

    with session_scope() as db:
        nodes = db.query(GraphNode).filter(GraphNode.tenant_id == uuid.UUID(tid)).count()
    assert nodes > 0  # the Control-Plane trigger actually produced a graph


def test_get_run_is_tenant_scoped(monkeypatch):
    _run_inline(monkeypatch)
    client_a, headers_a, _, cid_a = _auth()
    resp = client_a.post("/api/v1/discovery/runs", headers=headers_a,
                         json={"customer_id": cid_a, "providers": [], "seeds": {}})
    run_id = resp.json()["id"]

    # A different tenant must not see A's run.
    client_b, headers_b, _, _ = _auth()
    assert client_b.get(f"/api/v1/discovery/runs/{run_id}", headers=headers_b).status_code == 404


def test_create_run_requires_staff_write(monkeypatch):
    _run_inline(monkeypatch)
    # A reviewer is staff but NOT a write role → must be refused.
    client, headers, _, cid = _auth(role="reviewer")
    resp = client.post("/api/v1/discovery/runs", headers=headers,
                       json={"customer_id": cid, "providers": [], "seeds": {}})
    assert resp.status_code == 403


def test_active_gate_preserved_through_api(monkeypatch):
    """An active run through the API still blocks unauthorized targets (6C gate intact)."""
    from guardian_db.models import DomainEvent, GraphNode
    from guardian_db.session import session_scope

    _run_inline(monkeypatch)
    client, headers, tid, cid = _auth()
    resp = client.post("/api/v1/discovery/runs", headers=headers, json={
        "customer_id": cid, "providers": ["service_scan"],
        "seeds": {"active_targets": ["93.184.216.34"],
                  "settings": {"service_scan": {"93.184.216.34": {"443": {"port": 443}}}}},
    })
    assert resp.status_code == 202

    with session_scope() as db:
        services = db.query(GraphNode).filter(
            GraphNode.tenant_id == uuid.UUID(tid), GraphNode.node_type == "service").count()
        blocked = db.query(DomainEvent).filter(
            DomainEvent.tenant_id == uuid.UUID(tid),
            DomainEvent.type == "discovery.target.blocked").count()
    assert services == 0   # no authorization → nothing scanned
    assert blocked == 1    # and the denial was recorded (gate preserved)
