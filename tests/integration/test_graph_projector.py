"""Attack-graph read plane, end-to-end (Phase 6D). Gated by GUARDIAN_RUN_DB_TESTS=1.

Proves the projector reads a real tenant subgraph deterministically, enriches with findings via a
read-only join (no synthetic edges), classifies drift from real node history, and — the
non-negotiable — never crosses tenants (RLS + explicit filter). Plus graph-API authorization.
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


def _tenant():
    from guardian_db.models import Customer, Tenant, User
    from guardian_db.session import session_scope

    marker = uuid.uuid4().hex[:8]
    with session_scope() as db:
        t = Tenant(name=f"6d-{marker}", slug=f"6d-{marker}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        u = User(email=f"6d-{marker}@x.com", name="U", password_hash="x", status="active")
        db.add(u)
        db.flush()
        return str(t.id), str(c.id), str(u.id)


def _node(db, tid, node_type, key, *, exposure=0, internet=False, state="active",
          customer_id=None, asset_id=None):
    from guardian_db.models import GraphNode
    n = GraphNode(
        tenant_id=uuid.UUID(tid), node_type=node_type, canonical_key=key,
        metadata_={"internet_reachable": internet}, exposure_score=exposure, state=state,
        customer_id=uuid.UUID(customer_id) if customer_id else None, asset_id=asset_id,
        confidence=90, ownership_confidence=90,
    )
    db.add(n)
    db.flush()
    return n.id


def _edge(db, tid, src_id, relation, dst_id, *, src_type="subdomain", dst_type="ip_address"):
    from guardian_db.models import GraphEdge
    db.add(GraphEdge(
        tenant_id=uuid.UUID(tid), src_type=src_type, src_id=str(src_id), relation=relation,
        dst_type=dst_type, dst_id=str(dst_id), state="active", source="dns", confidence=90,
        first_seen_at=dt.datetime.now(dt.UTC), last_seen_at=dt.datetime.now(dt.UTC),
    ))


def _seed_chain(tid):
    """sub(internet) --resolves_to--> ip --hosts--> service(exposed). Returns the node ids."""
    from guardian_db.session import session_scope
    with session_scope() as db:
        sub = _node(db, tid, "subdomain", "a.example.com", internet=True)
        ip = _node(db, tid, "ip_address", "1.2.3.4")
        svc = _node(db, tid, "service", "1.2.3.4:443", exposure=70)
        _edge(db, tid, sub, "resolves_to", ip, src_type="subdomain", dst_type="ip_address")
        _edge(db, tid, ip, "hosts", svc, src_type="ip_address", dst_type="service")
        return str(sub), str(ip), str(svc)


def _projector(tid):
    from guardian_db.graph_read import DbGraphProjector
    from guardian_db.session import get_app_session, set_tenant
    s = get_app_session()
    set_tenant(s, tid)
    return DbGraphProjector(s), s


def test_exposure_paths_over_real_subgraph():
    tid, _, _ = _tenant()
    sub, ip, svc = _seed_chain(tid)
    proj, s = _projector(tid)
    try:
        out = proj.exposure_paths(tenant_id=tid)
    finally:
        s.close()
    assert out["truncated"] is False
    assert [[n["id"] for n in p] for p in out["paths"]] == [[sub, ip, svc]]


def test_blast_radius_and_chokepoint_over_real_subgraph():
    tid, _, _ = _tenant()
    sub, ip, svc = _seed_chain(tid)
    proj, s = _projector(tid)
    try:
        b = proj.blast_radius(tenant_id=tid, node_type="", node_id=sub)
        ch = proj.chokepoints(tenant_id=tid)
    finally:
        s.close()
    assert b["affected_nodes"] == 2 and b["sensitive_nodes"] == 1 and b["exposure_paths"] == 1
    ip_cp = next(c for c in ch["chokepoints"] if c["node_id"] == ip)
    assert ip_cp["paths_cut"] == 1 and ip_cp["fraction"] == 1.0
    assert ip_cp["evidence_paths"]  # explainable


def test_findings_enrich_sensitivity_via_read_join():
    """A low-exposure service linked to an asset with a CRITICAL finding becomes sensitive — via a
    read-only join (findings.asset_id), NOT a synthetic finding node or exposes edge."""
    from guardian_db.models import (
        Asset,
        Finding,
        Scan,
        ScanEngineRun,
    )
    from guardian_db.session import session_scope

    tid, cid, uid = _tenant()
    with session_scope() as db:
        asset = Asset(tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), name="web",
                      kind="web", identifier="https://svc", exposure="public")
        db.add(asset)
        db.flush()
        scan = Scan(tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), asset_id=asset.id,
                    status="completed")
        db.add(scan)
        db.flush()
        run = ScanEngineRun(scan_id=scan.id, engine="dast", status="completed")
        db.add(run)
        db.flush()
        db.add(Finding(
            tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), scan_id=scan.id,
            engine_run_id=run.id, asset_id=asset.id, fingerprint="fp1", title="RCE",
            category="injection", severity="critical", status="open",
        ))
        sub = _node(db, tid, "subdomain", "b.example.com", internet=True)
        # low exposure (below threshold) but linked to the asset with a critical finding
        svc = _node(db, tid, "service", "5.6.7.8:443", exposure=10, asset_id=asset.id)
        _edge(db, tid, sub, "resolves_to", svc, src_type="subdomain", dst_type="service")
        sub_id, svc_id = str(sub), str(svc)

    proj, s = _projector(tid)
    try:
        out = proj.exposure_paths(tenant_id=tid)
    finally:
        s.close()
    # the service is a sensitive endpoint ONLY because of the finding enrichment
    assert [[n["id"] for n in p] for p in out["paths"]] == [[sub_id, svc_id]]


def test_exposure_drift_from_real_node_events():
    from guardian_db.models import NodeEvent
    from guardian_db.session import session_scope

    tid, _, _ = _tenant()
    with session_scope() as db:
        nid = _node(db, tid, "service", "9.9.9.9:443", exposure=60)
        db.add(NodeEvent(tenant_id=uuid.UUID(tid), node_id=nid, event_type="observed",
                         detail={}, occurred_at=dt.datetime(2026, 3, 1, tzinfo=dt.UTC)))
        db.add(NodeEvent(tenant_id=uuid.UUID(tid), node_id=nid, event_type="changed",
                         detail={"changes": ["exposure 20->60"]},
                         occurred_at=dt.datetime(2026, 3, 2, tzinfo=dt.UTC)))

    proj, s = _projector(tid)
    try:
        out = proj.exposure_drift(
            tenant_id=tid, since="2026-01-01T00:00:00+00:00", until="2026-12-31T00:00:00+00:00")
    finally:
        s.close()
    kinds = sorted(i["kind"] for i in out["items"])
    assert kinds == ["appeared", "newly_exposed"]


def test_projector_never_crosses_tenants():
    a_tid, _, _ = _tenant()
    b_tid, _, _ = _tenant()
    _seed_chain(a_tid)
    b_sub, b_ip, b_svc = _seed_chain(b_tid)

    # Projector bound to A must never surface B's nodes.
    proj, s = _projector(a_tid)
    try:
        a_paths = proj.exposure_paths(tenant_id=a_tid)
        # RLS assertion (skip if the app session isn't RLS-enforced in this env)
        row = s.execute(
            text("SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = current_user")
        ).one()
        rls = not (row.rolbypassrls or row.rolsuper)
    finally:
        s.close()
    a_ids = {n["id"] for p in a_paths["paths"] for n in p}
    assert b_sub not in a_ids and b_ip not in a_ids and b_svc not in a_ids

    if rls:
        proj_b, sb = _projector(b_tid)
        try:
            b_paths = proj_b.exposure_paths(tenant_id=b_tid)
        finally:
            sb.close()
        b_ids = {n["id"] for p in b_paths["paths"] for n in p}
        assert b_ids and not (b_ids & a_ids)  # disjoint tenant subgraphs


# ── Graph API authorization ──
def test_graph_api_staff_can_read_and_is_tenant_scoped():
    tid, _, _ = _tenant()
    sub, ip, svc = _seed_chain(tid)
    # authenticate as a staff member OF THAT tenant
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token
    from guardian_db.models import TenantMembership, User
    from guardian_db.session import session_scope
    with session_scope() as db:
        u = User(email=f"gs-{uuid.uuid4().hex[:8]}@x.com", name="U", password_hash="x",
                 status="active")
        db.add(u)
        db.flush()
        db.add(TenantMembership(user_id=u.id, tenant_id=uuid.UUID(tid), role="analyst"))
        uid = str(u.id)
    settings = get_settings()
    headers = {"Authorization": "Bearer " + create_access_token(
        subject=uid, secret=settings.jwt_secret, algorithm=settings.jwt_algorithm)}
    client = TestClient(app)

    resp = client.get("/api/v1/graph/exposure-paths", headers=headers)
    assert resp.status_code == 200, resp.text
    assert [[n["id"] for n in p] for p in resp.json()["paths"]] == [[sub, ip, svc]]


def test_graph_api_requires_authentication():
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    assert TestClient(app).get("/api/v1/graph/exposure-paths").status_code in (401, 403)


def test_staff_dependency_rejects_non_staff():
    """The read routes are staff-only: a portal (non-staff) principal is refused (no DB needed)."""
    from fastapi import HTTPException
    from guardian_api.deps import Identity
    from guardian_api.routes.graph import _staff

    portal = Identity(user=None, tenant_id=uuid.uuid4(), staff_role=None,
                      portal_customer_id=uuid.uuid4())
    with pytest.raises(HTTPException) as ei:
        _staff(portal)
    assert ei.value.status_code == 403
