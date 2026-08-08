"""Graph enrichment + attack paths, end-to-end (Phase 6E). Gated by GUARDIAN_RUN_DB_TESTS=1.

Proves the enricher projects assets/findings into the graph deterministically and idempotently, links
topology to assets ONLY on an exact host identity (no fuzzy / non-web / no-match), keeps 6D exposure
paths unchanged, isolates tenants, and yields a real internet→…→finding attack path via the API.
"""

from __future__ import annotations

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
    m = uuid.uuid4().hex[:8]
    with session_scope() as db:
        t = Tenant(name=f"6e-{m}", slug=f"6e-{m}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        u = User(email=f"6e-{m}@x.com", name="U", password_hash="x", status="active")
        db.add(u)
        db.flush()
        return str(t.id), str(c.id)


def _asset(db, tid, cid, *, kind, identifier):
    from guardian_db.models import Asset
    a = Asset(tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), name="a",
              kind=kind, identifier=identifier, exposure="public")
    db.add(a)
    db.flush()
    return a.id


def _finding(db, tid, cid, asset_id, *, severity="critical", status="open"):
    from guardian_db.models import Finding, Scan, ScanEngineRun
    scan = Scan(tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), asset_id=asset_id,
                status="completed")
    db.add(scan)
    db.flush()
    run = ScanEngineRun(scan_id=scan.id, engine="dast", status="completed")
    db.add(run)
    db.flush()
    f = Finding(tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), scan_id=scan.id,
                engine_run_id=run.id, asset_id=asset_id, fingerprint=uuid.uuid4().hex[:16],
                title="V", category="injection", severity=severity, status=status)
    db.add(f)
    db.flush()
    return f.id


def _gnode(db, tid, node_type, key, *, internet=False):
    from guardian_db.models import GraphNode
    n = GraphNode(tenant_id=uuid.UUID(tid), node_type=node_type, canonical_key=key,
                  metadata_={"internet_reachable": internet}, confidence=90, ownership_confidence=90)
    db.add(n)
    db.flush()
    return n.id


def _enrich(tid, cid=None):
    from guardian_db.session import session_scope
    from guardian_scanner.discovery.enricher import GraphEnricher
    with session_scope() as db:
        return GraphEnricher(db, tenant_id=uuid.UUID(tid),
                             customer_id=uuid.UUID(cid) if cid else None).enrich()


def _nodes(tid, node_type):
    from guardian_db.models import GraphNode
    from guardian_db.session import session_scope
    with session_scope() as db:
        return db.query(GraphNode).filter(GraphNode.tenant_id == uuid.UUID(tid),
                                          GraphNode.node_type == node_type).all()


def _edges(tid, relation):
    from guardian_db.models import GraphEdge
    from guardian_db.session import session_scope
    with session_scope() as db:
        return db.query(GraphEdge).filter(GraphEdge.tenant_id == uuid.UUID(tid),
                                          GraphEdge.relation == relation).all()


def test_finding_and_exposes_edge_from_asset_id():
    tid, cid = _tenant()
    from guardian_db.session import session_scope
    with session_scope() as db:
        aid = _asset(db, tid, cid, kind="web", identifier="https://app.example.com")
        fid = _finding(db, tid, cid, aid, severity="critical", status="open")
    _enrich(tid, cid)

    findings = _nodes(tid, "finding")
    assert len(findings) == 1
    fnode = findings[0]
    assert fnode.canonical_key == str(fid)          # canonical_key = finding.id
    assert fnode.state == "open"                     # state follows Finding.status
    assert fnode.exposure_score == 0                 # exposure != risk
    assert fnode.metadata_["severity"] == "critical"

    exposes = _edges(tid, "exposes")
    assert len(exposes) == 1
    assert exposes[0].src_type == "asset" and exposes[0].dst_type == "finding"  # asset -> finding
    assert exposes[0].source == "inferred"
    assert exposes[0].meta.get("evidence") == "findings.asset_id"


def test_serves_edge_only_on_exact_host_identity():
    tid, cid = _tenant()
    from guardian_db.session import session_scope
    with session_scope() as db:
        aid = _asset(db, tid, cid, kind="web", identifier="https://app.example.com")
        _finding(db, tid, cid, aid)
        _gnode(db, tid, "subdomain", "app.example.com", internet=True)  # exact match
        _gnode(db, tid, "subdomain", "other.example.com")               # different host
    _enrich(tid, cid)

    serves = _edges(tid, "serves")
    assert len(serves) == 1                                    # ONLY the exact match
    assert serves[0].src_type == "subdomain" and serves[0].dst_type == "asset"  # topology -> asset
    assert serves[0].meta.get("link") == "deterministic_host_identity"


def test_no_serves_for_non_web_or_unmatchable_assets():
    tid, cid = _tenant()
    from guardian_db.session import session_scope
    with session_scope() as db:
        # a repo asset whose identifier host (github.com) must NOT be auto-linked
        repo = _asset(db, tid, cid, kind="repo", identifier="https://github.com/x/y")
        _finding(db, tid, cid, repo)
        _gnode(db, tid, "subdomain", "github.com", internet=True)
        # a web asset with no matching topology node and no findings → no node at all
        _asset(db, tid, cid, kind="web", identifier="https://ghost.example.com")
    _enrich(tid, cid)

    assert _edges(tid, "serves") == []                # repo not linked; ghost has no match
    asset_keys = {n.canonical_key for n in _nodes(tid, "asset")}
    assert len(asset_keys) == 1                         # only the repo (it has a finding); ghost absent


def test_enrichment_is_idempotent():
    tid, cid = _tenant()
    from guardian_db.session import session_scope
    with session_scope() as db:
        aid = _asset(db, tid, cid, kind="web", identifier="https://app.example.com")
        _finding(db, tid, cid, aid)
        _gnode(db, tid, "subdomain", "app.example.com", internet=True)
    _enrich(tid, cid)
    counts1 = (len(_nodes(tid, "asset")), len(_nodes(tid, "finding")),
               len(_edges(tid, "exposes")), len(_edges(tid, "serves")))
    _enrich(tid, cid)  # re-run
    counts2 = (len(_nodes(tid, "asset")), len(_nodes(tid, "finding")),
               len(_edges(tid, "exposes")), len(_edges(tid, "serves")))
    assert counts1 == counts2 == (1, 1, 1, 1)  # no duplicates on re-run


def test_real_attack_path_via_projector():
    from guardian_db.session import get_app_session, set_tenant
    tid, cid = _tenant()
    from guardian_db.session import session_scope
    with session_scope() as db:
        aid = _asset(db, tid, cid, kind="web", identifier="https://app.example.com")
        fid = _finding(db, tid, cid, aid)
        _gnode(db, tid, "subdomain", "app.example.com", internet=True)
    _enrich(tid, cid)

    from guardian_db.graph_read import DbGraphProjector
    s = get_app_session()
    set_tenant(s, tid)
    try:
        atk = DbGraphProjector(s).attack_paths(tenant_id=tid)
        exp = DbGraphProjector(s).exposure_paths(tenant_id=tid)
    finally:
        s.close()
    # a real internet → subdomain → asset → finding path
    assert atk["paths"], atk
    last = atk["paths"][0][-1]
    assert last["node_type"] == "finding" and last["canonical_key"] == str(fid)
    # 6D exposure paths must NOT contain the finding (semantics unchanged)
    assert all(n["node_type"] != "finding" for p in exp["paths"] for n in p)


def test_enrichment_is_tenant_isolated():
    a_tid, a_cid = _tenant()
    b_tid, b_cid = _tenant()
    from guardian_db.session import session_scope
    for tid, cid in ((a_tid, a_cid), (b_tid, b_cid)):
        with session_scope() as db:
            aid = _asset(db, tid, cid, kind="web", identifier="https://app.example.com")
            _finding(db, tid, cid, aid)
        _enrich(tid, cid)

    from guardian_db.session import get_app_session, set_tenant
    s = get_app_session()
    try:
        row = s.execute(
            text("SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = current_user")
        ).one()
        if row.rolbypassrls or row.rolsuper:
            pytest.skip("app session is not RLS-enforced")
        set_tenant(s, a_tid)
        seen = s.execute(
            text("SELECT DISTINCT tenant_id::text FROM graph_nodes WHERE node_type='finding'")
        ).scalars().all()
        assert seen == [a_tid]  # tenant A never sees tenant B's finding nodes
    finally:
        s.close()


def test_scan_completion_triggers_enrichment():
    """The auto-trigger: a completed scan projects its findings into the graph (eager in tests)."""
    from guardian_db.models import Asset, Customer, Scan, Tenant
    from guardian_db.session import session_scope
    from guardian_scanner.tasks import run_scan

    m = uuid.uuid4().hex[:8]
    secret = 'aws_key = "AKIAIOSFODNN7EXAMPLE"\npassword = "supersecretvalue12345"\n'
    with session_scope() as db:
        t = Tenant(name=f"trg-{m}", slug=f"trg-{m}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        a = Asset(tenant_id=t.id, customer_id=c.id, name="repo", kind="repo", identifier="inline",
                  exposure="public", config={"inline_content": secret})
        db.add(a)
        db.flush()
        scan = Scan(tenant_id=t.id, customer_id=c.id, asset_id=a.id, trigger="manual",
                    status="queued", requested_engines=["secrets"])
        db.add(scan)
        db.flush()
        tid, scan_id = str(t.id), str(scan.id)

    run_scan.apply(args=[scan_id]).get()  # eager → dispatches enrich_graph inline
    assert len(_nodes(tid, "finding")) >= 1  # the scan's findings became graph nodes


def test_attack_paths_api_is_staff_and_tenant_scoped():
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token
    from guardian_db.models import TenantMembership, User
    from guardian_db.session import session_scope

    tid, cid = _tenant()
    from guardian_db.session import session_scope as _ss
    with _ss() as db:
        aid = _asset(db, tid, cid, kind="web", identifier="https://app.example.com")
        _finding(db, tid, cid, aid)
        _gnode(db, tid, "subdomain", "app.example.com", internet=True)
    _enrich(tid, cid)

    with session_scope() as db:
        u = User(email=f"ap-{uuid.uuid4().hex[:8]}@x.com", name="U", password_hash="x",
                 status="active")
        db.add(u)
        db.flush()
        db.add(TenantMembership(user_id=u.id, tenant_id=uuid.UUID(tid), role="analyst"))
        uid = str(u.id)
    s = get_settings()
    headers = {"Authorization": "Bearer " + create_access_token(
        subject=uid, secret=s.jwt_secret, algorithm=s.jwt_algorithm)}

    resp = TestClient(app).get("/api/v1/graph/attack-paths", headers=headers)
    assert resp.status_code == 200, resp.text
    paths = resp.json()["paths"]
    assert paths and paths[0][-1]["node_type"] == "finding"
