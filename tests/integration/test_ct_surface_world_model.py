"""ct_surface → World Model, end-to-end (Provider #4, ADR-0026 Option 2). Gated by
GUARDIAN_RUN_DB_TESTS=1.

Proves the REAL seam the Discovery flagged — that a CT `discovered_asset` does not die at provider
output but flows all the way into the World Model:

    CT discovered_asset
      → Evidence hash-chain (persisted, tamper-evident)
      → DiscoveryRun(trigger="tool")            (real run, never NULL)
      → DbGraphIngestor
      → SUBDOMAIN GraphNode + SUBDOMAIN_OF edge (stamped with discovery_run_id == run.id)
      → ownership/customer scoping              (from the parent domain's managed asset)
      → dedup / lifecycle                       (re-run updates, never duplicates)

Runs the actual CtSurfaceProvider through the real dispatch pipeline (offline CT snapshot), so
governance, scope, signing, the sandbox, evidence persistence, and the binder are all exercised.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

_SNAPSHOT = {"example.com": ["www.example.com", "api.example.com", "example.com"]}


def _tenant_customer_asset_authz(domain, *, with_asset):
    from guardian_db.models import (
        Asset,
        Authorization,
        Customer,
        Tenant,
        TenantMembership,
        User,
    )
    from guardian_db.session import session_scope

    m = uuid.uuid4().hex[:8]
    now = dt.datetime.now(dt.UTC)
    with session_scope() as db:
        t = Tenant(name=f"ct-{m}", slug=f"ct-{m}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        u = User(email=f"ct-{m}@x.com", name="U", password_hash="x", status="active")
        db.add(u)
        db.flush()
        db.add(TenantMembership(user_id=u.id, tenant_id=t.id, role="pentester"))
        if with_asset:
            db.add(Asset(tenant_id=t.id, customer_id=c.id, name=domain, kind="web",
                         identifier=f"https://{domain}", exposure="external"))
        db.add(Authorization(
            tenant_id=t.id, customer_id=c.id, asset_id=None, scope="s",
            authorized_targets=[{"type": "domain", "value": domain}],
            method="active_recon", authorized_by=u.id,
            valid_from=now - dt.timedelta(hours=1), valid_until=now + dt.timedelta(hours=1),
        ))
        return str(t.id), str(c.id), str(u.id)


def _dispatch(tid, actor):
    from guardian_scanner.tools.tasks import dispatch_tool_job
    return dispatch_tool_job.apply(
        args=[tid, "ct_surface", ["example.com"], actor], kwargs={"settings": {"ct": _SNAPSHOT}}
    ).get()


def _nodes(tid, node_type):
    from guardian_db.models import GraphNode
    from guardian_db.session import session_scope
    with session_scope() as db:
        return db.query(GraphNode).filter(
            GraphNode.tenant_id == uuid.UUID(tid),
            GraphNode.node_type == node_type,
        ).all()


def test_ct_discovered_asset_reaches_world_model_with_run_and_ownership():
    from guardian_db.models import DiscoveryRun, EvidenceItem, GraphEdge
    from guardian_db.session import session_scope
    from guardian_scanner.tools.evidence import verify_chain

    tid, cid, actor = _tenant_customer_asset_authz("example.com", with_asset=True)
    res = _dispatch(tid, actor)
    assert res["status"] == "completed"

    # 1) Evidence hash-chain: discovered_asset evidence persisted and tamper-evident.
    with session_scope() as db:
        ev = db.query(EvidenceItem).filter(EvidenceItem.tenant_id == uuid.UUID(tid)).all()
        assert {e.kind for e in ev} == {"discovered_asset"}
        assert len(ev) == 3  # www, api, apex
        assert verify_chain(db, uuid.UUID(tid)) is True

        # 2) DiscoveryRun(trigger="tool") scoped to the owning customer.
        runs = db.query(DiscoveryRun).filter(DiscoveryRun.tenant_id == uuid.UUID(tid)).all()
        assert len(runs) == 1 and runs[0].trigger == "tool"
        assert runs[0].status == "completed"
        assert str(runs[0].customer_id) == cid          # ownership scoped by the parent asset
        run_id = runs[0].id

    # 3) SUBDOMAIN nodes exist, stamped with a REAL run id (never NULL), high ownership.
    subs = _nodes(tid, "subdomain")
    assert {n.canonical_key for n in subs} == {"www.example.com", "api.example.com"}
    assert all(n.discovery_run_id == run_id for n in subs)   # never-NULL provenance
    assert all(n.ownership_confidence == 90 for n in subs)

    # 4) SUBDOMAIN_OF edges to the parent DOMAIN node.
    doms = _nodes(tid, "domain")
    assert len(doms) == 1 and doms[0].canonical_key == "example.com"
    with session_scope() as db:
        edges = db.query(GraphEdge).filter(
            GraphEdge.tenant_id == uuid.UUID(tid), GraphEdge.relation == "subdomain_of").all()
        assert len(edges) == 2
        assert all(e.dst_id == str(doms[0].id) and e.discovery_run_id == run_id for e in edges)


def test_rerun_dedups_and_updates_lifecycle_not_duplicates():
    from guardian_db.models import DiscoveryRun
    from guardian_db.session import session_scope

    tid, cid, actor = _tenant_customer_asset_authz("example.com", with_asset=True)
    assert _dispatch(tid, actor)["status"] == "completed"
    assert _dispatch(tid, actor)["status"] == "completed"   # second pass, same surface

    # Two runs, but the SAME two subdomain nodes (dedup by identity), re-stamped to the latest run.
    subs = _nodes(tid, "subdomain")
    assert {n.canonical_key for n in subs} == {"www.example.com", "api.example.com"}   # no dupes
    with session_scope() as db:
        runs = db.query(DiscoveryRun).filter(
            DiscoveryRun.tenant_id == uuid.UUID(tid)).order_by(DiscoveryRun.created_at).all()
        assert len(runs) == 2
        latest = runs[-1].id
        assert runs[-1].stats.get("nodes_updated", 0) >= 2     # re-observed, not re-created
    assert all(n.discovery_run_id == latest for n in subs)      # lifecycle refreshed to newest run


def test_customerless_run_when_parent_domain_is_not_a_managed_asset():
    # No managed asset for the domain ⇒ still a real tenant-scoped run + nodes, customer_id NULL,
    # discovery_run_id still NEVER NULL (the invariant that mattered).
    from guardian_db.models import DiscoveryRun
    from guardian_db.session import session_scope

    tid, _cid, actor = _tenant_customer_asset_authz("example.com", with_asset=False)
    assert _dispatch(tid, actor)["status"] == "completed"

    subs = _nodes(tid, "subdomain")
    assert {n.canonical_key for n in subs} == {"www.example.com", "api.example.com"}
    with session_scope() as db:
        run = db.query(DiscoveryRun).filter(DiscoveryRun.tenant_id == uuid.UUID(tid)).one()
        assert run.customer_id is None and run.trigger == "tool"
    assert all(n.discovery_run_id is not None for n in subs)   # never-NULL provenance holds
