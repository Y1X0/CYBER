"""Netblock world-model completion, end-to-end (Phase 6F). Gated by GUARDIAN_RUN_DB_TESTS=1.

Proves 6F-a (authorized-netblock enrichment, CIDR containment) and 6F-b (passive ASN/RIR provider
through the 6C.4 recon result-return), their convergence on one canonical netblock identity, tenant
isolation, fail-safe behavior, and that `contains` never changes 6D exposure paths or 6E attack paths.
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
    m = uuid.uuid4().hex[:8]
    with session_scope() as db:
        t = Tenant(name=f"6f-{m}", slug=f"6f-{m}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        u = User(email=f"6f-{m}@x.com", name="U", password_hash="x", status="active")
        db.add(u)
        db.flush()
        return str(t.id), str(c.id), str(u.id)


def _authz_netblock(db, tid, cid, uid, cidr):
    from guardian_db.models import Authorization
    now = dt.datetime.now(dt.UTC)
    db.add(Authorization(
        tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), asset_id=None, scope="s",
        authorized_targets=[{"type": "netblock", "value": cidr}], method="active_recon",
        authorized_by=uuid.UUID(uid), valid_from=now - dt.timedelta(hours=1),
        valid_until=now + dt.timedelta(hours=1),
    ))


def _ip_node(db, tid, ip, *, internet=False, exposure=0):
    from guardian_db.models import GraphNode
    n = GraphNode(tenant_id=uuid.UUID(tid), node_type="ip_address", canonical_key=ip,
                  metadata_={"internet_reachable": internet}, exposure_score=exposure,
                  confidence=90, ownership_confidence=90)
    db.add(n)
    db.flush()
    return n.id


def _enrich_netblocks(tid, cid=None):
    from guardian_db.session import session_scope
    from guardian_scanner.discovery.netblock import NetblockEnricher
    with session_scope() as db:
        return NetblockEnricher(db, tenant_id=uuid.UUID(tid),
                                customer_id=uuid.UUID(cid) if cid else None).enrich()


def _nodes(tid, node_type):
    from guardian_db.models import GraphNode
    from guardian_db.session import session_scope
    with session_scope() as db:
        return db.query(GraphNode).filter(GraphNode.tenant_id == uuid.UUID(tid),
                                          GraphNode.node_type == node_type).all()


def _contains(tid):
    from guardian_db.models import GraphEdge
    from guardian_db.session import session_scope
    with session_scope() as db:
        return db.query(GraphEdge).filter(GraphEdge.tenant_id == uuid.UUID(tid),
                                          GraphEdge.relation == "contains").all()


def test_authorized_netblock_contains_only_ips_inside():
    tid, cid, uid = _tenant()
    from guardian_db.session import session_scope
    with session_scope() as db:
        _authz_netblock(db, tid, cid, uid, "1.2.3.0/24")
        _ip_node(db, tid, "1.2.3.4")   # inside
        _ip_node(db, tid, "9.9.9.9")   # outside
    _enrich_netblocks(tid, cid)

    nbs = _nodes(tid, "netblock")
    assert len(nbs) == 1 and nbs[0].canonical_key == "1.2.3.0/24"
    assert nbs[0].metadata_.get("source") == "authorized"
    edges = _contains(tid)
    assert len(edges) == 1                                   # only the inside IP
    assert edges[0].src_type == "netblock" and edges[0].dst_type == "ip_address"  # netblock -> ip
    assert edges[0].source == "inferred"
    assert edges[0].meta.get("link") == "cidr_containment"


def test_netblock_enrichment_is_idempotent():
    tid, cid, uid = _tenant()
    from guardian_db.session import session_scope
    with session_scope() as db:
        _authz_netblock(db, tid, cid, uid, "1.2.3.0/24")
        _ip_node(db, tid, "1.2.3.4")
    _enrich_netblocks(tid, cid)
    _enrich_netblocks(tid, cid)  # re-run
    assert len(_nodes(tid, "netblock")) == 1 and len(_contains(tid)) == 1


def test_malformed_authorized_cidr_is_skipped_failsafe():
    tid, cid, uid = _tenant()
    from guardian_db.session import session_scope
    with session_scope() as db:
        _authz_netblock(db, tid, cid, uid, "NOT-A-CIDR")
        _ip_node(db, tid, "1.2.3.4")
    stats = _enrich_netblocks(tid, cid)   # must not raise
    assert stats == {"netblock_nodes": 0, "contains_edges": 0}
    assert _nodes(tid, "netblock") == []


def test_no_authorized_netblocks_yields_nothing():
    tid, cid, _ = _tenant()
    from guardian_db.session import session_scope
    with session_scope() as db:
        _ip_node(db, tid, "1.2.3.4")
    assert _enrich_netblocks(tid, cid) == {"netblock_nodes": 0, "contains_edges": 0}


def test_asn_provider_end_to_end_via_run_discovery():
    """6F-b: a discovery run with the asn provider maps a discovered IP to its netblock (offline)."""
    from guardian_db.models import DiscoveryRun, DiscoveryScope
    from guardian_db.session import session_scope
    from guardian_scanner.discovery.tasks import run_discovery

    tid, cid, _ = _tenant()
    with session_scope() as db:
        _ip_node(db, tid, "1.2.3.4")   # a previously-discovered IP
        scope = DiscoveryScope(tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), name="s",
                               seeds={}, providers=["asn"])
        db.add(scope)
        db.flush()
        run = DiscoveryRun(tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), scope_id=scope.id,
                           status="queued", trigger="manual",
                           seeds={"settings": {"asn": {"1.2.3.4": {"netblock": "1.2.3.0/24",
                                                                   "asn": 64500}}}})
        db.add(run)
        db.flush()
        run_id = str(run.id)
    run_discovery.apply(args=[run_id]).get()

    nbs = _nodes(tid, "netblock")
    assert len(nbs) == 1 and nbs[0].canonical_key == "1.2.3.0/24"
    assert nbs[0].metadata_.get("asn") == 64500          # ASN attribute (RIR-derived provenance)
    edges = _contains(tid)
    assert len(edges) == 1 and edges[0].source == "asn_rir"


def test_6fa_and_6fb_converge_on_one_netblock():
    """The same CIDR from an authorization (6F-a) and the ASN provider (6F-b) is ONE node."""
    from guardian_db.models import DiscoveryRun, DiscoveryScope
    from guardian_db.session import session_scope
    from guardian_scanner.discovery.tasks import run_discovery

    tid, cid, uid = _tenant()
    with session_scope() as db:
        _authz_netblock(db, tid, cid, uid, "1.2.3.0/24")   # 6F-a source
        _ip_node(db, tid, "1.2.3.4")
        scope = DiscoveryScope(tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), name="s",
                               seeds={}, providers=["asn"])
        db.add(scope)
        db.flush()
        run = DiscoveryRun(tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), scope_id=scope.id,
                           status="queued", trigger="manual",
                           seeds={"settings": {"asn": {"1.2.3.4": {"netblock": "1.2.3.0/24"}}}})
        db.add(run)
        db.flush()
        run_id = str(run.id)
    # run_discovery runs 6F-b (asn provider) then 6F-a (NetblockEnricher in persist) — same CIDR.
    run_discovery.apply(args=[run_id]).get()

    assert len(_nodes(tid, "netblock")) == 1     # ONE canonical netblock node
    assert len(_contains(tid)) == 1              # ONE contains edge (idempotent convergence)


def test_netblock_nodes_tenant_isolated():
    from guardian_db.session import get_app_session, set_tenant
    a_tid, a_cid, a_uid = _tenant()
    b_tid, b_cid, b_uid = _tenant()
    from guardian_db.session import session_scope
    for tid, cid, uid in ((a_tid, a_cid, a_uid), (b_tid, b_cid, b_uid)):
        with session_scope() as db:
            _authz_netblock(db, tid, cid, uid, "1.2.3.0/24")
            _ip_node(db, tid, "1.2.3.4")
        _enrich_netblocks(tid, cid)

    s = get_app_session()
    try:
        row = s.execute(
            text("SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = current_user")
        ).one()
        if row.rolbypassrls or row.rolsuper:
            pytest.skip("app session is not RLS-enforced")
        set_tenant(s, a_tid)
        seen = s.execute(
            text("SELECT DISTINCT tenant_id::text FROM graph_nodes WHERE node_type='netblock'")
        ).scalars().all()
        assert seen == [a_tid]
    finally:
        s.close()


def test_contains_does_not_change_6d_6e_paths():
    """Adding netblock + contains must not add any exposure (6D) or attack (6E) path."""
    from guardian_db.graph_read import DbGraphProjector
    from guardian_db.session import get_app_session, session_scope, set_tenant

    tid, cid, uid = _tenant()
    with session_scope() as db:
        # a real exposure chain sub(internet) -> ip(sensitive)
        from guardian_db.models import GraphEdge, GraphNode
        sub = GraphNode(tenant_id=uuid.UUID(tid), node_type="subdomain", canonical_key="a.example.com",
                        metadata_={"internet_reachable": True}, confidence=90, ownership_confidence=90)
        db.add(sub)
        db.flush()
        ip = _ip_node(db, tid, "1.2.3.4", exposure=70)
        db.add(GraphEdge(tenant_id=uuid.UUID(tid), src_type="subdomain", src_id=str(sub.id),
                         relation="resolves_to", dst_type="ip_address", dst_id=str(ip),
                         state="active", source="dns", confidence=90))
        _authz_netblock(db, tid, cid, uid, "1.2.3.0/24")

    def paths():
        s = get_app_session()
        set_tenant(s, tid)
        try:
            return (DbGraphProjector(s).exposure_paths(tenant_id=tid)["paths"],
                    DbGraphProjector(s).attack_paths(tenant_id=tid)["paths"])
        finally:
            s.close()

    exp_before, atk_before = paths()
    _enrich_netblocks(tid, cid)                 # adds netblock + contains
    exp_after, atk_after = paths()
    assert exp_before == exp_after              # 6D exposure paths unchanged
    assert atk_before == atk_after              # 6E attack paths unchanged
    assert _nodes(tid, "netblock")              # (the netblock really was added)
