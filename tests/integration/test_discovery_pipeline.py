"""End-to-end EASM discovery (Phase 6B) — one domain in, an attack-surface graph out.

Runs the real pipeline (providers -> normalize -> dedup -> ingest -> lifecycle) synchronously against
a live DB, and asserts the properties the CTO review required: canonical dedup, idempotent re-runs,
shadow detection, edge lifecycle, and graph integrity (incl. no cross-tenant edges).

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

# CT reveals a subdomain; DNS resolves hosts. Mixed case / trailing dot must still dedup.
_SNAPSHOT = {
    "ct": {"example.com": ["api.example.com", "API.example.com."]},
    "dns": {
        "example.com": ["93.184.216.34"],
        "api.example.com": ["93.184.216.34"],
        "gone.example.com": [],  # dangling — takeover candidate
    },
}
_SEEDS = {
    "domains": ["example.com", "api.example.com", "gone.example.com"],
    "settings": _SNAPSHOT,
}


def _new_run(seeds=_SEEDS):
    from guardian_db.models import Customer, DiscoveryRun, Tenant
    from guardian_db.session import session_scope

    marker = uuid.uuid4().hex[:8]
    with session_scope() as db:
        t = Tenant(name=f"easm-{marker}", slug=f"easm-{marker}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        run = DiscoveryRun(tenant_id=t.id, customer_id=c.id, status="queued",
                           trigger="manual", seeds=seeds)
        db.add(run)
        db.flush()
        return str(t.id), str(run.id)


def _count(tenant_id, model_name, **filt):
    from guardian_db import models
    from guardian_db.session import session_scope

    model = getattr(models, model_name)
    with session_scope() as db:
        q = db.query(model).filter(model.tenant_id == uuid.UUID(tenant_id))
        for k, v in filt.items():
            q = q.filter(getattr(model, k) == v)
        return q.count()


def test_domain_expands_into_graph_with_canonical_dedup():
    from guardian_scanner.discovery.tasks import run_discovery

    tid, run_id = _new_run()
    result = run_discovery.apply(args=[run_id]).get()
    assert result["status"] == "completed"

    # api.example.com seen by CT twice (mixed case) + DNS once → ONE node, not three.
    assert _count(tid, "GraphNode", node_type="subdomain", canonical_key="api.example.com") == 1
    # The shared IP is one node despite two hosts resolving to it.
    assert _count(tid, "GraphNode", node_type="ip_address", canonical_key="93.184.216.34") == 1
    # Edges exist: subdomain_of (CT) and resolves_to (DNS).
    assert _count(tid, "GraphEdge", relation="subdomain_of") >= 1
    assert _count(tid, "GraphEdge", relation="resolves_to") >= 1


def test_public_host_becomes_shadow_asset():
    from guardian_db.models import GraphNode
    from guardian_db.session import session_scope
    from guardian_scanner.discovery.tasks import run_discovery

    tid, run_id = _new_run()
    run_discovery.apply(args=[run_id]).get()

    with session_scope() as db:
        api = db.query(GraphNode).filter(
            GraphNode.tenant_id == uuid.UUID(tid),
            GraphNode.canonical_key == "api.example.com",
        ).one()
        # Internet-reachable + high ownership + not a declared asset → shadow (the EASM payoff).
        assert api.state == "shadow"
        assert api.exposure_score > 0  # deterministic exposure, separate from risk


def test_dangling_record_flagged():
    from guardian_db.models import GraphNode
    from guardian_db.session import session_scope
    from guardian_scanner.discovery.tasks import run_discovery

    tid, run_id = _new_run()
    run_discovery.apply(args=[run_id]).get()
    with session_scope() as db:
        gone = db.query(GraphNode).filter(
            GraphNode.tenant_id == uuid.UUID(tid),
            GraphNode.canonical_key == "gone.example.com",
        ).one()
        assert gone.metadata_.get("dangling_dns") is True


def test_rerun_is_idempotent_no_duplicates():
    from guardian_scanner.discovery.tasks import run_discovery

    tid, run_id = _new_run()
    run_discovery.apply(args=[run_id]).get()
    nodes_after_first = _count(tid, "GraphNode")
    edges_after_first = _count(tid, "GraphEdge")

    # A second run over the same tenant with the same data must upsert, not duplicate.
    _, run_id2 = _new_run_same_tenant(tid)
    run_discovery.apply(args=[run_id2]).get()
    assert _count(tid, "GraphNode") == nodes_after_first
    assert _count(tid, "GraphEdge") == edges_after_first


def _new_run_same_tenant(tenant_id):
    from guardian_db.models import Customer, DiscoveryRun
    from guardian_db.session import session_scope

    with session_scope() as db:
        c = db.query(Customer).filter(Customer.tenant_id == uuid.UUID(tenant_id)).first()
        run = DiscoveryRun(tenant_id=uuid.UUID(tenant_id), customer_id=c.id, status="queued",
                           trigger="manual", seeds=_SEEDS)
        db.add(run)
        db.flush()
        return tenant_id, str(run.id)


def test_edge_goes_stale_when_relation_disappears():
    from guardian_db.models import GraphEdge
    from guardian_db.session import session_scope
    from guardian_scanner.discovery.tasks import run_discovery

    tid, run_id = _new_run()
    run_discovery.apply(args=[run_id]).get()

    # Re-run with api.example.com now resolving to a DIFFERENT ip — old resolves_to edge should stale.
    moved = {
        "ct": {"example.com": ["api.example.com"]},
        "dns": {"example.com": ["93.184.216.34"], "api.example.com": ["93.184.216.99"]},
    }
    seeds2 = {"domains": ["example.com", "api.example.com"], "settings": moved}
    _, run_id2 = _new_run_same_tenant_with_seeds(tid, seeds2)
    run_discovery.apply(args=[run_id2]).get()

    with session_scope() as db:
        states = {
            e.state for e in db.query(GraphEdge).filter(
                GraphEdge.tenant_id == uuid.UUID(tid), GraphEdge.relation == "resolves_to"
            )
        }
        assert "stale" in states  # the old relation was retired, not deleted
        assert "active" in states  # the new relation is live


def _new_run_same_tenant_with_seeds(tenant_id, seeds):
    from guardian_db.models import Customer, DiscoveryRun
    from guardian_db.session import session_scope

    with session_scope() as db:
        c = db.query(Customer).filter(Customer.tenant_id == uuid.UUID(tenant_id)).first()
        run = DiscoveryRun(tenant_id=uuid.UUID(tenant_id), customer_id=c.id, status="queued",
                           trigger="manual", seeds=seeds)
        db.add(run)
        db.flush()
        return tenant_id, str(run.id)


def test_graph_integrity_holds_after_discovery():
    from guardian_db.session import session_scope
    from guardian_scanner.discovery.integrity import validate_graph_integrity
    from guardian_scanner.discovery.tasks import run_discovery

    tid, run_id = _new_run()
    run_discovery.apply(args=[run_id]).get()
    with session_scope() as db:
        violations = validate_graph_integrity(db, tenant_id=tid)
    assert violations == [], f"discovery produced an inconsistent graph: {violations}"


def test_integrity_validator_catches_orphan_and_cross_tenant():
    """The guardrail must flag the two ways a polymorphic graph rots (RLS can't see across it)."""
    from guardian_db.models import GraphEdge, GraphNode
    from guardian_db.session import session_scope
    from guardian_scanner.discovery.integrity import validate_graph_integrity

    tid_a, _ = _new_run()
    tid_b, _ = _new_run()
    with session_scope() as db:
        # A real node in tenant A, a real node in tenant B.
        na = GraphNode(tenant_id=uuid.UUID(tid_a), node_type="domain", canonical_key="a.example")
        nb = GraphNode(tenant_id=uuid.UUID(tid_b), node_type="domain", canonical_key="b.example")
        db.add_all([na, nb])
        db.flush()
        # Orphan: dst points at a non-existent node.
        db.add(GraphEdge(tenant_id=uuid.UUID(tid_a), src_type="domain", src_id=str(na.id),
                         relation="routes_to", dst_type="domain", dst_id=str(uuid.uuid4())))
        # Cross-tenant: tenant A edge whose dst is tenant B's node.
        db.add(GraphEdge(tenant_id=uuid.UUID(tid_a), src_type="domain", src_id=str(na.id),
                         relation="trusts", dst_type="domain", dst_id=str(nb.id)))
        db.flush()

    with session_scope() as db:
        kinds = {v.kind for v in validate_graph_integrity(db, tenant_id=tid_a)}
    assert "orphan_dst" in kinds
    assert "cross_tenant" in kinds
