"""Phase 6·A schema tests — graph-node identity, edge provenance, and RLS on the new tables.

Gated by GUARDIAN_RUN_DB_TESTS=1. The RLS-mechanism test additionally needs the enforced app role.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


def _seed():
    from guardian_db.models import Customer, Tenant
    from guardian_db.session import session_scope

    marker = uuid.uuid4().hex[:8]
    with session_scope() as db:
        t = Tenant(name=f"p6-{marker}", slug=f"p6-{marker}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        return t.id, c.id


def test_new_tables_and_edge_provenance_exist():
    from guardian_db.session import get_session

    s = get_session()
    try:
        insp = inspect(s.get_bind())
        names = set(insp.get_table_names())
        assert {"graph_nodes", "discovery_runs", "discovery_scopes", "node_events"} <= names
        edge_cols = {c["name"] for c in insp.get_columns("graph_edges")}
        assert {"source", "confidence", "first_seen_at", "last_seen_at", "discovery_run_id"} <= edge_cols
        node_cols = {c["name"] for c in insp.get_columns("graph_nodes")}
        assert {"canonical_key", "exposure_score", "confidence", "ownership_confidence",
                "state", "asset_id", "last_seen_at"} <= node_cols
    finally:
        s.close()


def test_graph_node_identity_is_unique_but_uuid_is_stable():
    """Dedup on (tenant, type, canonical_key); the UUID id is the stable identity edges point at."""
    from guardian_db.models import GraphNode
    from guardian_db.session import session_scope

    tid, _ = _seed()

    def _mk():
        return GraphNode(tenant_id=tid, node_type="subdomain", canonical_key="api.example.com")

    with session_scope() as db:
        n = _mk()
        db.add(n)
        db.flush()
        node_uuid = n.id
    with pytest.raises(IntegrityError):
        with session_scope() as db:
            db.add(_mk())  # same identity → rejected

    # The canonical key can change; the UUID (what edges reference) does not.
    with session_scope() as db:
        n = db.get(GraphNode, node_uuid)
        n.canonical_key = "api.prod.example.com"
    with session_scope() as db:
        assert db.get(GraphNode, node_uuid).canonical_key == "api.prod.example.com"


def test_node_event_history_is_recorded():
    from guardian_db.models import GraphNode, NodeEvent
    from guardian_db.session import session_scope

    tid, _ = _seed()
    with session_scope() as db:
        n = GraphNode(tenant_id=tid, node_type="service", canonical_key="203.0.113.10:443")
        db.add(n)
        db.flush()
        db.add(NodeEvent(tenant_id=tid, node_id=n.id, event_type="port_opened",
                         detail={"port": 443}, occurred_at=dt.datetime.now(dt.UTC)))
        nid = n.id
    with session_scope() as db:
        ev = db.query(NodeEvent).filter(NodeEvent.node_id == nid).one()
        assert ev.event_type == "port_opened" and ev.detail["port"] == 443


def test_new_tables_are_rls_protected():
    """Every Phase-6 tenant-scoped table must carry an RLS policy (enforced by the CI guard too)."""
    from guardian_db.session import get_session

    s = get_session()
    try:
        policied = {r[0] for r in s.execute(text("SELECT tablename FROM pg_policies"))}
    finally:
        s.close()
    assert {"graph_nodes", "discovery_runs", "discovery_scopes", "node_events"} <= policied


def _app_is_rls_enforced() -> bool:
    from guardian_db.session import get_app_session

    s = get_app_session()
    try:
        row = s.execute(
            text("SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = current_user")
        ).one()
        return not row.rolbypassrls and not row.rolsuper
    finally:
        s.close()


def test_graph_nodes_isolate_across_tenants():
    if not _app_is_rls_enforced():
        pytest.skip("app session is not RLS-enforced")

    from guardian_db.models import GraphNode
    from guardian_db.session import get_app_session, session_scope, set_tenant

    tid_a, _ = _seed()
    tid_b, _ = _seed()
    with session_scope() as db:
        db.add(GraphNode(tenant_id=tid_a, node_type="domain", canonical_key="a.example.com"))
        db.add(GraphNode(tenant_id=tid_b, node_type="domain", canonical_key="b.example.com"))

    s = get_app_session()
    try:
        set_tenant(s, tid_a)
        keys = s.execute(text("SELECT canonical_key FROM graph_nodes")).scalars().all()
        assert keys == ["a.example.com"]  # only tenant A's node visible
    finally:
        s.close()
