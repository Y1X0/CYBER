"""Schema-integrity + backward-compatibility tests for the Phase 5B Tier-1 seams.

Confirms the storage foundations landed (graph_edges, domain_events, evidence_items) with their key
columns, that asset provenance columns exist with safe defaults, and — the backward-compat guarantee
— that code written before Phase 5 (an asset created without touching any new column) still works and
gets the declared/active defaults. No feature logic is exercised: these are storage seams only.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest
from sqlalchemy import inspect

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


def test_seam_tables_and_columns_exist():
    from guardian_db.session import get_session

    s = get_session()
    try:
        insp = inspect(s.get_bind())
        for table, expected in {
            "graph_edges": {"tenant_id", "src_type", "src_id", "dst_type", "dst_id",
                            "relation", "weight", "meta"},
            "domain_events": {"tenant_id", "type", "payload", "occurred_at", "processed_at"},
            "evidence_items": {"tenant_id", "finding_id", "kind", "content_sha256", "prev_hash"},
        }.items():
            cols = {c["name"] for c in insp.get_columns(table)}
            assert expected <= cols, f"{table} missing {expected - cols}"

        asset_cols = {c["name"] for c in insp.get_columns("assets")}
        assert {"source", "state", "discovered_by_scan_id", "first_seen_at", "secret_ref"} <= asset_cols
    finally:
        s.close()


def test_asset_provenance_defaults_are_backward_compatible():
    """An asset created the pre-Phase-5 way (no provenance fields) still persists and defaults sanely."""
    from guardian_db.models import Asset, Customer, Tenant
    from guardian_db.session import session_scope

    marker = uuid.uuid4().hex[:8]
    with session_scope() as db:
        tenant = Tenant(name=f"seam-{marker}", slug=f"seam-{marker}", mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="medium")
        db.add(customer)
        db.flush()
        # Note: no source / state / secret_ref set — exactly how existing call sites build an Asset.
        asset = Asset(
            tenant_id=tenant.id, customer_id=customer.id, name="legacy-asset",
            kind="repo", identifier="legacy", exposure="public", config={},
        )
        db.add(asset)
        db.flush()
        asset_id = asset.id

    with session_scope() as db:
        asset = db.get(Asset, asset_id)
        assert asset is not None
        assert asset.source == "declared"
        assert asset.state == "active"
        assert asset.discovered_by_scan_id is None
        assert asset.secret_ref is None


def test_asset_secret_is_encrypted_at_rest_via_api():
    """Creating an asset with `secret` stores ciphertext in secret_ref, never plaintext or in config."""
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.crypto import decrypt_json
    from guardian_common.security import create_access_token
    from guardian_db.models import Asset, Customer, Tenant, TenantMembership, User
    from guardian_db.session import session_scope

    settings = get_settings()
    client = TestClient(app)
    marker = uuid.uuid4().hex[:8]

    with session_scope() as db:
        tenant = Tenant(name=f"sec-{marker}", slug=f"sec-{marker}", mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        db.add(customer)
        db.flush()
        user = User(email=f"w-{marker}@x.com", name="W", password_hash="x", status="active")
        db.add(user)
        db.flush()
        db.add(TenantMembership(user_id=user.id, tenant_id=tenant.id, role="admin"))
        uid, cid = str(user.id), str(customer.id)

    headers = {
        "Authorization": f"Bearer {create_access_token(subject=uid, secret=settings.jwt_secret, algorithm=settings.jwt_algorithm)}"
    }
    secret_value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    resp = client.post(
        "/api/v1/assets",
        headers=headers,
        json={
            "customer_id": cid, "name": "cloud", "kind": "cloud_account",
            "identifier": "acct-1", "exposure": "internal", "config": {},
            "secret": {"aws_secret_access_key": secret_value},
        },
    )
    assert resp.status_code == 201, resp.text
    # The secret must never be echoed back to the client.
    assert secret_value not in resp.text
    asset_id = uuid.UUID(resp.json()["id"])

    with session_scope() as db:
        asset = db.get(Asset, asset_id)
        assert asset.secret_ref is not None
        assert secret_value not in asset.secret_ref  # stored as ciphertext
        assert secret_value not in str(asset.config)  # never lands in the public config blob
        # And it decrypts back to the original for in-memory use at scan time.
        assert decrypt_json(asset.secret_ref) == {"aws_secret_access_key": secret_value}


def test_seam_rows_round_trip():
    """Each seam persists and reads back — storage integrity, no feature behavior."""
    from guardian_db.models import DomainEvent, EvidenceItem, GraphEdge, Tenant
    from guardian_db.session import session_scope

    marker = uuid.uuid4().hex[:8]
    with session_scope() as db:
        tenant = Tenant(name=f"seamrt-{marker}", slug=f"seamrt-{marker}", mode="hybrid")
        db.add(tenant)
        db.flush()
        tid = tenant.id

        edge = GraphEdge(
            tenant_id=tid, src_type="asset", src_id=str(uuid.uuid4()),
            dst_type="asset", dst_id=str(uuid.uuid4()), relation="routes_to",
        )
        event = DomainEvent(
            tenant_id=tid, type="scan.completed", payload={"scan_id": str(uuid.uuid4())},
            occurred_at=dt.datetime.now(dt.UTC),
        )
        evidence = EvidenceItem(
            tenant_id=tid, kind="note", summary="seam smoke", content_sha256="0" * 64,
        )
        db.add_all([edge, event, evidence])
        db.flush()
        edge_id, event_id, ev_id = edge.id, event.id, evidence.id

    with session_scope() as db:
        assert db.get(GraphEdge, edge_id).relation == "routes_to"
        assert db.get(GraphEdge, edge_id).weight == 1.0  # default applied
        assert db.get(DomainEvent, event_id).processed_at is None  # no consumer yet
        assert db.get(EvidenceItem, ev_id).kind == "note"
