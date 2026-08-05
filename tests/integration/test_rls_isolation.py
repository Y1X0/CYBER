"""Cross-tenant isolation + negative-authorization tests for Row-Level Security (Phase 5A hard gate).

These verify the *database-level* backstop, independent of the application's own tenant filtering:
connecting as the non-owner `guardian_app` role, a session bound to tenant A must never see (or be
able to write) tenant B's rows — even on a raw, unfiltered query.

Gated twice:
  * GUARDIAN_RUN_DB_TESTS=1 — a live Postgres is available (as with the other integration tests).
  * the app session must actually be RLS-enforced — i.e. GUARDIAN_APP_DATABASE_URL points at a
    non-superuser, non-BYPASSRLS role. When it falls back to the owner (dev default), RLS is inert
    by design, so we skip with a clear reason rather than reporting a false pass.
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


def _app_is_rls_enforced() -> bool:
    """True only if the app session connects as a role that RLS actually applies to."""
    from guardian_db.session import get_app_session

    s = get_app_session()
    try:
        row = s.execute(
            text("SELECT current_user, rolbypassrls, rolsuper "
                 "FROM pg_roles WHERE rolname = current_user")
        ).one()
        _, bypass, super_ = row
        return not bypass and not super_
    finally:
        s.close()


@pytest.fixture()
def two_tenants():
    """Seed two isolated tenants, each with a customer, an asset, and a finding. Returns their ids."""
    from guardian_db.models import Asset, Customer, Finding, Scan, ScanEngineRun, Tenant
    from guardian_db.session import session_scope

    marker = uuid.uuid4().hex[:8]
    ids: dict[str, uuid.UUID] = {}
    with session_scope() as db:
        for label in ("a", "b"):
            tenant = Tenant(name=f"RLS-{label}-{marker}", slug=f"rls-{label}-{marker}", mode="hybrid")
            db.add(tenant)
            db.flush()
            customer = Customer(tenant_id=tenant.id, name=f"C-{label}", criticality="high")
            db.add(customer)
            db.flush()
            asset = Asset(
                tenant_id=tenant.id, customer_id=customer.id, name=f"asset-{label}",
                kind="repo", identifier=f"id-{label}", exposure="public", config={},
            )
            db.add(asset)
            db.flush()
            scan = Scan(
                tenant_id=tenant.id, customer_id=customer.id, asset_id=asset.id,
                trigger="manual", status="completed", requested_engines=["secrets"],
            )
            db.add(scan)
            db.flush()
            run = ScanEngineRun(scan_id=scan.id, engine="secrets", status="completed")
            db.add(run)
            db.flush()
            finding = Finding(
                tenant_id=tenant.id, customer_id=customer.id, scan_id=scan.id,
                engine_run_id=run.id, asset_id=asset.id,
                title=f"finding-{label}", severity="high", status="open",
                category="secrets", fingerprint=f"fp-{label}-{marker}",
            )
            db.add(finding)
            db.flush()
            ids[f"tenant_{label}"] = tenant.id
            ids[f"customer_{label}"] = customer.id
            ids[f"asset_{label}"] = asset.id
            ids[f"scan_{label}"] = scan.id
            ids[f"finding_{label}"] = finding.id
    return ids


def _bind(session, tenant_id) -> None:
    from guardian_db.session import set_tenant

    set_tenant(session, tenant_id)


def test_app_role_sees_only_its_tenant(two_tenants):
    """A session bound to tenant A sees only A's rows across direct, child, and self-scoped tables."""
    if not _app_is_rls_enforced():
        pytest.skip("app session is not RLS-enforced (GUARDIAN_APP_DATABASE_URL falls back to owner)")

    from guardian_db.session import get_app_session, reset_tenant

    ids = two_tenants
    s = get_app_session()
    try:
        _bind(s, ids["tenant_a"])

        # direct tenant_id table
        assets = s.execute(text("SELECT tenant_id FROM assets")).scalars().all()
        assert assets, "tenant A should see its own asset"
        assert all(a == ids["tenant_a"] for a in assets), "must not see tenant B's assets"

        findings = s.execute(text("SELECT tenant_id FROM findings")).scalars().all()
        assert all(f == ids["tenant_a"] for f in findings)

        # child table scoped through parent (scan_engine_runs -> scans)
        runs = s.execute(text("SELECT scan_id FROM scan_engine_runs")).scalars().all()
        assert ids["scan_a"] in runs
        assert ids["scan_b"] not in runs

        # self-scoped: the tenants table exposes only the caller's own row
        tenants = s.execute(text("SELECT id FROM tenants")).scalars().all()
        assert tenants == [ids["tenant_a"]]

        # switching context flips the visible set, on the same connection
        reset_tenant(s)
        _bind(s, ids["tenant_b"])
        assets_b = s.execute(text("SELECT tenant_id FROM assets")).scalars().all()
        assert assets_b and all(a == ids["tenant_b"] for a in assets_b)
    finally:
        s.close()


def test_no_tenant_context_sees_nothing(two_tenants):
    """With no tenant bound, RLS fails closed — zero rows, never a cross-tenant leak."""
    if not _app_is_rls_enforced():
        pytest.skip("app session is not RLS-enforced")

    from guardian_db.session import get_app_session, reset_tenant

    s = get_app_session()
    try:
        reset_tenant(s)  # empty GUC -> NULLIF -> NULL -> predicate never true
        assert s.execute(text("SELECT count(*) FROM assets")).scalar() == 0
        assert s.execute(text("SELECT count(*) FROM findings")).scalar() == 0
        assert s.execute(text("SELECT count(*) FROM tenants")).scalar() == 0
    finally:
        s.close()


def test_cannot_write_into_another_tenant(two_tenants):
    """Negative authorization: WITH CHECK rejects an INSERT/UPDATE that would land in another tenant."""
    if not _app_is_rls_enforced():
        pytest.skip("app session is not RLS-enforced")

    from guardian_db.session import get_app_session, reset_tenant

    ids = two_tenants
    s = get_app_session()
    try:
        _bind(s, ids["tenant_a"])

        # INSERT an asset stamped with tenant B while bound to A -> must be refused by WITH CHECK.
        with pytest.raises(ProgrammingError):
            s.execute(
                text(
                    "INSERT INTO assets (id, tenant_id, customer_id, name, kind, identifier, "
                    "exposure, config, source, state, created_at, updated_at) VALUES "
                    "(:id, :tid, :cid, 'evil', 'repo', 'x', 'public', '{}', 'declared', 'active', "
                    "now(), now())"
                ),
                {"id": uuid.uuid4(), "tid": ids["tenant_b"], "cid": ids["customer_b"]},
            )
        s.rollback()

        # UPDATE: try to re-parent tenant A's asset into tenant B -> must be refused.
        _bind(s, ids["tenant_a"])
        with pytest.raises(ProgrammingError):
            s.execute(
                text("UPDATE assets SET tenant_id = :tid WHERE id = :id"),
                {"tid": ids["tenant_b"], "id": ids["asset_a"]},
            )
        s.rollback()
    finally:
        reset_tenant(s)
        s.close()
