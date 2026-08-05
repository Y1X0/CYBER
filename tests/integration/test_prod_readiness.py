"""Production-Readiness sprint DB tests: RLS-coverage guard, asset identity, tenant-context safety.

Gated by GUARDIAN_RUN_DB_TESTS=1. The RLS-mechanism tests additionally require the app session to be
the non-owner enforced role (skip otherwise, same as test_rls_isolation).
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

# Tables that legitimately carry no tenant_id and need no RLS policy (global reference / identity).
_INTENTIONALLY_GLOBAL: set[str] = set()  # every tenant_id table MUST have a policy — no exceptions


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


def test_every_tenant_scoped_table_has_rls_policy():
    """The Phase-6 guard: any table with a tenant_id column must have RLS enabled AND a policy.

    This turns tenant isolation from a hand-maintained allowlist into an enforced invariant — a new
    tenant-scoped table that forgets its policy fails CI instead of leaking across tenants.
    """
    from guardian_db.session import get_session

    s = get_session()
    try:
        tenant_tables = {
            r[0] for r in s.execute(text(
                "SELECT table_name FROM information_schema.columns "
                "WHERE table_schema = 'public' AND column_name = 'tenant_id'"
            ))
        }
        policied = {r[0] for r in s.execute(text("SELECT tablename FROM pg_policies"))}
        rls_enabled = {
            r[0] for r in s.execute(text(
                "SELECT relname FROM pg_class WHERE relrowsecurity AND relkind = 'r'"
            ))
        }
    finally:
        s.close()

    assert tenant_tables, "expected to find tenant-scoped tables"
    missing_policy = tenant_tables - policied - _INTENTIONALLY_GLOBAL
    missing_rls = tenant_tables - rls_enabled - _INTENTIONALLY_GLOBAL
    assert not missing_policy, f"tenant-scoped tables without an RLS policy: {sorted(missing_policy)}"
    assert not missing_rls, f"tenant-scoped tables without RLS enabled: {sorted(missing_rls)}"


def test_customer_contacts_is_rls_protected():
    """A tenant-scoped table with no tenant_id (only customer_id) must still be covered."""
    from guardian_db.session import get_session

    s = get_session()
    try:
        policied = {r[0] for r in s.execute(text("SELECT tablename FROM pg_policies"))}
    finally:
        s.close()
    assert "customer_contacts" in policied


def _seed_tenant_customer():
    from guardian_db.models import Customer, Tenant
    from guardian_db.session import session_scope

    marker = uuid.uuid4().hex[:8]
    with session_scope() as db:
        tenant = Tenant(name=f"pr-{marker}", slug=f"pr-{marker}", mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        db.add(customer)
        db.flush()
        return tenant.id, customer.id


def test_asset_natural_identity_is_unique():
    """Discovery upsert relies on it: same (tenant, customer, kind, identifier) can't duplicate."""
    from guardian_db.models import Asset
    from guardian_db.session import session_scope

    tenant_id, customer_id = _seed_tenant_customer()

    def _mk(**kw):
        return Asset(tenant_id=tenant_id, customer_id=customer_id, name="a", kind="web",
                     identifier="https://example.com", exposure="public", config={}, **kw)

    with session_scope() as db:
        db.add(_mk())
    with pytest.raises(IntegrityError):
        with session_scope() as db:
            db.add(_mk())  # same identity → rejected


def test_identifierless_assets_are_exempt_from_unique_identity():
    """Inline/identifier-less assets (identifier = '') must not collide (partial unique index)."""
    from guardian_db.models import Asset
    from guardian_db.session import session_scope

    tenant_id, customer_id = _seed_tenant_customer()
    with session_scope() as db:
        db.add(Asset(tenant_id=tenant_id, customer_id=customer_id, name="i1", kind="repo",
                     identifier="", exposure="public", config={}))
        db.add(Asset(tenant_id=tenant_id, customer_id=customer_id, name="i2", kind="repo",
                     identifier="", exposure="public", config={}))
        # no raise on flush


def test_tenant_context_is_transaction_local_and_does_not_bleed():
    """The binding auto-clears at transaction end — a pooled connection can't carry it forward."""
    if not _app_is_rls_enforced():
        pytest.skip("app session is not RLS-enforced")

    from guardian_db.session import get_app_session, set_tenant

    tid = uuid.uuid4()
    s = get_app_session()
    try:
        set_tenant(s, tid)
        assert s.execute(text("SELECT current_setting('app.current_tenant', true)")).scalar() == str(tid)
        # Drop the binding and end the transaction; the transaction-local GUC clears itself.
        s.info.pop("app_tenant", None)
        s.commit()
        after = s.execute(text("SELECT current_setting('app.current_tenant', true)")).scalar()
        assert after in (None, ""), "tenant GUC leaked past the transaction"
    finally:
        s.close()


def test_security_definer_bootstrap_works_under_rls():
    """The identity bootstrap resolves memberships on the app session (no owner connection)."""
    if not _app_is_rls_enforced():
        pytest.skip("app session is not RLS-enforced")

    from guardian_db.models import TenantMembership, User
    from guardian_db.session import get_app_session, session_scope

    tenant_id, _ = _seed_tenant_customer()
    marker = uuid.uuid4().hex[:8]
    with session_scope() as db:
        user = User(email=f"pr-{marker}@x.com", name="PR", password_hash="x", status="active")
        db.add(user)
        db.flush()
        db.add(TenantMembership(user_id=user.id, tenant_id=tenant_id, role="admin"))
        uid = user.id

    s = get_app_session()  # RLS-enforced, NO tenant bound yet
    try:
        rows = s.execute(
            text("SELECT tenant_id, role FROM auth_memberships(:u)"), {"u": str(uid)}
        ).all()
        assert [(r.tenant_id, r.role) for r in rows] == [(tenant_id, "admin")]
        # And a raw read of the RLS table with no tenant context sees nothing (fail-closed).
        assert s.execute(text("SELECT count(*) FROM tenant_memberships")).scalar() == 0
    finally:
        s.close()
