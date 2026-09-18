"""Owner-direct scanning — the server-side gate, on the real API path.

The capability: the tenant OWNER may run an active scan against an UNVERIFIED target, bypassing the
ownership-verification gate for that one scan. Everyone else is unchanged. These tests prove the
gate is enforced server-side and is not a client flag:

  * a non-owner sending direct=true is refused (403), whatever they send;
  * with the feature off, even the owner is refused (403) — safe by default;
  * the first owner-direct scan of a target needs a legal affirmation (409), which is then recorded;
  * an affirmed owner-direct scan is dispatched with basis "owner-direct" and both the affirmation
    and the dispatch are written to the (immutable) audit log;
  * a normal scan is basis "verified-ownership" and the gate is untouched.

Gated by GUARDIAN_RUN_DB_TESTS=1 (needs a live database).
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


def _token(user_id: uuid.UUID) -> str:
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token

    s = get_settings()
    return create_access_token(subject=str(user_id), secret=s.jwt_secret,
                               algorithm=s.jwt_algorithm, claims={"tv": 0})


def _estate():
    """A tenant with an OWNER, a non-owner ADMIN, a customer, and one unverified web asset."""
    from guardian_core.enums import StaffRole
    from guardian_db.models import Asset, Customer, Tenant, TenantMembership, User
    from guardian_db.session import session_scope

    slug = f"od-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        owner = User(email=f"owner-{slug}@x.invalid", name="Owner", status="active")
        admin = User(email=f"admin-{slug}@x.invalid", name="Admin", status="active")
        db.add_all([customer, owner, admin])
        db.flush()
        db.add_all([
            TenantMembership(user_id=owner.id, tenant_id=tenant.id,
                             role=StaffRole.OWNER.value),
            TenantMembership(user_id=admin.id, tenant_id=tenant.id,
                             role=StaffRole.ADMIN.value),
        ])
        asset = Asset(tenant_id=tenant.id, customer_id=customer.id, name="app", kind="web",
                      identifier=f"https://{slug}.example.com", exposure="public", config={})
        db.add(asset)
        db.flush()
        return {"tenant": tenant.id, "asset": asset.id,
                "owner": owner.id, "admin": admin.id}


def _client():
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_api.ratelimit import login_limiter

    login_limiter().reset()
    return TestClient(app)


def _enable(monkeypatch, on: bool = True) -> None:
    from guardian_common.config import get_settings

    monkeypatch.setattr(get_settings(), "owner_direct_scan", on, raising=False)


def _hdr(user_id: uuid.UUID) -> dict:
    return {"Authorization": f"Bearer {_token(user_id)}"}


def _post_scan(client, ctx, user_id, **body):
    payload = {"asset_id": str(ctx["asset"]), "engines": ["dast"], **body}
    return client.post("/api/v1/scans", headers=_hdr(user_id), json=payload)


# ── (1) the owner check is server-side and not a client flag ──────────────────────────────────────
def test_a_non_owner_is_refused_owner_direct_even_with_the_flag_on(monkeypatch):
    ctx = _estate()
    _enable(monkeypatch, True)
    resp = _post_scan(_client(), ctx, ctx["admin"], direct=True, affirm=True)
    assert resp.status_code == 403, resp.text
    assert "owner" in resp.text.lower()


def test_owner_direct_is_refused_when_the_feature_is_off(monkeypatch):
    ctx = _estate()
    _enable(monkeypatch, False)
    resp = _post_scan(_client(), ctx, ctx["owner"], direct=True, affirm=True)
    assert resp.status_code == 403, resp.text
    assert "disabled" in resp.text.lower()


# ── (4) the first owner-direct scan of a target requires an affirmation ───────────────────────────
def test_owner_direct_requires_an_affirmation_the_first_time(monkeypatch):
    ctx = _estate()
    _enable(monkeypatch, True)
    resp = _post_scan(_client(), ctx, ctx["owner"], direct=True, affirm=False)
    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "owner_direct_affirmation_required"
    assert detail["target"] and detail["affirmation"]


# ── (2,3,5) an affirmed owner-direct scan runs, is labeled, and is audited immutably ──────────────
def test_owner_direct_with_affirmation_dispatches_and_is_audited(monkeypatch):
    from guardian_db.models import AuditLog, OwnerDirectAffirmation, Scan
    from guardian_db.session import session_scope

    ctx = _estate()
    _enable(monkeypatch, True)
    resp = _post_scan(_client(), ctx, ctx["owner"], direct=True, affirm=True)
    assert resp.status_code == 202, resp.text
    assert resp.json()["authorization_basis"] == "owner-direct"
    scan_id = uuid.UUID(resp.json()["id"])

    with session_scope() as db:
        scan = db.get(Scan, scan_id)
        assert scan.authorization_basis == "owner-direct"
        # The per-target affirmation was recorded.
        aff = db.query(OwnerDirectAffirmation).filter(
            OwnerDirectAffirmation.tenant_id == ctx["tenant"]).all()
        assert len(aff) == 1 and aff[0].affirmed_by == ctx["owner"]
        # Both the affirmation and the dispatch are in the audit log (accountability record).
        actions = {r.action for r in db.query(AuditLog).filter(
            AuditLog.tenant_id == ctx["tenant"]).all()}
        assert "scan.owner_direct.affirmed" in actions
        assert "scan.owner_direct.dispatch" in actions


def test_a_second_owner_direct_scan_of_the_same_target_needs_no_new_affirmation(monkeypatch):
    ctx = _estate()
    _enable(monkeypatch, True)
    client = _client()
    first = _post_scan(client, ctx, ctx["owner"], direct=True, affirm=True)
    assert first.status_code == 202, first.text
    # No affirm flag this time — the target was already affirmed, so it just runs.
    second = _post_scan(client, ctx, ctx["owner"], direct=True, affirm=False)
    assert second.status_code == 202, second.text
    assert second.json()["authorization_basis"] == "owner-direct"


def test_the_audit_row_cannot_be_edited_or_deleted(monkeypatch):
    """The accountability record is immutable at the database level (migration 0010)."""
    import sqlalchemy as sa
    from guardian_db.models import AuditLog
    from guardian_db.session import session_scope

    ctx = _estate()
    _enable(monkeypatch, True)
    assert _post_scan(_client(), ctx, ctx["owner"], direct=True, affirm=True).status_code == 202

    with session_scope() as db:
        row = db.query(AuditLog).filter(
            AuditLog.tenant_id == ctx["tenant"],
            AuditLog.action == "scan.owner_direct.dispatch").first()
        assert row is not None
        with pytest.raises(Exception):  # noqa: B017 - the DB trigger raises on any UPDATE/DELETE
            db.execute(sa.text("DELETE FROM audit_log WHERE id = :i"), {"i": str(row.id)})
            db.flush()


# ── the default path is unchanged ─────────────────────────────────────────────────────────────────
def test_a_normal_scan_is_labeled_verified_ownership(monkeypatch):
    from guardian_db.models import Scan
    from guardian_db.session import session_scope

    ctx = _estate()
    _enable(monkeypatch, True)  # even with the feature on, a non-direct scan is unaffected
    resp = _post_scan(_client(), ctx, ctx["owner"])  # no direct flag
    assert resp.status_code == 202, resp.text
    assert resp.json()["authorization_basis"] == "verified-ownership"
    with session_scope() as db:
        assert db.get(Scan, uuid.UUID(resp.json()["id"])).authorization_basis \
            == "verified-ownership"


# ── preflight tells the UI whether to offer the control ───────────────────────────────────────────
def test_preflight_is_eligible_only_for_the_owner_with_the_feature_on(monkeypatch):
    ctx = _estate()
    client = _client()

    _enable(monkeypatch, True)
    owner_pf = client.get("/api/v1/scans/owner-direct/preflight", headers=_hdr(ctx["owner"]))
    assert owner_pf.status_code == 200 and owner_pf.json()["eligible"] is True
    admin_pf = client.get("/api/v1/scans/owner-direct/preflight", headers=_hdr(ctx["admin"]))
    assert admin_pf.status_code == 200 and admin_pf.json()["eligible"] is False

    _enable(monkeypatch, False)
    off_pf = client.get("/api/v1/scans/owner-direct/preflight", headers=_hdr(ctx["owner"]))
    assert off_pf.json()["eligible"] is False and off_pf.json()["is_owner"] is True
