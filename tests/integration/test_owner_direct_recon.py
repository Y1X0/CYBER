"""Owner-direct RECON — the OWNER-ONLY, affirmed, audited gate on the real API path.

The capability: the tenant OWNER may dispatch a governed active port scan (nmap) under their own
asserted legal authority. It mirrors owner-direct scanning exactly, and these tests prove it is
enforced server-side and is not a client flag:

  * a NON-OWNER is refused (403) — even WITH a verified-ownership authorization for the target;
  * with the feature off, even the owner is refused (403) — safe by default;
  * the first recon of a target needs a legal affirmation (409), which is then recorded immutably;
  * an affirmed recon dispatch is accepted (202) and both the affirmation and the dispatch are
    written to the (immutable) audit log;
  * a second recon of the same target needs no new affirmation;
  * the trusted tool-dispatch plane RE-CHECKS owner-direct server-side (defense in depth): a
    non-owner, or the owner with the feature off, is refused at dispatch too.

Gated by GUARDIAN_RUN_DB_TESTS=1 (needs a live database).
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

_TARGET_IP = "203.0.113.7"


def _token(user_id: uuid.UUID) -> str:
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token

    s = get_settings()
    return create_access_token(subject=str(user_id), secret=s.jwt_secret,
                               algorithm=s.jwt_algorithm, claims={"tv": 0})


def _estate():
    """A tenant with an OWNER, a non-owner ADMIN, a customer, an asset, AND a verified-ownership
    authorization covering the target IP — so we can prove a non-owner is refused even with it."""
    from guardian_core.enums import StaffRole
    from guardian_db.models import Asset, Authorization, Customer, Tenant, TenantMembership, User
    from guardian_db.session import session_scope

    slug = f"odr-{uuid.uuid4().hex[:10]}"
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
            TenantMembership(user_id=owner.id, tenant_id=tenant.id, role=StaffRole.OWNER.value),
            TenantMembership(user_id=admin.id, tenant_id=tenant.id, role=StaffRole.ADMIN.value),
        ])
        asset = Asset(tenant_id=tenant.id, customer_id=customer.id, name="host", kind="host",
                      identifier=_TARGET_IP, exposure="public")
        db.add(asset)
        db.flush()
        now = dt.datetime.now(dt.UTC)
        db.add(Authorization(
            tenant_id=tenant.id, customer_id=customer.id, asset_id=asset.id,
            method="ownership_verified", authorized_by=admin.id,
            authorized_targets=[{"type": "ip", "value": _TARGET_IP}],
            valid_from=now - dt.timedelta(days=1), valid_until=now + dt.timedelta(days=1),
        ))
        return {"tenant": tenant.id, "asset": asset.id, "customer": customer.id,
                "owner": owner.id, "admin": admin.id}


def _client():
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_api.ratelimit import login_limiter

    login_limiter().reset()
    return TestClient(app)


def _enable(monkeypatch, on: bool = True) -> None:
    from guardian_common.config import get_settings

    monkeypatch.setattr(get_settings(), "owner_direct_recon", on, raising=False)


def _hdr(user_id: uuid.UUID) -> dict:
    return {"Authorization": f"Bearer {_token(user_id)}"}


def _post_recon(client, ctx, user_id, **body):
    payload = {"target": _TARGET_IP, "asset_id": str(ctx["asset"]), **body}
    return client.post("/api/v1/recon", headers=_hdr(user_id), json=payload)


# ── (1) OWNER-only, server-side — a non-owner is refused EVEN WITH verified ownership ──────────────
def test_a_non_owner_is_refused_recon_even_with_verified_ownership(monkeypatch):
    ctx = _estate()
    _enable(monkeypatch, True)
    # The admin holds a verified-ownership authorization for this exact IP, yet recon is owner-only.
    resp = _post_recon(_client(), ctx, ctx["admin"], affirm=True)
    assert resp.status_code == 403, resp.text
    assert "owner" in resp.text.lower()


def test_recon_is_refused_when_the_feature_is_off(monkeypatch):
    ctx = _estate()
    _enable(monkeypatch, False)
    resp = _post_recon(_client(), ctx, ctx["owner"], affirm=True)
    assert resp.status_code == 403, resp.text
    assert "disabled" in resp.text.lower()


# ── (4) the first recon of a target requires an affirmation ───────────────────────────────────────
def test_recon_requires_an_affirmation_the_first_time(monkeypatch):
    ctx = _estate()
    _enable(monkeypatch, True)
    resp = _post_recon(_client(), ctx, ctx["owner"], affirm=False)
    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "recon_affirmation_required"
    assert detail["target"] == _TARGET_IP
    assert "port-scan" in detail["affirmation"] or "port scan" in detail["affirmation"]


# ── (2,3,5) an affirmed recon dispatch is accepted, stored, and audited immutably ─────────────────
def test_recon_with_affirmation_dispatches_and_is_audited(monkeypatch):
    from guardian_db.models import AuditLog, ReconAffirmation
    from guardian_db.session import session_scope

    ctx = _estate()
    _enable(monkeypatch, True)
    resp = _post_recon(_client(), ctx, ctx["owner"], affirm=True)
    assert resp.status_code == 202, resp.text
    assert resp.json()["authorization_basis"] == "owner-direct-recon"

    with session_scope() as db:
        aff = db.query(ReconAffirmation).filter(
            ReconAffirmation.tenant_id == ctx["tenant"]).all()
        assert len(aff) == 1 and aff[0].affirmed_by == ctx["owner"]
        assert aff[0].target == _TARGET_IP
        actions = {r.action for r in db.query(AuditLog).filter(
            AuditLog.tenant_id == ctx["tenant"]).all()}
        assert "recon.affirmed" in actions
        assert "recon.dispatch" in actions


def test_a_second_recon_of_the_same_target_needs_no_new_affirmation(monkeypatch):
    ctx = _estate()
    _enable(monkeypatch, True)
    client = _client()
    first = _post_recon(client, ctx, ctx["owner"], affirm=True)
    assert first.status_code == 202, first.text
    second = _post_recon(client, ctx, ctx["owner"], affirm=False)  # already affirmed → just runs
    assert second.status_code == 202, second.text
    assert second.json()["authorization_basis"] == "owner-direct-recon"


def test_recon_rejects_a_non_ip_target(monkeypatch):
    ctx = _estate()
    _enable(monkeypatch, True)
    resp = _client().post("/api/v1/recon", headers=_hdr(ctx["owner"]),
                          json={"target": "evil.example.com", "affirm": True})
    assert resp.status_code == 422, resp.text


# ── preflight tells the UI whether to offer the control ───────────────────────────────────────────
def test_preflight_is_eligible_only_for_the_owner_with_the_feature_on(monkeypatch):
    ctx = _estate()
    client = _client()

    _enable(monkeypatch, True)
    owner_pf = client.get("/api/v1/recon/preflight", headers=_hdr(ctx["owner"]))
    assert owner_pf.status_code == 200 and owner_pf.json()["eligible"] is True
    admin_pf = client.get("/api/v1/recon/preflight", headers=_hdr(ctx["admin"]))
    assert admin_pf.status_code == 200 and admin_pf.json()["eligible"] is False

    _enable(monkeypatch, False)
    off_pf = client.get("/api/v1/recon/preflight", headers=_hdr(ctx["owner"]))
    assert off_pf.json()["eligible"] is False and off_pf.json()["is_owner"] is True


# ── defense in depth: the trusted tool-dispatch plane RE-CHECKS owner-direct server-side ───────────
def test_dispatch_plane_rechecks_owner_direct_recon(monkeypatch):
    """dispatch_tool_job must refuse owner-direct recon for a non-owner (even one who passes tool
    governance) and for the owner when the feature is off — never trusting the caller's flag."""
    from guardian_scanner.tools.tasks import dispatch_tool_job

    ctx = _estate()

    # Non-owner (admin passes L2 nmap governance) with owner_direct=True → refused as not owner.
    _enable(monkeypatch, True)
    res = dispatch_tool_job.apply(kwargs=dict(
        tenant_id=str(ctx["tenant"]), tool_key="nmap", requested_targets=[_TARGET_IP],
        actor_id=str(ctx["admin"]), human_approved=True,
        settings={"allow_live": False}, owner_direct=True, asset_id=str(ctx["asset"]))).get()
    assert res["status"] == "forbidden"
    assert any("owner" in r.lower() for r in res["reasons"])

    # Owner with the feature OFF → refused as disabled.
    _enable(monkeypatch, False)
    res2 = dispatch_tool_job.apply(kwargs=dict(
        tenant_id=str(ctx["tenant"]), tool_key="nmap", requested_targets=[_TARGET_IP],
        actor_id=str(ctx["owner"]), human_approved=True,
        settings={"allow_live": False}, owner_direct=True, asset_id=str(ctx["asset"]))).get()
    assert res2["status"] == "forbidden"
    assert any("disabled" in r.lower() for r in res2["reasons"])
