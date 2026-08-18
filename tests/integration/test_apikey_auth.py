"""Authenticating with an API key (WP-G1).

`api_keys` has been a table with no issuance path and no authentication path, so the only credential
that has ever worked against this API is a person's password. That is the gap a CI pipeline falls
into.

What has to be true of the fix, and is tested here against the live database:

* the key works, and it is scoped — a key without the scope is refused even though the endpoint
  would happily serve a human;
* revocation and expiry take effect on the next request, not on the next cache flush;
* a key cannot mint another key, and cannot use endpoints that require a human staff role;
* the secret is returned once and never appears again — not in a listing, not in an audit record;
* a key sees its own tenant and no other.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


def _tenant(role="owner"):
    from guardian_db.models import (
        Asset,
        Customer,
        Finding,
        Scan,
        ScanEngineRun,
        Tenant,
        TenantMembership,
        User,
    )
    from guardian_db.session import session_scope

    slug = f"g1-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        user = User(email=f"o-{slug}@x.invalid", name="Owner", status="active")
        db.add_all([customer, user])
        db.flush()
        db.add(TenantMembership(user_id=user.id, tenant_id=tenant.id, role=role))
        asset = Asset(tenant_id=tenant.id, customer_id=customer.id, name="app", kind="repo",
                      identifier=f"https://example.invalid/{slug}.git", config={})
        db.add(asset)
        db.flush()
        scan = Scan(tenant_id=tenant.id, customer_id=customer.id, asset_id=asset.id,
                    trigger="manual", status="completed", requested_engines=["secrets"], stats={})
        db.add(scan)
        db.flush()
        run = ScanEngineRun(scan_id=scan.id, engine="secrets", status="completed")
        db.add(run)
        db.flush()
        db.add(Finding(
            tenant_id=tenant.id, customer_id=customer.id, scan_id=scan.id, engine_run_id=run.id,
            asset_id=asset.id, fingerprint=uuid.uuid4().hex[:32], title="Hardcoded credential",
            description="", category="secret", severity="critical", risk_score=95, status="open",
            location={}, evidence={},
        ))
        db.flush()
        return {"tenant": tenant.id, "customer": customer.id, "user": user.id, "scan": scan.id,
                "asset": asset.id, "slug": slug}


def _client(ctx):
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token

    settings = get_settings()
    token = create_access_token(subject=str(ctx["user"]), secret=settings.jwt_secret,
                                algorithm=settings.jwt_algorithm)
    return TestClient(app), {"Authorization": f"Bearer {token}"}


def _issue(ctx, scopes, *, ttl_days=30):
    client, hdr = _client(ctx)
    response = client.post("/api/v1/api-keys", headers=hdr,
                           json={"name": "ci", "scopes": list(scopes), "ttl_days": ttl_days})
    assert response.status_code == 201, response.text
    body = response.json()
    return client, {"Authorization": f"Bearer {body['token']}"}, body


# ── issuance ──────────────────────────────────────────────────────────────────────────────────────
def test_a_key_is_returned_once_and_never_again():
    """A key you can re-read is a key that lives in whatever read it."""
    ctx = _tenant()
    client, key_hdr, created = _issue(ctx, ["findings:read"])
    _, hdr = _client(ctx)

    assert created["token"].startswith("gdn_")
    listing = client.get("/api/v1/api-keys", headers=hdr).json()
    assert listing[0]["id"] == created["id"]
    # No listing, and no other endpoint, carries the secret.
    assert created["token"] not in str(listing)
    del key_hdr


def test_the_secret_never_reaches_the_audit_log():
    from guardian_db.models import AuditLog
    from guardian_db.session import session_scope

    ctx = _tenant()
    _, _, created = _issue(ctx, ["findings:read"])

    with session_scope() as db:
        rows = db.query(AuditLog).filter(AuditLog.tenant_id == ctx["tenant"]).all()
        blob = " ".join(f"{r.action} {r.metadata_} {r.entity_id}" for r in rows)
    assert created["token"] not in blob
    assert "apikey.created" in blob


def test_an_unknown_scope_is_refused_rather_than_silently_dropped():
    ctx = _tenant()
    client, hdr = _client(ctx)
    response = client.post("/api/v1/api-keys", headers=hdr,
                           json={"name": "bad", "scopes": ["admin:*"], "ttl_days": 30})
    assert response.status_code == 422
    assert "admin:*" in response.text


# ── authentication ────────────────────────────────────────────────────────────────────────────────
def test_a_scoped_key_can_read_findings():
    ctx = _tenant()
    client, key_hdr, _ = _issue(ctx, ["findings:read"])

    response = client.get("/api/v1/findings", headers=key_hdr)

    assert response.status_code == 200
    assert response.json()[0]["title"] == "Hardcoded credential"


def test_a_key_without_the_scope_is_refused_on_an_endpoint_a_human_may_use():
    ctx = _tenant()
    client, key_hdr, _ = _issue(ctx, ["scans:read"])

    response = client.get("/api/v1/findings", headers=key_hdr)

    assert response.status_code == 403
    assert "findings:read" in response.text


def test_a_forged_key_is_refused():
    ctx = _tenant()
    client, _, created = _issue(ctx, ["findings:read"])
    forged = {"Authorization": f"Bearer gdn_{created['id'].replace('-', '')[:16]}_" + "x" * 43}

    assert client.get("/api/v1/findings", headers=forged).status_code == 401


def test_a_key_for_an_id_that_does_not_exist_is_refused():
    ctx = _tenant()
    client, _, _ = _issue(ctx, ["findings:read"])
    response = client.get("/api/v1/findings",
                          headers={"Authorization": "Bearer gdn_" + "0" * 16 + "_" + "y" * 43})
    assert response.status_code == 401


def test_a_revoked_key_stops_working_on_the_next_request():
    ctx = _tenant()
    client, key_hdr, created = _issue(ctx, ["findings:read"])
    _, hdr = _client(ctx)

    assert client.get("/api/v1/findings", headers=key_hdr).status_code == 200
    assert client.delete(f"/api/v1/api-keys/{created['id']}", headers=hdr).status_code == 204

    response = client.get("/api/v1/findings", headers=key_hdr)
    assert response.status_code == 401
    assert "revoked" in response.text


def test_an_expired_key_is_refused():
    from guardian_db.models import ApiKey
    from guardian_db.session import session_scope

    ctx = _tenant()
    client, key_hdr, created = _issue(ctx, ["findings:read"])
    with session_scope() as db:
        db.get(ApiKey, uuid.UUID(created["id"])).expires_at = (
            dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)
        )

    response = client.get("/api/v1/findings", headers=key_hdr)
    assert response.status_code == 401
    assert "expired" in response.text


def test_using_a_key_records_when_it_was_last_used():
    """An unused key that nobody remembers issuing is the one worth revoking."""
    from guardian_db.models import ApiKey
    from guardian_db.session import session_scope

    ctx = _tenant()
    client, key_hdr, created = _issue(ctx, ["findings:read"])
    client.get("/api/v1/findings", headers=key_hdr)

    with session_scope() as db:
        assert db.get(ApiKey, uuid.UUID(created["id"])).last_used_at is not None


# ── what a key may never do ───────────────────────────────────────────────────────────────────────
def test_a_key_cannot_mint_another_key():
    """A key that can mint keys can escalate past its own scopes and outlive its own revocation."""
    ctx = _tenant()
    client, key_hdr, _ = _issue(ctx, list(__import__("guardian_core.apikeys",
                                                     fromlist=["ALL_SCOPES"]).ALL_SCOPES))

    response = client.post("/api/v1/api-keys", headers=key_hdr,
                           json={"name": "second", "scopes": [], "ttl_days": 1})

    assert response.status_code == 403
    assert "cannot manage API keys" in response.text


def test_a_key_cannot_use_an_endpoint_that_requires_a_human_role():
    """Every endpoint written before keys existed stays closed to them: opting one in is an
    explicit act."""
    ctx = _tenant()
    client, key_hdr, _ = _issue(ctx, ["findings:read"])
    findings = client.get("/api/v1/findings", headers=key_hdr).json()

    response = client.patch(f"/api/v1/findings/{findings[0]['id']}", headers=key_hdr,
                            json={"status": "confirmed"})

    assert response.status_code == 403
    assert "human staff role" in response.text


def test_a_key_sees_only_its_own_tenant():
    mine, theirs = _tenant(), _tenant()
    client, key_hdr, _ = _issue(mine, ["findings:read"])
    _, their_key_hdr, _ = _issue(theirs, ["findings:read"])

    mine_titles = {row["id"] for row in client.get("/api/v1/findings", headers=key_hdr).json()}
    theirs_titles = {row["id"] for row in
                     client.get("/api/v1/findings", headers=their_key_hdr).json()}

    assert mine_titles and theirs_titles
    assert mine_titles.isdisjoint(theirs_titles)


def test_only_an_owner_or_admin_can_manage_keys():
    ctx = _tenant(role="analyst")
    client, hdr = _client(ctx)

    response = client.post("/api/v1/api-keys", headers=hdr,
                           json={"name": "x", "scopes": [], "ttl_days": 1})

    assert response.status_code == 403
    assert "owner or admin" in response.text


def test_the_scope_catalogue_is_discoverable():
    ctx = _tenant()
    client, hdr = _client(ctx)
    body = client.get("/api/v1/api-keys/scopes", headers=hdr).json()

    assert "findings:read" in body["scopes"]
    assert "assets:write" not in body["presets"]["ci"]
