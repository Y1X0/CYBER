"""Phase 4 end-to-end against Postgres:
authorization gate (blocks active engines), deployment gate, and the GitHub webhook.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

CLOUD = {
    "provider": "aws",
    "storage": [{"name": "b1", "public": True, "encrypted": False}],
    "network": [{"name": "sg1", "ingress": [{"cidr": "0.0.0.0/0", "port": 22}]}],
}


def _tenant_customer(db):
    from guardian_db.models import Customer, Tenant, TenantMembership, User

    tenant = Tenant(name="P4", slug=f"p4-{uuid.uuid4().hex[:8]}", mode="hybrid")
    db.add(tenant)
    db.flush()
    owner = User(
        email=f"o-{uuid.uuid4().hex[:6]}@x.com", name="O", password_hash="x", status="active"
    )
    db.add(owner)
    db.flush()
    db.add(TenantMembership(user_id=owner.id, tenant_id=tenant.id, role="owner"))
    customer = Customer(tenant_id=tenant.id, name="P4 Co", criticality="high")
    db.add(customer)
    db.flush()
    return tenant, owner, customer


def test_authorization_gate_blocks_then_allows_active_engine():
    from guardian_db.models import Asset, Authorization, Finding, Scan, ScanEngineRun
    from guardian_db.session import session_scope
    from guardian_scanner.tasks import run_scan

    with session_scope() as db:
        tenant, owner, customer = _tenant_customer(db)
        asset = Asset(
            tenant_id=tenant.id,
            customer_id=customer.id,
            name="aws",
            kind="cloud_account",
            identifier="aws:acct",
            exposure="public",
            config={"cloud_config": CLOUD},
        )
        db.add(asset)
        db.flush()
        asset_id, tenant_id, customer_id, owner_id = (asset.id, tenant.id, customer.id, owner.id)

        def mk_scan():
            s = Scan(
                tenant_id=tenant_id,
                customer_id=customer_id,
                asset_id=asset_id,
                trigger="manual",
                status="queued",
                requested_engines=["cspm"],
                stats={},
            )
            db.add(s)
            db.flush()
            return str(s.id)

        scan_blocked = mk_scan()

    # No authorization → active CSPM engine is skipped, zero findings.
    run_scan.apply(args=[scan_blocked]).get()
    with session_scope() as db:
        runs = (
            db.query(ScanEngineRun).filter(ScanEngineRun.scan_id == uuid.UUID(scan_blocked)).all()
        )
        assert any(r.engine == "cspm" and r.status == "skipped" for r in runs)
        assert db.query(Finding).filter(Finding.scan_id == uuid.UUID(scan_blocked)).count() == 0

        # Grant authorization, run again → findings appear.
        now = dt.datetime.now(dt.UTC)
        db.add(
            Authorization(
                tenant_id=tenant_id,
                customer_id=customer_id,
                asset_id=asset_id,
                scope="cloud audit",
                method="ownership_verified",
                authorized_by=owner_id,
                valid_from=now - dt.timedelta(hours=1),
                valid_until=now + dt.timedelta(days=1),
            )
        )
        scan_ok = Scan(
            tenant_id=tenant_id,
            customer_id=customer_id,
            asset_id=asset_id,
            trigger="manual",
            status="queued",
            requested_engines=["cspm"],
            stats={},
        )
        db.add(scan_ok)
        db.flush()
        scan_ok_id = str(scan_ok.id)

    run_scan.apply(args=[scan_ok_id]).get()
    with session_scope() as db:
        findings = db.query(Finding).filter(Finding.scan_id == uuid.UUID(scan_ok_id)).all()
        assert findings and any("storage" in f.title.lower() for f in findings)


def test_deployment_gate_and_webhook():
    import guardian_api.routes.scans as scans_route
    import guardian_api.routes.webhooks as wh
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token
    from guardian_db.models import Asset, Scan
    from guardian_db.session import session_scope
    from guardian_scanner.tasks import run_scan

    # Configure a webhook secret and neutralize the async enqueue (no broker in tests).
    os.environ["GUARDIAN_GITHUB_WEBHOOK_SECRET"] = "testsecret"
    get_settings.cache_clear()
    wh.enqueue_scan = lambda *_: None
    scans_route.enqueue_scan = lambda *_: None
    settings = get_settings()
    client = TestClient(app)

    with session_scope() as db:
        tenant, owner, customer = _tenant_customer(db)
        asset = Asset(
            tenant_id=tenant.id,
            customer_id=customer.id,
            name="repo",
            kind="repo",
            identifier="https://github.com/acme/app.git",
            exposure="public",
            config={"inline_content": "aws='AKIAIOSFODNN7EXAMPLE'\n"},
        )
        db.add(asset)
        db.flush()
        scan = Scan(
            tenant_id=tenant.id,
            customer_id=customer.id,
            asset_id=asset.id,
            trigger="manual",
            status="queued",
            requested_engines=["secrets"],
            stats={},
        )
        db.add(scan)
        db.flush()
        owner_id, scan_id = str(owner.id), str(scan.id)

    run_scan.apply(args=[scan_id]).get()  # yields a CRITICAL secret on a public asset
    hdr = {
        "Authorization": f"Bearer {create_access_token(subject=owner_id, secret=settings.jwt_secret, algorithm=settings.jwt_algorithm)}"
    }

    # Gate blocks on the critical finding (built-in DEFAULT_RULES).
    gate = client.get(f"/api/v1/scans/{scan_id}/gate", headers=hdr).json()
    assert gate["passed"] is False and gate["blocking_count"] >= 1

    # Triage the finding to false_positive → gate now passes.
    fid = client.get(f"/api/v1/findings?scan_id={scan_id}", headers=hdr).json()[0]["id"]
    client.patch(
        f"/api/v1/findings/{fid}",
        headers=hdr,
        json={"status": "false_positive", "note": "test fixture"},
    )
    assert client.get(f"/api/v1/scans/{scan_id}/gate", headers=hdr).json()["passed"] is True

    # Webhook: valid HMAC + push for the mapped repo → scan queued.
    payload = json.dumps(
        {"after": "abc123", "repository": {"clone_url": "https://github.com/acme/app.git"}}
    ).encode()
    sig = "sha256=" + hmac.new(b"testsecret", payload, hashlib.sha256).hexdigest()
    resp = client.post(
        "/webhooks/github",
        content=payload,
        headers={
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "push",
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 202 and resp.json()["status"] == "scan_queued"

    # Bad signature is rejected.
    bad = client.post(
        "/webhooks/github",
        content=payload,
        headers={"X-Hub-Signature-256": "sha256=deadbeef", "X-GitHub-Event": "push"},
    )
    assert bad.status_code == 401

    with session_scope() as db:
        # The webhook created a second scan for the asset.
        count = db.query(Scan).filter(Scan.trigger == "webhook").count()
        assert count >= 1
