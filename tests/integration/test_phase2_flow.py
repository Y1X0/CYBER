"""Phase 2 end-to-end against Postgres: KB-matched SCA + human-pentester workflow.

Gated by GUARDIAN_RUN_DB_TESTS=1 (CI provides Postgres). Verifies:
  - the offline KB seed loads,
  - an SCA scan matches a dependency against the KB and scores its risk,
  - a pentester can triage a finding (audited),
  - the report approval flow enforces reviewer gating and state transitions.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


def _mk_tenant_customer(db):
    from guardian_db.kb_seed import seed_knowledge_base
    from guardian_db.models import Customer, Tenant

    seed_knowledge_base(db)
    tenant = Tenant(name="P2", slug=f"p2-{uuid.uuid4().hex[:8]}", mode="hybrid")
    db.add(tenant)
    db.flush()
    customer = Customer(tenant_id=tenant.id, name="P2 Co", criticality="high")
    db.add(customer)
    db.flush()
    return tenant, customer


def test_sca_matches_kb_and_scores_risk():
    from guardian_db.models import Asset, Finding, Scan
    from guardian_db.session import session_scope
    from guardian_scanner.tasks import run_scan

    with session_scope() as db:
        tenant, customer = _mk_tenant_customer(db)
        asset = Asset(
            tenant_id=tenant.id,
            customer_id=customer.id,
            name="app",
            kind="repo",
            identifier="inline",
            exposure="public",
            config={"inline_content": "pyyaml==5.3\nrequests==2.31.0\n"},
        )
        db.add(asset)
        db.flush()
        scan = Scan(
            tenant_id=tenant.id,
            customer_id=customer.id,
            asset_id=asset.id,
            trigger="manual",
            status="queued",
            requested_engines=["sca"],
            stats={},
        )
        db.add(scan)
        db.flush()
        scan_id = str(scan.id)

    result = run_scan.apply(args=[scan_id]).get()
    assert result["status"] == "completed"

    with session_scope() as db:
        findings = db.query(Finding).filter(Finding.scan_id == uuid.UUID(scan_id)).all()
        assert len(findings) == 1
        f = findings[0]
        assert "CVE-2020-14343" in f.cve_ids
        assert f.category == "vuln-dep"
        # public + high-criticality + KB epss → elevated, with a transparent rationale.
        assert f.severity in ("high", "critical")
        assert f.risk_score > 0
        assert f.risk_rationale


def test_pentester_workflow_via_api():
    import guardian_api.routes.scans as sr
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token
    from guardian_db.models import Asset, TenantMembership, User
    from guardian_db.session import session_scope
    from guardian_scanner.tasks import run_scan

    settings = get_settings()
    sr.enqueue_scan = lambda scan_id: run_scan.apply(args=[scan_id]).get()
    client = TestClient(app)

    with session_scope() as db:
        tenant, customer = _mk_tenant_customer(db)
        # A pentester (write) and a reviewer (approval) in the same tenant.
        pentester = User(
            email=f"pt-{uuid.uuid4().hex[:6]}@x.com", name="PT", password_hash="x", status="active"
        )
        reviewer = User(
            email=f"rv-{uuid.uuid4().hex[:6]}@x.com", name="RV", password_hash="x", status="active"
        )
        db.add_all([pentester, reviewer])
        db.flush()
        db.add(TenantMembership(user_id=pentester.id, tenant_id=tenant.id, role="pentester"))
        db.add(TenantMembership(user_id=reviewer.id, tenant_id=tenant.id, role="reviewer"))
        asset = Asset(
            tenant_id=tenant.id,
            customer_id=customer.id,
            name="app",
            kind="repo",
            identifier="inline",
            exposure="public",
            config={"inline_content": "aws='AKIAIOSFODNN7EXAMPLE'\n"},
        )
        db.add(asset)
        db.flush()
        pt_id, rv_id, asset_id = str(pentester.id), str(reviewer.id), str(asset.id)

    def tok(uid):
        return {
            "Authorization": f"Bearer {create_access_token(subject=uid, secret=settings.jwt_secret, algorithm=settings.jwt_algorithm)}"
        }

    # Pentester runs a scan
    s = client.post(
        "/api/v1/scans",
        headers=tok(pt_id),
        json={"asset_id": asset_id, "engines": ["secrets", "sast"]},
    )
    assert s.status_code == 202
    scan_id = s.json()["id"]

    findings = client.get(f"/api/v1/findings?scan_id={scan_id}", headers=tok(pt_id)).json()
    assert findings
    fid = findings[0]["id"]

    # Triage without justification for a false positive → rejected
    bad = client.patch(
        f"/api/v1/findings/{fid}", headers=tok(pt_id), json={"status": "false_positive"}
    )
    assert bad.status_code == 422
    # With justification → accepted
    good = client.patch(
        f"/api/v1/findings/{fid}",
        headers=tok(pt_id),
        json={"status": "confirmed", "note": "verified manually"},
    )
    assert good.status_code == 200 and good.json()["status"] == "confirmed"

    # Report flow: create draft → submit → (pentester cannot approve) → reviewer approves → publish
    rep = client.post("/api/v1/reports", headers=tok(pt_id), json={"scan_id": scan_id}).json()
    rid = rep["id"]
    assert (
        client.post(f"/api/v1/reports/{rid}/submit", headers=tok(pt_id), json={}).json()["status"]
        == "in_review"
    )
    # pentester lacks reviewer role
    assert (
        client.post(f"/api/v1/reports/{rid}/approve", headers=tok(pt_id), json={}).status_code
        == 403
    )
    # reviewer approves
    assert (
        client.post(
            f"/api/v1/reports/{rid}/approve", headers=tok(rv_id), json={"notes": "ok"}
        ).json()["status"]
        == "approved"
    )
    # publish (pentester can publish an approved report)
    assert (
        client.post(f"/api/v1/reports/{rid}/publish", headers=tok(pt_id), json={}).json()["status"]
        == "published"
    )
    # cannot approve a published report (state guard)
    assert (
        client.post(f"/api/v1/reports/{rid}/approve", headers=tok(rv_id), json={}).status_code
        == 409
    )
