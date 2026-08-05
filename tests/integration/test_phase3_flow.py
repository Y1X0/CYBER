"""Phase 3 end-to-end against Postgres (offline stub provider):
scan → AI analysis → report generate + PDF export → grounded chat → dashboard.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

SECRET = "aws_key = 'AKIAIOSFODNN7EXAMPLE'\n"


def _setup(db):
    from guardian_db.kb_seed import seed_knowledge_base
    from guardian_db.models import Asset, Customer, Scan, Tenant, TenantMembership, User

    seed_knowledge_base(db)
    tenant = Tenant(name="P3", slug=f"p3-{uuid.uuid4().hex[:8]}", mode="hybrid")
    db.add(tenant)
    db.flush()
    owner = User(
        email=f"o-{uuid.uuid4().hex[:6]}@x.com", name="O", password_hash="x", status="active"
    )
    db.add(owner)
    db.flush()
    db.add(TenantMembership(user_id=owner.id, tenant_id=tenant.id, role="owner"))
    customer = Customer(tenant_id=tenant.id, name="P3 Co", criticality="high")
    db.add(customer)
    db.flush()
    asset = Asset(
        tenant_id=tenant.id,
        customer_id=customer.id,
        name="repo",
        kind="repo",
        identifier="inline",
        exposure="public",
        config={"inline_content": SECRET},
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
    return str(owner.id), str(scan.id), str(customer.id)


def test_phase3_end_to_end():
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token
    from guardian_db.models import Finding
    from guardian_db.session import session_scope
    from guardian_scanner.analysis import analyze_scan
    from guardian_scanner.tasks import run_scan

    settings = get_settings()
    client = TestClient(app)

    with session_scope() as db:
        owner_id, scan_id, customer_id = _setup(db)

    # Scan, then AI-analyze (stub provider — offline).
    assert run_scan.apply(args=[scan_id]).get()["status"] == "completed"
    result = analyze_scan.apply(args=[scan_id]).get()
    assert result["status"] == "completed" and result["provider"] == "stub"
    assert result["analyzed"] >= 1

    with session_scope() as db:
        findings = db.query(Finding).filter(Finding.scan_id == uuid.UUID(scan_id)).all()
        assert findings and all(f.ai_explanation for f in findings)
        # AI never invented a reference outside the finding's own standards mapping.
        for f in findings:
            allowed = set(f.cve_ids or []) | {f.cwe_id, f.owasp_ref}
            for ref in (f.remediation or {}).get("references", []):
                assert ref in allowed

    hdr = {
        "Authorization": f"Bearer {create_access_token(subject=owner_id, secret=settings.jwt_secret, algorithm=settings.jwt_algorithm)}"
    }

    # Report: create → generate → export PDF.
    rid = client.post("/api/v1/reports", headers=hdr, json={"scan_id": scan_id}).json()["id"]
    gen = client.post(f"/api/v1/reports/{rid}/generate", headers=hdr, json={}).json()
    assert gen["summary"]["security_score"] is not None
    assert gen["summary"]["total_findings"] >= 1
    pdf = client.get(f"/api/v1/reports/{rid}/export?format=pdf", headers=hdr)
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    html = client.get(f"/api/v1/reports/{rid}/export?format=html", headers=hdr)
    assert "Executive Summary" in html.text

    # Grounded chat.
    chat = client.post(
        "/api/v1/chat",
        headers=hdr,
        json={"question": "what is my biggest risk?", "scan_id": scan_id},
    ).json()
    assert chat["cited_finding_ids"]
    assert "AKIAIOSFODNN7EXAMPLE" not in chat["answer"]  # never echoes raw secrets

    # Dashboard.
    dash = client.get(f"/api/v1/dashboard?customer_id={customer_id}", headers=hdr).json()
    assert 0 <= dash["security_score"] <= 100
    assert dash["total_findings"] >= 1
