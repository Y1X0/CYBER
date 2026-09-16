"""SBOM download endpoints, end to end.

What is proved: a stored SBOM is downloadable as CycloneDX by its own tenant, the meta endpoint
tells the UI whether there is anything to download, and a scan belonging to another tenant is not
reachable (tenant isolation) — the same guarantee every scan-scoped endpoint must hold.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


def _tenant(*, with_sbom: bool):
    from guardian_core.sbom import Component, Vulnerability, build_sbom
    from guardian_db.models import (
        Asset,
        Customer,
        Scan,
        ScanEngineRun,
        Tenant,
        TenantMembership,
        User,
    )
    from guardian_db.sbom_store import store_sbom
    from guardian_db.session import session_scope

    slug = f"sbom-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        staff = User(email=f"s-{slug}@x.invalid", name="Analyst", status="active")
        db.add_all([customer, staff])
        db.flush()
        db.add(TenantMembership(user_id=staff.id, tenant_id=tenant.id, role="pentester"))
        asset = Asset(tenant_id=tenant.id, customer_id=customer.id, name="app", kind="repo",
                      identifier=f"https://example.invalid/{slug}.git", config={})
        db.add(asset)
        db.flush()
        scan = Scan(tenant_id=tenant.id, customer_id=customer.id, asset_id=asset.id,
                    trigger="manual", status="completed", requested_engines=["sca"], stats={})
        db.add(scan)
        db.flush()
        db.add(ScanEngineRun(scan_id=scan.id, engine="sca", status="completed"))
        db.flush()
        if with_sbom:
            sbom = build_sbom(
                [Component("Flask", "2.0.1", "pypi", "requirements.txt"),
                 Component("requests", "2.25.0", "pypi", "requirements.txt")],
                [Vulnerability("CVE-2020-1", "high", "Flask", "2.0.1", "pypi")],
                subject_name=asset.identifier)
            store_sbom(db, tenant_id=tenant.id, customer_id=customer.id, scan_id=scan.id,
                       asset_id=asset.id, sbom=sbom)
        return {"tenant": tenant.id, "scan": scan.id, "staff": staff.id, "slug": slug}


def _client(ctx):
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token

    settings = get_settings()
    token = create_access_token(subject=str(ctx["staff"]), secret=settings.jwt_secret,
                                algorithm=settings.jwt_algorithm)
    return TestClient(app), {"Authorization": f"Bearer {token}"}


def test_meta_reports_availability_and_counts():
    ctx = _tenant(with_sbom=True)
    client, hdr = _client(ctx)
    r = client.get(f"/api/v1/scans/{ctx['scan']}/sbom/meta", headers=hdr)
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is True
    assert body["component_count"] == 2
    assert body["vulnerable_count"] == 1
    assert body["format"] == "CycloneDX"


def test_download_returns_cyclonedx_document():
    ctx = _tenant(with_sbom=True)
    client, hdr = _client(ctx)
    r = client.get(f"/api/v1/scans/{ctx['scan']}/sbom", headers=hdr)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert "attachment" in r.headers.get("content-disposition", "")
    doc = r.json()
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    assert len(doc["components"]) == 2
    assert doc["vulnerabilities"][0]["id"] == "CVE-2020-1"


def test_a_scan_with_no_sbom_reports_unavailable_and_404s_on_download():
    ctx = _tenant(with_sbom=False)
    client, hdr = _client(ctx)
    assert client.get(f"/api/v1/scans/{ctx['scan']}/sbom/meta",
                      headers=hdr).json()["available"] is False
    assert client.get(f"/api/v1/scans/{ctx['scan']}/sbom", headers=hdr).status_code == 404


def test_another_tenants_scan_is_not_reachable():
    owner = _tenant(with_sbom=True)
    intruder = _tenant(with_sbom=False)
    client, hdr = _client(intruder)  # intruder's token, owner's scan
    assert client.get(f"/api/v1/scans/{owner['scan']}/sbom", headers=hdr).status_code == 404
    assert client.get(f"/api/v1/scans/{owner['scan']}/sbom/meta",
                      headers=hdr).status_code == 404
