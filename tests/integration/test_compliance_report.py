"""Compliance in the API and in the report a customer actually receives (WP-F4).

`test_compliance.py` proves the assessment logic. This proves the two places it reaches a reader:
the `/compliance` endpoint and the exported report — and that in both, a control nothing assessed
is shown as not assessed rather than folded into a pass rate.

It also covers the thing a report is uniquely dangerous for: the evidence it prints. A report is
emailed, attached to a board pack and forwarded to prospects, so it is the worst possible place for
the one credential an engine failed to redact.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def _estate(*, engines=("secrets",), engine_status="completed", findings=()):
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

    slug = f"f4-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        user = User(email=f"u-{slug}@x.invalid", name="Analyst", status="active")
        db.add_all([customer, user])
        db.flush()
        db.add(TenantMembership(user_id=user.id, tenant_id=tenant.id, role="pentester"))
        asset = Asset(tenant_id=tenant.id, customer_id=customer.id, name="app", kind="repo",
                      identifier=f"https://example.invalid/{slug}.git", config={})
        db.add(asset)
        db.flush()
        scan = Scan(tenant_id=tenant.id, customer_id=customer.id, asset_id=asset.id,
                    trigger="manual", status="completed", requested_engines=list(engines),
                    stats={})
        db.add(scan)
        db.flush()
        runs = {}
        for engine in engines:
            run = ScanEngineRun(scan_id=scan.id, engine=engine, status=engine_status)
            db.add(run)
            db.flush()
            runs[engine] = run.id

        for spec in findings:
            db.add(Finding(
                tenant_id=tenant.id, customer_id=customer.id, scan_id=scan.id,
                engine_run_id=runs[spec.get("engine", engines[0])], asset_id=asset.id,
                fingerprint=uuid.uuid4().hex[:32], title=spec["title"], description="",
                category=spec.get("category", "secret"), severity=spec.get("severity", "high"),
                risk_score=spec.get("risk", 80), status=spec.get("status", "open"),
                cwe_id=spec.get("cwe"), location={"rule": spec.get("rule", "")},
                evidence=spec.get("evidence", {}),
            ))
        db.flush()
        return {"tenant": tenant.id, "customer": customer.id, "scan": scan.id, "user": user.id,
                "slug": slug}


def _client(ctx):
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token

    settings = get_settings()
    token = create_access_token(subject=str(ctx["user"]), secret=settings.jwt_secret,
                                algorithm=settings.jwt_algorithm)
    return TestClient(app), {"Authorization": f"Bearer {token}"}


def _framework(body, name):
    return next(f for f in body["frameworks"] if f["framework"] == name)


def _control(framework, control_id):
    return next(c for c in framework["controls"] if c["id"] == control_id)


# ── the API ───────────────────────────────────────────────────────────────────────────────────────
def test_a_finding_fails_its_control_through_the_api():
    ctx = _estate(findings=[{"title": "Hardcoded AWS credential", "cwe": "CWE-798",
                             "category": "secret"}])
    client, hdr = _client(ctx)

    body = client.get(f"/api/v1/compliance?scan_id={ctx['scan']}", headers=hdr).json()
    soc2 = _framework(body, "soc2")

    assert _control(soc2, "CC6.2")["status"] == "failing"
    assert _control(soc2, "CC6.2")["findings"][0]["title"] == "Hardcoded AWS credential"


def test_a_control_no_engine_assessed_is_reported_as_not_assessed():
    """Only the secrets engine ran. Nothing looked at the cloud logging controls, and the report
    must say so rather than counting them as passing."""
    ctx = _estate(engines=("secrets",))
    client, hdr = _client(ctx)

    soc2 = _framework(client.get(f"/api/v1/compliance?scan_id={ctx['scan']}",
                                 headers=hdr).json(), "soc2")

    assert _control(soc2, "CC7.2")["status"] == "not_assessed"
    assert _control(soc2, "CC6.2")["status"] == "passing"   # secrets ran and found nothing
    assert soc2["coverage"] < 100


def test_an_engine_that_failed_did_not_assess_anything():
    """A failed run produces no findings, which is indistinguishable from a clean one unless the
    run's status is what decides."""
    ctx = _estate(engines=("secrets",), engine_status="failed")
    client, hdr = _client(ctx)

    soc2 = _framework(client.get(f"/api/v1/compliance?scan_id={ctx['scan']}",
                                 headers=hdr).json(), "soc2")
    assert _control(soc2, "CC6.2")["status"] == "not_assessed"


def test_the_response_carries_the_disclaimer_and_overall_coverage():
    ctx = _estate()
    client, hdr = _client(ctx)
    body = client.get("/api/v1/compliance", headers=hdr).json()

    assert "does not certify compliance" in body["disclaimer"]
    assert isinstance(body["overall_coverage"], int)


def test_a_single_framework_can_be_requested():
    ctx = _estate()
    client, hdr = _client(ctx)
    body = client.get("/api/v1/compliance?framework=pci-dss", headers=hdr).json()

    assert [f["framework"] for f in body["frameworks"]] == ["pci-dss"]


def test_an_unknown_framework_is_refused():
    ctx = _estate()
    client, hdr = _client(ctx)
    assert client.get("/api/v1/compliance?framework=hipaa", headers=hdr).status_code == 422


def test_one_tenants_findings_never_affect_anothers_controls():
    mine, theirs = _estate(), _estate(findings=[{"title": "Hardcoded credential",
                                                 "cwe": "CWE-798"}])
    client, hdr = _client(mine)

    soc2 = _framework(client.get("/api/v1/compliance", headers=hdr).json(), "soc2")
    assert _control(soc2, "CC6.2")["status"] != "failing"
    del theirs


# ── the report ────────────────────────────────────────────────────────────────────────────────────
def test_the_report_carries_the_control_table_with_unassessed_controls():
    from guardian_db.models import Report
    from guardian_db.session import session_scope

    ctx = _estate(engines=("secrets",),
                  findings=[{"title": "Hardcoded AWS credential", "cwe": "CWE-798"}])
    client, hdr = _client(ctx)

    report = client.post("/api/v1/reports", headers=hdr,
                         json={"scan_id": str(ctx["scan"])}).json()
    client.post(f"/api/v1/reports/{report['id']}/generate", headers=hdr, json={})

    with session_scope() as db:
        row = db.get(Report, uuid.UUID(report["id"]))
        summary = row.summary
        sections = {s.kind: s.body for s in row.sections}

    soc2 = _framework(summary["compliance"], "soc2")
    assert _control(soc2, "CC6.2")["status"] == "failing"
    assert any(c["status"] == "not_assessed" for c in soc2["controls"])
    assert "not assessed" in sections["compliance"]
    assert "does not certify compliance" in sections["compliance"]


def test_the_exported_report_prints_coverage_rather_than_only_a_pass_rate():
    ctx = _estate(engines=("secrets",),
                  findings=[{"title": "Hardcoded AWS credential", "cwe": "CWE-798"}])
    client, hdr = _client(ctx)
    report = client.post("/api/v1/reports", headers=hdr,
                         json={"scan_id": str(ctx["scan"])}).json()
    client.post(f"/api/v1/reports/{report['id']}/generate", headers=hdr, json={})

    html = client.get(f"/api/v1/reports/{report['id']}/export?format=html", headers=hdr).text

    assert "Control Coverage" in html
    assert "not assessed" in html
    assert "% of controls were assessed" in html


def test_a_credential_an_engine_missed_is_not_printed_in_the_report():
    """The report is emailed, attached to a board pack and forwarded to prospects. It is the worst
    possible place for the one value an engine failed to redact, and the copy nobody can recall."""
    ctx = _estate(findings=[{
        "title": "Credential in configuration", "cwe": "CWE-798",
        "evidence": {"match": f"aws_secret = '{AWS_KEY}'"},
    }])
    client, hdr = _client(ctx)
    report = client.post("/api/v1/reports", headers=hdr,
                         json={"scan_id": str(ctx["scan"])}).json()
    client.post(f"/api/v1/reports/{report['id']}/generate", headers=hdr, json={})

    html = client.get(f"/api/v1/reports/{report['id']}/export?format=html", headers=hdr).text

    assert AWS_KEY not in html
    assert "[redacted]" in html
