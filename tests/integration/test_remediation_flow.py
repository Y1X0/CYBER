"""The remediation loop, end to end (WP-F5).

`remediation_items` has been a table with nothing writing to it since the first schema. What this
proves is the loop it was for, against the live database: a finding becomes tracked work with an
owner and a date; a person can claim a fix; and **only a scan that ran the engine and completed
cleanly can call it verified**.

The negative cases are the point. An engine that failed proves nothing, and an item closed on the
strength of a scan that did not happen is worse than an item nobody closed.

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

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def _estate(*, exposure="public", findings=()):
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

    slug = f"f5-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        user = User(email=f"u-{slug}@x.invalid", name="Analyst", status="active")
        engineer = User(email=f"e-{slug}@x.invalid", name="Engineer", status="active")
        db.add_all([customer, user, engineer])
        db.flush()
        db.add(TenantMembership(user_id=user.id, tenant_id=tenant.id, role="pentester"))
        asset = Asset(tenant_id=tenant.id, customer_id=customer.id, name="app", kind="repo",
                      identifier=f"https://example.invalid/{slug}.git", exposure=exposure,
                      config={})
        db.add(asset)
        db.flush()
        scan = Scan(tenant_id=tenant.id, customer_id=customer.id, asset_id=asset.id,
                    trigger="manual", status="completed", requested_engines=["secrets"], stats={})
        db.add(scan)
        db.flush()
        run = ScanEngineRun(scan_id=scan.id, engine="secrets", status="completed")
        db.add(run)
        db.flush()

        finding_ids = []
        for spec in findings or ({"title": "Hardcoded AWS credential", "cwe": "CWE-798"},):
            row = Finding(
                tenant_id=tenant.id, customer_id=customer.id, scan_id=scan.id,
                engine_run_id=run.id, asset_id=asset.id, fingerprint=uuid.uuid4().hex[:32],
                title=spec["title"], description=spec.get("description", ""),
                category=spec.get("category", "secret"), severity=spec.get("severity", "critical"),
                risk_score=spec.get("risk", 95), status="open", cwe_id=spec.get("cwe"),
                correlation_id=None, location={"rule": spec.get("rule", "")},
                evidence=spec.get("evidence", {}),
            )
            db.add(row)
            db.flush()
            finding_ids.append(row.id)

        return {"tenant": tenant.id, "customer": customer.id, "scan": scan.id, "user": user.id,
                "engineer": engineer.id, "asset": asset.id, "findings": finding_ids, "slug": slug}


def _client(ctx):
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token

    settings = get_settings()
    token = create_access_token(subject=str(ctx["user"]), secret=settings.jwt_secret,
                                algorithm=settings.jwt_algorithm)
    return TestClient(app), {"Authorization": f"Bearer {token}"}


def _open(ctx):
    from guardian_db.session import session_scope
    from guardian_scanner.remediation import open_items

    with session_scope() as db:
        return open_items(db, tenant_id=ctx["tenant"])


def _items(ctx):
    from guardian_db.models import RemediationItem
    from guardian_db.session import session_scope

    with session_scope() as db:
        return [
            {"id": i.id, "finding_id": i.finding_id, "status": i.status, "due_at": i.due_at,
             "verified_by_scan_id": i.verified_by_scan_id, "assignee": i.assignee_id}
            for i in db.query(RemediationItem).filter(
                RemediationItem.tenant_id == ctx["tenant"]
            ).all()
        ]


def _verify(ctx, verdict: str, *, engine="secrets"):
    """Record a WP-E2 verification for the finding and run the closer."""
    from guardian_db.models import FindingVerification
    from guardian_db.session import session_scope
    from guardian_scanner.remediation import verify_after_scan

    with session_scope() as db:
        db.add(FindingVerification(
            tenant_id=ctx["tenant"], finding_id=ctx["findings"][0], scan_id=ctx["scan"],
            verdict=verdict, method="rescan", engine=engine, rationale="test", evidence={},
            checked_at=dt.datetime.now(dt.UTC),
        ))
        db.flush()
        return verify_after_scan(db, scan_id=ctx["scan"])


# ── opening ───────────────────────────────────────────────────────────────────────────────────────
def test_a_finding_becomes_tracked_work_with_a_deadline():
    ctx = _estate()
    result = _open(ctx)

    assert result["opened"] == 1
    item = _items(ctx)[0]
    assert item["status"] == "open"
    assert item["due_at"] is not None
    # Critical on a public asset: seven days halved.
    assert (item["due_at"] - dt.datetime.now(dt.UTC)).days <= 4


def test_opening_twice_does_not_open_a_second_item():
    """This runs after every scan."""
    ctx = _estate()
    _open(ctx)
    second = _open(ctx)

    assert second["opened"] == 0
    assert len(_items(ctx)) == 1


def test_one_item_is_opened_per_underlying_issue_not_per_finding():
    """Three engines reporting the same credential is one thing to fix, and three tickets for it is
    how a remediation backlog stops being believed."""
    from guardian_db.models import Finding, FindingCorrelation
    from guardian_db.session import session_scope

    ctx = _estate(findings=[
        {"title": "Hardcoded credential (secrets)", "cwe": "CWE-798"},
        {"title": "Hardcoded credential (sast)", "cwe": "CWE-798", "category": "insecure-code"},
    ])
    with session_scope() as db:
        group = FindingCorrelation(
            tenant_id=ctx["tenant"], customer_id=ctx["customer"], rule="same-secret",
            fingerprint=uuid.uuid4().hex[:32], title="One credential", description="",
            kind="duplicate", severity="critical", risk_score=95, rationale=["test"],
            member_count=2,
        )
        db.add(group)
        db.flush()
        for finding_id in ctx["findings"]:
            db.get(Finding, finding_id).correlation_id = group.id

    result = _open(ctx)
    assert result["opened"] == 1
    assert result["grouped"] == 1


# ── the rule ──────────────────────────────────────────────────────────────────────────────────────
def test_a_person_cannot_mark_an_item_verified_through_the_api():
    """The assertion this whole package exists for."""
    ctx = _estate()
    _open(ctx)
    item = _items(ctx)[0]
    client, hdr = _client(ctx)

    response = client.patch(f"/api/v1/remediation/{item['id']}", headers=hdr,
                            json={"status": "verified"})

    assert response.status_code == 422
    assert "verifying scan" in response.text
    assert _items(ctx)[0]["status"] == "open"


def test_a_person_can_claim_a_fix_and_it_stays_a_claim():
    ctx = _estate()
    _open(ctx)
    item = _items(ctx)[0]
    client, hdr = _client(ctx)

    response = client.patch(f"/api/v1/remediation/{item['id']}", headers=hdr,
                            json={"status": "fixed"})

    assert response.status_code == 200
    assert _items(ctx)[0]["status"] == "fixed"
    assert _items(ctx)[0]["verified_by_scan_id"] is None


def test_a_scan_that_no_longer_reports_it_verifies_the_fix():
    ctx = _estate()
    _open(ctx)
    result = _verify(ctx, "resolved")

    assert result["verified"] == 1
    item = _items(ctx)[0]
    assert item["status"] == "verified"
    assert item["verified_by_scan_id"] == ctx["scan"]


def test_an_engine_that_did_not_run_verifies_nothing():
    """`not_checked` means the engine failed or never ran. Its silence is not evidence, and closing
    a customer's ticket on it would be closing it on a scan that did not happen."""
    ctx = _estate()
    _open(ctx)
    result = _verify(ctx, "not_checked")

    assert result["verified"] == 0
    assert _items(ctx)[0]["status"] == "open"


def test_an_inconclusive_verification_verifies_nothing():
    ctx = _estate()
    _open(ctx)
    _verify(ctx, "inconclusive")
    assert _items(ctx)[0]["status"] == "open"


def test_a_claimed_fix_the_scanner_still_sees_is_reopened():
    """Somebody said it was fixed and the scanner disagrees. The scanner is looking at the running
    system."""
    ctx = _estate()
    _open(ctx)
    item = _items(ctx)[0]
    client, hdr = _client(ctx)
    client.patch(f"/api/v1/remediation/{item['id']}", headers=hdr, json={"status": "fixed"})

    result = _verify(ctx, "still_present")

    assert result["reopened"] == 1
    assert _items(ctx)[0]["status"] == "reopened"


# ── the workbench surface ─────────────────────────────────────────────────────────────────────────
def test_declining_to_fix_needs_a_reason():
    ctx = _estate()
    _open(ctx)
    item = _items(ctx)[0]
    client, hdr = _client(ctx)

    refused = client.patch(f"/api/v1/remediation/{item['id']}", headers=hdr,
                           json={"status": "risk_accepted"})
    assert refused.status_code == 422

    accepted = client.patch(f"/api/v1/remediation/{item['id']}", headers=hdr,
                            json={"status": "risk_accepted",
                                  "justification": "compensating control in place"})
    assert accepted.status_code == 200


def test_an_item_can_be_assigned():
    ctx = _estate()
    _open(ctx)
    item = _items(ctx)[0]
    client, hdr = _client(ctx)

    response = client.patch(f"/api/v1/remediation/{item['id']}", headers=hdr,
                            json={"assignee_id": str(ctx["engineer"])})

    assert response.status_code == 200
    assert _items(ctx)[0]["assignee"] == ctx["engineer"]


def test_the_sla_endpoint_reports_the_backlog():
    ctx = _estate()
    _open(ctx)
    client, hdr = _client(ctx)

    body = client.get("/api/v1/remediation/sla", headers=hdr).json()

    assert body["total"] == 1
    assert body["active"] == 1
    assert body["verified"] == 0
    assert 0 <= body["on_time_rate"] <= 100


def test_the_ticket_payload_is_ready_to_file_and_carries_no_credential():
    """The body leaves the platform for a system with a different audience."""
    ctx = _estate(findings=[{
        "title": "Hardcoded AWS credential", "cwe": "CWE-798", "severity": "critical",
        "description": f"Found aws_key = '{AWS_KEY}' in config.py",
        "evidence": {"summary": f"config.py:12 aws_key = '{AWS_KEY}'"},
    }])
    _open(ctx)
    item = _items(ctx)[0]
    client, hdr = _client(ctx)

    body = client.get(f"/api/v1/remediation/{item['id']}/ticket", headers=hdr).json()

    assert body["title"].startswith("[CRITICAL]")
    assert "closes when a scan" in body["body"]
    assert AWS_KEY not in body["body"]
    assert "[redacted]" in body["body"]


def test_one_tenants_items_are_invisible_to_another():
    mine, theirs = _estate(), _estate()
    _open(theirs)
    client, hdr = _client(mine)

    assert client.get("/api/v1/remediation", headers=hdr).json() == []
    foreign = _items(theirs)[0]
    assert client.patch(f"/api/v1/remediation/{foreign['id']}", headers=hdr,
                        json={"status": "fixed"}).status_code == 404
