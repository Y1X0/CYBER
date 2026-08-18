"""The scan gate, on the real path (WP-H1).

The unit tests fix the rules. This proves the gate in `run_scan` actually asks them — and in
particular that the loop WP-F1 opened now closes: a customer proves they own a domain, and the
active engines will run against that domain's asset. Before this, the gate matched on `asset_id`
alone, so the proof authorized nothing and every active engine was skipped with "no valid
authorization".

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

DOMAIN_SUFFIX = "example.com"


def _estate(*, kind="web", identifier=None, authorization=None):
    """A customer with one asset, and optionally one authorization of a given shape."""
    from guardian_db.models import Asset, Authorization, Customer, Scan, Tenant, User
    from guardian_db.session import session_scope

    slug = f"h1-{uuid.uuid4().hex[:10]}"
    host = f"{slug}.{DOMAIN_SUFFIX}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        user = User(email=f"u-{slug}@x.invalid", name="U", status="active")
        db.add_all([customer, user])
        db.flush()
        asset = Asset(tenant_id=tenant.id, customer_id=customer.id, name="app", kind=kind,
                      identifier=identifier or f"https://{host}", exposure="public",
                      config={"http_snapshot": {"url": f"https://{host}", "headers": {},
                                                "cookies": []}})
        db.add(asset)
        db.flush()
        scan = Scan(tenant_id=tenant.id, customer_id=customer.id, asset_id=asset.id,
                    trigger="manual", status="queued", requested_engines=["dast"], stats={})
        db.add(scan)
        db.flush()

        if authorization:
            now = dt.datetime.now(dt.UTC)
            db.add(Authorization(
                tenant_id=tenant.id, customer_id=customer.id,
                asset_id=asset.id if authorization.get("by_asset") else None,
                scope="test", authorized_targets=authorization.get("targets", []),
                method=authorization["method"], authorized_by=user.id,
                valid_from=now - dt.timedelta(days=1),
                valid_until=now + (dt.timedelta(days=30) if authorization.get("valid", True)
                                   else dt.timedelta(days=-2)),
                revoked_at=now if authorization.get("revoked") else None,
            ))
            db.flush()
        return {"tenant": tenant.id, "scan": scan.id, "asset": asset.id, "host": host}


def _run(ctx):
    from guardian_scanner.tasks import run_scan

    return run_scan(str(ctx["scan"]))


def _dast_run(ctx):
    from guardian_db.models import ScanEngineRun
    from guardian_db.session import session_scope

    with session_scope() as db:
        row = db.query(ScanEngineRun).filter(
            ScanEngineRun.scan_id == ctx["scan"], ScanEngineRun.engine == "dast"
        ).one()
        return {"status": row.status, "error": row.error}


# ── the loop WP-F1 opened ─────────────────────────────────────────────────────────────────────────
def test_a_proved_domain_now_authorizes_scanning_that_domains_asset():
    """The gap: WP-F1's authorization is scoped by target with no asset, and the gate matched on
    `asset_id` alone — so the proof authorized nothing."""
    ctx = _estate(authorization={"method": "ownership_verified",
                                 "targets": [{"type": "domain", "value": DOMAIN_SUFFIX}]})
    _run(ctx)

    assert _dast_run(ctx)["status"] != "skipped"


def test_an_asset_scoped_authorization_still_works():
    ctx = _estate(authorization={"method": "active_recon", "by_asset": True})
    _run(ctx)
    assert _dast_run(ctx)["status"] != "skipped"


# ── refusals, with reasons ────────────────────────────────────────────────────────────────────────
def test_no_authorization_skips_the_active_engine_and_says_what_is_missing():
    ctx = _estate()
    _run(ctx)

    run = _dast_run(ctx)
    assert run["status"] == "skipped"
    assert ctx["host"] in run["error"]
    assert "prove ownership" in run["error"]


def test_artifact_consent_does_not_authorize_touching_the_network():
    """A customer handing over a repository has said nothing about their network."""
    ctx = _estate(authorization={"method": "written_consent",
                                 "targets": [{"type": "domain", "value": DOMAIN_SUFFIX}]})
    _run(ctx)

    run = _dast_run(ctx)
    assert run["status"] == "skipped"
    assert "artifact" in run["error"]


def test_a_revoked_authorization_stops_authorizing():
    """WP-F1 revokes the authorization when the ownership proof is withdrawn. This is what makes
    that revocation mean something."""
    ctx = _estate(authorization={"method": "ownership_verified", "by_asset": True,
                                 "revoked": True})
    _run(ctx)
    assert _dast_run(ctx)["status"] == "skipped"


def test_an_expired_authorization_stops_authorizing():
    ctx = _estate(authorization={"method": "ownership_verified", "by_asset": True,
                                 "valid": False})
    _run(ctx)

    run = _dast_run(ctx)
    assert run["status"] == "skipped"
    assert "expired or revoked" in run["error"]


def test_another_domains_proof_does_not_authorize_this_one():
    ctx = _estate(authorization={"method": "ownership_verified",
                                 "targets": [{"type": "domain", "value": "somewhere-else.test"}]})
    _run(ctx)
    assert _dast_run(ctx)["status"] == "skipped"


def test_the_refusal_is_audited_with_its_reason():
    """"Blocked" in an audit log with no cause is a support ticket."""
    from guardian_db.models import AuditLog
    from guardian_db.session import session_scope

    ctx = _estate()
    _run(ctx)

    with session_scope() as db:
        rows = db.query(AuditLog).filter(
            AuditLog.tenant_id == ctx["tenant"],
            AuditLog.action == "scan.engine.blocked_unauthorized",
        ).all()
    assert rows
    assert any(ctx["host"] in str(row.metadata_.get("reason", "")) for row in rows)


# ── the artifact plane is unaffected ──────────────────────────────────────────────────────────────
def test_a_repository_scan_needs_no_network_authorization():
    """The passive engines were never gated and must not become gated by this change."""
    from guardian_db.models import Scan, ScanEngineRun
    from guardian_db.session import session_scope

    ctx = _estate(kind="repo", identifier="inline")
    with session_scope() as db:
        scan = db.get(Scan, ctx["scan"])
        scan.requested_engines = ["secrets"]

    _run(ctx)

    with session_scope() as db:
        row = db.query(ScanEngineRun).filter(
            ScanEngineRun.scan_id == ctx["scan"], ScanEngineRun.engine == "secrets"
        ).one()
    assert row.status != "skipped"
