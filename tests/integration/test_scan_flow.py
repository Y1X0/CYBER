"""End-to-end scan flow against a real Postgres (Phase 1 exit criterion, doc 05).

Gated by GUARDIAN_RUN_DB_TESTS=1 so the pure unit suite runs anywhere; CI sets it with a
Postgres service. Verifies: asset → scan → engine run → normalized+scored findings → audit.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

SECRET_SAMPLE = 'aws_key = "AKIAIOSFODNN7EXAMPLE"\npassword = "supersecretvalue12345"\n'


def test_scan_produces_persisted_findings():
    from guardian_db.models import (
        AuditLog,
        Customer,
        Finding,
        Scan,
        ScanEngineRun,
        Tenant,
    )
    from guardian_db.session import session_scope
    from guardian_scanner.tasks import run_scan

    slug = f"itest-{uuid.uuid4().hex[:8]}"
    with session_scope() as db:
        tenant = Tenant(name="ITest", slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="ITest Co", criticality="high")
        db.add(customer)
        db.flush()
        from guardian_db.models import Asset

        asset = Asset(
            tenant_id=tenant.id,
            customer_id=customer.id,
            name="repo",
            kind="repo",
            identifier="inline",
            exposure="public",
            config={"inline_content": SECRET_SAMPLE},
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
        scan_id = str(scan.id)
        tenant_id = tenant.id

    # Run the task synchronously (no broker).
    result = run_scan.apply(args=[scan_id]).get()
    assert result["status"] in ("completed", "partial")

    with session_scope() as db:
        scan = db.get(Scan, uuid.UUID(scan_id))
        assert scan.status == "completed"
        assert scan.stats.get("total", 0) >= 1

        runs = db.query(ScanEngineRun).filter(ScanEngineRun.scan_id == scan.id).all()
        assert any(r.engine == "secrets" and r.status == "completed" for r in runs)

        findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
        assert findings
        # Public + critical/high asset should elevate at least one finding.
        assert any(f.severity in ("high", "critical") for f in findings)
        # Evidence is redacted.
        assert all("AKIAIOSFODNN7EXAMPLE" not in str(f.evidence) for f in findings)

        audit = (
            db.query(AuditLog)
            .filter(AuditLog.tenant_id == tenant_id, AuditLog.action == "scan.completed")
            .all()
        )
        assert audit, "scan completion must be audited"
