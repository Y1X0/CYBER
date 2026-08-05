"""End-to-end scan through the worker sandbox (Phase 5A). Proves the sandboxed execution path
marshals engine findings back across the fork and persists them exactly like the in-process path.

Gated by GUARDIAN_RUN_DB_TESTS=1 (live DB) and the POSIX fork sandbox being available.
"""

from __future__ import annotations

import os
import uuid

import pytest

sandbox = pytest.importorskip("guardian_scanner.sandbox")

pytestmark = [
    pytest.mark.skipif(os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"),
    pytest.mark.skipif(not sandbox.supported(), reason="fork-based sandbox is POSIX-only"),
]

SECRET_SAMPLE = 'aws_key = "AKIAIOSFODNN7EXAMPLE"\npassword = "supersecretvalue12345"\n'


def test_scan_under_sandbox_persists_findings(monkeypatch):
    from guardian_common.config import get_settings
    from guardian_db.models import Asset, Customer, Finding, Scan, Tenant
    from guardian_db.session import session_scope
    from guardian_scanner.tasks import run_scan

    # Force the sandbox path on for this run, independent of ambient config.
    get_settings.cache_clear()
    monkeypatch.setenv("GUARDIAN_SANDBOX_ENGINES", "true")
    get_settings.cache_clear()

    slug = f"sbx-{uuid.uuid4().hex[:8]}"
    try:
        with session_scope() as db:
            tenant = Tenant(name="SBX", slug=slug, mode="hybrid")
            db.add(tenant)
            db.flush()
            customer = Customer(tenant_id=tenant.id, name="SBX Co", criticality="high")
            db.add(customer)
            db.flush()
            asset = Asset(
                tenant_id=tenant.id, customer_id=customer.id, name="repo", kind="repo",
                identifier="inline", exposure="public", config={"inline_content": SECRET_SAMPLE},
            )
            db.add(asset)
            db.flush()
            scan = Scan(
                tenant_id=tenant.id, customer_id=customer.id, asset_id=asset.id,
                trigger="manual", status="queued", requested_engines=["secrets"], stats={},
            )
            db.add(scan)
            db.flush()
            scan_id = str(scan.id)

        assert get_settings().sandbox_engines is True
        result = run_scan.apply(args=[scan_id]).get()
        assert result["status"] in ("completed", "partial")

        with session_scope() as db:
            scan = db.get(Scan, uuid.UUID(scan_id))
            assert scan.status == "completed"
            findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
            assert findings, "sandboxed engine findings must round-trip and persist"
            assert all("AKIAIOSFODNN7EXAMPLE" not in str(f.evidence) for f in findings)
    finally:
        monkeypatch.delenv("GUARDIAN_SANDBOX_ENGINES", raising=False)
        get_settings.cache_clear()
