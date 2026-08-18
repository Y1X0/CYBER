"""Correlation groups persisted, and kept honest (WP-E1).

The rules themselves are tested without a database in `test_correlation.py`. What this file proves
is the part that touches customer data:

* a group is idempotent — a weekly re-scan updates it rather than growing a second copy;
* **no member is deleted or hidden**. Correlation exists to stop one issue being counted three
  times, not to make evidence disappear: a scanner that quietly drops one of three corroborating
  observations has destroyed exactly what a customer would use to check the claim;
* the tables carry RLS, because a correlation names findings and therefore says what a customer has.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


def _tenant():
    from guardian_db.models import Asset, Customer, Scan, ScanEngineRun, Tenant
    from guardian_db.session import session_scope

    slug = f"e1-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        db.add(customer)
        db.flush()
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
        return {"tenant": tenant.id, "customer": customer.id, "asset": asset.id,
                "scan": scan.id, "run": run.id}


def _finding(ctx, *, engine="secrets", redacted="AK********EY", severity="high", risk=70,
             category="secret", rule="aws-key"):
    from guardian_db.models import Finding
    from guardian_db.session import session_scope

    with session_scope() as db:
        finding = Finding(
            tenant_id=ctx["tenant"], customer_id=ctx["customer"], scan_id=ctx["scan"],
            engine_run_id=ctx["run"], asset_id=ctx["asset"],
            fingerprint=uuid.uuid4().hex[:32], title="Hardcoded credential",
            description="", category=category, severity=severity, risk_score=risk,
            status="open", location={"engine": engine, "rule": rule},
            evidence={"detail": {"redacted": redacted}},
        )
        db.add(finding)
        db.flush()
        return finding.id


def _correlations(tenant_id):
    from guardian_db.models import FindingCorrelation
    from guardian_db.session import session_scope

    with session_scope() as db:
        return db.query(FindingCorrelation).filter(
            FindingCorrelation.tenant_id == tenant_id
        ).all()


def _members(correlation_id):
    from guardian_db.models import FindingCorrelationMember
    from guardian_db.session import session_scope

    with session_scope() as db:
        return db.query(FindingCorrelationMember).filter(
            FindingCorrelationMember.correlation_id == correlation_id
        ).all()


# ── persistence ───────────────────────────────────────────────────────────────────────────────────
def test_a_group_is_persisted_with_its_members_and_rationale():
    from guardian_scanner.correlation import correlate_tenant

    ctx = _tenant()
    first = _finding(ctx, engine="secrets")
    second = _finding(ctx, engine="sast", category="insecure-code")

    stats = correlate_tenant(str(ctx["tenant"]))
    assert stats["findings"] == 2
    assert stats["created"] == 1

    groups = _correlations(ctx["tenant"])
    assert len(groups) == 1
    assert groups[0].rule == "same-secret"
    assert groups[0].kind == "duplicate"
    assert groups[0].member_count == 2
    assert groups[0].rationale

    members = _members(groups[0].id)
    assert {m.finding_id for m in members} == {first, second}
    assert sorted(m.role for m in members) == ["duplicate", "primary"]


def test_re_running_updates_rather_than_creating_a_second_group():
    from guardian_scanner.correlation import correlate_tenant

    ctx = _tenant()
    _finding(ctx, engine="secrets")
    _finding(ctx, engine="sast", category="insecure-code")

    correlate_tenant(str(ctx["tenant"]))
    second = correlate_tenant(str(ctx["tenant"]))

    assert second["created"] == 0
    assert second["updated"] == 1
    assert len(_correlations(ctx["tenant"])) == 1


def test_no_member_is_deleted_or_closed():
    """Correlation stops one issue being counted three times. It must never make evidence vanish."""
    from guardian_db.models import Finding
    from guardian_db.session import session_scope
    from guardian_scanner.correlation import correlate_tenant

    ctx = _tenant()
    ids = [_finding(ctx, engine="secrets"), _finding(ctx, engine="sast",
                                                     category="insecure-code")]
    correlate_tenant(str(ctx["tenant"]))

    with session_scope() as db:
        rows = db.query(Finding).filter(Finding.id.in_(ids)).all()
    assert len(rows) == 2
    assert all(row.status == "open" for row in rows)
    assert all(row.correlation_id is not None for row in rows)


def test_findings_that_do_not_correlate_are_left_alone():
    from guardian_db.models import Finding
    from guardian_db.session import session_scope
    from guardian_scanner.correlation import correlate_tenant

    ctx = _tenant()
    lonely = _finding(ctx, engine="secrets", redacted="only-one")
    stats = correlate_tenant(str(ctx["tenant"]))

    assert stats["groups"] == 0
    with session_scope() as db:
        assert db.get(Finding, lonely).correlation_id is None


def test_a_chain_escalates_and_says_why():
    """The escalation has to be traceable. One a customer cannot trace is one they learn to
    ignore."""
    from guardian_scanner.correlation import correlate_tenant

    ctx = _tenant()
    _finding(ctx, engine="web_checks", category="misconfig", severity="medium", risk=50,
             rule="web-check-git-config-exposure")
    _finding(ctx, engine="secrets", severity="high", risk=70)

    correlate_tenant(str(ctx["tenant"]))
    chain = next(g for g in _correlations(ctx["tenant"]) if g.kind == "chain")
    assert chain.severity == "critical"
    assert chain.risk_score == 75
    assert any("Escalated to critical" in line for line in chain.rationale)


def test_one_tenants_findings_never_join_anothers_group():
    from guardian_scanner.correlation import correlate_tenant

    mine, theirs = _tenant(), _tenant()
    _finding(mine, engine="secrets")
    _finding(mine, engine="sast", category="insecure-code")
    _finding(theirs, engine="secrets")
    _finding(theirs, engine="sast", category="insecure-code")

    correlate_tenant(str(mine["tenant"]))
    groups = _correlations(mine["tenant"])
    assert len(groups) == 1
    assert _correlations(theirs["tenant"]) == []
    assert all(m.tenant_id == mine["tenant"] for m in _members(groups[0].id))


# ── row-level security ────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("table", ["finding_correlations", "finding_correlation_members"])
def test_correlation_tables_enforce_row_level_security(table):
    """A correlation names findings, so it says what a customer has."""
    from guardian_db.session import session_scope

    with session_scope() as db:
        enabled = db.execute(
            text("SELECT rowsecurity FROM pg_tables WHERE tablename = :t"), {"t": table}
        ).scalar_one()
        policies = db.execute(
            text("SELECT polname FROM pg_policy WHERE polrelid = to_regclass(:t)"), {"t": table}
        ).scalars().all()
    assert enabled is True
    assert "tenant_isolation" in policies
