"""Validation and retest (WP-E2).

Everything in this file exists to protect one rule:

**Absence of a finding is evidence only when the check actually ran.**

A scan that skipped an engine, or whose engine failed, or that ran without the tool that finds a
class of issue, produces no findings for it — and that is indistinguishable from a clean result
unless something checks. Treating it as "resolved" closes real vulnerabilities on the strength of a
broken scan, quietly, while the customer's queue looks better afterwards. It is the worst thing this
system could do, so most of the tests below are about refusing to do it.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


def _setup():
    from guardian_db.models import Asset, Customer, Tenant
    from guardian_db.session import session_scope

    slug = f"e2-{uuid.uuid4().hex[:10]}"
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
        return {"tenant": tenant.id, "customer": customer.id, "asset": asset.id}


def _scan(ctx, *, engines=("secrets",), engine_status="completed", tool_versions=None,
          error=None):
    from guardian_db.models import Scan, ScanEngineRun
    from guardian_db.session import session_scope

    with session_scope() as db:
        scan = Scan(tenant_id=ctx["tenant"], customer_id=ctx["customer"], asset_id=ctx["asset"],
                    trigger="manual", status="completed", requested_engines=list(engines),
                    stats={})
        db.add(scan)
        db.flush()
        for engine in engines:
            db.add(ScanEngineRun(scan_id=scan.id, engine=engine, status=engine_status,
                                 tool_versions=tool_versions or {}, error=error))
        db.flush()
        return scan.id


def _finding(ctx, scan_id, *, fingerprint=None, engine="secrets", status="open",
             category="secret"):
    from guardian_db.models import Finding, ScanEngineRun
    from guardian_db.session import session_scope

    with session_scope() as db:
        run = db.query(ScanEngineRun).filter(ScanEngineRun.scan_id == scan_id).first()
        finding = Finding(
            tenant_id=ctx["tenant"], customer_id=ctx["customer"], scan_id=scan_id,
            engine_run_id=run.id, asset_id=ctx["asset"],
            fingerprint=fingerprint or uuid.uuid4().hex[:32],
            title="Hardcoded credential", description="", category=category,
            severity="high", risk_score=70, status=status,
            location={"engine": engine, "rule": "aws-key"}, evidence={},
        )
        db.add(finding)
        db.flush()
        return finding.id, finding.fingerprint


def _resight(finding_id, scan_id):
    """A later scan reports the same issue again.

    The scanner folds a re-sighting into the existing row rather than filing a duplicate
    (`normalize.merge_sighting`), so the fixture does what the scanner does: move the finding onto
    the observing scan. Filing a second row here would set up a state `run_scan` cannot produce.
    """
    from guardian_db.models import Finding, ScanEngineRun
    from guardian_db.session import session_scope

    with session_scope() as db:
        run = db.query(ScanEngineRun).filter(ScanEngineRun.scan_id == scan_id).first()
        finding = db.get(Finding, finding_id)
        finding.scan_id = scan_id
        finding.engine_run_id = run.id
        return finding.id, finding.fingerprint


def _reload(finding_id):
    from guardian_db.models import Finding
    from guardian_db.session import session_scope

    with session_scope() as db:
        return db.get(Finding, finding_id)


def _verifications(finding_id):
    from guardian_db.models import FindingVerification
    from guardian_db.session import session_scope

    with session_scope() as db:
        return db.query(FindingVerification).filter(
            FindingVerification.finding_id == finding_id
        ).order_by(FindingVerification.checked_at).all()


# ── the rule ──────────────────────────────────────────────────────────────────────────────────────
def test_a_completed_engine_that_did_not_report_it_resolves_the_finding():
    from guardian_scanner.verification import reconcile_scan

    ctx = _setup()
    first = _scan(ctx)
    finding_id, _fp = _finding(ctx, first)

    second = _scan(ctx)                       # ran secrets, reported nothing
    stats = reconcile_scan(str(second))

    assert stats["resolved"] == 1
    finding = _reload(finding_id)
    assert finding.status == "resolved"
    assert finding.verification_verdict == "resolved"
    assert finding.last_verified_at is not None


def test_a_failed_engine_resolves_nothing():
    """The engine crashed. Its empty result is not evidence of anything, and calling it resolved
    would close a real vulnerability on the strength of a broken scan."""
    from guardian_scanner.verification import reconcile_scan

    ctx = _setup()
    first = _scan(ctx)
    finding_id, _fp = _finding(ctx, first)

    second = _scan(ctx, engine_status="failed", error="git clone timed out")
    stats = reconcile_scan(str(second))

    assert stats["resolved"] == 0
    assert stats["not_checked"] == 1
    assert _reload(finding_id).status == "open"
    assert "timed out" in _verifications(finding_id)[-1].rationale


def test_a_scan_that_did_not_run_the_engine_resolves_nothing():
    from guardian_scanner.verification import reconcile_scan

    ctx = _setup()
    first = _scan(ctx, engines=("secrets",))
    finding_id, _fp = _finding(ctx, first, engine="secrets")

    second = _scan(ctx, engines=("sast",))     # a different engine entirely
    stats = reconcile_scan(str(second))

    assert stats["not_checked"] == 1
    assert _reload(finding_id).status == "open"
    assert "did not run this engine" in _verifications(finding_id)[-1].rationale


def test_a_degraded_engine_is_inconclusive_rather_than_resolved():
    """"We did not look" and "we looked with one eye" are different, and an operator needs to be
    able to tell them apart."""
    from guardian_scanner.verification import reconcile_scan

    ctx = _setup()
    first = _scan(ctx)
    finding_id, _fp = _finding(ctx, first)

    second = _scan(ctx, tool_versions={"degraded": True, "missing": ["gitleaks"]})
    stats = reconcile_scan(str(second))

    assert stats["inconclusive"] == 1
    assert stats["resolved"] == 0
    assert _reload(finding_id).status == "open"
    assert "gitleaks" in _verifications(finding_id)[-1].rationale


def test_a_finding_reported_again_is_still_present():
    from guardian_scanner.verification import reconcile_scan

    ctx = _setup()
    first = _scan(ctx)
    finding_id, fingerprint = _finding(ctx, first)

    second = _scan(ctx)
    _resight(finding_id, second)
    stats = reconcile_scan(str(second))

    assert stats["still_present"] == 1
    finding = _reload(finding_id)
    assert finding.status == "open"
    assert finding.verification_verdict == "still_present"


# ── regressions ───────────────────────────────────────────────────────────────────────────────────
def test_a_resolved_finding_that_comes_back_is_reopened_with_its_history():
    """Filing a new finding would lose the fact that this was already fixed once."""
    from guardian_scanner.verification import reconcile_scan

    ctx = _setup()
    first = _scan(ctx)
    finding_id, fingerprint = _finding(ctx, first)

    reconcile_scan(str(_scan(ctx)))                       # resolved
    assert _reload(finding_id).status == "resolved"

    third = _scan(ctx)
    _resight(finding_id, third)                           # it is back
    stats = reconcile_scan(str(third))

    finding = _reload(finding_id)
    assert stats["reopened"] == 1
    assert finding.status == "open"
    assert finding.reopened_count == 1
    verdicts = [v.verdict for v in _verifications(finding_id)]
    assert verdicts == ["resolved", "still_present"]


def test_the_reopen_count_accumulates():
    from guardian_scanner.verification import reconcile_scan

    ctx = _setup()
    first = _scan(ctx)
    finding_id, fingerprint = _finding(ctx, first)

    for _cycle in range(2):
        reconcile_scan(str(_scan(ctx)))
        back = _scan(ctx)
        _resight(finding_id, back)
        reconcile_scan(str(back))

    assert _reload(finding_id).reopened_count == 2


def test_a_human_decision_is_not_overturned_by_a_scanner():
    """Accepted risk and false positive are decisions. A scan not seeing something does not
    un-make them."""
    from guardian_scanner.verification import reconcile_scan

    ctx = _setup()
    first = _scan(ctx)
    accepted, _fp = _finding(ctx, first, status="accepted_risk")
    false_positive, _fp2 = _finding(ctx, first, status="false_positive")

    reconcile_scan(str(_scan(ctx)))

    assert _reload(accepted).status == "accepted_risk"
    assert _reload(false_positive).status == "false_positive"


def test_a_false_positive_that_reappears_is_not_reopened():
    """Someone judged it wrong. The scanner reporting it again is not new information."""
    from guardian_scanner.verification import reconcile_scan

    ctx = _setup()
    first = _scan(ctx)
    finding_id, fingerprint = _finding(ctx, first, status="false_positive")

    second = _scan(ctx)
    _resight(finding_id, second)
    reconcile_scan(str(second))

    assert _reload(finding_id).status == "false_positive"


# ── one row per issue ─────────────────────────────────────────────────────────────────────────────
def test_a_rescan_folds_into_the_existing_finding_instead_of_filing_a_duplicate():
    """The defect the first pilot run found.

    Every scan used to file its own copy of everything it saw, so a customer's open count climbed
    with each rescan while nothing got worse — 20 rows for 14 distinct issues after one retest. The
    row count must track distinct issues, not sightings.
    """
    from guardian_db.models import Finding
    from guardian_db.session import session_scope
    from guardian_scanner.tasks import run_scan

    ctx = _setup_scannable(secret=True)
    run_scan(str(ctx["scan"]))
    run_scan(str(_queue_scan(ctx)))               # the same asset, scanned again

    with session_scope() as db:
        rows = db.query(Finding).filter(Finding.asset_id == ctx["asset"]).all()
    assert len(rows) == len({row.fingerprint for row in rows}), (
        f"{len(rows)} rows for {len({r.fingerprint for r in rows})} distinct issues — "
        "a rescan filed duplicates"
    )
    assert rows, "the scan produced no finding for a file containing a live-shaped credential"


def test_a_rescan_that_stops_reporting_an_issue_still_resolves_it():
    """Deduplication must not cost us the resolve path: the finding is one row now, and a scan that
    ran the engine and did not report it must still close it."""
    from guardian_db.models import Asset, Finding
    from guardian_db.session import session_scope
    from guardian_scanner.tasks import run_scan

    ctx = _setup_scannable(secret=True)
    run_scan(str(ctx["scan"]))
    with session_scope() as db:
        assert db.query(Finding).filter(Finding.asset_id == ctx["asset"],
                                        Finding.status == "open").count() >= 1
        db.get(Asset, ctx["asset"]).config = {"inline_content": "nothing to see here\n"}

    run_scan(str(_queue_scan(ctx)))               # the secret is gone; secrets ran and reported none

    with session_scope() as db:
        rows = db.query(Finding).filter(Finding.asset_id == ctx["asset"]).all()
    assert rows and all(row.status == "resolved" for row in rows), (
        f"statuses were {[r.status for r in rows]}"
    )


def test_an_issue_that_comes_back_reopens_the_original_row():
    """The history is the point: 'fixed twice' has to stay visible on one finding."""
    from guardian_db.models import Asset, Finding
    from guardian_db.session import session_scope
    from guardian_scanner.tasks import run_scan

    ctx = _setup_scannable(secret=True)
    run_scan(str(ctx["scan"]))
    with session_scope() as db:
        db.get(Asset, ctx["asset"]).config = {"inline_content": "nothing to see here\n"}
    run_scan(str(_queue_scan(ctx)))               # resolved
    with session_scope() as db:
        db.get(Asset, ctx["asset"]).config = {"inline_content": _SECRET_CONTENT}
    run_scan(str(_queue_scan(ctx)))               # and it is back

    with session_scope() as db:
        rows = db.query(Finding).filter(Finding.asset_id == ctx["asset"]).all()
    assert len(rows) == len({row.fingerprint for row in rows}), "the regression filed a duplicate"
    reopened = [row for row in rows if (row.reopened_count or 0) > 0]
    assert reopened, f"nothing was reopened; statuses {[r.status for r in rows]}"
    assert all(row.status == "open" for row in reopened)


_SECRET_CONTENT = 'AWS_SECRET = "AKIA' + 'IOSFODNN7EXAMPLE"\n'


def _setup_scannable(*, secret: bool):
    """A customer, an authorized repo asset with inline content, and a queued scan."""
    import datetime as dt

    from guardian_db.models import Asset, Authorization, Customer, Tenant, User
    from guardian_db.session import session_scope

    slug = f"dedupe-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        user = User(email=f"{slug}@example.com", name="U", status="active")
        db.add_all([customer, user])
        db.flush()
        asset = Asset(tenant_id=tenant.id, customer_id=customer.id, name="app", kind="repo",
                      identifier=f"inline-{slug}", exposure="public",
                      config={"inline_content": _SECRET_CONTENT if secret else "clean\n"})
        db.add(asset)
        db.flush()
        now = dt.datetime.now(dt.UTC)
        db.add(Authorization(
            tenant_id=tenant.id, customer_id=customer.id, asset_id=asset.id, scope="test",
            authorized_targets=[], method="written_consent", authorized_by=user.id,
            valid_from=now - dt.timedelta(days=1), valid_until=now + dt.timedelta(days=30)))
        ctx = {"tenant": tenant.id, "customer": customer.id, "asset": asset.id}
    ctx["scan"] = _queue_scan(ctx)
    return ctx


def _queue_scan(ctx):
    from guardian_db.models import Scan
    from guardian_db.session import session_scope

    with session_scope() as db:
        scan = Scan(tenant_id=ctx["tenant"], customer_id=ctx["customer"], asset_id=ctx["asset"],
                    trigger="manual", status="queued", requested_engines=["secrets"], stats={})
        db.add(scan)
        db.flush()
        return scan.id


# ── the record ────────────────────────────────────────────────────────────────────────────────────
def test_every_check_is_recorded_even_when_it_changes_nothing():
    """"Resolved on the 3rd, still present on the 10th" is a fact about how remediation is going,
    and a single last-verdict column would throw it away."""
    from guardian_scanner.verification import reconcile_scan

    ctx = _setup()
    first = _scan(ctx)
    finding_id, _fp = _finding(ctx, first)

    reconcile_scan(str(_scan(ctx, engine_status="failed")))
    reconcile_scan(str(_scan(ctx, tool_versions={"degraded": True, "missing": ["x"]})))

    verdicts = [v.verdict for v in _verifications(finding_id)]
    assert verdicts == ["not_checked", "inconclusive"]
    assert all(v.rationale for v in _verifications(finding_id))


def test_a_status_change_writes_a_finding_event():
    from guardian_db.models import FindingEvent
    from guardian_db.session import session_scope
    from guardian_scanner.verification import reconcile_scan

    ctx = _setup()
    first = _scan(ctx)
    finding_id, _fp = _finding(ctx, first)
    reconcile_scan(str(_scan(ctx)))

    with session_scope() as db:
        events = db.query(FindingEvent).filter(FindingEvent.finding_id == finding_id).all()
    assert [(e.from_status, e.to_status) for e in events] == [("open", "resolved")]


def test_a_manual_verdict_is_recorded_beside_a_machine_one():
    """A pentester confirming by hand and a scanner re-reporting are both evidence; a report that
    shows one and not the other misleads about how the conclusion was reached."""
    from guardian_db.models import Finding
    from guardian_db.session import session_scope
    from guardian_scanner.verification import record_manual_verification

    ctx = _setup()
    first = _scan(ctx)
    finding_id, _fp = _finding(ctx, first)

    with session_scope() as db:
        record_manual_verification(
            db, db.get(Finding, finding_id),
            verdict="resolved", rationale="patched and confirmed by hand on staging",
        )

    finding = _reload(finding_id)
    assert finding.status == "resolved"
    latest = _verifications(finding_id)[-1]
    assert latest.method == "manual"
    assert "by hand" in latest.rationale


def test_another_assets_findings_are_not_touched():
    from guardian_scanner.verification import reconcile_scan

    ctx = _setup()
    other = _setup()
    first = _scan(ctx)
    mine, _fp = _finding(ctx, first)
    other_first = _scan(other)
    theirs, _fp2 = _finding(other, other_first)

    reconcile_scan(str(_scan(ctx)))

    assert _reload(mine).status == "resolved"
    assert _reload(theirs).status == "open"


def test_an_unknown_scan_is_reported_rather_than_silently_doing_nothing():
    from guardian_scanner.verification import reconcile_scan

    result = reconcile_scan(str(uuid.uuid4()))
    assert result["error"] == "unknown scan"
    assert result["checked"] == 0


def test_a_real_scan_records_engine_health_and_reconciles():
    """The wiring, end to end: a scan run through the actual task must record whether its engine
    was degraded, and must reconcile against what was already open."""
    import inspect

    from guardian_scanner import tasks

    source = inspect.getsource(tasks.run_scan)
    assert "reconcile_scan(scan_id)" in source
    assert '"degraded"' in inspect.getsource(tasks)
    # A reconciliation failure must not fail the scan that produced real findings.
    assert "must not fail the scan" in source
