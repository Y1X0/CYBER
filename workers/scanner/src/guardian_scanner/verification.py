"""Validation and retest — closing the loop on a finding (WP-E2).

A finding was created and never revisited. A customer who fixed something had no way to have that
confirmed, and a problem that came back returned as a *new* finding with no history, so nobody could
see it had been fixed twice.

Everything here turns on one rule:

**Absence of a finding is evidence only when the check actually ran.**

A scan that did not include the engine, or whose engine failed, or ran degraded because a tool was
missing, produces no findings for that engine — and that is indistinguishable from a clean result
unless something checks. Treating it as "resolved" silently closes real vulnerabilities on the
strength of a broken scan, which is the worst thing this system could do, because it does it
quietly and the customer's queue looks better afterwards.

So a reconciliation produces one of four verdicts, never two:

* `resolved` — the engine ran to completion and did not report the finding.
* `still_present` — the engine ran and reported it again.
* `not_checked` — the engine did not run, failed, or ran without the tool that finds this class.
  The finding stays exactly as it was.
* `inconclusive` — the engine ran degraded. Recorded distinctly from `not_checked` so an operator
  can tell "we did not look" from "we looked with one eye".
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass

from guardian_common.logging import get_logger
from guardian_db.models import (
    Finding,
    FindingEvent,
    FindingVerification,
    Scan,
    ScanEngineRun,
)
from guardian_db.session import session_scope
from sqlalchemy import select

from guardian_scanner.celery_app import celery_app

log = get_logger("guardian.verification")

STILL_PRESENT = "still_present"
RESOLVED = "resolved"
NOT_CHECKED = "not_checked"
INCONCLUSIVE = "inconclusive"

# Statuses a reconciliation may move a finding out of. A human decision — accepted risk, marked a
# false positive — is not overturned because a scanner did or did not see something.
_OPEN_STATUSES = frozenset({"open", "triaged", "confirmed"})
# A finding here was closed by evidence, so evidence may reopen it.
_CLOSED_BY_EVIDENCE = frozenset({"resolved"})


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


@dataclass(frozen=True)
class Verdict:
    verdict: str
    rationale: str
    engine: str | None = None

    @property
    def is_evidence(self) -> bool:
        """Whether this verdict may change a finding's status."""
        return self.verdict in {STILL_PRESENT, RESOLVED}


def engine_outcome(run: ScanEngineRun | None) -> Verdict:
    """What a scan's engine run entitles us to conclude.

    This is the whole safety property, in one function, so there is one place to read and one place
    to get wrong.
    """
    if run is None:
        return Verdict(NOT_CHECKED, "the scan did not run this engine, so it saw nothing")
    if run.status == "failed":
        return Verdict(NOT_CHECKED,
                       f"the engine failed ({(run.error or 'no reason recorded')[:120]}), so its "
                       "empty result is not evidence of anything", engine=run.engine)
    if run.status != "completed":
        return Verdict(NOT_CHECKED,
                       f"the engine run is {run.status}, not completed", engine=run.engine)
    tools = run.tool_versions or {}
    if isinstance(tools, dict) and tools.get("degraded"):
        missing = ", ".join(tools.get("missing") or []) or "a tool"
        return Verdict(
            INCONCLUSIVE,
            f"the engine completed without {missing}, so it was looking with reduced coverage",
            engine=run.engine,
        )
    return Verdict(RESOLVED, "the engine completed and did not report this finding",
                   engine=run.engine)


def reconcile_scan(scan_id: str) -> dict:
    """Compare a completed scan against the asset's existing findings.

    Called after a scan finishes. Findings the scan reported again are marked still present;
    findings it did not report are resolved *only* if the engine that would have found them
    completed cleanly.
    """
    stats = {"checked": 0, RESOLVED: 0, STILL_PRESENT: 0, NOT_CHECKED: 0, INCONCLUSIVE: 0,
             "reopened": 0}

    with session_scope() as session:
        scan = session.get(Scan, uuid.UUID(scan_id))
        if scan is None:
            log.warning("reconcile_unknown_scan", scan_id=scan_id)
            return {**stats, "error": "unknown scan"}

        runs = {
            run.engine: run for run in session.execute(
                select(ScanEngineRun).where(ScanEngineRun.scan_id == scan.id)
            ).scalars()
        }
        # What this scan reported, by fingerprint.
        reported = {
            finding.fingerprint for finding in session.execute(
                select(Finding).where(Finding.scan_id == scan.id)
            ).scalars()
        }

        # Every finding on this asset, including the ones this scan just re-observed.
        #
        # It used to exclude `scan_id == scan.id`, which was correct only while each scan filed its
        # own copy of everything it saw. Now that a re-sighting folds into the existing row (WP-P0,
        # `normalize.merge_sighting`), excluding them would mean a finding that had been resolved
        # and has just come back is never looked at — it would stay `resolved` while the scanner is
        # reporting it. Judging every finding keeps the reopen path alive and leaves this the only
        # place a status moves.
        existing = session.execute(
            select(Finding).where(
                Finding.tenant_id == scan.tenant_id,
                Finding.asset_id == scan.asset_id,
            )
        ).scalars().all()

        for finding in existing:
            stats["checked"] += 1
            verdict = _verdict_for(finding, reported, runs)
            stats[verdict.verdict] = stats.get(verdict.verdict, 0) + 1
            if _apply(session, finding, verdict, scan):
                stats["reopened"] += 1

    log.info("reconcile_complete", scan_id=scan_id, **stats)
    return stats


def _engine_key(finding: Finding) -> str:
    """Which engine's completion licenses a conclusion about this finding."""
    location = finding.location or {}
    engine = location.get("engine")
    if isinstance(engine, str) and engine:
        return engine
    rule = str(location.get("rule") or "")
    for prefix, name in (("taint-", "sast"), ("py-", "sast"), ("js-", "sast"),
                         ("image-", "container"), ("iac-", "iac"),
                         ("web-check-", "web_checks"), ("service-cve-", "service_cve")):
        if rule.startswith(prefix):
            return name
    return {"secret": "secrets", "vuln-dep": "sca", "vuln-service": "service_cve",
            "insecure-code": "sast"}.get(finding.category, finding.category)


def _verdict_for(finding: Finding, reported: set[str], runs: dict) -> Verdict:
    if finding.fingerprint in reported:
        return Verdict(STILL_PRESENT, "the scan reported this finding again",
                       engine=_engine_key(finding))
    return engine_outcome(runs.get(_engine_key(finding)))


def _apply(session, finding: Finding, verdict: Verdict, scan: Scan) -> bool:  # noqa: ANN001
    """Record the verdict and, where it is evidence, move the finding. Returns True if reopened."""
    now = _now()
    session.add(FindingVerification(
        tenant_id=finding.tenant_id, finding_id=finding.id, scan_id=scan.id,
        verdict=verdict.verdict, method="rescan", engine=verdict.engine,
        rationale=verdict.rationale, checked_at=now,
        evidence={"scan_id": str(scan.id), "asset_id": str(scan.asset_id)},
    ))
    finding.last_verified_at = now
    finding.verification_verdict = verdict.verdict

    if not verdict.is_evidence:
        # `not_checked` and `inconclusive` are recorded and change nothing. The finding is exactly
        # as true or false as it was before a scan that could not see it.
        return False

    reopened = False
    previous = finding.status

    if verdict.verdict == RESOLVED and previous in _OPEN_STATUSES:
        finding.status = "resolved"
        _event(session, finding, previous, "resolved", verdict.rationale)
    elif verdict.verdict == STILL_PRESENT and previous in _CLOSED_BY_EVIDENCE:
        # It came back. Reopening the original rather than filing a new finding is what preserves
        # the history — otherwise "fixed twice" is invisible.
        finding.status = "open"
        finding.reopened_count = (finding.reopened_count or 0) + 1
        _event(session, finding, previous, "open",
               f"regression: {verdict.rationale} (reopened {finding.reopened_count}x)")
        reopened = True

    return reopened


def _event(session, finding: Finding, from_status: str, to_status: str, note: str) -> None:  # noqa: ANN001
    session.add(FindingEvent(
        finding_id=finding.id, actor_id=None, from_status=from_status, to_status=to_status,
        note=note[:1000],
    ))


# ── explicit retest ───────────────────────────────────────────────────────────────────────────────
@celery_app.task(name="guardian.retest_finding")
def retest_finding(finding_id: str) -> dict:
    """Queue a scan that will re-check one finding, then reconcile against it.

    A retest is an ordinary scan of the finding's asset restricted to the engine that produced it —
    not a special code path. Using the same machinery means a retest cannot disagree with a scan
    about what "present" means, which is exactly the kind of divergence that makes a customer stop
    believing either number.
    """
    from guardian_core.enums import ScanStatus  # noqa: PLC0415

    with session_scope() as session:
        finding = session.get(Finding, uuid.UUID(finding_id))
        if finding is None:
            return {"status": "unknown_finding"}

        engine = _engine_key(finding)
        scan = Scan(
            tenant_id=finding.tenant_id, customer_id=finding.customer_id,
            asset_id=finding.asset_id, trigger="retest", status=ScanStatus.QUEUED.value,
            requested_engines=[engine], stats={"retest_of": str(finding.id)},
        )
        session.add(scan)
        session.flush()
        scan_id = str(scan.id)

        session.add(FindingVerification(
            tenant_id=finding.tenant_id, finding_id=finding.id, scan_id=scan.id,
            verdict=NOT_CHECKED, method="manual", engine=engine,
            rationale="retest requested; awaiting the scan that will answer it",
            checked_at=_now(), evidence={"scan_id": scan_id},
        ))

    celery_app.send_task("guardian.run_scan", args=[scan_id])
    log.info("retest_queued", finding=finding_id, scan=scan_id, engine=engine)
    return {"status": "queued", "scan_id": scan_id, "engine": engine}


def record_manual_verification(
    session, finding: Finding, *, verdict: str, rationale: str, actor_id=None  # noqa: ANN001
) -> FindingVerification:
    """A human's verdict, recorded in the same place as a machine's.

    A pentester confirming a finding by hand and a scanner re-reporting it are both evidence, and a
    report that shows one and not the other is misleading about how the conclusion was reached.
    """
    now = _now()
    record = FindingVerification(
        tenant_id=finding.tenant_id, finding_id=finding.id, scan_id=None,
        verdict=verdict, method="manual", engine=None, rationale=rationale[:2000],
        checked_at=now, evidence={"actor_id": str(actor_id) if actor_id else None},
    )
    session.add(record)
    finding.last_verified_at = now
    finding.verification_verdict = verdict
    if verdict == RESOLVED and finding.status in _OPEN_STATUSES:
        _event(session, finding, finding.status, "resolved", rationale)
        finding.status = "resolved"
    elif verdict == STILL_PRESENT and finding.status in _CLOSED_BY_EVIDENCE:
        finding.reopened_count = (finding.reopened_count or 0) + 1
        _event(session, finding, finding.status, "open", rationale)
        finding.status = "open"
    return record
