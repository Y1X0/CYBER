"""Opening and closing remediation items (WP-F5).

Two operations, and the second is the one that makes the first worth anything.

`open_items` turns findings into tracked work — one item per *underlying issue*, not per finding.
WP-E1 already worked out that three engines reporting the same credential is one problem; opening
three tickets for it is how a remediation backlog stops being believed.

`verify_after_scan` is the close. It runs after WP-E2's reconciliation and promotes an item to
`verified` only where the verification says the finding is genuinely gone — which means the engine
that found it ran again and completed cleanly. An engine that failed, or never ran, resolves
nothing: its silence is not evidence, and a workflow that treated it as evidence would close the
customer's tickets on the strength of a scan that did not happen.
"""

from __future__ import annotations

import datetime as dt
import uuid

from guardian_common.logging import get_logger
from guardian_core import remediation as rem
from guardian_db.models import Asset, Finding, FindingVerification, RemediationItem
from sqlalchemy import select
from sqlalchemy.orm import Session

log = get_logger("guardian.remediation")

# Findings a human has already dismissed do not need a fix tracked.
_TRACKABLE_STATUSES = ("open", "triaged", "confirmed")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def open_items(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    customer_id: uuid.UUID | None = None,
    finding_ids: list[uuid.UUID] | None = None,
    assignee_id: uuid.UUID | None = None,
    now: dt.datetime | None = None,
) -> dict:
    """Open remediation items for findings that need one.

    One item per correlation group where a group exists, so a credential found by three engines is
    one piece of work. Idempotent: re-running never opens a second item for the same finding, which
    matters because this is called after every scan.
    """
    now = now or _now()
    query = select(Finding).where(
        Finding.tenant_id == tenant_id, Finding.status.in_(_TRACKABLE_STATUSES)
    )
    if customer_id:
        query = query.where(Finding.customer_id == customer_id)
    if finding_ids:
        query = query.where(Finding.id.in_(finding_ids))
    findings = list(session.execute(query.limit(5000)).scalars())
    if not findings:
        return {"opened": 0, "existing": 0, "grouped": 0}

    existing_finding_ids = {
        row.finding_id for row in session.execute(
            select(RemediationItem).where(
                RemediationItem.tenant_id == tenant_id,
                RemediationItem.finding_id.in_([f.id for f in findings]),
            )
        ).scalars()
    }

    # Which correlation groups already have an item, so a duplicate does not open a second one.
    covered_groups: set[uuid.UUID] = set()
    for finding in findings:
        if finding.id in existing_finding_ids and finding.correlation_id:
            covered_groups.add(finding.correlation_id)
    for row in session.execute(
        select(Finding.correlation_id).join(
            RemediationItem, RemediationItem.finding_id == Finding.id
        ).where(Finding.tenant_id == tenant_id, Finding.correlation_id.isnot(None))
    ).scalars():
        if row:
            covered_groups.add(row)

    exposures = {
        asset.id: asset.exposure for asset in session.execute(
            select(Asset).where(Asset.id.in_({f.asset_id for f in findings}))
        ).scalars()
    }

    opened = grouped = 0
    # Worst first, so the item that represents a group is opened against its most severe member.
    for finding in sorted(findings, key=lambda f: (-int(f.risk_score or 0), str(f.id))):
        if finding.id in existing_finding_ids:
            continue
        if finding.correlation_id and finding.correlation_id in covered_groups:
            grouped += 1
            continue
        session.add(RemediationItem(
            tenant_id=finding.tenant_id,
            customer_id=finding.customer_id,
            finding_id=finding.id,
            status=rem.OPEN,
            assignee_id=assignee_id,
            due_at=rem.due_at(finding.severity,
                              exposure=exposures.get(finding.asset_id, "unknown"),
                              opened_at=now),
        ))
        opened += 1
        if finding.correlation_id:
            covered_groups.add(finding.correlation_id)
    session.flush()

    log.info("remediation_items_opened", tenant=str(tenant_id), opened=opened,
             existing=len(existing_finding_ids), grouped=grouped)
    return {"opened": opened, "existing": len(existing_finding_ids), "grouped": grouped}


def verify_after_scan(session: Session, *, scan_id: uuid.UUID, now: dt.datetime | None = None
                      ) -> dict:
    """Close what the scan proved fixed, and reopen what came back.

    Reads WP-E2's verification records rather than the finding's status, because the verification is
    the thing that knows *why* a finding is absent. `resolved` means the engine ran, completed and
    did not report it. `not_checked` means the engine failed or never ran — and an item must never
    be closed on that, however tempting the empty result looks.
    """
    now = now or _now()
    verifications = list(session.execute(
        select(FindingVerification).where(FindingVerification.scan_id == scan_id)
    ).scalars())
    if not verifications:
        return {"verified": 0, "reopened": 0, "unchanged": 0}

    items = {
        item.finding_id: item for item in session.execute(
            select(RemediationItem).where(
                RemediationItem.finding_id.in_([v.finding_id for v in verifications])
            )
        ).scalars()
    }

    verified = reopened = unchanged = 0
    for verification in verifications:
        item = items.get(verification.finding_id)
        if item is None:
            continue
        if verification.verdict == "resolved":
            if item.status == rem.VERIFIED:
                unchanged += 1
                continue
            rem.validate_transition(item.status, rem.VERIFIED, by_scan=True)
            item.status = rem.VERIFIED
            item.verified_by_scan_id = scan_id
            verified += 1
        elif verification.verdict == "still_present" and item.status in (rem.FIXED, rem.VERIFIED):
            # Somebody said it was fixed and the scanner disagrees. The scanner is looking at the
            # running system.
            rem.validate_transition(item.status, rem.REOPENED, by_scan=True)
            item.status = rem.REOPENED
            item.verified_by_scan_id = None
            reopened += 1
        else:
            # `not_checked` / `inconclusive`: the engine failed, ran degraded, or never ran. Nothing
            # was proved, so nothing changes.
            unchanged += 1

    session.flush()
    log.info("remediation_verified", scan=str(scan_id), verified=verified, reopened=reopened,
             unchanged=unchanged)
    return {"verified": verified, "reopened": reopened, "unchanged": unchanged}


__all__ = ["open_items", "verify_after_scan"]
