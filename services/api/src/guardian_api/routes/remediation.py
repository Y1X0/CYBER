"""Remediation workflow (WP-F5).

The loop the platform existed to close: finding → an owner and a date → a fix → a rescan that proves
it → verified. `remediation_items` has been a table with no code behind it since the first schema;
this is the code.

The one endpoint that is deliberately missing is "mark verified". A person can set `fixed`; only a
scan sets `verified`, and it does so from `guardian_scanner.remediation.verify_after_scan` using
WP-E2's verification records. A workflow where the assignee under deadline pressure certifies their
own fix is a to-do list, and security teams already have one of those.

External ticketing is exposed as a **payload**, not an integration: `GET /{id}/ticket` renders the
Jira/GitHub-ready body so a customer's automation files it with their own credential. Guardian holds
no ticketing credential, which is the right side of that trade.
"""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from guardian_core import remediation as rem
from guardian_core.redaction import scrub_text
from guardian_db.audit import record_audit
from guardian_db.models import Asset, Finding, RemediationItem, User
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from guardian_api.deps import (
    Identity,
    client_ip,
    get_current_identity,
    get_db,
    require_staff_write,
)

router = APIRouter()


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class ItemOut(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    customer_id: uuid.UUID
    status: str
    assignee_id: uuid.UUID | None = None
    due_at: str | None = None
    overdue: bool = False
    justification: str | None = None
    verified_by_scan_id: uuid.UUID | None = None
    finding_title: str = ""
    severity: str = ""
    risk_score: int = 0


class OpenRequest(BaseModel):
    finding_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)
    customer_id: uuid.UUID | None = None
    assignee_id: uuid.UUID | None = None


class UpdateRequest(BaseModel):
    status: str | None = Field(default=None, max_length=20)
    assignee_id: uuid.UUID | None = None
    justification: str = Field(default="", max_length=4000)
    due_at: dt.datetime | None = None


class SlaOut(BaseModel):
    total: int
    active: int
    overdue: int
    verified: int
    accepted: int
    on_time_rate: int
    by_severity: dict[str, int]


def _visible(query, identity: Identity):
    query = query.where(RemediationItem.tenant_id == identity.tenant_id)
    if not identity.is_staff:
        query = query.where(RemediationItem.customer_id == identity.portal_customer_id)
    return query


def _out(item: RemediationItem, finding: Finding | None, now: dt.datetime) -> ItemOut:
    return ItemOut(
        id=item.id, finding_id=item.finding_id, customer_id=item.customer_id, status=item.status,
        assignee_id=item.assignee_id,
        due_at=item.due_at.isoformat() if item.due_at else None,
        overdue=rem.is_overdue(item.status, item.due_at, now=now),
        justification=item.justification, verified_by_scan_id=item.verified_by_scan_id,
        finding_title=finding.title if finding else "",
        severity=finding.severity if finding else "",
        risk_score=int(finding.risk_score or 0) if finding else 0,
    )


def _findings_for(db: Session, items: list[RemediationItem]) -> dict:
    if not items:
        return {}
    rows = db.execute(
        select(Finding).where(Finding.id.in_([i.finding_id for i in items]))
    ).scalars()
    return {row.id: row for row in rows}


# ── open ──────────────────────────────────────────────────────────────────────────────────────────
@router.post("", response_model=dict, status_code=201)
def open_remediation(
    body: OpenRequest,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> dict:
    """Open tracked work for findings. One item per underlying issue, not per finding."""
    from guardian_scanner.remediation import open_items

    result = open_items(
        db, tenant_id=identity.tenant_id, customer_id=body.customer_id,
        finding_ids=body.finding_ids or None, assignee_id=body.assignee_id,
    )
    record_audit(
        db, action="remediation.opened", tenant_id=identity.tenant_id,
        customer_id=body.customer_id, actor_id=identity.user.id, entity_type="remediation",
        entity_id="bulk", ip=ip, metadata=result,
    )
    db.commit()
    del request
    return result


# ── read ──────────────────────────────────────────────────────────────────────────────────────────
@router.get("", response_model=list[ItemOut])
def list_remediation(
    status_filter: str | None = Query(default=None, alias="status", max_length=20),
    assignee_id: uuid.UUID | None = None,
    customer_id: uuid.UUID | None = None,
    overdue: bool | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> list[ItemOut]:
    if status_filter and status_filter not in rem.STATUSES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"unknown status: {status_filter}")
    query = _visible(select(RemediationItem), identity)
    if status_filter:
        query = query.where(RemediationItem.status == status_filter)
    if assignee_id:
        query = query.where(RemediationItem.assignee_id == assignee_id)
    if customer_id:
        query = query.where(RemediationItem.customer_id == customer_id)

    items = list(db.execute(query.order_by(RemediationItem.due_at.asc()).limit(limit)).scalars())
    findings = _findings_for(db, items)
    now = _now()
    out = [_out(item, findings.get(item.finding_id), now) for item in items]
    if overdue is not None:
        out = [row for row in out if row.overdue is overdue]
    return out


@router.get("/sla", response_model=SlaOut)
def get_sla(
    customer_id: uuid.UUID | None = None,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> SlaOut:
    """How the remediation backlog is doing against its own clock."""
    query = _visible(select(RemediationItem), identity)
    if customer_id:
        query = query.where(RemediationItem.customer_id == customer_id)
    items = list(db.execute(query.limit(5000)).scalars())
    findings = _findings_for(db, items)
    summary = rem.summarize(
        [
            {"status": item.status, "due_at": item.due_at,
             "severity": getattr(findings.get(item.finding_id), "severity", "medium")}
            for item in items
        ],
        now=_now(),
    )
    return SlaOut(
        total=summary.total, active=summary.active, overdue=summary.overdue,
        verified=summary.verified, accepted=summary.accepted,
        on_time_rate=summary.on_time_rate, by_severity=summary.by_severity,
    )


@router.get("/{item_id}/ticket", response_model=dict)
def get_ticket_payload(
    item_id: uuid.UUID,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> dict:
    """The ticket body for a customer's own Jira/GitHub automation.

    Rendered rather than filed: Guardian holds no ticketing credential, and a body that leaves the
    platform lands in a system with a different audience — so the evidence in it is scrubbed.
    """
    item = db.execute(
        _visible(select(RemediationItem), identity).where(RemediationItem.id == item_id)
    ).scalar_one_or_none()
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "remediation item not found")
    finding = db.get(Finding, item.finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "the finding no longer exists")

    asset = db.get(Asset, finding.asset_id)
    duplicates = 0
    if finding.correlation_id:
        # Counted in the database (WP-G2): this loaded every finding in the correlation group to
        # take its length, which on a group of a thousand duplicates is a thousand rows fetched to
        # produce one integer.
        duplicates = int(db.execute(
            select(func.count()).select_from(Finding)
            .where(Finding.correlation_id == finding.correlation_id)
        ).scalar_one()) - 1

    remediation_text = ""
    if isinstance(finding.remediation, dict):
        remediation_text = str(finding.remediation.get("remediation")
                               or finding.remediation.get("summary") or "")
    evidence = str((finding.evidence or {}).get("summary")
                   or (finding.evidence or {}).get("match") or "")

    payload = rem.ticket_payload(
        finding_title=finding.title,
        severity=finding.severity,
        risk_score=int(finding.risk_score or 0),
        asset=asset.name if asset else str(finding.asset_id),
        description=scrub_text(finding.description or "")[0],
        remediation=scrub_text(remediation_text)[0],
        cwe_id=finding.cwe_id,
        owasp_ref=finding.owasp_ref,
        cve_ids=tuple(finding.cve_ids or []),
        evidence_summary=scrub_text(evidence)[0],
        due=item.due_at,
        finding_url=f"/findings/{finding.id}",
        duplicate_count=max(0, duplicates),
    )
    return {
        "title": payload.title, "body": payload.body, "labels": list(payload.labels),
        "due_at": payload.due_at, "fields": payload.fields,
    }


# ── update ────────────────────────────────────────────────────────────────────────────────────────
@router.patch("/{item_id}", response_model=ItemOut)
def update_remediation(
    item_id: uuid.UUID,
    body: UpdateRequest,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> ItemOut:
    """Assign, schedule, or move an item along.

    `verified` is refused here whatever the caller's role. It is set by a scan that ran the engine
    which found the issue, completed cleanly, and did not report it again — see
    `guardian_scanner.remediation.verify_after_scan`.
    """
    item = db.execute(
        _visible(select(RemediationItem), identity).where(RemediationItem.id == item_id)
    ).scalar_one_or_none()
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "remediation item not found")

    if body.status:
        try:
            rem.validate_transition(item.status, body.status, by_scan=False,
                                    justification=body.justification)
        except rem.InvalidTransition as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    if body.assignee_id is not None:
        assignee = db.get(User, body.assignee_id)
        if assignee is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "assignee not found")
        item.assignee_id = body.assignee_id
    if body.due_at is not None:
        item.due_at = body.due_at
    if body.justification:
        item.justification = body.justification
    if body.status:
        previous, item.status = item.status, body.status
        record_audit(
            db, action="remediation.status", tenant_id=identity.tenant_id,
            customer_id=item.customer_id, actor_id=identity.user.id, entity_type="remediation",
            entity_id=str(item.id), ip=ip,
            metadata={"from": previous, "to": body.status,
                      "justification": body.justification[:500]},
        )
    db.commit()
    del request
    return _out(item, db.get(Finding, item.finding_id), _now())
