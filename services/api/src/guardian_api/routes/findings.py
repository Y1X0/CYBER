"""Findings workbench: query, dossier, and triage (WP-F2).

An analyst's whole day happens here, so the endpoints are shaped around the three things they
actually do — narrow a large list to the handful that matter, read everything known about one
finding, and record a decision about many at once.

Three properties are load-bearing:

* **The list is ordered and paged in SQL.** The previous implementation took 1000 rows in
  unspecified order and sorted that page in Python, so a customer with more findings than that
  was shown a "worst first" list whose worst findings the database had already discarded.
* **Evidence is scrubbed on the way out.** The engines redact at write time; this is the second
  line, and a hit is logged rather than swallowed, because a hit means an engine persisted a
  credential and that is a defect somebody has to fix.
* **A decision that silences a finding is justified and attributed**, one `finding_events` row per
  finding, whether it was made one at a time or fifty at a time.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from guardian_common.logging import get_logger
from guardian_core.apikeys import Scope
from guardian_core.redaction import scrub
from guardian_db.audit import record_audit
from guardian_db.models import (
    Asset,
    Finding,
    FindingCorrelation,
    FindingEvent,
    FindingVerification,
    Scan,
    ScanEngineRun,
)
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from guardian_api.deps import (
    Identity,
    client_ip,
    get_current_identity,
    get_db,
    require_scope,
    require_staff_write,
)
from guardian_api.schemas import FindingOut, FindingTriage
from guardian_api.workbench import (
    MAX_PAGE,
    SEVERITIES,
    STATUSES,
    Filters,
    InvalidCursor,
    apply_cursor,
    apply_filters,
    apply_order,
    decode_cursor,
    encode_cursor,
    page_size,
    triage_requires_note,
    validate_transition,
)

router = APIRouter()
log = get_logger("guardian.workbench")


def _reject_unknown(name: str, values: list[str] | None, allowed: tuple[str, ...]) -> None:
    unknown = [v for v in (values or []) if v not in allowed]
    if unknown:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"unknown {name} value(s): {', '.join(sorted(unknown))}",
        )


# ── serialization ─────────────────────────────────────────────────────────────────────────────────
def _scrubbed(finding: Finding, payload: dict) -> dict:
    """Mask anything credential-shaped, and say so in the log if something was.

    Never silent: a hit means the value reached the database, so redacting it here fixes this
    response and nothing else. The log line is what makes the underlying engine defect findable.
    """
    cleaned, hits = scrub(payload)
    if hits:
        log.warning(
            "evidence_redacted_at_boundary", finding_id=str(finding.id),
            patterns=sorted(set(hits)),
            detail="an engine persisted a credential-shaped value; the engine must redact at write "
                   "time — this response was masked but the stored row was not",
        )
    return cleaned


def _out(finding: Finding) -> FindingOut:
    model = FindingOut.model_validate(finding, from_attributes=True)
    return model.model_copy(update={
        "evidence": _scrubbed(finding, model.evidence or {}),
        "location": _scrubbed(finding, model.location or {}),
    })


def _visible(query, identity: Identity):
    """Tenant scoping, plus the portal restriction. Applied to every read path without exception."""
    query = query.where(Finding.tenant_id == identity.tenant_id)
    if identity.is_machine:
        # An API key belongs to a tenant, not to a customer contact. It sees the tenant it was
        # issued for and nothing else; what it may *do* there is decided by its scopes (WP-G1).
        return query
    if not identity.is_staff:
        # A portal contact sees their own customer or nothing — never "everything" because the
        # customer id happened to be null.
        query = query.where(Finding.customer_id == identity.portal_customer_id)
    return query


# ── list ──────────────────────────────────────────────────────────────────────────────────────────
# Paging is reported in headers rather than by wrapping the array in an envelope. The endpoint
# already has consumers — the web client and the report builder — and changing the body shape would
# break them to carry two fields. `X-Next-Cursor` is absent when there is no next page, which is the
# same signal an envelope's null would give.
@router.get("", response_model=list[FindingOut])
def list_findings(  # noqa: PLR0913 - a workbench filter set is wide by nature
    response: Response,
    scan_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    customer_id: uuid.UUID | None = None,
    severity: list[str] | None = Query(default=None),
    status_filter: list[str] | None = Query(default=None, alias="status"),
    category: str | None = Query(default=None, max_length=60),
    engine: str | None = Query(default=None, max_length=30),
    cwe: str | None = Query(default=None, max_length=20),
    cve: str | None = Query(default=None, max_length=30),
    min_risk: int | None = Query(default=None, ge=0, le=100),
    correlated: bool | None = None,
    verdict: str | None = Query(default=None, max_length=20),
    exploited: bool | None = None,
    q: str | None = Query(default=None, max_length=200),
    cursor: str | None = Query(default=None, max_length=500),
    limit: int = Query(default=50, ge=1, le=MAX_PAGE),
    identity: Identity = Depends(require_scope(Scope.FINDINGS_READ)),
    db: Session = Depends(get_db),
) -> list[FindingOut]:
    """Worst first, filtered, and keyset-paged so the order survives writes underneath it."""
    # An unrecognized value is refused rather than dropped. Dropping it would widen the query the
    # caller asked to narrow — `?severity=criticl` would quietly return everything.
    _reject_unknown("severity", severity, SEVERITIES)
    _reject_unknown("status", status_filter, STATUSES)

    filters = Filters(
        scan_id=scan_id, asset_id=asset_id, customer_id=customer_id,
        severity=tuple(severity or ()), status=tuple(status_filter or ()),
        category=category, engine=engine, cwe=cwe, cve=cve, min_risk=min_risk,
        correlated=correlated, verdict=verdict, exploited=exploited, query=q,
    )
    stmt = apply_order(apply_filters(_visible(select(Finding), identity), filters))
    if cursor:
        try:
            stmt = apply_cursor(stmt, decode_cursor(cursor))
        except InvalidCursor as exc:
            # Refused, not ignored: silently restarting at page 1 reads as "no more findings".
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    size = page_size(limit)
    # One extra row is the cheapest way to know whether another page exists without a COUNT over
    # the filtered set, which is the query that takes the database down on every keystroke.
    rows = list(db.execute(stmt.limit(size + 1)).scalars())
    has_more = len(rows) > size
    rows = rows[:size]
    response.headers["X-Has-More"] = "true" if has_more else "false"
    if has_more and rows:
        response.headers["X-Next-Cursor"] = encode_cursor(rows[-1])
    return [_out(row) for row in rows]


# ── summary ───────────────────────────────────────────────────────────────────────────────────────
class FindingSummary(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    by_engine: dict[str, int]
    exploitable: int
    correlated: int
    unverified: int


@router.get("/summary", response_model=FindingSummary)
def summarize_findings(
    scan_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    customer_id: uuid.UUID | None = None,
    identity: Identity = Depends(require_scope(Scope.FINDINGS_READ)),
    db: Session = Depends(get_db),
) -> FindingSummary:
    """Counts, aggregated by the database.

    The same visibility rules as the list. A summary that counted rows the caller cannot read would
    disclose the existence of another customer's findings, which is most of what a finding is.
    """
    filters = Filters(scan_id=scan_id, asset_id=asset_id, customer_id=customer_id)

    def grouped(column):
        stmt = apply_filters(
            _visible(select(column, func.count()), identity), filters
        ).group_by(column)
        return {str(key): int(count) for key, count in db.execute(stmt).all() if key is not None}

    by_severity = grouped(Finding.severity)
    by_status = grouped(Finding.status)

    engine_stmt = apply_filters(
        _visible(
            select(ScanEngineRun.engine, func.count())
            .select_from(Finding)
            .join(ScanEngineRun, ScanEngineRun.id == Finding.engine_run_id),
            identity,
        ),
        filters,
    ).group_by(ScanEngineRun.engine)
    by_engine = {str(k): int(v) for k, v in db.execute(engine_stmt).all()}

    def count_where(condition) -> int:
        stmt = apply_filters(
            _visible(select(func.count()).select_from(Finding), identity), filters
        ).where(condition)
        return int(db.execute(stmt).scalar_one())

    return FindingSummary(
        total=sum(by_severity.values()),
        by_severity=by_severity,
        by_status=by_status,
        by_engine=by_engine,
        exploitable=count_where(
            Finding.kev.is_(True) | Finding.exploit_maturity.in_(("functional", "high"))
        ),
        correlated=count_where(Finding.correlation_id.isnot(None)),
        unverified=count_where(Finding.last_verified_at.is_(None)),
    )


# ── dossier ───────────────────────────────────────────────────────────────────────────────────────
class FindingDossier(BaseModel):
    """Everything known about one finding, in the order an analyst asks for it."""

    finding: FindingOut
    asset: dict
    scan: dict
    engine: str | None
    risk_rationale: list
    exploit: dict
    correlation: dict | None = None
    # Sibling findings in the same correlation group — the corroboration, never a replacement for
    # the members' own records.
    related: list[FindingOut] = Field(default_factory=list)
    verifications: list[dict] = Field(default_factory=list)
    timeline: list[dict] = Field(default_factory=list)


@router.get("/{finding_id}", response_model=FindingDossier)
def get_finding(
    finding_id: uuid.UUID,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> FindingDossier:
    finding = db.execute(
        _visible(select(Finding), identity).where(Finding.id == finding_id)
    ).scalar_one_or_none()
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")

    asset = db.get(Asset, finding.asset_id)
    scan = db.get(Scan, finding.scan_id)
    run = db.get(ScanEngineRun, finding.engine_run_id)

    correlation = None
    related: list[Finding] = []
    if finding.correlation_id:
        group = db.get(FindingCorrelation, finding.correlation_id)
        if group is not None and group.tenant_id == identity.tenant_id:
            correlation = {
                "id": str(group.id), "rule": group.rule, "kind": group.kind,
                "severity": group.severity, "risk_score": group.risk_score,
                "rationale": group.rationale, "member_count": group.member_count,
            }
            related = list(db.execute(
                _visible(select(Finding), identity)
                .where(Finding.correlation_id == group.id, Finding.id != finding.id)
                .limit(50)
            ).scalars())

    verifications = [
        {"checked_at": v.checked_at.isoformat() if v.checked_at else None,
         "verdict": v.verdict, "rationale": v.rationale, "engine": v.engine,
         "scan_id": str(v.scan_id) if v.scan_id else None}
        for v in db.execute(
            select(FindingVerification)
            .where(FindingVerification.finding_id == finding.id)
            .order_by(FindingVerification.checked_at.desc()).limit(50)
        ).scalars()
    ]
    timeline = [
        {"at": e.created_at.isoformat() if e.created_at else None,
         "actor_id": str(e.actor_id) if e.actor_id else None,
         "from_status": e.from_status, "to_status": e.to_status,
         # A triage note is free text written by a human and can quote the very credential the
         # finding is about.
         "note": _scrubbed(finding, {"note": e.note or ""})["note"]}
        for e in db.execute(
            select(FindingEvent).where(FindingEvent.finding_id == finding.id)
            .order_by(FindingEvent.created_at.asc()).limit(200)
        ).scalars()
    ]

    return FindingDossier(
        finding=_out(finding),
        asset={"id": str(asset.id), "name": asset.name, "kind": asset.kind,
               "identifier": asset.identifier, "exposure": asset.exposure} if asset else {},
        scan={"id": str(scan.id), "status": scan.status, "trigger": scan.trigger,
              "finished_at": scan.finished_at.isoformat() if scan and scan.finished_at else None}
        if scan else {},
        engine=run.engine if run else None,
        risk_rationale=finding.risk_rationale or [],
        exploit={"kev": finding.kev, "maturity": finding.exploit_maturity,
                 "ransomware": finding.ransomware,
                 "epss": float(finding.epss_score) if finding.epss_score is not None else None,
                 "cvss_base": float(finding.cvss_base) if finding.cvss_base is not None else None},
        correlation=correlation,
        related=[_out(row) for row in related],
        verifications=verifications,
        timeline=timeline,
    )


# ── triage ────────────────────────────────────────────────────────────────────────────────────────
def _apply_triage(
    db: Session, finding: Finding, body: FindingTriage, identity: Identity, ip: str | None,
) -> None:
    """One triage decision. Records the transition, the attribution, and the justification."""
    refusal = validate_transition(finding.status, body.status)
    if refusal:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, refusal)

    if body.status and body.status != finding.status:
        db.add(FindingEvent(
            finding_id=finding.id, actor_id=identity.user.id,
            from_status=finding.status, to_status=body.status, note=body.note,
        ))
        finding.status = body.status

    if body.severity_override and body.severity_override != finding.severity:
        record_audit(
            db, action="finding.severity_override", tenant_id=identity.tenant_id,
            customer_id=finding.customer_id, actor_id=identity.user.id, entity_type="finding",
            entity_id=str(finding.id), ip=ip,
            metadata={"from": finding.severity, "to": body.severity_override, "note": body.note},
        )
        finding.severity = body.severity_override
        finding.source = "manual"  # a human has adjudicated this finding

    finding.reviewed_by = identity.user.id
    record_audit(
        db, action="finding.triage", tenant_id=identity.tenant_id,
        customer_id=finding.customer_id, actor_id=identity.user.id, entity_type="finding",
        entity_id=str(finding.id), ip=ip, metadata={"status": finding.status},
    )


@router.patch("/{finding_id}", response_model=FindingOut)
def triage_finding(
    finding_id: uuid.UUID,
    body: FindingTriage,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> FindingOut:
    """Pentester triage: change status and/or override severity, with an audited justification."""
    finding = db.execute(
        select(Finding).where(Finding.id == finding_id, Finding.tenant_id == identity.tenant_id)
    ).scalar_one_or_none()
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")

    if triage_requires_note(status=body.status, severity_override=body.severity_override) \
            and not body.note.strip():
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "a justification note is required for severity overrides and risk decisions",
        )

    _apply_triage(db, finding, body, identity, ip)
    db.commit()
    del request
    return _out(finding)


class BulkTriage(FindingTriage):
    finding_ids: list[uuid.UUID] = Field(min_length=1, max_length=500)


class BulkTriageResult(BaseModel):
    updated: list[uuid.UUID]
    # Named, never silently dropped: an analyst who selected 50 findings and saw "done" while 12
    # were skipped believes decisions were recorded that were not.
    refused: list[dict]


@router.post("/bulk-triage", response_model=BulkTriageResult)
def bulk_triage(
    body: BulkTriage,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> BulkTriageResult:
    """Apply one decision to many findings.

    The justification requirement is not relaxed because the action is bulk — if anything the
    opposite: fifty findings closed in one click with no stated reason is exactly the pattern that
    makes a backlog look clean while nothing was fixed. Each finding gets its own event and its own
    audit row, so the decision is reconstructable per finding afterwards.
    """
    if triage_requires_note(status=body.status, severity_override=body.severity_override) \
            and not body.note.strip():
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "a justification note is required for severity overrides and risk decisions",
        )

    requested = list(dict.fromkeys(body.finding_ids))
    found = {
        f.id: f for f in db.execute(
            select(Finding).where(
                Finding.id.in_(requested), Finding.tenant_id == identity.tenant_id
            )
        ).scalars()
    }

    updated: list[uuid.UUID] = []
    refused: list[dict] = []
    for finding_id in requested:
        finding = found.get(finding_id)
        if finding is None:
            refused.append({"id": str(finding_id), "reason": "not found in this tenant"})
            continue
        reason = validate_transition(finding.status, body.status)
        if reason:
            refused.append({"id": str(finding_id), "reason": reason})
            continue
        _apply_triage(db, finding, body, identity, ip)
        updated.append(finding.id)

    record_audit(
        db, action="finding.bulk_triage", tenant_id=identity.tenant_id, customer_id=None,
        actor_id=identity.user.id, entity_type="finding", entity_id="bulk", ip=ip,
        metadata={"requested": len(requested), "updated": len(updated), "refused": len(refused),
                  "status": body.status, "severity_override": body.severity_override},
    )
    db.commit()
    del request
    return BulkTriageResult(updated=updated, refused=refused)
