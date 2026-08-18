"""The findings workbench: query, order, page, and serve evidence (WP-F2).

The old list endpoint took up to 1000 rows in whatever order PostgreSQL felt like returning them and
then sorted *that page* in Python. On a customer with 1200 findings it would show a "critical first"
list whose criticals were simply absent — the database had already discarded them. Sorting has to
happen in SQL, and paging has to be stable while a scan is writing rows underneath it.

Hence keyset pagination on the full sort key `(severity rank, risk score desc, created_at desc, id)`
rather than OFFSET. Keyset cannot skip or repeat a row when rows are inserted mid-scroll, and it
does not get slower on page 400.

Everything here is a pure function of its arguments so the ordering, the cursor and the filters can
be tested without HTTP.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import datetime as dt
import json
import uuid

from guardian_db.models import Finding, ScanEngineRun
from sqlalchemy import Select, and_, case, func, or_, select

# Ordered worst-first. The rank is expressed in SQL so the database, not the page, decides order.
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_UNKNOWN_RANK = 9

STATUSES = ("open", "triaged", "confirmed", "false_positive", "accepted_risk", "resolved")
SEVERITIES = tuple(SEVERITY_RANK)

# A decision that makes a finding stop demanding attention has to be justified: somebody is
# asserting, on the record, that the customer does not need to act. `resolved` is in this set for
# the same reason as `false_positive` — a scanner can observe that an issue is gone, but a human
# marking it resolved by hand is making a claim, and WP-E2 will reopen it if the claim was wrong.
NOTE_REQUIRED_STATUSES = frozenset({"false_positive", "accepted_risk", "resolved"})

MAX_PAGE = 200
DEFAULT_PAGE = 50


def severity_rank_expr():
    """SQL ordering key for severity. Unknown values sort last rather than first."""
    return case(SEVERITY_RANK, value=Finding.severity, else_=_UNKNOWN_RANK)


# ── cursor ────────────────────────────────────────────────────────────────────────────────────────
@dataclasses.dataclass(frozen=True)
class Cursor:
    rank: int
    risk: int
    created_at: dt.datetime
    id: uuid.UUID


class InvalidCursor(ValueError):
    """The cursor is not one this endpoint issued."""


def encode_cursor(finding: Finding) -> str:
    payload = {
        "r": SEVERITY_RANK.get(finding.severity, _UNKNOWN_RANK),
        "s": int(finding.risk_score),
        "t": finding.created_at.isoformat(),
        "i": str(finding.id),
    }
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")


def decode_cursor(raw: str) -> Cursor:
    """Parse a cursor, or raise.

    A malformed cursor is rejected, never ignored. Silently starting from the beginning would show
    the caller page 1 while they believed they were reading page 40, which reads as "no more
    findings" — the failure mode that hides work.
    """
    try:
        padded = raw + "=" * (-len(raw) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()))
        return Cursor(
            rank=int(payload["r"]), risk=int(payload["s"]),
            created_at=dt.datetime.fromisoformat(payload["t"]), id=uuid.UUID(payload["i"]),
        )
    except (KeyError, ValueError, TypeError, binascii.Error, json.JSONDecodeError) as exc:
        raise InvalidCursor(f"malformed cursor: {type(exc).__name__}") from exc


# ── filters ───────────────────────────────────────────────────────────────────────────────────────
@dataclasses.dataclass(frozen=True)
class Filters:
    """Everything the workbench can narrow by. All optional; all combined with AND."""

    scan_id: uuid.UUID | None = None
    asset_id: uuid.UUID | None = None
    customer_id: uuid.UUID | None = None
    severity: tuple[str, ...] = ()
    status: tuple[str, ...] = ()
    category: str | None = None
    engine: str | None = None
    cwe: str | None = None
    cve: str | None = None
    min_risk: int | None = None
    correlated: bool | None = None
    verdict: str | None = None
    exploited: bool | None = None
    query: str | None = None


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def apply_filters(stmt: Select, filters: Filters) -> Select:
    """Narrow a findings SELECT. Tenant scoping is the caller's job and is never optional."""
    f = filters
    if f.scan_id is not None:
        stmt = stmt.where(Finding.scan_id == f.scan_id)
    if f.asset_id is not None:
        stmt = stmt.where(Finding.asset_id == f.asset_id)
    if f.customer_id is not None:
        stmt = stmt.where(Finding.customer_id == f.customer_id)
    if f.severity:
        stmt = stmt.where(Finding.severity.in_(f.severity))
    if f.status:
        stmt = stmt.where(Finding.status.in_(f.status))
    if f.category:
        stmt = stmt.where(Finding.category == f.category)
    if f.engine:
        # The engine is on the run, not the finding. A join is cheaper and more honest than the
        # `location->>'engine'` convention, which not every engine writes.
        stmt = stmt.where(Finding.engine_run_id.in_(
            select(ScanEngineRun.id).where(ScanEngineRun.engine == f.engine)
        ))
    if f.cwe:
        stmt = stmt.where(Finding.cwe_id == f.cwe)
    if f.cve:
        stmt = stmt.where(Finding.cve_ids.any(f.cve.upper()))
    if f.min_risk is not None:
        stmt = stmt.where(Finding.risk_score >= f.min_risk)
    if f.correlated is not None:
        stmt = stmt.where(
            Finding.correlation_id.isnot(None) if f.correlated
            else Finding.correlation_id.is_(None)
        )
    if f.verdict:
        stmt = stmt.where(Finding.verification_verdict == f.verdict)
    if f.exploited is not None:
        # "Somebody has working exploit code" — KEV membership or a functional/high maturity.
        exploited = or_(Finding.kev.is_(True),
                        Finding.exploit_maturity.in_(("functional", "high")))
        stmt = stmt.where(exploited if f.exploited else ~exploited)
    if f.query:
        needle = f"%{_escape_like(f.query.strip())}%"
        stmt = stmt.where(or_(
            Finding.title.ilike(needle, escape="\\"),
            Finding.description.ilike(needle, escape="\\"),
            func.array_to_string(Finding.cve_ids, ",").ilike(needle, escape="\\"),
        ))
    return stmt


def apply_order(stmt: Select) -> Select:
    """Worst first, deterministic to the last tiebreak.

    `id` is in the sort key not for the reader's benefit but because keyset paging is only correct
    when the ordering is a total order: two findings sharing severity, score and timestamp would
    otherwise straddle a page boundary and one of them would be skipped.
    """
    return stmt.order_by(
        severity_rank_expr().asc(), Finding.risk_score.desc(), Finding.created_at.desc(),
        Finding.id.asc(),
    )


def apply_cursor(stmt: Select, cursor: Cursor) -> Select:
    """Everything strictly after `cursor` in the sort order above."""
    rank = severity_rank_expr()
    return stmt.where(or_(
        rank > cursor.rank,
        and_(rank == cursor.rank, Finding.risk_score < cursor.risk),
        and_(rank == cursor.rank, Finding.risk_score == cursor.risk,
             Finding.created_at < cursor.created_at),
        and_(rank == cursor.rank, Finding.risk_score == cursor.risk,
             Finding.created_at == cursor.created_at, Finding.id > cursor.id),
    ))


def page_size(requested: int | None) -> int:
    if not requested or requested < 1:
        return DEFAULT_PAGE
    return min(requested, MAX_PAGE)


# ── triage rules ──────────────────────────────────────────────────────────────────────────────────
def triage_requires_note(*, status: str | None, severity_override: str | None) -> bool:
    return bool(severity_override) or (status in NOTE_REQUIRED_STATUSES)


def validate_transition(current: str, target: str | None) -> str | None:
    """Return the reason a transition is refused, or None if it is allowed.

    Deliberately permissive about direction — reopening a resolved finding is a legitimate thing for
    an analyst to do, and WP-E2 does it automatically. What is refused is a status outside the
    vocabulary, which would otherwise silently create a state no filter, gate or report understands.
    """
    if target is None or target == current:
        return None
    if target not in STATUSES:
        return f"{target!r} is not a finding status"
    return None


__all__ = [
    "DEFAULT_PAGE",
    "MAX_PAGE",
    "NOTE_REQUIRED_STATUSES",
    "SEVERITIES",
    "SEVERITY_RANK",
    "STATUSES",
    "Cursor",
    "Filters",
    "InvalidCursor",
    "apply_cursor",
    "apply_filters",
    "apply_order",
    "decode_cursor",
    "encode_cursor",
    "page_size",
    "severity_rank_expr",
    "triage_requires_note",
    "validate_transition",
]
