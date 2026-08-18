"""Vulnerability intelligence ingestion (WP-C1).

Before this, `sync_feeds` only *enriched* knowledge-base rows that already existed — and nothing put
rows there. The knowledge base started empty and stayed empty, so every SCA match depended on a
live per-package query to OSV, and a service version had nothing at all to match against.

This module populates it, and does so incrementally: `feed_state` records a watermark per source, so
a daily run fetches what changed instead of re-downloading a quarter of a million advisories.

Three rules the old sync broke, all variations on one theme — an outage that looks like good news:

**A failure never advances the watermark.** Advancing it on failure skips the window that failed,
permanently, with nothing to indicate the gap.

**A failure is recorded as a failure.** The previous implementation caught everything, wrote
`status=completed, items=0`, and left the operator with a green sync over a stale KB.

**Created and updated are counted separately.** "0 new advisories" is a healthy Tuesday; "0 records
seen" is an outage. One number cannot say both.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Iterable

from guardian_clients.feeds import FeedError, NormalizedVuln
from guardian_common.logging import get_logger
from guardian_db.models import FeedState, FeedSync, Vulnerability
from guardian_db.session import session_scope
from sqlalchemy import select

log = get_logger("guardian.intel")

# How far back a first sync reaches when a source has no watermark. Two years covers everything an
# internet-facing estate is realistically running while keeping the first run finite; a full
# backfill is an explicit operator action, not something a scheduled job does by surprise.
FIRST_SYNC_LOOKBACK_DAYS = 730
# Re-fetch a little before the watermark: feeds are eventually consistent, and a record modified at
# the moment of the last run can land after it.
OVERLAP_MINUTES = 30
MAX_CONSECUTIVE_FAILURES = 5


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


# ── watermarks ────────────────────────────────────────────────────────────────────────────────────
def get_state(session, source: str) -> FeedState:  # noqa: ANN001
    state = session.get(FeedState, source)
    if state is None:
        state = FeedState(source=source)
        session.add(state)
        session.flush()
    return state


def window_for(
    state: FeedState, *, now: dt.datetime | None = None
) -> tuple[dt.datetime, dt.datetime]:
    """The (since, until) a sync should request."""
    now = now or _now()
    if state.watermark is None:
        return now - dt.timedelta(days=FIRST_SYNC_LOOKBACK_DAYS), now
    return state.watermark - dt.timedelta(minutes=OVERLAP_MINUTES), now


# ── upsert ────────────────────────────────────────────────────────────────────────────────────────
def upsert_vulnerabilities(session, records: Iterable[NormalizedVuln]) -> tuple[int, int]:  # noqa: ANN001
    """Insert or update advisories. Returns (created, updated).

    A record from a weaker source never overwrites a field a stronger one already filled. NVD is
    authoritative for CVSS and CPE applicability; OSV is authoritative for package ranges. Letting
    whichever feed synced last win would make the knowledge base depend on scheduling order.
    """
    created = updated = 0
    for record in records:
        if not record.external_id:
            continue
        existing = session.execute(
            select(Vulnerability).where(Vulnerability.external_id == record.external_id)
        ).scalar_one_or_none()

        if existing is None:
            session.add(_new_vulnerability(record))
            created += 1
            continue
        if _merge(existing, record):
            updated += 1
    return created, updated


def normalize_affected(affected: Iterable[dict]) -> list[dict]:
    """Canonicalize package identity before it is stored.

    The KB matcher narrows candidates with a JSONB containment query on `{"package", "ecosystem"}`,
    which is exact — and feeds publish `PyPI`, `npm`, `crates.io` with their own capitalization
    while a scan asks with whatever the lockfile said. Storing the feed's spelling means the index
    lookup silently matches nothing, so an advisory is ingested, sits in the table, and is never
    found. The original spelling is kept alongside for display.
    """
    rows: list[dict] = []
    for entry in affected or []:
        if not isinstance(entry, dict):
            continue
        package = str(entry.get("package") or "")
        ecosystem = str(entry.get("ecosystem") or "")
        row = dict(entry)
        row["package"] = package.lower()
        row["ecosystem"] = ecosystem.lower()
        if package != row["package"]:
            row["package_display"] = package
        if ecosystem != row["ecosystem"]:
            row["ecosystem_display"] = ecosystem
        rows.append(row)
    return rows


def _new_vulnerability(record: NormalizedVuln) -> Vulnerability:
    return Vulnerability(
        external_id=record.external_id,
        source=record.source,
        summary=record.summary or "",
        details=record.details or "",
        cwe_ids=list(record.cwe_ids or []),
        cvss_vector=record.cvss_vector,
        cvss_base=record.cvss_base,
        severity=record.severity,
        affected=normalize_affected(record.affected or []),
        cpe_configurations=list(record.cpe_configurations or []),
        references=list(record.references or []),
        published_at=record.published_at,
        modified_at=record.modified_at,
    )


def _merge(existing: Vulnerability, record: NormalizedVuln) -> bool:
    """Fold a new record into an existing row. Returns whether anything changed."""
    changed = False

    def set_if(field: str, value: object, *, overwrite: bool = False) -> None:
        nonlocal changed
        if value in (None, "", [], {}):
            return
        current = getattr(existing, field)
        if current in (None, "", [], {}) or overwrite:
            if current != value:
                setattr(existing, field, value)
                changed = True

    authoritative_cvss = record.source == "nvd"
    set_if("summary", record.summary)
    set_if("details", record.details)
    set_if("cwe_ids", list(record.cwe_ids or []))
    set_if("cvss_vector", record.cvss_vector, overwrite=authoritative_cvss)
    set_if("cvss_base", record.cvss_base, overwrite=authoritative_cvss)
    set_if("severity", record.severity, overwrite=authoritative_cvss)
    # Package ranges come from OSV; CPE applicability comes from NVD. Each source owns its own.
    set_if("affected", normalize_affected(record.affected or []),
           overwrite=record.source == "osv")
    set_if("cpe_configurations", list(record.cpe_configurations or []),
           overwrite=record.source == "nvd")
    set_if("references", list(record.references or []))
    set_if("published_at", record.published_at)

    if record.modified_at and existing.modified_at != record.modified_at:
        existing.modified_at = record.modified_at
        changed = True
    return changed


# ── one source, one run ───────────────────────────────────────────────────────────────────────────
def run_source(
    source: str,
    fetch: Callable[[dt.datetime, dt.datetime], Iterable[NormalizedVuln]],
    *,
    now: dt.datetime | None = None,
) -> dict:
    """Sync one feed inside its own transaction, recording the outcome truthfully."""
    now = now or _now()
    with session_scope() as session:
        state = get_state(session, source)
        since, until = window_for(state, now=now)
        record = FeedSync(source=source, status="running", started_at=now,
                          cursor=since.isoformat())
        session.add(record)
        session.flush()
        state.last_attempt_at = now

        try:
            records = list(fetch(since, until))
        except FeedError as exc:
            return record_failure(state, record, str(exc), source)
        except Exception as exc:  # noqa: BLE001 - an unexpected shape is still a feed failure
            return record_failure(state, record, f"{type(exc).__name__}: {exc}", source)

        try:
            created, updated = upsert_vulnerabilities(session, records)
        except Exception as exc:  # noqa: BLE001 - a bad record must not advance the watermark
            return record_failure(state, record,
                                  f"ingest failed: {type(exc).__name__}: {exc}", source)

        record.status = "completed"
        record.items_ingested = created + updated
        record.items_created = created
        record.items_failed = 0
        record.finished_at = _now()

        # Only now, and only here.
        state.watermark = until
        state.last_success_at = now
        state.last_error = None
        state.consecutive_failures = 0
        state.records_ingested = (state.records_ingested or 0) + created + updated

        log.info("feed_sync_complete", source=source, seen=len(records),
                 created=created, updated=updated, watermark=until.isoformat())
        return {"source": source, "status": "completed", "seen": len(records),
                "created": created, "updated": updated}


def record_failure(state: FeedState, record: FeedSync, error: str, source: str) -> dict:
    """Write a failure down honestly and leave the watermark where it was.

    Public because the enrichment tasks need exactly this behaviour, and a second copy of it is how
    two code paths end up disagreeing about whether a failed sync counts as a failure.
    """
    record.status = "failed"
    record.error = error[:2000]
    record.finished_at = _now()
    state.last_error = error[:2000]
    state.consecutive_failures = (state.consecutive_failures or 0) + 1
    # The watermark is deliberately untouched: the next run re-requests this window.
    log.error("feed_sync_failed", source=source, error=error[:300],
              consecutive_failures=state.consecutive_failures)
    if state.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
        log.error("feed_stale", source=source,
                  reason="repeated failures — the knowledge base is no longer current",
                  consecutive_failures=state.consecutive_failures)
    return {"source": source, "status": "failed", "error": error[:300],
            "consecutive_failures": state.consecutive_failures}


# ── enrichment ────────────────────────────────────────────────────────────────────────────────────
def apply_kev(session, kev_records) -> int:  # noqa: ANN001
    """Mark the advisories CISA says are being exploited. Returns how many changed."""
    by_id = {record.cve_id: record for record in kev_records}
    if not by_id:
        raise FeedError("refusing to apply an empty KEV catalogue")

    changed = 0
    rows = session.execute(
        select(Vulnerability).where(Vulnerability.external_id.in_(list(by_id)))
    ).scalars().all()
    for row in rows:
        if not row.kev:
            row.kev = True
            changed += 1
    return changed


def apply_epss(session, scores: dict[str, float]) -> int:  # noqa: ANN001
    """Attach exploit probabilities. Returns how many changed.

    Scores move daily, so an existing value is replaced rather than kept: a stale probability is
    worse than none, because it is trusted.
    """
    if not scores:
        raise FeedError("refusing to apply an empty EPSS score set")

    changed = 0
    rows = session.execute(
        select(Vulnerability).where(Vulnerability.external_id.in_(list(scores)))
    ).scalars().all()
    for row in rows:
        score = scores.get(row.external_id)
        if score is None:
            continue
        if row.epss_score is None or abs(float(row.epss_score) - score) > 1e-9:
            row.epss_score = score
            changed += 1
    return changed
