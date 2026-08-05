"""Feed-sync task — refresh the vulnerability knowledge base from external sources.

Phase 2 wires KEV (which CVEs are actively exploited) and EPSS (exploit probability) enrichment on
top of the existing KB. It is safe to run offline: feed clients return empty results on failure and
the task records the outcome in `feed_syncs` without erroring the worker.

Scheduling (Celery beat) is configured in production; here the task is callable on demand.
"""

from __future__ import annotations

import datetime as dt

from guardian_clients.feeds import EpssClient, KevClient
from guardian_common.logging import get_logger
from guardian_db.models import FeedSync, Vulnerability
from guardian_db.session import session_scope

from guardian_scanner.celery_app import celery_app

log = get_logger("guardian.feeds")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


@celery_app.task(name="guardian.sync_feeds")
def sync_feeds() -> dict:
    """Enrich KB vulnerabilities with KEV flags and EPSS scores."""
    with session_scope() as session:
        record = FeedSync(source="kev+epss", status="running", started_at=_now())
        session.add(record)
        session.flush()

        updated = 0
        try:
            kev_ids = KevClient().fetch_kev_ids()
            epss = EpssClient()
            for vuln in session.query(Vulnerability).all():
                changed = False
                if kev_ids and vuln.external_id in kev_ids and not vuln.kev:
                    vuln.kev = True
                    changed = True
                if vuln.epss_score is None and vuln.external_id.startswith("CVE-"):
                    score = epss.score_for(vuln.external_id)
                    if score is not None:
                        vuln.epss_score = score
                        changed = True
                if changed:
                    vuln.modified_at = _now()
                    updated += 1
            record.status = "completed"
            record.items_ingested = updated
        except Exception as exc:  # noqa: BLE001 - never let a feed outage crash the worker
            record.status = "failed"
            record.error = str(exc)[:2000]
            log.error("feed_sync_failed", error=str(exc))
        finally:
            record.finished_at = _now()

        return {"status": record.status, "updated": updated}
