"""Feed-sync tasks — keep the vulnerability knowledge base current (WP-C1).

Four sources, each with its own task so one outage does not stop the others and each gets its own
`feed_state` watermark:

* **NVD** — the authoritative CVE record, and the only source of CPE applicability, which is what
  lets a service version be matched to advisories at all.
* **OSV** — package ranges per ecosystem, which is what an SCA match evaluates.
* **KEV** — which CVEs are actually being exploited.
* **EPSS** — how likely each one is to be exploited next.

`sync_all` runs them in that order because the enrichment sources only mark records that already
exist: applying KEV before ingesting advisories flags nothing and reports success.

Nothing here catches a feed failure and reports success. A failed source raises out of its fetch,
`intel.run_source` records the failure, leaves the watermark alone so the window is retried, and
the returned summary says which sources failed. Every one of those was a bug in the version this
replaces.
"""

from __future__ import annotations

import datetime as dt
import os

from guardian_clients.feeds import EpssClient, FeedError, KevClient, NvdClient, OsvClient
from guardian_common.logging import get_logger
from guardian_db.models import FeedSync
from guardian_db.session import session_scope

from guardian_scanner import intel
from guardian_scanner.celery_app import celery_app

log = get_logger("guardian.feeds")

# The ecosystems Guardian's own lockfile parsers can produce. Syncing an ecosystem nothing can
# report on costs bandwidth and buys nothing.
OSV_ECOSYSTEMS = ("PyPI", "npm", "Go", "Maven", "RubyGems", "crates.io", "Packagist", "NuGet")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


@celery_app.task(name="guardian.sync_nvd")
def sync_nvd() -> dict:
    """Ingest CVEs modified since the last successful run."""
    client = NvdClient(api_key=os.getenv("GUARDIAN_NVD_API_KEY") or None)

    def fetch(since: dt.datetime, until: dt.datetime):  # noqa: ANN202
        from guardian_clients.feeds.nvd import windows  # noqa: PLC0415

        for start, end in windows(since, until):
            page_index = 0
            while True:
                page = client.fetch_page(start_index=page_index, modified_since=start,
                                         modified_until=end)
                yield from page.records
                if page.exhausted or not page.records:
                    break
                page_index = page.next_index

    return intel.run_source("nvd", fetch)


@celery_app.task(name="guardian.sync_osv")
def sync_osv(ecosystems: tuple[str, ...] = OSV_ECOSYSTEMS) -> dict:
    """Ingest package advisories per ecosystem.

    Each ecosystem is its own source, so a failure downloading npm does not roll back what PyPI
    already ingested and does not stop the ecosystems after it.
    """
    results = []
    for ecosystem in ecosystems:
        client = OsvClient()

        def fetch(_since, _until, _eco=ecosystem, _client=client):  # noqa: ANN001, ANN202
            # OSV publishes the whole corpus per ecosystem rather than a delta, so the watermark
            # records when it was last refreshed rather than filtering the request.
            return _client.fetch_ecosystem(_eco)

        results.append(intel.run_source(f"osv:{ecosystem}", fetch))

    failed = [r for r in results if r["status"] != "completed"]
    return {"sources": results, "failed": len(failed),
            "status": "completed" if not failed else "partial"}


@celery_app.task(name="guardian.sync_kev")
def sync_kev() -> dict:
    """Flag advisories CISA reports as actively exploited."""
    return _enrich("kev", lambda session: intel.apply_kev(session, KevClient().fetch()))


@celery_app.task(name="guardian.sync_epss")
def sync_epss() -> dict:
    """Attach exploit probabilities from the daily bulk file."""
    return _enrich("epss", lambda session: intel.apply_epss(session, EpssClient().fetch_all()))


def _enrich(source: str, apply) -> dict:  # noqa: ANN001
    """Run an enrichment source. Unlike ingestion these have no window — they refresh a flag or a
    score across the whole knowledge base — but they fail just as loudly."""
    started = _now()
    with session_scope() as session:
        state = intel.get_state(session, source)
        record = FeedSync(source=source, status="running", started_at=started)
        session.add(record)
        session.flush()
        state.last_attempt_at = started

        try:
            changed = apply(session)
        except FeedError as exc:
            return intel.record_failure(state, record, str(exc), source)
        except Exception as exc:  # noqa: BLE001
            return intel.record_failure(state, record, f"{type(exc).__name__}: {exc}", source)

        record.status = "completed"
        record.items_ingested = changed
        record.finished_at = _now()
        state.watermark = started
        state.last_success_at = started
        state.last_error = None
        state.consecutive_failures = 0
        log.info("feed_enrichment_complete", source=source, changed=changed)
        return {"source": source, "status": "completed", "changed": changed}


@celery_app.task(name="guardian.sync_feeds")
def sync_feeds() -> dict:
    """Refresh everything, ingestion before enrichment.

    Order matters: KEV and EPSS mark advisories that already exist, so running them first flags
    nothing and reports success — which is exactly how the previous implementation could report a
    healthy sync over an empty knowledge base.
    """
    results = [sync_nvd(), sync_osv(), sync_kev(), sync_epss()]
    failed = [r for r in results if r.get("status") not in {"completed", None}]
    status = "completed" if not failed else ("failed" if len(failed) == len(results) else "partial")
    log.info("feed_sync_all", status=status, failed=len(failed))
    return {"status": status, "results": results, "failed": len(failed)}
