"""Job publisher — the API's single seam for enqueuing work.

Uses a lightweight Celery client that dispatches by task NAME, so the API service does not import
the worker package (services stay independently deployable; ADR-003).
"""

from __future__ import annotations

from functools import lru_cache

from celery import Celery
from guardian_common.config import get_settings


@lru_cache
def _client() -> Celery:
    settings = get_settings()
    return Celery("guardian-api", broker=settings.redis_url, backend=settings.redis_url)


def enqueue_scan(scan_id: str) -> None:
    _client().send_task("guardian.run_scan", args=[scan_id])


def enqueue_analysis(scan_id: str) -> None:
    _client().send_task("guardian.analyze_scan", args=[scan_id])


def enqueue_discovery(run_id: str) -> None:
    # The trusted orchestrator runs on `default` (it authorizes + persists in the DB plane); it then
    # dispatches only the DB-less probing step to the isolated `recon` plane (6C.4). Routing is by
    # task name via task_routes, so the API stays a pure publisher (ADR-003).
    _client().send_task("guardian.run_discovery", args=[run_id])
