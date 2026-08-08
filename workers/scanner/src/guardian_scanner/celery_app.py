"""Celery application. Redis is the broker + result backend (ADR-003)."""

from __future__ import annotations

from celery import Celery
from guardian_common.config import get_settings

settings = get_settings()

celery_app = Celery(
    "guardian",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "guardian_scanner.tasks",
        "guardian_scanner.feeds",
        "guardian_scanner.analysis",
        # Register the discovery orchestration task so a real worker can execute it — previously it
        # existed but was never registered, so 6B/6C were runnable only from tests (6C.1 fix).
        "guardian_scanner.discovery.tasks",
    ],
)

celery_app.conf.update(
    task_acks_late=True,  # redeliver on worker crash; tasks are idempotent
    task_reject_on_worker_lost=True,
    task_track_started=True,
    task_time_limit=1800,  # hard cap per scan job (sandbox resource control)
    task_soft_time_limit=1500,
    worker_max_tasks_per_child=50,
    result_expires=3600,
    # Isolate active/passive discovery on its own queue (`recon`), separate from scan/analysis work
    # on `default`. This is the first step toward a dedicated recon execution plane (6C.3).
    task_routes={"guardian.run_discovery": {"queue": "recon"}},
)
