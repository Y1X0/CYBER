"""Celery application. Redis is the broker + result backend (ADR-003)."""

from __future__ import annotations

from celery import Celery
from guardian_common.config import get_settings

settings = get_settings()

celery_app = Celery(
    "guardian",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["guardian_scanner.tasks", "guardian_scanner.feeds", "guardian_scanner.analysis"],
)

celery_app.conf.update(
    task_acks_late=True,  # redeliver on worker crash; tasks are idempotent
    task_reject_on_worker_lost=True,
    task_track_started=True,
    task_time_limit=1800,  # hard cap per scan job (sandbox resource control)
    task_soft_time_limit=1500,
    worker_max_tasks_per_child=50,
    result_expires=3600,
)
