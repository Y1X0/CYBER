"""Celery application. Redis is the broker + result backend (ADR-003)."""

from __future__ import annotations

from celery import Celery
from celery.signals import worker_ready
from guardian_common.config import get_settings

settings = get_settings()


@worker_ready.connect
def _reap_isolation_orphans(**_kwargs) -> None:  # noqa: ANN003
    """On tool-plane startup, delete nft egress tables orphaned by a crashed run."""
    if not get_settings().tool_plane:
        return
    from guardian_scanner.tools.backends.uid_nft import reap_orphans
    reap_orphans()

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
        # Security Tool Framework (Phase 1): dispatch (trusted) + run_tool (execution plane).
        "guardian_scanner.tools.tasks",
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
    # Execution-plane split (6C.4). The DB-bound orchestrator (`run_discovery`: authorize + persist)
    # runs on `default`; only the DB-less probing step (`recon_collect`) runs on the `recon` plane.
    # Keeping them on separate queues is what lets the recon worker hold no DB credentials.
    task_routes={
        "guardian.run_discovery": {"queue": "default"},
        "guardian.recon_collect": {"queue": "recon"},
        # Tool framework: the DB-less execution step runs on the isolated `tools` plane; the trusted
        # dispatcher (authorize/scope/policy/persist) stays on `default`.
        "guardian.dispatch_tool_job": {"queue": "default"},
        "guardian.dispatch_artifact_job": {"queue": "default"},
        "guardian.run_tool": {"queue": "tools"},
    },
)
