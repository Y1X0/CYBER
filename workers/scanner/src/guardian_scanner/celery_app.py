"""Celery application. Redis is the broker + result backend (ADR-003)."""

from __future__ import annotations

import os

from celery import Celery
from celery.signals import worker_init, worker_process_init
from guardian_common.config import get_settings

settings = get_settings()

# The tool plane's concurrency, resolved in the MainProcess and passed to prefork children via the
# environment. worker_ready fires AFTER the pool forks, so a child that runs `run_tool` would never
# see a value set there and its uid_nft guard would fail-close every live run; worker_init fires
# BEFORE the fork (verified), so the value is captured there and re-applied in each child.
_TOOL_CONCURRENCY_ENV = "_GUARDIAN_TOOL_WORKER_CONCURRENCY"


@worker_init.connect
def _tool_worker_init(sender=None, **_kwargs) -> None:  # noqa: ANN001, ANN003
    """MainProcess init, BEFORE the prefork pool forks its children. Resolve THIS tool-plane
    worker's actual concurrency and (a) stash it in the environment so every child inherits the real
    value, (b) apply it locally for non-forking pools (solo/threads) and MainProcess-run tasks, and
    (c) reap nft tables orphaned by a crashed run."""
    if not get_settings().tool_plane:
        return
    from guardian_scanner.tools.backends import uid_nft
    conc = uid_nft.detect_concurrency(sender, celery_app.conf.worker_concurrency)
    if conc is not None:
        os.environ[_TOOL_CONCURRENCY_ENV] = str(conc)
    uid_nft.set_worker_concurrency(conc)
    uid_nft.reap_orphans()


@worker_process_init.connect
def _tool_worker_child_init(**_kwargs) -> None:  # noqa: ANN003
    """Each prefork CHILD at startup (the process that actually runs `run_tool`): adopt the
    concurrency the MainProcess resolved, read from the inherited environment — so the uid_nft
    single-allocator guard sees the real value, not None (which would fail-close every live run)."""
    if not get_settings().tool_plane:
        return
    from guardian_scanner.tools.backends import uid_nft
    raw = os.environ.get(_TOOL_CONCURRENCY_ENV)
    uid_nft.set_worker_concurrency(int(raw) if raw and raw.lstrip("-").isdigit() else None)

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
        # The sweep that turns tenant schedules into queued work (WP-A3).
        "guardian_scanner.scheduling",
        # Discovered service version → advisory → finding (WP-C3). Registered here or the task
        # exists and is unreachable from a real worker, which is how 6B/6C stayed test-only.
        "guardian_scanner.service_cve",
        # Cross-engine correlation (WP-E1).
        "guardian_scanner.correlation",
        # Validation and retest (WP-E2).
        "guardian_scanner.verification",
        # Domain ownership verification (WP-F1).
        "guardian_scanner.ownership",
        # Outbound webhook delivery (WP-G3). A customer's slow endpoint must never hold up a scan,
        # which is why this is a queue rather than a call.
        "guardian_scanner.webhooks",
    ],
)

celery_app.conf.update(
    # Unrouted tasks (run_scan, analyze_scan, enrich_graph) publish to the DEFAULT queue, and the
    # workers consume `default`. Celery's built-in default queue is `celery`, which no worker
    # consumes — so API-triggered scans would never run. Pin the default queue to `default`.
    # (task_routes below still pins the plane-isolated tasks to their own queues.)
    task_default_queue="default",
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
        "guardian.sweep_schedules": {"queue": "default"},
        "guardian.sync_feeds": {"queue": "default"},
        "guardian.sync_nvd": {"queue": "default"},
        "guardian.sync_osv": {"queue": "default"},
        "guardian.sync_kev": {"queue": "default"},
        "guardian.sync_epss": {"queue": "default"},
        "guardian.sync_exploits": {"queue": "default"},
        "guardian.match_service_versions": {"queue": "default"},
        "guardian.correlate_findings": {"queue": "default"},
        "guardian.retest_finding": {"queue": "default"},
        "guardian.check_domain_verification": {"queue": "default"},
        "guardian.deliver_webhook": {"queue": "default"},
        "guardian.sweep_webhook_deliveries": {"queue": "default"},
    },
    # Recurring work. Beat fires these; per-tenant cadence lives in the `schedules` table, because
    # a static config file cannot be edited through the API and cannot hold one customer's timing
    # separately from another's.
    beat_schedule={
        "sweep-schedules": {
            "task": "guardian.sweep_schedules",
            # Every five minutes. The sweep is cheap (one indexed query) and this bounds how late
            # a schedule can fire to well under the shortest cadence the table permits.
            "schedule": 300.0,
        },
        "retry-webhook-deliveries": {
            "task": "guardian.sweep_webhook_deliveries",
            # Every minute: the shortest retry backoff is 60 seconds, and a sweep slower than the
            # backoff turns "retry in a minute" into "retry whenever the sweep next runs".
            "schedule": 60.0,
        },
        "sync-vulnerability-feeds": {
            "task": "guardian.sync_feeds",
            # Daily. Ingestion is incremental (`feed_state` holds a watermark per source), so this
            # fetches the day's changes rather than the corpus; KEV and EPSS publish daily, and a
            # fresher pull would spend rate limit without changing an answer.
            "schedule": 86400.0,
        },
    },
    # Beat's own bookkeeping. Without a persistent schedule file a restarted beat re-fires
    # everything it thinks it missed.
    beat_max_loop_interval=60,
)
