"""Test harness configuration.

Phase 6C.4 splits discovery into two tasks across two planes (`run_discovery` on the DB plane
dispatches `recon_collect` on the recon plane). In the test process there is a single worker, so we
run Celery eagerly: `run_discovery.apply(...)` executes, and its `recon_collect.apply_async(...)`
sub-task runs inline in the same call. This keeps every existing 6C/6D test unchanged — it is harness
configuration, not a test edit. The plane-pinning guard (`_enforce_plane`) is a deployment property
and is intentionally skipped under eager mode; it is tested directly instead.
"""

from __future__ import annotations

from guardian_scanner.celery_app import celery_app

celery_app.conf.task_always_eager = True
celery_app.conf.task_eager_propagates = True
