"""Prefork concurrency correctness (P1-2 follow-up) — REAL worker/process lifecycle, not a mock.

Regression guard for the defect where uid_nft's single-allocator concurrency was set in `worker_ready`
(MainProcess only). Under Celery prefork the child that actually runs `run_tool` is forked BEFORE
worker_ready fires, so its `_worker_concurrency` stayed None and `_assert_single_allocator()` raised
"concurrency unknown" — silently fail-closing EVERY live external-binary scan.

This starts a genuine prefork worker (GUARDIAN_TOOL_PLANE=true) and runs a task in the forked child,
asserting the child observes the real concurrency the MainProcess resolved (1 and 2), so the guard
sees a value instead of None. Combined with the unit guard tests (1 → allowed, >1/None → fail closed),
this proves the whole chain: prefork child sees the correct value; concurrency=1 permits execution;
concurrency>1 still fails closed.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires local Redis + worker spawning"
)

_HELPER = """
from guardian_scanner.celery_app import celery_app


@celery_app.task(name="test.observe_tool_concurrency")
def observe_tool_concurrency():
    # Runs IN THE PREFORK CHILD. Report what the child's uid_nft guard would see.
    import os
    from guardian_scanner.tools.backends import uid_nft
    return {"concurrency": uid_nft._worker_concurrency, "pid": os.getpid()}
"""


def _redis_up(url: str) -> bool:
    import redis  # dependency already present

    try:
        redis.Redis.from_url(url).ping()
        return True
    except Exception:  # noqa: BLE001
        return False


@pytest.mark.parametrize("concurrency", [1, 2])
def test_prefork_child_observes_resolved_concurrency(tmp_path, concurrency):
    redis_url = os.environ.get("GUARDIAN_REDIS_URL", "redis://localhost:6379/0")
    if not _redis_up(redis_url):
        pytest.skip("no reachable Redis broker")

    # Helper task module the spawned worker will import via -I (needs to be on PYTHONPATH).
    (tmp_path / "toolconc_probe.py").write_text(_HELPER)

    env = dict(os.environ)
    env["GUARDIAN_TOOL_PLANE"] = "true"          # exercise the tool-plane startup hooks
    env["GUARDIAN_ENV"] = "ci"
    env["GUARDIAN_REDIS_URL"] = redis_url
    env["PYTHONPATH"] = str(tmp_path) + os.pathsep + env.get("PYTHONPATH", "")

    worker = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "celery", "-A", "guardian_scanner.celery_app.celery_app", "worker",
         "-P", "prefork", "--concurrency", str(concurrency), "-Q", "celery",
         "-I", "toolconc_probe", "--loglevel=error", "--without-gossip", "--without-mingle",
         "--without-heartbeat"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        from guardian_scanner.celery_app import celery_app

        deadline = time.time() + 45
        result = None
        last_exc = None
        while time.time() < deadline:
            if worker.poll() is not None:  # worker died — surface its log
                raise AssertionError(f"worker exited early:\n{worker.stdout.read()}")
            try:
                async_res = celery_app.send_task("test.observe_tool_concurrency", queue="celery")
                result = async_res.get(timeout=5)
                break
            except Exception as exc:  # noqa: BLE001 - worker still booting; retry until deadline
                last_exc = exc
                time.sleep(1)
        assert result is not None, f"no result before deadline (last error: {last_exc})"

        # The task ran in a forked child that saw the MainProcess-resolved concurrency — NOT None.
        assert result["concurrency"] == concurrency, (
            f"prefork child saw concurrency={result['concurrency']!r}, expected {concurrency}")
        assert result["pid"] != os.getpid()          # genuinely a separate worker process
    finally:
        worker.terminate()
        try:
            worker.wait(timeout=10)
        except subprocess.TimeoutExpired:
            worker.kill()
