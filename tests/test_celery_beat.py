"""The periodic scheduler (Celery beat) must actually run in production.

The full product audit's sole P0 was that beat was defined in the Celery app but launched by no
standing deployment, so recovery / feed-sync / webhook-retry / scheduled scans never fired. These
tests prove the fix is *usable*, not merely present:

  * every `beat_schedule` entry names a task that is really registered on the app (a typo'd task
    name would enqueue nothing) and routes to a queue a standing worker consumes (so something
    executes what beat publishes);
  * each deployment topology launches exactly ONE scheduler — the single Render worker embeds beat
    (`--beat`), the scalable compose workers do NOT (which would fire every job N times) and a
    dedicated `beat` service does.

They deliberately parse the real command structures and cross-check them against the registered
task set, rather than asserting a string exists in a file.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from guardian_scanner.celery_app import celery_app

_ROOT = Path(__file__).resolve().parents[1]

# The four periodic jobs the audit named, mapped to the task the beat entry must enqueue.
_EXPECTED = {
    "sweep-schedules": "guardian.sweep_schedules",
    "retry-webhook-deliveries": "guardian.sweep_webhook_deliveries",
    "recover-stranded-scans": "guardian.sweep_stranded_scans",
    "sync-vulnerability-feeds": "guardian.sync_feeds",
}


# ── the app + schedule are internally consistent and usable ─────────────────────────────────────
def test_celery_app_loads_and_default_queue_is_consumed():
    # The default queue must be the one the standing workers consume, or beat-published work sits
    # unrouted forever (Celery's built-in default is `celery`, which no worker reads).
    assert celery_app.conf.task_default_queue == "default"


def test_beat_schedule_contains_exactly_the_expected_periodic_jobs():
    schedule = celery_app.conf.beat_schedule or {}
    assert set(schedule) == set(_EXPECTED), (
        "beat_schedule drifted from the audited periodic-job set")
    for name, task in _EXPECTED.items():
        entry = schedule[name]
        assert entry["task"] == task
        assert isinstance(entry["schedule"], (int, float)) and entry["schedule"] > 0


def test_every_beat_task_is_a_registered_task():
    # A beat entry that names a task the app never registered enqueues nothing — the exact
    # "defined but never runs" shape. Registration is what proves the schedule is executable.
    # Tasks register when their modules import, which a worker does at boot by loading the app's
    # `include` list; import_default_modules() replicates exactly that step here.
    celery_app.loader.import_default_modules()
    for task in _EXPECTED.values():
        assert task in celery_app.tasks, f"beat task {task!r} is not registered on the app"


def test_every_beat_task_routes_to_a_queue_a_standing_worker_consumes():
    routes = celery_app.conf.task_routes or {}
    for task in _EXPECTED.values():
        queue = (routes.get(task) or {}).get("queue", celery_app.conf.task_default_queue)
        # All periodic jobs are control-plane DB work → the `default` queue that worker-default and
        # the single Render worker consume. If one were routed to recon/tools it would never run.
        assert queue == "default", f"{task} routes to {queue!r}, which no scheduler-fed worker reads"


def test_beat_state_file_is_pinned_to_a_writable_path():
    # PersistentScheduler needs a writable shelve; the project dir can be read-only (Render). A lost
    # file is safe (idempotent sweeps) but an unwritable one crashes beat at startup.
    fname = celery_app.conf.beat_schedule_filename
    assert fname and (fname.startswith("/tmp/") or fname.startswith("/var/"))  # noqa: S108


# ── exactly one scheduler per deployment topology ───────────────────────────────────────────────
def _services(compose_path: Path) -> dict:
    return (yaml.safe_load(compose_path.read_text()) or {}).get("services", {})


def _command_str(svc: dict) -> str:
    cmd = svc.get("command", "")
    return " ".join(cmd) if isinstance(cmd, list) else str(cmd)


def _is_celery(cmd: str, role: str) -> bool:
    return "celery" in cmd and "guardian_scanner.celery_app" in cmd and role in cmd.split()


def _assert_single_beat_service(compose_path: Path):
    services = _services(compose_path)
    beats = [n for n, s in services.items() if _is_celery(_command_str(s), "beat")]
    workers = [(n, _command_str(s)) for n, s in services.items()
               if _is_celery(_command_str(s), "worker")]
    # Exactly one dedicated beat service…
    assert len(beats) == 1, f"{compose_path.name}: expected 1 beat service, found {beats}"
    # …and no scalable worker embeds beat (would multiply every periodic job).
    for name, cmd in workers:
        assert "--beat" not in cmd and " -B" not in f" {cmd}", (
            f"{compose_path.name}: worker {name} embeds --beat; that duplicates the scheduler")


def test_prod_compose_runs_exactly_one_dedicated_beat():
    _assert_single_beat_service(_ROOT / "docker-compose.prod.yml")


def test_dev_compose_runs_exactly_one_dedicated_beat():
    _assert_single_beat_service(_ROOT / "docker-compose.yml")


def test_render_split_runs_exactly_one_scheduler_and_isolates_the_scan_plane():
    # The Render free tier now runs the stack across TWO free services (the capacity split): guardian-
    # api (infra/render/start.sh) runs the API + the control-plane worker (queue `default`) with the
    # single embedded scheduler, and guardian-scan (infra/render/start-scan-plane.sh) runs the
    # isolated scan-plane worker (queue `scan`) on its own instance. Embedding beat is still the one
    # correct scheduler and must sit on EXACTLY ONE worker across BOTH files, and the scan worker must
    # stay off guardian-api. This parses the real command structures, not a string in a file.
    start = (_ROOT / "infra/render/start.sh").read_text()
    scan = (_ROOT / "infra/render/start-scan-plane.sh").read_text()

    # guardian-api: exactly one embedded scheduler, on the control (default) worker; the scan worker
    # has MOVED off this instance, so start.sh must no longer run a `scan` queue worker.
    api_worker_lines = re.findall(r"celery[^\n]*\bworker\b[^\n]*", start)
    assert len([ln for ln in api_worker_lines if "--beat" in ln]) == 1, (
        "exactly one worker embeds --beat on guardian-api")
    assert "--queues default" in start, "start.sh must run the control-plane (default) worker"
    assert "--queues scan" not in start, (
        "the scan worker moved to guardian-scan (start-scan-plane.sh); start.sh must not run it")
    after_beat = start[start.index("worker --beat"):][:180]
    assert "--queues default" in after_beat, "the embedded scheduler must ride the default worker"

    # guardian-scan: runs exactly one celery worker, on the `scan` queue, embeds NO scheduler, and
    # never migrates or seeds (it is DB-less — running either would need a DB URL it must not hold).
    scan_worker_lines = re.findall(r"celery[^\n]*\bworker\b[^\n]*", scan)
    assert len(scan_worker_lines) == 1, "start-scan-plane.sh runs exactly one celery worker"
    assert "--queues scan" in scan, "start-scan-plane.sh must run the scan-plane worker"
    assert "--queues default" not in scan, "the scan plane consumes `scan`, never `default`"
    assert "--beat" not in scan, "the scan plane must not embed beat (guardian-api owns the schedule)"
    assert "alembic upgrade" not in scan and "guardian_api.seed" not in scan, (
        "the scan plane is DB-less: it must not migrate or seed")

    # Exactly ONE embedded scheduler across BOTH Render services, and no standalone beat process (a
    # `celery ... beat` line with no `worker`) in either file — that would double-schedule.
    both = start + "\n" + scan
    beat_workers = [ln for ln in re.findall(r"celery[^\n]*\bworker\b[^\n]*", both) if "--beat" in ln]
    assert len(beat_workers) == 1, (
        "exactly one embedded scheduler across guardian-api + guardian-scan")
    standalone_beat = [
        ln for ln in both.splitlines()
        if re.search(r"\bcelery\b", ln) and re.search(r"\bbeat\b", ln) and "worker" not in ln
    ]
    assert not standalone_beat, (
        f"no separate beat process alongside the embedded one: {standalone_beat}")
