"""Discovery operationalization unit tests (Phase 6C.1) — registration, routing, enqueue. No DB."""

from __future__ import annotations


def test_run_discovery_task_is_registered():
    """The regression this phase fixes: the task must be discoverable by a real worker via include."""
    from guardian_scanner.celery_app import celery_app

    celery_app.loader.import_default_modules()  # imports everything in `include`
    assert "guardian.run_discovery" in celery_app.tasks


def test_discovery_tasks_are_routed_to_their_planes():
    """6C.4: the DB orchestrator runs on `default`; only the DB-less probing step is on `recon`.

    (Pre-6C.4 this test asserted `run_discovery`→recon; the phase deliberately inverts that so the
    plane that touches untrusted network holds no DB — the orchestrator must be on the trusted plane.)
    """
    from guardian_scanner.celery_app import celery_app

    routes = celery_app.conf.task_routes or {}
    assert routes.get("guardian.run_discovery", {}).get("queue") == "default"
    assert routes.get("guardian.recon_collect", {}).get("queue") == "recon"
    # Scans stay on the default queue (no explicit route).
    assert "guardian.run_scan" not in routes


def test_recon_collect_task_is_registered():
    from guardian_scanner.celery_app import celery_app

    celery_app.loader.import_default_modules()
    assert "guardian.recon_collect" in celery_app.tasks


def test_enqueue_discovery_sends_named_task(monkeypatch):
    import guardian_api.publisher as pub

    captured = {}

    class _FakeClient:
        def send_task(self, name, args=None, queue=None, **_):  # noqa: ANN001, ANN003
            captured.update(name=name, args=args, queue=queue)

    monkeypatch.setattr(pub, "_client", lambda: _FakeClient())
    pub.enqueue_discovery("run-123")

    assert captured["name"] == "guardian.run_discovery"   # by name → API stays decoupled from worker
    assert captured["args"] == ["run-123"]
    # 6C.4: no forced queue — task_routes sends the orchestrator to `default` (the trusted plane).
    assert captured["queue"] is None
