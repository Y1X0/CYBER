"""Control-plane isolation tests (Phase 6C.3) — the API opens no external sockets, imports no worker.

The control plane's only seam to execution is `send_task` by task NAME (ADR-003): it enqueues work
and returns. It must never import the worker package (which owns sockets, the sandbox, and active
recon), so it can neither run a probe in-process nor reach the recon plane. Proven in a clean
subprocess so the assertion isn't fooled by modules another test already imported.
"""

from __future__ import annotations

import subprocess
import sys


def test_control_plane_does_not_import_worker():
    code = (
        "import sys\n"
        "import guardian_api.main\n"
        "import guardian_api.publisher\n"
        "leaked = [m for m in sys.modules if m.startswith('guardian_scanner')]\n"
        "assert not leaked, f'control plane imported the worker: {leaked}'\n"
        "print('ok')\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=120
    )
    assert out.returncode == 0, f"stdout={out.stdout!r} stderr={out.stderr!r}"
    assert "ok" in out.stdout


def test_publisher_dispatches_discovery_by_task_name():
    """The API enqueues discovery by name onto the recon queue — no worker import, no socket here."""
    import inspect

    from guardian_api import publisher

    src = inspect.getsource(publisher.enqueue_discovery)
    assert 'send_task("guardian.run_discovery"' in src  # by NAME, not an imported task object
    assert 'queue="recon"' in src                        # routed to the isolated recon plane
    assert "guardian_scanner" not in inspect.getsource(publisher)  # no worker import anywhere
