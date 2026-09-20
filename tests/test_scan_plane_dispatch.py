"""On-demand provisioning of the external GitHub Actions scan plane.

ensure_scan_plane_running() is what turns the operator flow into "open console, enter URL": when a
scan is claimed and engines are offloaded, it triggers the guardian-scan-plane workflow so the runner
spins up on its own. These tests prove it (a) does nothing unless it is both enabled and given a
token, (b) triggers the workflow when no run is active, (c) does NOT pile on when one already is, and
(d) never raises — a dispatch problem must never fail a scan.
"""

from __future__ import annotations

import json
import urllib.request

import pytest
from guardian_common import scan_plane_dispatch
from guardian_common.config import get_settings


class _Resp:
    def __init__(self, body: bytes = b""):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def read(self) -> bytes:
        return self._body


def _install(monkeypatch, *, active: bool, calls: list):
    """Fake api.github.com: GET runs reports active/idle, POST dispatches records the call."""
    def fake_urlopen(req, timeout=None):  # noqa: ANN001, ANN202
        calls.append((req.get_method(), req.full_url))
        if req.get_method() == "GET":
            return _Resp(json.dumps({"total_count": 1 if active else 0}).encode())
        return _Resp(b"")
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)


def _configure(monkeypatch, *, external: bool, token: str) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "external_scan_plane", external, raising=False)
    monkeypatch.setattr(s, "github_dispatch_token", token, raising=False)
    monkeypatch.setattr(s, "github_repo", "Y1X0/CYBER", raising=False)
    monkeypatch.setattr(s, "scan_plane_workflow_file", "guardian-scan-plane.yml", raising=False)
    monkeypatch.setattr(s, "scan_plane_workflow_ref", "main", raising=False)
    monkeypatch.setattr(s, "scan_plane_window_minutes", 30, raising=False)


def test_noop_without_a_token(monkeypatch):
    # Enabled but no token → the safe default is to do nothing (and touch the network not at all).
    calls: list = []
    _install(monkeypatch, active=False, calls=calls)
    _configure(monkeypatch, external=True, token="")
    scan_plane_dispatch.ensure_scan_plane_running()
    assert calls == []


def test_noop_when_not_external(monkeypatch):
    # A token but in-instance mode (a local consumer exists) → don't dispatch a redundant runner.
    calls: list = []
    _install(monkeypatch, active=False, calls=calls)
    _configure(monkeypatch, external=False, token="ghp_x")
    scan_plane_dispatch.ensure_scan_plane_running()
    assert calls == []


def test_dispatches_the_workflow_when_idle(monkeypatch):
    calls: list = []
    _install(monkeypatch, active=False, calls=calls)
    _configure(monkeypatch, external=True, token="ghp_x")
    scan_plane_dispatch.ensure_scan_plane_running()
    methods = [m for m, _ in calls]
    urls = [u for _, u in calls]
    assert "POST" in methods, "an idle scan plane must be dispatched"
    assert any(u.endswith("/actions/workflows/guardian-scan-plane.yml/dispatches") for u in urls)


def test_does_not_dispatch_when_a_run_is_active(monkeypatch):
    # A consumer is already (about to be) up → check only, never POST a second run.
    calls: list = []
    _install(monkeypatch, active=True, calls=calls)
    _configure(monkeypatch, external=True, token="ghp_x")
    scan_plane_dispatch.ensure_scan_plane_running()
    assert all(m == "GET" for m, _ in calls), "must not dispatch while a run is active"
    assert calls, "it should have checked for an active run"


def test_never_raises_on_a_network_error(monkeypatch):
    _configure(monkeypatch, external=True, token="ghp_x")

    def boom(req, timeout=None):  # noqa: ANN001, ANN202
        raise OSError("github unreachable")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    # Must swallow — a dispatch problem only means the scan waits for a manual window.
    scan_plane_dispatch.ensure_scan_plane_running()


def test_dispatch_payload_carries_ref_and_window(monkeypatch):
    # The workflow_dispatch body must name the ref and the window length the workflow expects.
    captured: dict = {}

    def fake_urlopen(req, timeout=None):  # noqa: ANN001, ANN202
        if req.get_method() == "GET":
            return _Resp(json.dumps({"total_count": 0}).encode())
        captured["body"] = json.loads(req.data.decode())
        return _Resp(b"")
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    _configure(monkeypatch, external=True, token="ghp_x")

    scan_plane_dispatch.ensure_scan_plane_running()
    assert captured["body"]["ref"] == "main"
    assert captured["body"]["inputs"]["minutes"] == "30"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
