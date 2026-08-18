"""Runtime engine health, and the difference between broken and degraded.

An engine whose external tool is missing returns fewer findings and still reports success. To a
customer an empty result and a clean result look identical, so the difference has to be visible at
the runtime level rather than inferred from a report nobody can calibrate.

This is not hypothetical: the deployed image shipped without semgrep, so the SAST engine reported
healthy while contributing 13 regex rules instead of thousands, and nothing said so.
"""

from __future__ import annotations

import importlib

import pytest
from guardian_scanner.engines.base import EngineHealth
from guardian_scanner.engines.sast_engine import SastEngine
from guardian_scanner.registry import available_engines, health_report


def test_every_registered_engine_reports_health():
    report = health_report()
    assert report["count"] == len(available_engines())
    for key, entry in report["engines"].items():
        assert isinstance(entry["ok"], bool), key
        assert entry["detail"], f"{key} reports no detail"


def test_runtime_is_ok_when_no_engine_has_failed():
    """Degraded is not failed: a builtin-only configuration is legitimate in CI and air-gapped
    deployments, and must not crash a container that can genuinely scan."""
    report = health_report()
    assert report["ok"] is (not report["failed"])


def test_missing_tool_is_reported_as_degraded_not_healthy(monkeypatch):
    monkeypatch.setattr("guardian_scanner.engines.sast_engine.shutil.which", lambda _n: None)
    health = SastEngine().health()
    assert health.ok is True             # the builtin rules still run
    assert health.degraded is True       # but this is not full capability
    assert "semgrep" in health.missing
    assert "semgrep absent" in health.detail


def test_present_tool_clears_the_degraded_flag(monkeypatch):
    monkeypatch.setattr("guardian_scanner.engines.sast_engine.shutil.which",
                        lambda _n: "/usr/local/bin/semgrep")
    health = SastEngine().health()
    assert health.degraded is False
    assert health.missing == ()


def test_report_aggregates_the_tools_an_image_is_missing(monkeypatch):
    monkeypatch.setattr("guardian_scanner.engines.sast_engine.shutil.which", lambda _n: None)
    report = health_report()
    assert "sast" in report["degraded"]
    assert "semgrep" in report["missing_tools"]


def test_an_engine_that_raises_is_failed_not_silently_skipped(monkeypatch):
    class _Broken:
        key = type("K", (), {"value": "broken"})()
        version = "0"

        def health(self):
            raise RuntimeError("tool binary is corrupt")

    monkeypatch.setattr("guardian_scanner.registry.available_engines",
                        lambda: {"broken": _Broken()})
    report = health_report()
    assert report["ok"] is False
    assert "broken" in report["failed"]
    assert "RuntimeError" in report["engines"]["broken"]["detail"]


@pytest.mark.parametrize("field,default", [("degraded", False), ("missing", ())])
def test_health_defaults_keep_existing_engines_valid(field, default):
    """Engines written before degradation existed must still construct."""
    assert getattr(EngineHealth(ok=True, detail="x"), field) == default


def test_every_declared_scanner_plugin_resolves():
    """A typo in an entry-point path is invisible until deploy: the engine simply never loads, the
    scan reports fewer findings, and nothing says why. Assert the declarations import."""
    import tomllib
    from pathlib import Path

    pyproject = tomllib.loads(Path("pyproject.toml").read_text())
    declared = pyproject["project"]["entry-points"]["guardian.scanner_plugins"]
    assert declared, "no scanner plugins declared"

    for key, target in declared.items():
        module_path, _, class_name = target.partition(":")
        module = importlib.import_module(module_path)
        engine = getattr(module, class_name)()
        assert engine.key.value == key, f"{key} declares an engine whose key is {engine.key.value}"
        assert engine.health().ok is not None
