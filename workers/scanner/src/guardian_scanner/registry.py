"""Plugin registry — discovers scanner engines via entry points (doc 07 §4).

First-party and third-party engines register identically under the
``guardian.scanner_plugins`` entry-point group, so adding an engine never edits the core.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.metadata import entry_points

from guardian_core.enums import EngineKey

from guardian_scanner.engines.base import ScanEngine

_GROUP = "guardian.scanner_plugins"


@lru_cache
def _load() -> dict[str, ScanEngine]:
    engines: dict[str, ScanEngine] = {}
    for ep in entry_points(group=_GROUP):
        cls = ep.load()
        instance = cls()
        if not isinstance(instance, ScanEngine):
            raise TypeError(f"Plugin '{ep.name}' does not implement ScanEngine")
        engines[instance.key.value] = instance
    return engines


def available_engines() -> dict[str, ScanEngine]:
    """All discovered engines keyed by EngineKey value."""
    return dict(_load())


def get_engine(key: str | EngineKey) -> ScanEngine | None:
    value = key.value if isinstance(key, EngineKey) else key
    return _load().get(value)


def health_report() -> dict:
    """Every engine's readiness, and whether the runtime as a whole can be trusted to scan.

    This exists because of a specific failure mode: an engine whose external tool is missing
    degrades to producing no findings, and a scan with no findings is indistinguishable from a
    clean result. The deployed image shipped without semgrep for exactly this reason — the SAST
    engine reported success and quietly contributed nothing.

    So an engine that cannot do its job is an unhealthy runtime, surfaced at container start
    rather than discovered when a customer asks why a report is empty.
    """
    engines: dict[str, dict] = {}
    failed: list[str] = []
    degraded: list[str] = []
    missing_tools: set[str] = set()
    for key, engine in sorted(available_engines().items()):
        try:
            health = engine.health()
            ok, detail = bool(health.ok), str(health.detail)
            is_degraded = bool(getattr(health, "degraded", False))
            missing = tuple(getattr(health, "missing", ()) or ())
        except Exception as exc:  # noqa: BLE001 - a broken engine must not break the report
            ok, detail, is_degraded, missing = False, f"{type(exc).__name__}: {exc}"[:200], True, ()
        engines[key] = {"ok": ok, "degraded": is_degraded, "detail": detail,
                        "missing": list(missing), "version": getattr(engine, "version", "?")}
        if not ok:
            failed.append(key)
        if is_degraded:
            degraded.append(key)
        missing_tools.update(missing)
    # `ok` means the runtime can scan; degradation is reported without failing a container that is
    # legitimately running the builtin-only configuration (CI, offline, air-gapped).
    return {"ok": not failed, "failed": failed, "degraded": degraded,
            "missing_tools": sorted(missing_tools), "engines": engines, "count": len(engines)}
