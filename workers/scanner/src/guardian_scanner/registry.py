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
