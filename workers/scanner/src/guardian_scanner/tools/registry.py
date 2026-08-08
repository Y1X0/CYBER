"""Capability registry (Framework Phase 1) — tools plug in via entry points, no core change.

A tool registers under ``guardian.tool_providers``; the registry exposes it AND its declared
`ToolCapabilities`, so the policy engine can decide "this tool is not allowed in this
context" BEFORE a job ever reaches the execution plane. No tool ships in Phase 1 — this is the seam.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.metadata import entry_points

from guardian_common.ports import ToolProvider

_GROUP = "guardian.tool_providers"


@lru_cache
def _load() -> dict[str, ToolProvider]:
    providers: dict[str, ToolProvider] = {}
    for ep in entry_points(group=_GROUP):
        instance = ep.load()()
        if not isinstance(instance, ToolProvider):
            raise TypeError(f"Tool provider '{ep.name}' does not implement ToolProvider")
        providers[instance.key] = instance
    return providers


def available_tool_providers() -> dict[str, ToolProvider]:
    """All registered tool providers keyed by `key` (empty until a provider ships)."""
    return dict(_load())


def tool_for(key: str) -> ToolProvider | None:
    return _load().get(key)


def capabilities_for(key: str):  # noqa: ANN201
    """The declared capabilities of a tool, or None if unknown — the policy engine's input."""
    provider = _load().get(key)
    return provider.capabilities if provider is not None else None
