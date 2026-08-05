"""Discovery-provider registry — entry-point discovery, identical pattern to the scanner registry.

Providers register under the ``guardian.discovery_providers`` group, so a new collector (Shodan, an
internal CMDB) plugs in without editing the core or the pipeline.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.metadata import entry_points

from guardian_common.ports import DiscoveryProvider

_GROUP = "guardian.discovery_providers"


@lru_cache
def _load() -> dict[str, DiscoveryProvider]:
    providers: dict[str, DiscoveryProvider] = {}
    for ep in entry_points(group=_GROUP):
        instance = ep.load()()
        if not isinstance(instance, DiscoveryProvider):
            raise TypeError(f"Discovery plugin '{ep.name}' does not implement DiscoveryProvider")
        providers[instance.key] = instance
    return providers


def available_providers() -> dict[str, DiscoveryProvider]:
    """All discovered providers keyed by their `key`."""
    return dict(_load())


def get_provider(key: str) -> DiscoveryProvider | None:
    return _load().get(key)
