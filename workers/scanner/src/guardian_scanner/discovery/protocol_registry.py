"""Protocol-probe registry — entry-point discovery, same pattern as the other registries.

Probes register under ``guardian.protocol_probes``, so a new protocol (SSH, a database, …) plugs in
by shipping a probe + an entry point — no change to the orchestrator or the core.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.metadata import entry_points

from guardian_common.ports import ProtocolProbe

_GROUP = "guardian.protocol_probes"


@lru_cache
def _load() -> dict[str, ProtocolProbe]:
    probes: dict[str, ProtocolProbe] = {}
    for ep in entry_points(group=_GROUP):
        instance = ep.load()()
        if not isinstance(instance, ProtocolProbe):
            raise TypeError(f"Protocol plugin '{ep.name}' does not implement ProtocolProbe")
        probes[instance.key] = instance
    return probes


def available_protocol_probes() -> dict[str, ProtocolProbe]:
    """All registered probes keyed by their `key` (e.g. {'http': ..., 'tls': ...})."""
    return dict(_load())


def probe_for(port: int) -> ProtocolProbe | None:
    """The probe that serves this port, or None. First match wins (ports are disjoint today)."""
    for probe in _load().values():
        if port in probe.ports:
            return probe
    return None


def probed_ports() -> tuple[int, ...]:
    """The full, data-driven set of ports any registered probe serves (80/443 in 6C.2)."""
    ports: set[int] = set()
    for probe in _load().values():
        ports.update(probe.ports)
    return tuple(sorted(ports))
