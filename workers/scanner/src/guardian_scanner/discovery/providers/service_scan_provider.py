"""Active service-scan orchestrator (Phase 6C.2) — the platform's first *active* discovery.

The orchestrator owns *what* to probe (authorized targets × registered ports) and turns evidence
into graph nodes/edges. It owns NO protocol knowledge: HTTP/TLS lives in `ProtocolProbe` plugins
(`guardian.protocol_probes`), dispatched by port via the protocol registry. Adding a protocol later
(SSH, a database) is a new probe + entry point — no change here or in core.

Scope stays frozen at what the probes register (80/443 in 6C.2); it probes only
`ctx.authorized_targets` (the set the authorization gate already cleared) and never sends payloads.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from guardian_core.discovery import DiscoveredAsset, DiscoveredEdge, DiscoveryContext
from guardian_core.enums import DiscoverySource, EdgeRelation, NodeType

from guardian_scanner.discovery.protocol_registry import probe_for, probed_ports

_TIMEOUT = 4  # seconds per connection, matching the pre-6C.2 behavior


def _host_node_type(host: str) -> NodeType:
    try:
        ipaddress.ip_address(host)
        return NodeType.IP_ADDRESS
    except ValueError:
        return NodeType.SUBDOMAIN


class ServiceScanProvider:
    key = "service_scan"
    requires_authorization = True

    def collect(self, ctx: DiscoveryContext) -> Iterable[DiscoveredAsset]:
        snapshot: dict = ctx.settings.get("service_scan", {})
        allow_live = bool(ctx.settings.get("allow_live"))
        for target in ctx.authorized_targets:  # ONLY pre-authorized targets, never raw seeds
            host = target.split(":")[0]
            host_type = _host_node_type(host)
            host_snap = snapshot.get(host)
            offline = host_snap is not None  # a snapshotted host is never probed live (unchanged)
            for port in probed_ports():
                probe = probe_for(port)
                if probe is None:
                    continue
                if offline:
                    port_snap = host_snap.get(str(port)) or host_snap.get(port)
                    evidence = probe.probe(host, port, timeout=_TIMEOUT,
                                           allow_live=False, snapshot=port_snap)
                else:
                    evidence = probe.probe(host, port, timeout=_TIMEOUT,
                                           allow_live=allow_live, snapshot=None)
                if evidence is None:
                    continue  # closed/unreachable → nothing observed
                service_key = f"{host}:{port}"
                attrs = {"port": port, "internet_reachable": True, **evidence.attributes}
                # The service node, carrying the evidence the probe observed.
                yield DiscoveredAsset(
                    node_type=NodeType.SERVICE, canonical_key=service_key,
                    source=DiscoverySource.PORT_SCAN, confidence=evidence.confidence,
                    ownership_confidence=90, attributes=attrs,
                )
                # The host --hosts--> service edge (host is the source; it hosts the service).
                yield DiscoveredAsset(
                    node_type=host_type, canonical_key=host,
                    source=DiscoverySource.PORT_SCAN, confidence=90, ownership_confidence=90,
                    edges=[DiscoveredEdge(
                        relation=EdgeRelation.HOSTS, dst_type=NodeType.SERVICE,
                        dst_key=service_key, confidence=95,
                    )],
                )
