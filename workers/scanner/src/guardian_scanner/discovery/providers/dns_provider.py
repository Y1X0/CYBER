"""DNS discovery provider (Phase 6B) — passive resolution of hosts to IPs.

Resolves each seed host (and any subdomains passed in) to its A/AAAA records, producing ip_address
nodes and `resolves_to` edges. Passive → no authorization. Flags public reachability from whether
resolved IP is globally routable, and a dangling record (a name that no longer resolves) as a
subdomain-takeover signal.

Offline-first: reads `ctx.settings["dns"]` ({host: [ips]}) for deterministic CI. A live resolver
slots in behind the same interface when `ctx.settings["allow_live"]` is set.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from guardian_core.discovery import DiscoveredAsset, DiscoveredEdge, DiscoveryContext
from guardian_core.enums import DiscoverySource, EdgeRelation, NodeType


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


class DnsProvider:
    key = "dns"
    requires_authorization = False

    def collect(self, ctx: DiscoveryContext) -> Iterable[DiscoveredAsset]:
        snapshot: dict = ctx.settings.get("dns", {})
        hosts = list(ctx.seeds.get("domains", [])) + list(ctx.seeds.get("hosts", []))
        for host in hosts:
            ips = snapshot.get(host, [])
            if not ips:
                # A seed host that resolves to nothing — a dangling record (takeover candidate).
                yield DiscoveredAsset(
                    node_type=NodeType.SUBDOMAIN, canonical_key=host,
                    source=DiscoverySource.DNS_RESOLVER, confidence=70, ownership_confidence=80,
                    attributes={"public_dns": True, "dangling_dns": True},
                )
                continue
            public = any(_is_public(ip) for ip in ips)
            yield DiscoveredAsset(
                node_type=NodeType.SUBDOMAIN, canonical_key=host,
                source=DiscoverySource.DNS_RESOLVER, confidence=90, ownership_confidence=85,
                attributes={"public_dns": True, "internet_reachable": public},
                edges=[
                    DiscoveredEdge(relation=EdgeRelation.RESOLVES_TO,
                                   dst_type=NodeType.IP_ADDRESS, dst_key=ip, confidence=90)
                    for ip in ips
                ],
            )
            for ip in ips:
                yield DiscoveredAsset(
                    node_type=NodeType.IP_ADDRESS, canonical_key=ip,
                    source=DiscoverySource.DNS_RESOLVER, confidence=90,
                    ownership_confidence=60 if _is_public(ip) else 40,
                    attributes={"internet_reachable": _is_public(ip)},
                )
