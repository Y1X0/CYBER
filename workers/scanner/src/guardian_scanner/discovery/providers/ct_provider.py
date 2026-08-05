"""CT-log discovery provider (Phase 6B) — passive subdomain enumeration from cert transparency.

Certificate Transparency logs list every cert issued for a domain, revealing subdomains that never
appear in public DNS. Passive (no target contact) → no authorization needed. High confidence: a CT
record is a real issued certificate.

Offline-first, exactly like the scanner engines: reads a snapshot from `ctx.settings["ct"]`
({domain: [subdomains]}) so it's deterministic in CI. A live crt.sh lookup slots in behind the same
interface when `ctx.settings["allow_live"]` is set (not exercised in tests).
"""

from __future__ import annotations

from collections.abc import Iterable

from guardian_core.discovery import DiscoveredAsset, DiscoveredEdge, DiscoveryContext
from guardian_core.enums import DiscoverySource, EdgeRelation, NodeType


class CtLogProvider:
    key = "ct"
    requires_authorization = False

    def collect(self, ctx: DiscoveryContext) -> Iterable[DiscoveredAsset]:
        snapshot: dict = ctx.settings.get("ct", {})
        domains = ctx.seeds.get("domains", [])
        for domain in domains:
            subs = snapshot.get(domain, [])
            for sub in subs:
                yield DiscoveredAsset(
                    node_type=NodeType.SUBDOMAIN,
                    canonical_key=sub,
                    source=DiscoverySource.CT_LOG,
                    confidence=95,           # a CT record is a real issued cert
                    ownership_confidence=90,  # under the tenant's seed domain → very likely theirs
                    attributes={"public_dns": True},
                    edges=[DiscoveredEdge(
                        relation=EdgeRelation.SUBDOMAIN_OF,
                        dst_type=NodeType.DOMAIN, dst_key=domain, confidence=95,
                    )],
                )
