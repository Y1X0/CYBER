"""CT-log discovery provider (Phase 6B) — passive subdomain enumeration from cert transparency.

Certificate Transparency logs list every cert issued for a domain, revealing subdomains that never
appear in public DNS. Passive (no target contact) → no authorization needed. High confidence: a CT
record is a real issued certificate.

Live by default when the run allows it. The hardened fetch — fixed host, query-string-only target,
no redirects, public-address enforcement, bounded response — lives in `guardian_scanner.sources.ct`
and is shared with the CT tool provider, so there is one SSRF surface to review rather than two.

Offline remains available and is what CI uses: without `allow_live` the provider reads a snapshot
from `ctx.settings["ct"]` ({domain: [subdomains]}) and opens no socket.
"""

from __future__ import annotations

from collections.abc import Iterable

from guardian_core.discovery import DiscoveredAsset, DiscoveredEdge, DiscoveryContext
from guardian_core.enums import DiscoverySource, EdgeRelation, NodeType

from guardian_scanner.sources import ct as ct_source


class CtLogProvider:
    key = "ct"
    requires_authorization = False

    def collect(self, ctx: DiscoveryContext) -> Iterable[DiscoveredAsset]:
        allow_live = bool(ctx.settings.get("allow_live"))
        snapshot: dict = ctx.settings.get("ct", {}) or {}
        for raw_domain in ctx.seeds.get("domains", []):
            domain = str(raw_domain).strip().lower().rstrip(".")
            hosts = ct_source.hosts_for_domain(domain, allow_live=allow_live, snapshot=snapshot)
            for sub in hosts:
                if sub == domain:
                    continue  # the seed itself is not a discovery
                yield DiscoveredAsset(
                    node_type=NodeType.SUBDOMAIN,
                    canonical_key=sub,
                    source=DiscoverySource.CT_LOG,
                    confidence=95,           # a CT record is a real issued cert
                    ownership_confidence=90,  # under the tenant's seed domain → very likely theirs
                    attributes={"public_dns": True, "mode": "live" if allow_live else "offline"},
                    edges=[DiscoveredEdge(
                        relation=EdgeRelation.SUBDOMAIN_OF,
                        dst_type=NodeType.DOMAIN, dst_key=domain, confidence=95,
                    )],
                )
