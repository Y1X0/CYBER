"""DNS discovery provider (Phase 6B) — resolution of hosts to addresses.

Resolves each seed host (and any subdomains passed in) to its A/AAAA records, producing ip_address
nodes and `resolves_to` edges, and flags public reachability from whether the resolved address is
globally routable. Passive → no authorization.

Live by default when the run allows it, via `guardian_scanner.sources.dns`; offline reads a
snapshot from `ctx.settings["dns"]` so CI opens no socket.

**Takeover findings require positive evidence.** A host we did not observe yields nothing. A host
that resolves is inventory. Only a host whose CNAME points at a name that authoritatively does not
exist is emitted as a takeover candidate — that is the actual signal, and the earlier behaviour of
treating "no snapshot entry" as "no longer resolves" fabricated one such candidate for every seed
on any run without fixture data.

Wildcard answers are marked rather than dropped, so a domain answering `*.example.com` cannot
inflate the inventory with hosts that do not exist while still leaving the observation visible.
"""

from __future__ import annotations

from collections.abc import Iterable

from guardian_common.logging import get_logger
from guardian_core.discovery import DiscoveredAsset, DiscoveredEdge, DiscoveryContext
from guardian_core.enums import DiscoverySource, EdgeRelation, NodeType

from guardian_scanner.sources import dns as dns_source

log = get_logger("guardian.discovery.dns")


def _registrable(host: str) -> str:
    """The domain a wildcard profile would belong to. Not a public-suffix lookup — one label up is
    the right scope for the wildcard probe, and being wrong only costs an extra query."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) > 2 else host


class DnsProvider:
    key = "dns"
    requires_authorization = False

    def collect(self, ctx: DiscoveryContext) -> Iterable[DiscoveredAsset]:
        allow_live = bool(ctx.settings.get("allow_live"))
        snapshot: dict = ctx.settings.get("dns", {}) or {}
        hosts = list(ctx.seeds.get("domains", [])) + list(ctx.seeds.get("hosts", []))

        # One wildcard probe per registrable domain, not per host — a domain either answers for
        # nonexistent names or it does not, and probing per host would multiply queries for nothing.
        wildcards: dict[str, dns_source.WildcardProfile] = {}
        if allow_live:
            for domain in {_registrable(str(h).strip().lower()) for h in hosts}:
                try:
                    wildcards[domain] = dns_source.wildcard_profile(domain)
                except Exception as exc:  # noqa: BLE001 - a probe failure must not stop discovery
                    # Without a profile we simply cannot tell wildcard answers apart; say so rather
                    # than silently degrade, because it changes how the results should be read.
                    log.warning("wildcard_probe_failed", domain=domain, error=type(exc).__name__)

        for raw_host in hosts:
            host = str(raw_host).strip().lower().rstrip(".")
            if not host:
                continue
            if allow_live:
                answer = dns_source.resolve(host, wildcard=wildcards.get(_registrable(host)))
            else:
                answer = dns_source.answers_from_snapshot(host, snapshot)

            if not answer.observed:
                continue  # we did not look — infer nothing, emit nothing

            yield from self._assets_for(answer)

    def _assets_for(self, answer: dns_source.DnsAnswer) -> Iterable[DiscoveredAsset]:
        attributes: dict = {"public_dns": True, "internet_reachable": answer.public}
        if answer.cname:
            attributes["cname"] = answer.cname
        if answer.wildcard:
            attributes["wildcard"] = True
        if answer.unresolved:
            # We asked and the name answers with nothing. Worth recording — a seed that no longer
            # resolves is stale inventory at minimum. Never emitted for a name we did not query.
            attributes["dangling_dns"] = True
        if answer.takeover_candidate:
            # The strong signal, kept separate so triage can rank a claimable alias above a name
            # that is merely gone.
            attributes["takeover_candidate"] = True

        confidence = 90 if answer.resolves else (85 if answer.takeover_candidate else 70)

        yield DiscoveredAsset(
            node_type=NodeType.SUBDOMAIN,
            canonical_key=answer.host,
            source=DiscoverySource.DNS_RESOLVER,
            confidence=confidence,
            ownership_confidence=85,
            attributes=attributes,
            edges=[
                DiscoveredEdge(relation=EdgeRelation.RESOLVES_TO,
                               dst_type=NodeType.IP_ADDRESS, dst_key=ip, confidence=90)
                for ip in answer.ips
            ],
        )

        for ip in answer.ips:
            public = dns_source.is_public_ip(ip)
            yield DiscoveredAsset(
                node_type=NodeType.IP_ADDRESS,
                canonical_key=ip,
                source=DiscoverySource.DNS_RESOLVER,
                confidence=90,
                # A shared-hosting or CDN address is far less likely to be the tenant's than
                # the name that pointed at it, so ownership stays lower than the host's.
                ownership_confidence=60 if public else 40,
                attributes={"internet_reachable": public},
            )
