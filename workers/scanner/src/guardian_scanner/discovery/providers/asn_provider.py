"""Passive ASN/RIR discovery provider (Phase 6F-b) — netblocks for discovered IPs.

Passive, public registry data only (RIR/RDAP) — like CT/DNS, NOT an active probe: no traceroute, no
ICMP, no port scan, no new ports/protocols, no credentials. It maps a discovered IP to the
netblock (CIDR) that registers it, producing `netblock` nodes and `contains` edges to the IP.

Offline-first + deterministic: reads a snapshot from `ctx.settings["asn"]` ({ip: {netblock, asn}})
so tests are hermetic. A live RDAP lookup slots in behind an explicit `allow_live` flag
(best-effort, fail-safe; not exercised in tests) — mirroring the DNS/CT providers.

The IPs it works on come from `ctx.seeds["ips"]` — the trusted orchestrator supplies discovered
ip_address node keys (never raw user seeds). Fail-safe: bad/absent data for an IP is skipped, never
raised, so a provider hiccup cannot corrupt graph state.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from guardian_core.discovery import DiscoveredAsset, DiscoveredEdge, DiscoveryContext
from guardian_core.enums import DiscoverySource, EdgeRelation, NodeType


def _rdap_live(ip: str) -> dict | None:  # pragma: no cover - network, behind allow_live only
    """Best-effort passive RDAP lookup for `ip` → {"netblock": cidr, ...}, or None on failure.

    Passive HTTP GET to a public RDAP redirector; never an active probe. Any error → None.
    """
    import json
    import urllib.request

    try:
        with urllib.request.urlopen(f"https://rdap.org/ip/{ip}", timeout=5) as r:  # noqa: S310
            data = json.loads(r.read().decode("utf-8", "replace"))
        cidrs = data.get("cidr0_cidrs") or []
        if cidrs:
            entry = cidrs[0]
            prefix = entry.get("v4prefix") or entry.get("v6prefix")
            length = entry.get("length")
            if prefix is not None and length is not None:
                return {"netblock": f"{prefix}/{length}"}
    except Exception:  # noqa: BLE001 - passive lookup is best-effort; never destabilize the run
        return None
    return None


class AsnRirProvider:
    key = "asn"
    requires_authorization = False  # passive public registry data — no authorization gate

    def collect(self, ctx: DiscoveryContext) -> Iterable[DiscoveredAsset]:
        snapshot: dict = ctx.settings.get("asn", {})
        allow_live = bool(ctx.settings.get("allow_live"))
        seen: set[str] = set()
        for ip in ctx.seeds.get("ips", []):
            if ip in seen:
                continue  # dedup IP inputs before any lookup
            seen.add(ip)

            info = snapshot.get(ip)
            if info is None and allow_live:
                info = _rdap_live(ip)
            if not info:
                continue

            netblock = info.get("netblock")
            if not netblock:
                continue
            try:
                ipaddress.ip_network(netblock, strict=False)  # fail-safe: skip malformed CIDRs
            except ValueError:
                continue

            attrs: dict = {}
            if info.get("asn") is not None:
                attrs["asn"] = info["asn"]
            # netblock node + netblock --contains--> ip (containment, NOT a reachability/attack hop)
            yield DiscoveredAsset(
                node_type=NodeType.NETBLOCK, canonical_key=netblock,
                source=DiscoverySource.ASN_RIR, confidence=90, ownership_confidence=0,
                attributes=attrs,
                edges=[DiscoveredEdge(relation=EdgeRelation.CONTAINS,
                                      dst_type=NodeType.IP_ADDRESS, dst_key=ip, confidence=90)],
            )
