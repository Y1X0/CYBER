"""The canonical shape a discovery provider emits — the discovery analogue of `RawFinding`.

Every EASM collector (CT logs, passive DNS, ASN, cloud, port scan) returns `DiscoveredAsset`s in one
shape, so upsert-by-identity, edge creation, and provenance are uniform regardless of source. The
normalizer (Phase 6B) maps these onto graph nodes / assets and edges. Engine-agnostic by design.

Every observation carries a `confidence` (0–100) and its `source`, so a low-confidence signal
(a brute-forced subdomain) is never treated like a high-confidence one (a resolved CT-log record).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from guardian_core.enums import DiscoverySource, EdgeRelation, NodeType


@dataclass
class DiscoveredEdge:
    """A relation this observation implies, e.g. subdomain --resolves_to--> ip_address."""

    relation: EdgeRelation
    dst_type: NodeType
    dst_key: str  # canonical key of the destination node (FQDN / ARN / ip)
    confidence: int = 100


@dataclass
class DiscoveryContext:
    """Everything a discovery provider needs for one run — populated by the task from scope + auth.

    `authorized` gates active methods (port/service scan): passive collectors ignore it; active ones
    must refuse to touch a target when it is False (the safe-scanning gate, mirrored from scanning).
    """

    tenant_id: str
    run_id: str
    seeds: dict[str, Any] = field(default_factory=dict)  # domains / orgs / cloud accounts
    customer_id: str | None = None
    authorized: bool = False
    # The targets an active provider is cleared to probe — pre-filtered by the authorization gate
    # against a valid, tenant-owned authorization. An active provider MUST touch nothing outside it.
    authorized_targets: list[str] = field(default_factory=list)
    settings: dict[str, Any] = field(default_factory=dict)


@dataclass
class DiscoveredAsset:
    """A single node observed by a discovery provider, before normalization/upsert."""

    node_type: NodeType
    canonical_key: str  # the natural key that drives dedup/upsert (FQDN, ARN, ip, netblock)
    source: DiscoverySource
    confidence: int = 100  # 0–100 — how sure the provider is this is real
    ownership_confidence: int = 0  # 0–100 — how sure it belongs to this tenant
    attributes: dict[str, Any] = field(default_factory=dict)  # ASN, TLS, region, banner, ...
    edges: list[DiscoveredEdge] = field(default_factory=list)  # relations to other nodes

    def __post_init__(self) -> None:
        self.confidence = max(0, min(100, int(self.confidence)))
        self.ownership_confidence = max(0, min(100, int(self.ownership_confidence)))


# ── result-return wire format (Phase 6C.4) ──
# The recon execution plane (no DB) returns evidence as plain JSON-able dicts; the trusted
# persistence plane rebuilds `DiscoveredAsset`s and ingests them. Enums cross the boundary as their
# string values; no behaviour changes — the same assets, just serialized between planes.
def asset_to_wire(a: DiscoveredAsset) -> dict[str, Any]:
    """Serialize a `DiscoveredAsset` (and its edges) to a plain dict for cross-plane transport."""
    return {
        "node_type": a.node_type.value,
        "canonical_key": a.canonical_key,
        "source": a.source.value,
        "confidence": a.confidence,
        "ownership_confidence": a.ownership_confidence,
        "attributes": a.attributes,
        "edges": [
            {"relation": e.relation.value, "dst_type": e.dst_type.value,
             "dst_key": e.dst_key, "confidence": e.confidence}
            for e in a.edges
        ],
    }


def asset_from_wire(d: dict[str, Any]) -> DiscoveredAsset:
    """Rebuild a `DiscoveredAsset` from its wire dict (inverse of `asset_to_wire`)."""
    return DiscoveredAsset(
        node_type=NodeType(d["node_type"]),
        canonical_key=d["canonical_key"],
        source=DiscoverySource(d["source"]),
        confidence=d.get("confidence", 100),
        ownership_confidence=d.get("ownership_confidence", 0),
        attributes=dict(d.get("attributes") or {}),
        edges=[
            DiscoveredEdge(
                relation=EdgeRelation(e["relation"]), dst_type=NodeType(e["dst_type"]),
                dst_key=e["dst_key"], confidence=e.get("confidence", 100),
            )
            for e in (d.get("edges") or [])
        ],
    )
