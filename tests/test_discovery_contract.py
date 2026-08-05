"""Discovery contract unit tests (Phase 6·A) — the shape every collector must emit."""

from __future__ import annotations

from guardian_common.ports import (
    DiscoveryProvider,
    NullDiscoveryProvider,
    NullGraphIngestor,
    NullGraphProjector,
)
from guardian_core.discovery import DiscoveredAsset, DiscoveredEdge
from guardian_core.enums import DiscoverySource, EdgeRelation, NodeType


def test_discovered_asset_clamps_confidence():
    a = DiscoveredAsset(
        node_type=NodeType.SUBDOMAIN, canonical_key="api.example.com",
        source=DiscoverySource.CT_LOG, confidence=150, ownership_confidence=-5,
    )
    assert a.confidence == 100
    assert a.ownership_confidence == 0


def test_discovered_asset_carries_edges_and_provenance():
    a = DiscoveredAsset(
        node_type=NodeType.SUBDOMAIN, canonical_key="api.example.com",
        source=DiscoverySource.PASSIVE_DNS, confidence=80,
        edges=[DiscoveredEdge(relation=EdgeRelation.RESOLVES_TO,
                              dst_type=NodeType.IP_ADDRESS, dst_key="203.0.113.10")],
    )
    assert a.source is DiscoverySource.PASSIVE_DNS
    assert a.edges[0].relation is EdgeRelation.RESOLVES_TO
    assert a.edges[0].dst_key == "203.0.113.10"


def test_null_providers_satisfy_their_protocols():
    # Structural: the Null defaults must implement the ports so later phases can swap real ones in.
    assert isinstance(NullDiscoveryProvider(), DiscoveryProvider)
    assert NullDiscoveryProvider().requires_authorization is False
    assert list(NullDiscoveryProvider().collect(None)) == []  # type: ignore[arg-type]
    assert NullGraphProjector().paths_to(tenant_id="t", target_type="asset", target_id="x") == []
    assert NullGraphIngestor().upsert_node(tenant_id="t", node=None, run_id="r") == ""  # type: ignore[arg-type]
