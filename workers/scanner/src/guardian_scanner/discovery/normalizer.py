"""Normalizer (Phase 6B) — the step between a provider and the graph.

Canonicalizes a `DiscoveredAsset` and every edge destination it references, so identity resolution
and dedup downstream compare like-for-like keys. Pure: no DB, no network — just the canonical rules.
"""

from __future__ import annotations

from dataclasses import replace

from guardian_core.canonicalize import canonical_key
from guardian_core.discovery import DiscoveredAsset, DiscoveredEdge


def normalize(asset: DiscoveredAsset) -> DiscoveredAsset:
    """Return a copy with the node key and all edge destination keys canonicalized."""
    edges = [
        replace(e, dst_key=canonical_key(e.dst_type, e.dst_key))
        for e in asset.edges
    ]
    return replace(
        asset,
        canonical_key=canonical_key(asset.node_type, asset.canonical_key),
        edges=edges,
    )


def edge_target(edge: DiscoveredEdge, source, confidence: int | None = None) -> DiscoveredAsset:  # noqa: ANN001
    """A minimal node for an edge's destination, to get a stable UUID before the edge is linked."""
    return DiscoveredAsset(
        node_type=edge.dst_type,
        canonical_key=edge.dst_key,
        source=source,
        confidence=confidence if confidence is not None else edge.confidence,
    )
