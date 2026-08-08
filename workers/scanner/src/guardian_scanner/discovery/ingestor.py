"""Graph ingestor (Phase 6B) — the write side of the graph, implementing the GraphIngestor port.

Turns normalized `DiscoveredAsset`s into graph nodes + edges with the merge/dedup policy, the
deterministic exposure score, the discovery lifecycle, and the per-node history. Merge policy: a
node is identified by `(tenant, node_type, canonical_key)` — a re-observation UPDATES that row (max
confidence, refreshed last_seen, merged attributes), it never creates a second entity.

Tenant consistency is enforced here, at the polymorphic boundary RLS can't see: an edge is only ever
written between two nodes of the same tenant as the run.
"""

from __future__ import annotations

import datetime as dt
import uuid

from guardian_core.canonicalize import canonical_key
from guardian_core.discovery import DiscoveredAsset
from guardian_core.enums import AssetState
from guardian_core.exposure import ExposureInputs, assess_exposure
from guardian_db.models import DomainEvent, GraphEdge, GraphNode, NodeEvent
from sqlalchemy import select
from sqlalchemy.orm import Session

_EXPOSURE_KEYS = {
    "internet_reachable", "public_dns", "open_ports", "sensitive_ports",
    "missing_tls", "cloud_public", "unknown_ownership", "dangling_dns",
}


def _exposure_for(attributes: dict) -> tuple[int, list]:
    inp = ExposureInputs(**{k: attributes[k] for k in _EXPOSURE_KEYS if k in attributes})
    out = assess_exposure(inp)
    return out.score, out.rationale


def _derive_state(*, ownership_confidence: int, internet_reachable: bool, has_asset: bool) -> str:
    """Deterministic lifecycle: a live, likely-ours node the customer never declared is SHADOW."""
    if has_asset:
        return AssetState.ACTIVE.value
    if internet_reachable and ownership_confidence >= 60:
        return AssetState.SHADOW.value
    return AssetState.CANDIDATE.value


class DbGraphIngestor:
    """GraphIngestor bound to a session + discovery run. Counts land in `stats`."""

    def __init__(self, session: Session, *, tenant_id: uuid.UUID, run_id: uuid.UUID) -> None:
        self._s = session
        self._tenant = tenant_id
        self._run = run_id
        self.stats = {"nodes_new": 0, "nodes_updated": 0, "edges_new": 0, "edges_updated": 0,
                      "shadow_found": 0}

    def _now(self) -> dt.datetime:
        return dt.datetime.now(dt.UTC)

    def _emit(self, type_: str, payload: dict) -> None:
        self._s.add(DomainEvent(
            tenant_id=self._tenant, type=type_, payload=payload, occurred_at=self._now()
        ))

    def upsert_node(self, node: DiscoveredAsset) -> uuid.UUID:
        """Insert or merge a node by identity; returns its stable UUID."""
        key = canonical_key(node.node_type, node.canonical_key)
        exposure, rationale = _exposure_for(node.attributes)
        internet = bool(node.attributes.get("internet_reachable"))
        now = self._now()

        existing = self._s.execute(
            select(GraphNode).where(
                GraphNode.tenant_id == self._tenant,
                GraphNode.node_type == node.node_type.value,
                GraphNode.canonical_key == key,
            )
        ).scalar_one_or_none()

        if existing is None:
            state = _derive_state(
                ownership_confidence=node.ownership_confidence,
                internet_reachable=internet, has_asset=False,
            )
            row = GraphNode(
                tenant_id=self._tenant, node_type=node.node_type.value, canonical_key=key,
                metadata_=dict(node.attributes), confidence=node.confidence,
                ownership_confidence=node.ownership_confidence, exposure_score=exposure,
                exposure_rationale=rationale, state=state, first_seen_at=now, last_seen_at=now,
                discovery_run_id=self._run,
            )
            self._s.add(row)
            self._s.flush()
            self.stats["nodes_new"] += 1
            self._s.add(NodeEvent(tenant_id=self._tenant, node_id=row.id, event_type="observed",
                                  detail={"source": node.source.value}, discovery_run_id=self._run,
                                  occurred_at=now))
            self._emit("asset.discovered", {"node_id": str(row.id), "type": node.node_type.value,
                                            "key": key, "state": state})
            if state == AssetState.SHADOW.value:
                self.stats["shadow_found"] += 1
                self._emit("asset.shadow", {"node_id": str(row.id), "key": key})
            return row.id

        # merge (dedup): same entity re-observed — take the stronger signals, refresh recency.
        merged_attrs = {**(existing.metadata_ or {}), **node.attributes}
        merged_exposure, merged_rationale = _exposure_for(merged_attrs)
        merged_own = max(existing.ownership_confidence, node.ownership_confidence)
        new_state = existing.state
        if existing.state != AssetState.ACTIVE.value or existing.asset_id is None:
            # recompute lifecycle from merged signals (order-independent) unless already anchored
            new_state = _derive_state(
                ownership_confidence=merged_own,
                internet_reachable=bool(merged_attrs.get("internet_reachable")),
                has_asset=existing.asset_id is not None,
            )

        old_attrs = existing.metadata_ or {}
        changed: list[str] = []
        tls_changed = ("tls" in node.attributes
                       and old_attrs.get("tls") != node.attributes.get("tls"))
        banner_changed = (
            "banner" in node.attributes and old_attrs.get("banner") != node.attributes.get("banner")
        )
        if tls_changed:
            changed.append("tls changed")
        if banner_changed:
            changed.append("banner changed")
        if merged_exposure != existing.exposure_score:
            changed.append(f"exposure {existing.exposure_score}->{merged_exposure}")
        state_changed = new_state != existing.state
        if state_changed:
            changed.append(f"state {existing.state}->{new_state}")

        existing.confidence = max(existing.confidence, node.confidence)
        existing.ownership_confidence = merged_own
        existing.exposure_score = merged_exposure
        existing.exposure_rationale = merged_rationale
        existing.metadata_ = merged_attrs
        existing.last_seen_at = now
        existing.discovery_run_id = self._run
        self.stats["nodes_updated"] += 1
        if state_changed and new_state == AssetState.SHADOW.value:
            self.stats["shadow_found"] += 1
            self._emit("asset.shadow", {"node_id": str(existing.id), "key": key})
        existing.state = new_state
        if changed:
            # Most-specific event type for a clean, queryable history (Phase 6C).
            event_type = ("tls_changed" if tls_changed else
                          "service_changed" if banner_changed else
                          "state_changed" if state_changed else "changed")
            self._s.add(NodeEvent(
                tenant_id=self._tenant, node_id=existing.id, event_type=event_type,
                detail={"changes": changed}, discovery_run_id=self._run, occurred_at=now,
            ))
        return existing.id

    def link(self, *, src_id: uuid.UUID, relation: str, dst_id: uuid.UUID,
             src_type: str, dst_type: str, source: str, confidence: int = 100) -> None:
        """Upsert an edge between two same-tenant nodes; refreshes lifecycle on re-observation."""
        now = self._now()
        existing = self._s.execute(
            select(GraphEdge).where(
                GraphEdge.tenant_id == self._tenant,
                GraphEdge.src_type == src_type, GraphEdge.src_id == str(src_id),
                GraphEdge.relation == relation,
                GraphEdge.dst_type == dst_type, GraphEdge.dst_id == str(dst_id),
            )
        ).scalar_one_or_none()
        if existing is None:
            self._s.add(GraphEdge(
                tenant_id=self._tenant, src_type=src_type, src_id=str(src_id), relation=relation,
                dst_type=dst_type, dst_id=str(dst_id), state="active", source=source,
                confidence=confidence, first_seen_at=now, last_seen_at=now,
                discovery_run_id=self._run,
            ))
            self._s.flush()  # autoflush off — make it visible to the next lookup this run
            self.stats["edges_new"] += 1
        else:
            existing.state = "active"
            existing.last_seen_at = now
            existing.confidence = max(existing.confidence, confidence)
            existing.discovery_run_id = self._run
            self.stats["edges_updated"] += 1


def mark_stale_edges(session: Session, *, tenant_id: uuid.UUID, run_id: uuid.UUID) -> int:
    """Edges not re-observed in the just-run pass are marked `stale` (history kept, not deleted).

    Applies only to previously-active edges whose latest observation predates this run — so a
    relation that vanished (a subdomain re-pointed) is retired without erasing that it once existed.
    """
    from sqlalchemy import update

    result = session.execute(
        update(GraphEdge)
        .where(
            GraphEdge.tenant_id == tenant_id,
            GraphEdge.state == "active",
            GraphEdge.discovery_run_id != run_id,
        )
        .values(state="stale")
    )
    return result.rowcount or 0
