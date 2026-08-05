"""Graph edges — the attack-graph relationship spine (seam in 5B, provenance added in Phase 6).

A polymorphic edge between two nodes referenced by (type, id). `src_id`/`dst_id` hold the **stable
internal UUID** of a `graph_nodes` row (or a finding/asset id for those node types) — never the
mutable natural key — so a rename never breaks a relation. It deliberately does NOT foreign-key to
node tables, so new node types are added without a schema change here.

Phase 6 makes provenance mandatory in practice: every edge records `source` (which provider or
inference produced it), a `confidence`, first/last-seen, and the `discovery_run_id` that observed
it — a graph without provenance can't be trusted or time-sliced.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from guardian_db.base import Base, TimestampMixin, uuid_pk


class GraphEdge(Base, TimestampMixin):
    __tablename__ = "graph_edges"
    __table_args__ = (
        # Identity of a relation → dedup/upsert target; a re-observed edge updates, not dupes.
        UniqueConstraint(
            "tenant_id", "src_type", "src_id", "relation", "dst_type", "dst_id",
            name="uq_graph_edge_identity",
        ),
        Index("idx_graph_src", "tenant_id", "src_type", "src_id"),
        Index("idx_graph_dst", "tenant_id", "dst_type", "dst_id"),
        Index("idx_graph_edges_run", "tenant_id", "discovery_run_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    # node references (type + stable UUID) — e.g. ("subdomain", <graph_nodes.id>), ("finding", <id>)
    src_type: Mapped[str] = mapped_column(String(30), nullable=False)
    src_id: Mapped[str] = mapped_column(String(64), nullable=False)
    dst_type: Mapped[str] = mapped_column(String(30), nullable=False)
    dst_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # relation kind: resolves_to | hosts | subdomain_of | routes_to | exposes | enables | ...
    relation: Mapped[str] = mapped_column(String(40), nullable=False)
    weight: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    # Lifecycle: a relation can disappear (a subdomain re-points) without erasing its history.
    # active (seen in the latest run) | stale (not re-observed) | removed (confirmed gone).
    state: Mapped[str] = mapped_column(String(20), default="active", nullable=False)

    # ── mandatory provenance (Phase 6) ──
    source: Mapped[str | None] = mapped_column(String(40), nullable=True)  # DiscoverySource value
    confidence: Mapped[int] = mapped_column(Integer, default=100, nullable=False)  # 0–100
    first_seen_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    discovery_run_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)

    meta: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
