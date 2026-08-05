"""Attack-graph node registry (Phase 6).

Every node in the attack graph — owned or external — is a row here with a **stable internal UUID**
and a searchable, *mutable* `canonical_key` (FQDN / ARN / referenced-row id). Edges point at the
UUID, so a node keeps its relations even when its canonical key changes or the asset moves. Dedup is
on `(tenant_id, node_type, canonical_key)`.

Carries the asset-intelligence layer: discovery `confidence`, `ownership_confidence`, a
deterministic `exposure_score` (kept separate from vulnerability risk), the discovery `state`
lifecycle, and first/last-seen for freshness. `asset_id` links a node to a managed asset when
applicable; external nodes (a third-party CDN IP) have none.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from guardian_db.base import Base, TimestampMixin, uuid_pk


class GraphNode(Base, TimestampMixin):
    __tablename__ = "graph_nodes"
    __table_args__ = (
        UniqueConstraint("tenant_id", "node_type", "canonical_key", name="uq_graph_node_identity"),
        Index("idx_graph_nodes_tenant_type", "tenant_id", "node_type"),
        Index("idx_graph_nodes_tenant_state", "tenant_id", "state"),
        Index("idx_graph_nodes_asset", "tenant_id", "asset_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    # Nullable: an external/unattributed node (e.g. a shared CDN IP) belongs to no customer yet.
    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("customers.id"), nullable=True
    )
    # NodeType value: domain | subdomain | ip_address | netblock | service | cloud_resource
    #                 | asset | finding
    node_type: Mapped[str] = mapped_column(String(30), nullable=False)
    # Searchable natural key (FQDN / ARN / referenced-row id). Mutable — the UUID is the identity.
    canonical_key: Mapped[str] = mapped_column(String(255), nullable=False)
    # Link to a managed asset when this node is one; null for pure topology / external nodes.
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id"), nullable=True)

    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict, nullable=False)

    # ── asset-intelligence layer (all deterministic; AI never sets these) ──
    confidence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)  # 0–100 real?
    ownership_confidence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)  # 0–100
    exposure_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)  # 0–100, ≠ risk
    exposure_rationale: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    # AssetState value: candidate | active | shadow | inactive
    state: Mapped[str] = mapped_column(String(20), default="active", nullable=False)

    first_seen_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # The most recent discovery run that observed this node (provenance / snapshot filtering).
    discovery_run_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
