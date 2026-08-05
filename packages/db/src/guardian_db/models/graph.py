"""Graph edge seam (Phase 5B) — storage only, no analysis logic.

A polymorphic edge between two nodes referenced by (type, id). This is the hardest-to-retrofit
relationship spine for the future attack-path graph and EASM topology. It deliberately does NOT
foreign-key to node tables (identity/data_store don't exist yet) so new node types can be added in
their feature phases without a schema change here. No graph projection/analysis is implemented yet.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Float, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from guardian_db.base import Base, TimestampMixin, uuid_pk


class GraphEdge(Base, TimestampMixin):
    __tablename__ = "graph_edges"
    __table_args__ = (
        Index("idx_graph_src", "tenant_id", "src_type", "src_id"),
        Index("idx_graph_dst", "tenant_id", "dst_type", "dst_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    # node references (type + id) — e.g. ("asset", <uuid>); later "identity"|"data_store"|"finding"
    src_type: Mapped[str] = mapped_column(String(30), nullable=False)
    src_id: Mapped[str] = mapped_column(String(64), nullable=False)
    dst_type: Mapped[str] = mapped_column(String(30), nullable=False)
    dst_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # relation kind: resolves_to | hosts | subdomain_of | routes_to | trusts | can_access | ...
    relation: Mapped[str] = mapped_column(String(40), nullable=False)
    weight: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    meta: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
