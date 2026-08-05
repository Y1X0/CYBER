"""Attack-graph node history (Phase 6) — append-only change log per node.

More than `first_seen_at` / `last_seen_at`: a timeline of what *changed* about a node — a port
opened, TLS changed, a new certificate, a transition to `shadow`. This is the substrate the AI
analyst and attack-path narration reason over later ("this host became internet-facing three days
ago"). Append-only; never mutated.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from guardian_db.base import Base, uuid_pk


class NodeEvent(Base):
    __tablename__ = "node_events"
    __table_args__ = (Index("idx_node_events_node", "tenant_id", "node_id", "occurred_at"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    node_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("graph_nodes.id"), nullable=False)
    # observed | port_opened | port_closed | tls_changed | certificate_changed |
    # state_changed | resolved | ownership_changed
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    detail: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    discovery_run_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    occurred_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
