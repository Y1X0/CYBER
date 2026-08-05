"""Discovery runs + scopes (Phase 6).

`DiscoveryRun` versions every discovery pass — nodes and edges are stamped with `discovery_run_id`,
so an "attack surface as of last month" snapshot is a filter by run/time, not a separate store.

`DiscoveryScope` holds the seeds a tenant authorized plus a **freshness cadence**
(`refresh_interval_seconds` / `next_run_at`). This is EASM scheduling — recurring re-discovery of a
scope — and is deliberately distinct from SOAR (event-driven response), which stays in Phase 7.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from guardian_db.base import Base, TimestampMixin, uuid_pk


class DiscoveryScope(Base, TimestampMixin):
    __tablename__ = "discovery_scopes"
    __table_args__ = (
        Index("idx_discovery_scopes_tenant", "tenant_id", "customer_id"),
        Index("idx_discovery_scopes_due", "next_run_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    # Authorized seeds: domains / org names / cloud accounts to enumerate from.
    seeds: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    # Which discovery providers are enabled for this scope (keys). Empty = all passive.
    providers: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Freshness cadence (EASM scheduling, NOT SOAR). Null = manual runs only.
    refresh_interval_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    next_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class DiscoveryRun(Base, TimestampMixin):
    __tablename__ = "discovery_runs"
    __table_args__ = (Index("idx_discovery_runs_tenant_created", "tenant_id", "created_at"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("customers.id"), nullable=True
    )
    scope_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("discovery_scopes.id"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(20), default="queued", nullable=False)
    trigger: Mapped[str] = mapped_column(String(20), default="manual", nullable=False)
    seeds: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    # Delta counts: {"nodes_new":.., "nodes_updated":.., "edges_new":..} — powers incremental view.
    stats: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
