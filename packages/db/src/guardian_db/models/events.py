"""Domain-event outbox seam (Phase 5B) — storage only, no consumers.

An append-only transactional outbox: business events are written in the same transaction as the
state change that produced them. This is the eventing spine for future SOAR, notifications, and
agent triggers — adding it now avoids re-plumbing every write path later. No dispatcher/consumer is
implemented yet; `processed_at` stays null until a future phase adds delivery.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from guardian_db.base import Base, uuid_pk


class DomainEvent(Base):
    __tablename__ = "domain_events"
    __table_args__ = (Index("idx_events_unprocessed", "processed_at", "occurred_at"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tenants.id"), nullable=True)
    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("customers.id"), nullable=True
    )
    # e.g. "finding.created", "scan.completed", "gate.failed"
    type: Mapped[str] = mapped_column(String(60), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    occurred_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # null until a future consumer processes it (no consumer exists yet — storage seam only).
    processed_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
