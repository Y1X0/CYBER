"""Outbound webhook endpoints and deliveries (WP-G3)."""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from guardian_db.base import Base, TimestampMixin, uuid_pk


class WebhookEndpoint(Base, TimestampMixin):
    """Where a customer wants to be told, and what about."""

    __tablename__ = "webhook_endpoints"
    __table_args__ = (Index("idx_webhook_endpoint_tenant", "tenant_id", "enabled"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("customers.id"), nullable=True
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    # An empty list receives nothing: subscribing to everything is an explicit choice, never the
    # effect of leaving a field blank.
    events: Mapped[list[str]] = mapped_column(ARRAY(String), default=list, nullable=False)
    # Stored rather than digested because the sender must *produce* signatures, not only check
    # them. Returned to the customer once, at creation, and by no endpoint afterwards.
    secret: Mapped[str] = mapped_column(String(120), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    disabled_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_success_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class WebhookDelivery(Base, TimestampMixin):
    """What was actually sent, and what came back.

    The audit trail that settles "we never got the alert", which is why the exact signed bytes are
    kept: without them, "the signature did not verify" has no resolution.
    """

    __tablename__ = "webhook_deliveries"
    __table_args__ = (
        Index("idx_webhook_delivery_endpoint", "endpoint_id", "created_at"),
        Index("idx_webhook_delivery_pending", "status", "next_attempt_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("webhook_endpoints.id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(60), nullable=False)
    event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # pending | delivered | failed | dropped
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    next_attempt_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    delivered_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    payload: Mapped[str] = mapped_column(Text, default="", nullable=False)
