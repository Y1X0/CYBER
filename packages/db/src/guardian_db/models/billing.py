"""Billing-ready layer (doc 07 §5). SCHEMA ONLY — no payment processing in Phase 1.

`plan_entitlement` is used to ENFORCE limits (max assets, scan concurrency) even though no
invoicing exists yet. A BillingProvider (Stripe, ...) plugs into these tables later.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Numeric, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from guardian_db.base import Base, TimestampMixin, uuid_pk


class Plan(Base, TimestampMixin):
    __tablename__ = "plans"

    id: Mapped[uuid.UUID] = uuid_pk()
    key: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)  # free|pro|enterprise
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    price_ref: Mapped[str | None] = mapped_column(String(120), nullable=True)  # external price id
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    entitlements: Mapped[list[PlanEntitlement]] = relationship(back_populates="plan")


class PlanEntitlement(Base, TimestampMixin):
    __tablename__ = "plan_entitlements"

    id: Mapped[uuid.UUID] = uuid_pk()
    plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("plans.id"), nullable=False)
    # e.g. "max_assets", "scans_per_month", "seats", "retention_days"
    key: Mapped[str] = mapped_column(String(60), nullable=False)
    limit_value: Mapped[int | None] = mapped_column(Integer, nullable=True)  # null = unlimited
    feature_flag: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    plan: Mapped[Plan] = relationship(back_populates="entitlements")


class Subscription(Base, TimestampMixin):
    __tablename__ = "subscriptions"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id"), nullable=False)
    plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("plans.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="trialing", nullable=False)
    period_start: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    period_end: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancel_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UsageRecord(Base, TimestampMixin):
    """Metered events for future billing + limit enforcement."""

    __tablename__ = "usage_records"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id"), nullable=False)
    subscription_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("subscriptions.id"), nullable=True
    )
    metric: Mapped[str] = mapped_column(String(60), nullable=False)  # e.g. "scan_run"
    quantity: Mapped[float] = mapped_column(Numeric, default=1, nullable=False)
    meta: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
