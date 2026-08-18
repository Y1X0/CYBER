"""Recurring work: what should run, for which tenant, and when it is next due (WP-A3).

A subscription is sold on recurring work. A one-off scan is a consulting deliverable; what a
customer pays monthly for is that Guardian keeps looking after they stop thinking about it. Nothing
in this repository ran on a schedule before this — `trigger="schedule"` was an accepted value that
nothing ever produced, and `feeds.py` claimed Celery beat was "configured in production" when no
beat service existed anywhere.

Schedules are rows rather than beat entries because they are tenant data. Beat's static config
cannot express "this customer's repository weekly, that customer's domain daily", cannot be edited
through the API, and would put one tenant's cadence in a file every tenant shares. Beat runs one
sweep; the sweep reads these rows.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from guardian_db.base import Base, TimestampMixin, uuid_pk


class Schedule(Base, TimestampMixin):
    """One recurring job for one tenant.

    Cadence is an interval rather than a cron expression on purpose: "every 24 hours" is
    unambiguous across time zones and daylight saving, which a customer-facing cadence has to be,
    and it makes `next_run_at` a plain addition rather than a parse.
    """

    __tablename__ = "schedules"
    __table_args__ = (
        # One schedule per (tenant, kind, target). Re-creating an existing schedule should update
        # the cadence rather than silently double the customer's scan volume — and their bill.
        UniqueConstraint("tenant_id", "kind", "target_id", name="uq_schedule_tenant_kind_target"),
        CheckConstraint("kind IN ('scan','discovery')", name="ck_schedule_kind"),
        # A cadence below five minutes is a mistake or an attempt to use a scheduler as a load
        # generator; either way it should not reach the queue. Declared here as well as in
        # migration 0012 so a database built from the baseline enforces it too.
        CheckConstraint("interval_seconds >= 300", name="ck_schedule_interval_floor"),
        Index("idx_schedules_due", "enabled", "next_run_at"),
        Index("idx_schedules_tenant", "tenant_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk(db_generated=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("customers.id"), nullable=True
    )

    # scan | discovery — what the sweep enqueues when this becomes due.
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    # The asset (scan) or discovery scope this recurs over. Null means tenant-wide.
    target_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)

    interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=86400,
                                                  server_default="86400")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False,
                                          server_default=text("true"))

    next_run_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_run_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Consecutive failures. A schedule that keeps failing is disabled rather than left to retry
    # forever against a target that may no longer exist — and to stop billing a customer for work
    # that cannot succeed.
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False,
                                                      server_default="0")

    # Engines for a scan schedule, and any provider settings for a discovery schedule.
    settings: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False,
                                           server_default="{}")
