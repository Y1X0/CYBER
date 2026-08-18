"""Recurring schedules (WP-A3).

Nothing ran on a schedule before this: `trigger="schedule"` was an accepted value no code produced,
and the feed-sync docstring claimed Celery beat was configured in production when no beat service
existed. A subscription is sold on recurring work, so the cadence has to be data a tenant owns
rather than a static entry in a config file every tenant shares.

RLS applies here exactly as it does everywhere else. A schedule names an asset and a customer, so
leaking one across tenants would disclose that a competitor is a customer and what they scan.

Revision ID: 0012_scheduling
Revises: 0011_web_checks_catalog
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from guardian_db.migration_utils import table_exists

revision = "0012_scheduling"
down_revision = "0011_web_checks_catalog"
branch_labels = None
depends_on = None

_CUR = "NULLIF(current_setting('app.current_tenant', true), '')::uuid"


def upgrade() -> None:
    # On an empty database `0001_baseline`'s `create_all` has already built this table from the
    # model, so creating it here is a collision rather than a step. RLS and the grant below run
    # either way — the baseline produces neither.
    if not table_exists("schedules"):
        _create()

    op.execute("ALTER TABLE schedules ENABLE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON schedules TO guardian_app "
        f"USING (tenant_id = {_CUR}) WITH CHECK (tenant_id = {_CUR})"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON schedules TO guardian_app")


def _create() -> None:
    op.create_table(
        "schedules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("customer_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("customers.id"), nullable=True),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("interval_seconds", sa.Integer(), nullable=False, server_default="86400"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(20), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("settings", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("tenant_id", "kind", "target_id",
                            name="uq_schedule_tenant_kind_target"),
        sa.CheckConstraint("kind IN ('scan','discovery')", name="ck_schedule_kind"),
        # A cadence below five minutes is a mistake or an attempt to use a scheduler as a
        # load generator; either way it should not reach the queue.
        sa.CheckConstraint("interval_seconds >= 300", name="ck_schedule_interval_floor"),
    )
    # The sweep's only query is "enabled and due", so that is the index it gets.
    op.create_index("idx_schedules_due", "schedules", ["enabled", "next_run_at"])
    op.create_index("idx_schedules_tenant", "schedules", ["tenant_id"])


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON schedules")
    op.drop_index("idx_schedules_tenant", table_name="schedules")
    op.drop_index("idx_schedules_due", table_name="schedules")
    op.drop_table("schedules")
