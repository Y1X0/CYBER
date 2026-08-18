"""Outbound webhook endpoints and their delivery history (WP-G3).

Two tables because they answer different questions and age differently. `webhook_endpoints` is
configuration a customer manages; `webhook_deliveries` is an audit trail of what Guardian actually
sent, which is what a support conversation about "we never got the alert" is settled with.

Only the signing secret's own value is stored — there is nothing to derive it from and no endpoint
that returns it after creation, on the same reasoning as WP-G1's API keys. It is stored rather than
digested because the sender must be able to *produce* a signature, not merely check one.

Revision ID: 0018_webhooks
Revises: 0017_ownership_verification
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from guardian_db.migration_utils import create_index_if_absent, table_exists

revision = "0018_webhooks"
down_revision = "0017_ownership_verification"
branch_labels = None
depends_on = None

_CUR = "NULLIF(current_setting('app.current_tenant', true), '')::uuid"


def upgrade() -> None:
    # Guarded: `0001_baseline` builds every registered model, so on an empty database these tables
    # already exist. RLS and the grants below run either way.
    if not table_exists("webhook_endpoints"):
        _create_endpoints()
    if not table_exists("webhook_deliveries"):
        _create_deliveries()

    for table in ("webhook_endpoints", "webhook_deliveries"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} TO guardian_app "
            f"USING (tenant_id = {_CUR}) WITH CHECK (tenant_id = {_CUR})"
        )
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO guardian_app")


def _create_endpoints() -> None:
    op.create_table(
        "webhook_endpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"),
                  nullable=False),
        sa.Column("customer_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("customers.id"),
                  nullable=True),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("description", sa.String(200), default="", nullable=False),
        # The events this endpoint asked for. An empty list receives nothing: subscribing to
        # everything has to be an explicit choice, not the effect of leaving a field blank.
        sa.Column("events", postgresql.ARRAY(sa.String()), nullable=False,
                  server_default="{}"),
        sa.Column("secret", sa.String(120), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        # Set when Guardian gives up on an endpoint that has failed repeatedly, so a dead endpoint
        # stops consuming delivery attempts forever.
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_reason", sa.Text(), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"),
                  nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    create_index_if_absent("idx_webhook_endpoint_tenant", "webhook_endpoints",
                           ["tenant_id", "enabled"])


def _create_deliveries() -> None:
    op.create_table(
        "webhook_deliveries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"),
                  nullable=False),
        sa.Column("endpoint_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("webhook_endpoints.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(60), nullable=False),
        sa.Column("event_id", sa.String(64), nullable=False),
        # pending | delivered | failed | dropped
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("response_status", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        # The exact bytes that were signed and sent. Without them, "the signature did not verify"
        # is unresolvable — and they are already redacted, because the payload was.
        sa.Column("payload", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    create_index_if_absent("idx_webhook_delivery_endpoint", "webhook_deliveries",
                           ["endpoint_id", "created_at"])
    create_index_if_absent("idx_webhook_delivery_pending", "webhook_deliveries",
                           ["status", "next_attempt_at"])


def downgrade() -> None:
    for table in ("webhook_deliveries", "webhook_endpoints"):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
    op.drop_index("idx_webhook_delivery_pending", table_name="webhook_deliveries")
    op.drop_index("idx_webhook_delivery_endpoint", table_name="webhook_deliveries")
    op.drop_table("webhook_deliveries")
    op.drop_index("idx_webhook_endpoint_tenant", table_name="webhook_endpoints")
    op.drop_table("webhook_endpoints")
