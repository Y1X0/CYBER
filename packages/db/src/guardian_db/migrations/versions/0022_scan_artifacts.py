"""Scan artifacts — tenant-scoped storage for uploaded .apk / .ipa binaries.

One row per uploaded artifact: the raw bytes in a `bytea`, plus size/sha256/kind metadata and the
owning asset. Isolated per tenant by Row-Level Security like every other tenant-owned table, and the
asset FK cascades so deleting an asset removes its artifacts (no orphaned, indefinitely-stored blob).

Revision ID: 0022_scan_artifacts
Revises: 0021_sbom
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from guardian_db.migration_utils import create_index_if_absent, table_exists

revision = "0022_scan_artifacts"
down_revision = "0021_sbom"
branch_labels = None
depends_on = None

_CUR = "NULLIF(current_setting('app.current_tenant', true), '')::uuid"


def upgrade() -> None:
    # Guarded: 0001_baseline builds every registered model, so on an empty database this table
    # already exists. RLS, the index, and the grant run either way.
    if not table_exists("scan_artifacts"):
        op.create_table(
            "scan_artifacts",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                      server_default=sa.text("gen_random_uuid()")),
            sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"),
                      nullable=False),
            sa.Column("customer_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("customers.id"),
                      nullable=False),
            sa.Column("asset_id", postgresql.UUID(as_uuid=True),
                      sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
            sa.Column("kind", sa.String(10), nullable=False),
            sa.Column("filename", sa.String(255), server_default="", nullable=False),
            sa.Column("content_type", sa.String(100), server_default="", nullable=False),
            sa.Column("size_bytes", sa.BigInteger(), nullable=False),
            sa.Column("sha256", sa.String(64), nullable=False),
            sa.Column("status", sa.String(20), server_default="stored", nullable=False),
            sa.Column("content", sa.LargeBinary(), nullable=False),
            sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"),
                      nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.text("now()"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      server_default=sa.text("now()"), nullable=False),
        )

    # The worker resolves an artifact by (tenant_id, asset_id); the API lists an asset's artifacts.
    create_index_if_absent(
        "ix_scan_artifacts_tenant_asset", "scan_artifacts", ["tenant_id", "asset_id"]
    )

    op.execute("ALTER TABLE scan_artifacts ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON scan_artifacts TO guardian_app "
        f"USING (tenant_id = {_CUR}) WITH CHECK (tenant_id = {_CUR})"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON scan_artifacts TO guardian_app")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS scan_artifacts CASCADE")
