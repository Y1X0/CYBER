"""SBOM store — per-scan CycloneDX dependency inventory of a scanned asset.

One row per scan that resolved a dependency inventory: the CycloneDX document in plain JSONB (an
SBOM is a deliverable, not a secret) plus counts for list views. Isolated per tenant by Row-Level
Security like every other tenant-owned table.

Revision ID: 0021_sbom
Revises: 0020_proof_vault
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from guardian_db.migration_utils import create_index_if_absent, table_exists

revision = "0021_sbom"
down_revision = "0020_proof_vault"
branch_labels = None
depends_on = None

_CUR = "NULLIF(current_setting('app.current_tenant', true), '')::uuid"


def upgrade() -> None:
    # Guarded: 0001_baseline builds every registered model, so on an empty database this table
    # already exists. RLS, the index, and the grant run either way.
    if not table_exists("sbom_documents"):
        op.create_table(
            "sbom_documents",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                      server_default=sa.text("gen_random_uuid()")),
            sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"),
                      nullable=False),
            sa.Column("customer_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("customers.id"),
                      nullable=True),
            sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id"),
                      nullable=False),
            sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id"),
                      nullable=True),
            sa.Column("bom_format", sa.String(20), server_default="CycloneDX", nullable=False),
            sa.Column("spec_version", sa.String(10), server_default="1.5", nullable=False),
            sa.Column("component_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("vulnerable_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("document", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"),
                      nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.text("now()"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      server_default=sa.text("now()"), nullable=False),
        )

    create_index_if_absent("ix_sbom_documents_scan_id", "sbom_documents", ["scan_id"])

    op.execute("ALTER TABLE sbom_documents ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON sbom_documents TO guardian_app "
        f"USING (tenant_id = {_CUR}) WITH CHECK (tenant_id = {_CUR})"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON sbom_documents TO guardian_app")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS sbom_documents CASCADE")
