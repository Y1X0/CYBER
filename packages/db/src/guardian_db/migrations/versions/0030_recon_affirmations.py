"""Owner-direct RECON — per-target owner affirmations for governed nmap port scanning.

The exact analogue of migration 0026's `owner_direct_affirmations`, for the network recon plane:

  * `recon_affirmations` — the tenant OWNER's one-time, per-target legal affirmation that they may
    port-scan the target. Tenant-scoped by the same RLS as every other tenant-owned table. The
    affirmation is ALSO written to the immutable audit_log; this table is the operational
    "already affirmed?" record, not an authorization grant, and is never consulted by the tool
    authorization gate or the uid+nftables egress cage.

Additive and reversible. No column is added to any existing table.

Revision ID: 0030_recon_affirmations
Revises: 0029_secret_correlation_id
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from guardian_db.migration_utils import create_index_if_absent, table_exists

revision = "0030_recon_affirmations"
down_revision = "0029_secret_correlation_id"
branch_labels = None
depends_on = None

_CUR = "NULLIF(current_setting('app.current_tenant', true), '')::uuid"


def upgrade() -> None:
    # Guarded: 0001_baseline builds every registered model, so on a fresh DB the table already
    # exists. On an incrementally-migrated DB, create it here.
    if not table_exists("recon_affirmations"):
        op.create_table(
            "recon_affirmations",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                      server_default=sa.text("gen_random_uuid()")),
            sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"),
                      nullable=False),
            sa.Column("target", sa.Text(), nullable=False),
            sa.Column("affirmed_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"),
                      nullable=False),
            sa.Column("affirmed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.text("now()"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      server_default=sa.text("now()"), nullable=False),
            sa.UniqueConstraint("tenant_id", "target", name="uq_recon_affirmation_target"),
        )

    create_index_if_absent(
        "idx_recon_affirmation_tenant", "recon_affirmations", ["tenant_id"]
    )

    # Same tenant isolation as every other tenant-owned table: Postgres itself rejects a
    # cross-tenant read or write, whatever a handler does.
    op.execute("ALTER TABLE recon_affirmations ENABLE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON recon_affirmations")
    op.execute(
        "CREATE POLICY tenant_isolation ON recon_affirmations TO guardian_app "
        f"USING (tenant_id = {_CUR}) WITH CHECK (tenant_id = {_CUR})"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON recon_affirmations TO guardian_app")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS recon_affirmations CASCADE")
