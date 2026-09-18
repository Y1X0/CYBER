"""Owner-direct scanning — scan authorization basis + per-target owner affirmations.

Two additive, reversible changes supporting the owner-direct capability (owner runs an active scan
against an unverified target, ownership gate bypassed for that scan only):

  * `scans.authorization_basis` — "verified-ownership" (the default, and every pre-existing scan)
    or "owner-direct". Set once by the API at dispatch after a server-side owner-role re-check; the
    worker reads it to decide whether to bypass the ownership gate. NOT NULL with a safe default so
    a backfill is unnecessary and no scan is ever unlabeled.
  * `owner_direct_affirmations` — the tenant OWNER's one-time, per-target legal affirmation that
    they may scan the target. Tenant-scoped by the same RLS as every other tenant-owned table. The
    affirmation is ALSO written to the immutable audit_log; this table is the operational
    "already affirmed?" record, not an authorization grant.

Revision ID: 0026_owner_direct_scan
Revises: 0025_password_reset_tokens
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from guardian_db.migration_utils import add_column_if_absent, create_index_if_absent, table_exists

revision = "0026_owner_direct_scan"
down_revision = "0025_password_reset_tokens"
branch_labels = None
depends_on = None

_CUR = "NULLIF(current_setting('app.current_tenant', true), '')::uuid"


def upgrade() -> None:
    # ── scans.authorization_basis ────────────────────────────────────────────────────────────────
    # Guarded: 0001_baseline builds every registered model, so on a fresh DB the column already
    # exists. On an incrementally-migrated DB, add it NOT NULL with a safe server default so every
    # existing scan is labeled "verified-ownership" without a separate backfill.
    add_column_if_absent(
        "scans",
        sa.Column("authorization_basis", sa.String(20), nullable=False,
                  server_default="verified-ownership"),
    )

    # ── owner_direct_affirmations ────────────────────────────────────────────────────────────────
    if not table_exists("owner_direct_affirmations"):
        op.create_table(
            "owner_direct_affirmations",
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
            sa.UniqueConstraint("tenant_id", "target",
                                name="uq_owner_direct_affirmation_target"),
        )

    create_index_if_absent(
        "idx_owner_direct_affirmation_tenant", "owner_direct_affirmations", ["tenant_id"]
    )

    # Same tenant isolation as every other tenant-owned table: Postgres itself rejects a
    # cross-tenant read or write, whatever a handler does.
    op.execute("ALTER TABLE owner_direct_affirmations ENABLE ROW LEVEL SECURITY")
    op.execute(
        "DROP POLICY IF EXISTS tenant_isolation ON owner_direct_affirmations"
    )
    op.execute(
        "CREATE POLICY tenant_isolation ON owner_direct_affirmations TO guardian_app "
        f"USING (tenant_id = {_CUR}) WITH CHECK (tenant_id = {_CUR})"
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON owner_direct_affirmations TO guardian_app"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS owner_direct_affirmations CASCADE")
    if table_exists("scans"):
        op.drop_column("scans", "authorization_basis")
