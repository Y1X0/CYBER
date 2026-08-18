"""Cross-engine correlation (WP-E1).

Nine engines now report on the same estate, and nothing joined their answers. Three of them can find
the same hardcoded credential — in the source, in the git history, in an image layer — and a customer
saw three criticals for one problem. Meanwhile the two findings that together mean "the credential is
publicly retrievable" sat in different sections of the report with nothing saying so.

`finding_correlations` records a group of findings that describe one underlying issue, and the rule
that grouped them. `finding_correlation_members` records who is in it and in what role.

**Correlation never deletes or hides a finding.** A duplicate is marked, not removed: the evidence
trail is the product, and a scanner that quietly drops one of three corroborating observations has
destroyed the thing a customer would use to check the claim. A report renders the group; the members
remain individually inspectable.

Both tables carry `tenant_id` and RLS, because a correlation names findings and therefore says what
a customer has.

Revision ID: 0015_correlation
Revises: 0014_exploit_intelligence
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from guardian_db.migration_utils import (
    add_column_if_absent,
    create_index_if_absent,
    table_exists,
)

revision = "0015_correlation"
down_revision = "0014_exploit_intelligence"
branch_labels = None
depends_on = None

_CUR = "NULLIF(current_setting('app.current_tenant', true), '')::uuid"


def upgrade() -> None:
    # Guarded: `0001_baseline` builds every registered model, so on an empty database these tables
    # and this column already exist. RLS and the grants below run either way.
    if not table_exists("finding_correlations"):
        _create_correlations()
    if not table_exists("finding_correlation_members"):
        _create_members()
    add_column_if_absent("findings", sa.Column("correlation_id", postgresql.UUID(as_uuid=True),
                                               sa.ForeignKey("finding_correlations.id"),
                                               nullable=True))

    for table in ("finding_correlations", "finding_correlation_members"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} TO guardian_app "
            f"USING (tenant_id = {_CUR}) WITH CHECK (tenant_id = {_CUR})"
        )
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO guardian_app")


def _create_correlations() -> None:
    op.create_table(
        "finding_correlations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"),
                  nullable=False),
        sa.Column("customer_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("customers.id"),
                  nullable=False),
        sa.Column("rule", sa.String(60), nullable=False),
        # Stable identity for the group, so a re-run updates it rather than creating a second one.
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("kind", sa.String(20), nullable=False, server_default="duplicate"),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        # Why the group exists and why its severity is what it is — the same auditability rule the
        # risk engine follows. An escalation a customer cannot trace is an escalation they distrust.
        sa.Column("rationale", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("member_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("tenant_id", "fingerprint", name="uq_correlation_tenant_fingerprint"),
    )
    create_index_if_absent("idx_correlation_tenant_customer", "finding_correlations",
                           ["tenant_id", "customer_id"])


def _create_members() -> None:
    op.create_table(
        "finding_correlation_members",
        sa.Column("correlation_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("finding_correlations.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"),
                  nullable=False),
        # primary | corroborating | duplicate
        sa.Column("role", sa.String(20), nullable=False, server_default="corroborating"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    create_index_if_absent("idx_correlation_member_finding", "finding_correlation_members",
                           ["finding_id"])


def downgrade() -> None:
    op.drop_column("findings", "correlation_id")
    for table in ("finding_correlation_members", "finding_correlations"):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
    op.drop_index("idx_correlation_member_finding", table_name="finding_correlation_members")
    op.drop_table("finding_correlation_members")
    op.drop_index("idx_correlation_tenant_customer", table_name="finding_correlations")
    op.drop_table("finding_correlations")
