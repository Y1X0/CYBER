"""Validation and retest (WP-E2).

A finding was created and never revisited. A customer who fixed something had no way to have that
confirmed, and a finding that came back after being fixed came back as a *new* finding with no
history — so nobody could see that the same problem had been fixed twice.

`finding_verifications` is the record of each time a finding was checked and what was concluded.
It is a separate table rather than a column because the history is the point: "resolved on the 3rd,
still present on the 10th, resolved again on the 24th" is a fact about how the remediation is going,
and a single last-verdict column throws it away.

The verdict vocabulary is deliberately four values, not two. `not_checked` exists because **absence
of a finding is only evidence when the check actually ran** — if the engine that produced a finding
failed, was skipped, or ran degraded, the finding not reappearing says nothing, and calling that
"resolved" would silently close real vulnerabilities on the strength of a broken scan.

Revision ID: 0016_verification
Revises: 0015_correlation
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

revision = "0016_verification"
down_revision = "0015_correlation"
branch_labels = None
depends_on = None

_CUR = "NULLIF(current_setting('app.current_tenant', true), '')::uuid"


def upgrade() -> None:
    # Guarded: `0001_baseline` builds every registered model, so on an empty database this table and
    # these columns already exist. RLS and the grant below run either way.
    if not table_exists("finding_verifications"):
        _create()

    op.execute("ALTER TABLE finding_verifications ENABLE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON finding_verifications TO guardian_app "
        f"USING (tenant_id = {_CUR}) WITH CHECK (tenant_id = {_CUR})"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON finding_verifications TO guardian_app")

    add_column_if_absent("findings", sa.Column("last_verified_at", sa.DateTime(timezone=True),
                                               nullable=True))
    add_column_if_absent("findings", sa.Column("verification_verdict", sa.String(20),
                                               nullable=True))
    # How many times this exact issue has come back after being resolved. A finding on its third
    # reopen is a process problem, not a scanning problem, and the number is what shows that.
    add_column_if_absent("findings", sa.Column("reopened_count", sa.Integer(), nullable=False,
                                               server_default="0"))


def _create() -> None:
    op.create_table(
        "finding_verifications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"),
                  nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        # The scan that produced the evidence for this verdict, when there was one.
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id"),
                  nullable=True),
        # still_present | resolved | not_checked | inconclusive
        sa.Column("verdict", sa.String(20), nullable=False),
        # rescan | manual | correlation
        sa.Column("method", sa.String(20), nullable=False, server_default="rescan"),
        sa.Column("engine", sa.String(30), nullable=True),
        # Why this verdict and not another — the same auditability rule the risk engine follows.
        sa.Column("rationale", sa.Text(), nullable=False, server_default=""),
        sa.Column("evidence", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    create_index_if_absent("idx_verification_finding", "finding_verifications",
                           ["finding_id", "checked_at"])


def downgrade() -> None:
    op.drop_column("findings", "reopened_count")
    op.drop_column("findings", "verification_verdict")
    op.drop_column("findings", "last_verified_at")
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON finding_verifications")
    op.drop_index("idx_verification_finding", table_name="finding_verifications")
    op.drop_table("finding_verifications")
