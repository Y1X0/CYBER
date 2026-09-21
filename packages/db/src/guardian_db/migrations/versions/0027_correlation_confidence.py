"""Correlation confidence — how strongly the *relationship* between grouped findings is evidenced.

One additive, reversible change supporting WP-E1 slice 1:

  * `finding_correlations.confidence` — "confirmed" | "strong_evidence" | "potential". Derived by
    each correlation rule from the *kind of evidence* that established the link (an identical secret
    value → confirmed; a shared CVE/CWE key without proof of the same instance → strong_evidence; a
    customer-only key → potential), never from member count or the members' own severity/confidence.

    NOT NULL with server_default "potential" (the safest tier): existing rows predate the model and
    were persisted without recording what proved the relationship, so a historical group is labeled
    plausible-but-unproven rather than silently upgraded to confirmed. New rows carry the rule's own
    derived tier.

Revision ID: 0027_correlation_confidence
Revises: 0026_owner_direct_scan
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from guardian_db.migration_utils import add_column_if_absent, table_exists

revision = "0027_correlation_confidence"
down_revision = "0026_owner_direct_scan"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Guarded: 0001_baseline builds every registered model, so on a fresh DB the column already
    # exists. On an incrementally-migrated DB, add it NOT NULL with the safe "potential" default so
    # every pre-existing correlation is labeled without a separate backfill.
    add_column_if_absent(
        "finding_correlations",
        sa.Column("confidence", sa.String(20), nullable=False, server_default="potential"),
    )


def downgrade() -> None:
    if table_exists("finding_correlations"):
        op.drop_column("finding_correlations", "confidence")
