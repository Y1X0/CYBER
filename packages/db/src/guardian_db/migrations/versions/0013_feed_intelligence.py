"""Vulnerability intelligence ingestion (WP-C1).

Two additions, both driven by what the platform could not do before.

`feed_state` gives a feed a **watermark**. Without one, the only honest sync is a full re-download
of every advisory ever published — roughly 280,000 CVEs — which is slow enough that it would be run
rarely, which is the opposite of what a vulnerability feed is for. With a watermark a daily run
fetches what changed since the last successful run, and a failure leaves the watermark where it was
so the next run re-fetches rather than skipping the window that failed.

`vulnerabilities.cpe_configurations` gives an advisory a machine-readable statement of *which
product versions* it applies to, in CPE terms. The existing `affected` column carries OSV package
ranges, which answers "is this dependency vulnerable"; it says nothing about "is this OpenSSH build
vulnerable", which is the question WP-B2's service fingerprints raise and WP-C3 answers.

The knowledge base is reference data shared by every tenant — an advisory is not anyone's secret —
so these tables carry no tenant column and no RLS policy, unlike everything holding customer data.

Revision ID: 0013_feed_intelligence
Revises: 0012_scheduling
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0013_feed_intelligence"
down_revision = "0012_scheduling"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column("cpe_configurations", postgresql.JSONB(), nullable=False, server_default="[]"),
    )
    # The lookup WP-C3 performs is "which advisories mention this CPE product", which is a
    # containment query over JSONB — the one thing a GIN index makes fast.
    op.create_index(
        "idx_vuln_cpe_configurations", "vulnerabilities", ["cpe_configurations"],
        postgresql_using="gin",
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("severity", sa.String(20), nullable=True),
    )

    op.create_table(
        "feed_state",
        sa.Column("source", sa.String(32), primary_key=True),
        # The high-water mark of the last SUCCESSFUL sync. A failed run must not advance it, or the
        # window it failed on is never fetched again and the gap is invisible.
        sa.Column("watermark", sa.DateTime(timezone=True), nullable=True),
        sa.Column("etag", sa.String(200), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_ingested", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON feed_state TO guardian_app")

    # `items_ingested` counted only enrichment before. A sync now reports what it created and what
    # it updated separately, because "0 new advisories" is a healthy daily result and "0 records
    # seen" is an outage, and one number cannot say both.
    op.add_column("feed_syncs", sa.Column("items_created", sa.Integer(), nullable=False,
                                          server_default="0"))
    op.add_column("feed_syncs", sa.Column("items_failed", sa.Integer(), nullable=False,
                                          server_default="0"))


def downgrade() -> None:
    op.drop_column("feed_syncs", "items_failed")
    op.drop_column("feed_syncs", "items_created")
    op.drop_table("feed_state")
    op.drop_column("vulnerabilities", "severity")
    op.drop_index("idx_vuln_cpe_configurations", table_name="vulnerabilities")
    op.drop_column("vulnerabilities", "cpe_configurations")
