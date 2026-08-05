"""phase 2 — vulnerability knowledge base + risk-score columns

Adds the KB tables (vulnerabilities, weaknesses, advisories, kb_entries, feed_syncs) and the Risk
Engine columns on findings (risk_score, risk_rationale).

This migration is written DEFENSIVELY (idempotent). The baseline migration uses
`metadata.create_all`, which always reflects the *current* models — so on a brand-new database the
baseline already creates these objects and this migration becomes a no-op. On a database that was
first created at the Phase-1 era (before these models existed), this migration adds them. Both paths
converge on the same schema.

Revision ID: 0002_phase2
Revises: 0001_baseline
Create Date: 2026-08-05
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.dialects.postgresql import JSONB

# Register all tables on the metadata before create_all.
import guardian_db.models  # noqa: F401
from guardian_db.base import Base

revision = "0002_phase2"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None

_NEW_TABLES = ["vulnerabilities", "weaknesses", "advisories", "kb_entries", "feed_syncs"]


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)

    # Create any KB tables that don't already exist (checkfirst skips existing).
    tables = [Base.metadata.tables[name] for name in _NEW_TABLES]
    Base.metadata.create_all(bind=bind, tables=tables, checkfirst=True)

    # Add the Risk Engine columns only if missing.
    finding_cols = {c["name"] for c in insp.get_columns("findings")}
    if "risk_score" not in finding_cols:
        op.add_column(
            "findings",
            sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        )
        op.alter_column("findings", "risk_score", server_default=None)
    if "risk_rationale" not in finding_cols:
        op.add_column(
            "findings",
            sa.Column("risk_rationale", JSONB(), nullable=False, server_default="[]"),
        )
        op.alter_column("findings", "risk_rationale", server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    finding_cols = {c["name"] for c in insp.get_columns("findings")}
    if "risk_rationale" in finding_cols:
        op.drop_column("findings", "risk_rationale")
    if "risk_score" in finding_cols:
        op.drop_column("findings", "risk_score")
    tables = [Base.metadata.tables[name] for name in _NEW_TABLES]
    Base.metadata.drop_all(bind=bind, tables=tables, checkfirst=True)
