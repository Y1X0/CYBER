"""phase 6·B — edge lifecycle + edge identity (for upsert dedup)

Adds `graph_edges.state` (active|stale|removed) so a relation that disappears is retired, not
deleted (history preserved), and a unique edge identity so re-observing the same relation upserts
instead of duplicating. Additive + reversible + idempotent.

Revision ID: 0008_phase6b_edges
Revises: 0007_phase6_graph
Create Date: 2026-08-05
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "0008_phase6b_edges"
down_revision = "0007_phase6_graph"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    cols = {c["name"] for c in insp.get_columns("graph_edges")}
    if "state" not in cols:
        op.add_column(
            "graph_edges",
            sa.Column("state", sa.String(20), nullable=False, server_default="active"),
        )
        op.alter_column("graph_edges", "state", server_default=None)
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_graph_edge_identity "
        "ON graph_edges (tenant_id, src_type, src_id, relation, dst_type, dst_id)"
    )


def downgrade() -> None:
    # On a fresh DB the baseline create_all builds this as a CONSTRAINT (from the model); a real
    # 0007->0008 upgrade builds a plain unique INDEX. Drop whichever form exists.
    op.execute("ALTER TABLE graph_edges DROP CONSTRAINT IF EXISTS uq_graph_edge_identity")
    op.execute("DROP INDEX IF EXISTS uq_graph_edge_identity")
    bind = op.get_bind()
    insp = inspect(bind)
    if "state" in {c["name"] for c in insp.get_columns("graph_edges")}:
        op.drop_column("graph_edges", "state")
