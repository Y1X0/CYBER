"""phase 6·A — attack-graph & discovery foundation (schema + contracts milestone)

Additive only — no feature logic. Creates the graph-node registry, discovery runs/scopes, and the
per-node history table; adds mandatory provenance columns to graph_edges; and enables RLS + grants on
every new tenant-scoped table so the isolation guarantee (and the CI coverage guard) holds.

Idempotent: new tables via create_all(checkfirst); columns added only if missing; policies dropped-
if-exists then recreated.

Revision ID: 0007_phase6_graph
Revises: 0006_prod_readiness
Create Date: 2026-08-05
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

import guardian_db.models  # noqa: F401 - populate Base.metadata
from guardian_db.base import Base

revision = "0007_phase6_graph"
down_revision = "0006_prod_readiness"
branch_labels = None
depends_on = None

_NEW_TABLES = ["graph_nodes", "discovery_scopes", "discovery_runs", "node_events"]
# All four carry a direct tenant_id → the standard tenant-isolation policy.
_RLS_TABLES = _NEW_TABLES

_EDGE_COLS = [
    ("source", sa.Column("source", sa.String(40), nullable=True)),
    ("confidence", sa.Column("confidence", sa.Integer(), nullable=False, server_default="100")),
    ("first_seen_at", sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True)),
    ("last_seen_at", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True)),
    ("discovery_run_id", sa.Column("discovery_run_id", sa.Uuid(), nullable=True)),
]

_CUR = "NULLIF(current_setting('app.current_tenant', true), '')::uuid"


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)

    # 1) new tables
    tables = [Base.metadata.tables[name] for name in _NEW_TABLES]
    Base.metadata.create_all(bind=bind, tables=tables, checkfirst=True)

    # 2) graph_edges provenance columns
    existing = {c["name"] for c in insp.get_columns("graph_edges")}
    for name, col in _EDGE_COLS:
        if name not in existing:
            op.add_column("graph_edges", col)
    if "confidence" not in existing:
        op.alter_column("graph_edges", "confidence", server_default=None)
    op.execute("CREATE INDEX IF NOT EXISTS idx_graph_edges_run ON graph_edges (tenant_id, discovery_run_id)")

    # 3) RLS + grants on the new tenant-scoped tables (only where the app role exists)
    if bind.execute(
        sa.text("SELECT 1 FROM pg_roles WHERE rolname = 'guardian_app'")
    ).scalar():
        for t in _RLS_TABLES:
            op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {t} TO guardian_app")
            op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
            op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
            op.execute(
                f"CREATE POLICY tenant_isolation ON {t} TO guardian_app "
                f"USING (tenant_id = {_CUR}) WITH CHECK (tenant_id = {_CUR})"
            )


def downgrade() -> None:
    for t in _RLS_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")

    op.execute("DROP INDEX IF EXISTS idx_graph_edges_run")
    bind = op.get_bind()
    insp = inspect(bind)
    existing = {c["name"] for c in insp.get_columns("graph_edges")}
    for name, _ in reversed(_EDGE_COLS):
        if name in existing:
            op.drop_column("graph_edges", name)

    tables = [Base.metadata.tables[name] for name in _NEW_TABLES]
    Base.metadata.drop_all(bind=bind, tables=tables, checkfirst=True)
