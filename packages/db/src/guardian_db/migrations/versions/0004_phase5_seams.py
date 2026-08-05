"""phase 5B — foundational seams (graph_edges, domain_events, evidence_items) + asset provenance

Idempotent: new tables via create_all(checkfirst); asset columns added only if missing. Tier-1
seams only — storage foundations, no feature logic (graph analysis, event consumers, evidence
workflow all land in later phases).

Revision ID: 0004_phase5
Revises: 0003_phase4
Create Date: 2026-08-05
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

import guardian_db.models  # noqa: F401
from guardian_db.base import Base

revision = "0004_phase5"
down_revision = "0003_phase4"
branch_labels = None
depends_on = None

_NEW_TABLES = ["graph_edges", "domain_events", "evidence_items"]
_ASSET_COLS = [
    ("source", sa.Column("source", sa.String(20), nullable=False, server_default="declared")),
    ("state", sa.Column("state", sa.String(20), nullable=False, server_default="active")),
    ("discovered_by_scan_id", sa.Column("discovered_by_scan_id", sa.Uuid(), nullable=True)),
    ("first_seen_at", sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True)),
    ("secret_ref", sa.Column("secret_ref", sa.Text(), nullable=True)),
]


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)

    tables = [Base.metadata.tables[name] for name in _NEW_TABLES]
    Base.metadata.create_all(bind=bind, tables=tables, checkfirst=True)

    existing = {c["name"] for c in insp.get_columns("assets")}
    for name, col in _ASSET_COLS:
        if name not in existing:
            op.add_column("assets", col)
    # Drop server defaults for the enum-like columns now that rows are backfilled.
    for name in ("source", "state"):
        if name not in existing:
            op.alter_column("assets", name, server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    existing = {c["name"] for c in insp.get_columns("assets")}
    for name, _ in reversed(_ASSET_COLS):
        if name in existing:
            op.drop_column("assets", name)
    tables = [Base.metadata.tables[name] for name in _NEW_TABLES]
    Base.metadata.drop_all(bind=bind, tables=tables, checkfirst=True)
