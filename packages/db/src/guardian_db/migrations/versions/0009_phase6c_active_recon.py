"""phase 6·C — active-recon authorization targets

Adds `authorizations.authorized_targets` (JSONB): the structured target list a scope-based active
discovery authorization grants (used when asset_id is null). Reuses the existing authorizations table
and its RLS — no new table. Additive, idempotent, reversible.

Revision ID: 0009_phase6c_recon
Revises: 0008_phase6b_edges
Create Date: 2026-08-05
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "0009_phase6c_recon"
down_revision = "0008_phase6b_edges"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    if "authorized_targets" not in {c["name"] for c in insp.get_columns("authorizations")}:
        op.add_column(
            "authorizations",
            sa.Column("authorized_targets", sa.dialects.postgresql.JSONB(),
                      nullable=False, server_default="[]"),
        )
        op.alter_column("authorizations", "authorized_targets", server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    if "authorized_targets" in {c["name"] for c in insp.get_columns("authorizations")}:
        op.drop_column("authorizations", "authorized_targets")
