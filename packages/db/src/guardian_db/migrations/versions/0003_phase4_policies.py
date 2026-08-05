"""phase 4 — deployment-gate policies table

Idempotent (create_all with checkfirst) so it is a no-op on a fresh DB where the baseline already
created it, and additive on a DB first created before Phase 4.

Revision ID: 0003_phase4
Revises: 0002_phase2
Create Date: 2026-08-05
"""

from __future__ import annotations

from alembic import op

import guardian_db.models  # noqa: F401
from guardian_db.base import Base

revision = "0003_phase4"
down_revision = "0002_phase2"
branch_labels = None
depends_on = None

_NEW_TABLES = ["policies"]


def upgrade() -> None:
    bind = op.get_bind()
    tables = [Base.metadata.tables[name] for name in _NEW_TABLES]
    Base.metadata.create_all(bind=bind, tables=tables, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    tables = [Base.metadata.tables[name] for name in _NEW_TABLES]
    Base.metadata.drop_all(bind=bind, tables=tables, checkfirst=True)
