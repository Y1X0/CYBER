"""baseline schema — creates the full Phase 1 data model from model metadata

Using metadata.create_all for the baseline guarantees the initial migration and the SQLAlchemy
models can never diverge. Subsequent migrations are authored with `alembic revision --autogenerate`
and hand-reviewed (expand → migrate → contract; see docs/architecture/03-database-schema.md).

Revision ID: 0001_baseline
Revises:
Create Date: 2026-08-05
"""

from __future__ import annotations

from alembic import op

# Ensure all tables are registered on the metadata before create_all.
import guardian_db.models  # noqa: F401
from guardian_db.base import Base

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    # Extensions used by the platform (pgcrypto for hashing; pgvector reserved for the KB in Phase 2).
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
