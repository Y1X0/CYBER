"""baseline schema — creates the full Phase 1 data model from model metadata

Using metadata.create_all for the baseline guarantees the initial migration and the SQLAlchemy
models can never diverge. Subsequent migrations are authored with `alembic revision --autogenerate`
and hand-reviewed (expand → migrate → contract; see docs/architecture/03-database-schema.md).

One consequence is easy to miss and broke every from-scratch deploy for seven migrations: because
this runs over whatever is *currently* registered, a table added to the models later is created
here too, on an empty database, before its own migration runs. `alembic upgrade head` then aborted
at the first collision (`0012_scheduling`: "relation schedules already exists"). Existing databases
were unaffected — the baseline had run long before those models existed — so the breakage was
invisible anywhere the schema had been built incrementally, and only ever showed up on a clean one.

Freezing this list is not the fix: `create_all` emits each table's *current* definition, columns and
foreign keys included, so a frozen table list still drags later columns into the baseline (findings
would gain its `correlation_id` FK to a table that does not exist yet). Instead every migration that
creates a table backing a model is replay-safe: it creates the table only if it is absent, and
applies its indexes, constraints and RLS policies either way. Both paths therefore converge on the
same schema — which `tests/integration/test_migrations.py` checks by diffing them.

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
