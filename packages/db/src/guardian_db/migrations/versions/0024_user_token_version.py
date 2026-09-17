"""Add users.token_version for server-side access-token revocation.

Every access token carries the `token_version` it was minted at (JWT claim `tv`); the API rejects a
token whose `tv` does not match the user's current value. Bumping the column (logout, password
change/reset, account disable) invalidates every token issued before the bump — stateless
revocation with no server-side token store. Existing tokens (and any minted without a `tv` claim)
are treated as version 0, which matches the DEFAULT here, so this migration is backwards compatible.

Revision ID: 0024_user_token_version
Revises: 0023_strip_path_asset_config
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from guardian_db.migration_utils import column_exists, table_exists

revision = "0024_user_token_version"
down_revision = "0023_strip_path_asset_config"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if not table_exists("users") or column_exists("users", "token_version"):
        return
    op.add_column(
        "users",
        sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"),
    )
    # Drop the server_default so future inserts go through the model default rather than the DDL
    # constant — the column stays NOT NULL with existing rows backfilled to 0.
    op.alter_column("users", "token_version", server_default=None)


def downgrade() -> None:
    if table_exists("users") and column_exists("users", "token_version"):
        op.drop_column("users", "token_version")
