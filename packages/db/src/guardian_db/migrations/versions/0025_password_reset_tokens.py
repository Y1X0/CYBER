"""Password-reset tokens: single-use, hashed, expiring (Item 6).

Stores only the SHA-256 hex of each reset token, never the raw token, so a database read cannot
reset anyone's password. `used_at` consumes a token; `expires_at` bounds its lifetime (30 minutes).

Revision ID: 0025_password_reset_tokens
Revises: 0024_user_token_version
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from guardian_db.migration_utils import create_index_if_absent, table_exists

revision = "0025_password_reset_tokens"
down_revision = "0024_user_token_version"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if not table_exists("password_reset_tokens"):
        op.create_table(
            "password_reset_tokens",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                      server_default=sa.text("gen_random_uuid()")),
            sa.Column("user_id", postgresql.UUID(as_uuid=True),
                      sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.text("now()"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      server_default=sa.text("now()"), nullable=False),
        )
    create_index_if_absent(
        "ix_password_reset_tokens_user_id", "password_reset_tokens", ["user_id"]
    )


def downgrade() -> None:
    if table_exists("password_reset_tokens"):
        op.drop_table("password_reset_tokens")
