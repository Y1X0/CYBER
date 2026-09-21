"""Keyed secret-correlation identity on findings (WP-E1 same-secret collision fix).

One additive, reversible column: ``findings.secret_correlation_id``.

WHY a column and not an evidence key. The ``same-secret`` correlation rule used the lossy display
redaction as the secret's identity, so two different credentials whose redactions collide (any two
values of equal length ≤ 8, or sharing first-two/last-two/length) were grouped and marked CONFIRMED
— a false relationship. The fix derives a keyed, one-way identity (HMAC-SHA256 under a server-side
key) from the raw secret at detection time. That identity is internal: it must persist so a re-scan
correlates the same credential, but it must never reach a customer. ``findings.evidence`` is
serialized to customers through several paths, so the identity lives in its own column that no
serializer reads, and is relocated out of ``evidence`` at normalize time.

Nullable with no default and no backfill: it is NULL for non-secret findings, for gitleaks findings
(pre-redacted, no raw value to key), and for every finding created before this migration. A NULL
identity never confers CONFIRMED — legacy findings fall back to the conservative value/position
basis (STRONG_EVIDENCE at most). Nothing historical is upgraded.

Revision ID: 0029_finding_secret_correlation_id
Revises: 0028_correlation_ordered_edges
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from guardian_db.migration_utils import add_column_if_absent, table_exists

revision = "0029_finding_secret_correlation_id"
down_revision = "0028_correlation_ordered_edges"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Guarded: 0001_baseline builds every registered model, so on a fresh DB the column already
    # exists. On an incrementally-migrated DB, add it nullable with no default — never backfilled,
    # so historical findings carry no fabricated identity.
    add_column_if_absent(
        "findings", sa.Column("secret_correlation_id", sa.String(64), nullable=True))


def downgrade() -> None:
    if table_exists("findings"):
        op.drop_column("findings", "secret_correlation_id")
