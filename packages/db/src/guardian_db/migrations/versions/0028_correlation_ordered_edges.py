"""Ordered correlation members + per-edge relationship evidence (WP-E1 slice 2).

Four additive, reversible columns on ``finding_correlation_members``:

  * ``ordinal`` — a deterministic PRESENTATION order within a correlation (primary first, then by
    finding id). It is NOT a causal/attack sequence; E1 stays direction-neutral. NOT NULL with a
    server_default of 0, then backfilled to distinct per-group ordinals below.
  * ``edge_source_finding_id`` / ``edge_rationale`` / ``edge_confidence`` — the single incoming
    RELATIONSHIP edge each non-primary member carries (source, why, and how strongly that pair is
    evidenced: confirmed | strong_evidence | potential). All nullable and left NULL for historical
    rows: the evidence that would justify an edge was not recorded before this slice, so it is NOT
    fabricated here — a group is preserved without inventing edges, and correlation populates real,
    recomputed edges the next time it runs.

The ordinal IS backfilled, because presentation order can be derived honestly from identifiers the
rows already carry (the primary role and the finding id) without asserting any relationship. The
backfill is deterministic: primary first, then finding id — never insertion order or a timestamp.

Revision ID: 0028_correlation_ordered_edges
Revises: 0027_correlation_confidence
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from guardian_db.migration_utils import add_column_if_absent, table_exists

revision = "0028_correlation_ordered_edges"
down_revision = "0027_correlation_confidence"
branch_labels = None
depends_on = None

_TABLE = "finding_correlation_members"


def upgrade() -> None:
    # Guarded: 0001_baseline builds every registered model, so on a fresh DB these already exist. On
    # an incrementally-migrated DB, add them; ordinal NOT NULL with a safe default, the edge columns
    # nullable so historical rows carry no fabricated edge.
    add_column_if_absent(
        _TABLE, sa.Column("ordinal", sa.Integer(), nullable=False, server_default="0"))
    add_column_if_absent(
        _TABLE, sa.Column("edge_source_finding_id", postgresql.UUID(as_uuid=True), nullable=True))
    add_column_if_absent(
        _TABLE, sa.Column("edge_rationale", sa.Text(), nullable=True))
    add_column_if_absent(
        _TABLE, sa.Column("edge_confidence", sa.String(20), nullable=True))

    # Backfill a deterministic presentation ordinal for existing rows: within each correlation, the
    # primary member is 0 and the rest follow by finding id. This is stable, independent of
    # insertion order, and asserts no relationship — only how a report renders the group. Edge
    # columns are deliberately NOT backfilled.
    if table_exists(_TABLE):
        # _TABLE is a module-level constant (this file's own table name), never user input — the
        # S608 heuristic only sees an f-string near UPDATE. No value here comes from a request.
        backfill = f"""
            UPDATE {_TABLE} AS m
            SET ordinal = ranked.rn - 1
            FROM (
                SELECT correlation_id, finding_id,
                       ROW_NUMBER() OVER (
                           PARTITION BY correlation_id
                           ORDER BY (role = 'primary') DESC, finding_id
                       ) AS rn
                FROM {_TABLE}
            ) AS ranked
            WHERE m.correlation_id = ranked.correlation_id
              AND m.finding_id = ranked.finding_id
        """  # noqa: S608
        op.execute(backfill)


def downgrade() -> None:
    if table_exists(_TABLE):
        op.drop_column(_TABLE, "edge_confidence")
        op.drop_column(_TABLE, "edge_rationale")
        op.drop_column(_TABLE, "edge_source_finding_id")
        op.drop_column(_TABLE, "ordinal")
