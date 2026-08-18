"""Helpers that make a migration replay-safe on an empty database.

`0001_baseline` builds the schema from `Base.metadata`, which means it creates whatever is
registered *at the time it runs* — including tables and columns whose own migrations come later. On
a database that already existed, those later migrations ran against a schema the baseline had not
anticipated and everything was consistent. On an empty one the baseline gets there first, and the
later migration fails with "relation already exists" — which is how `alembic upgrade head` stopped
working from scratch while every incrementally-upgraded database looked fine.

So a migration that creates a model-backed table or column asks first. Everything else it does —
constraints, RLS policies, grants — runs either way, because those are the parts the baseline does
not produce, and the parts whose absence would leave a silently weaker database.

Guarding is not the same as tolerating drift: `tests/integration/test_migrations.py` builds a
database from scratch and compares it, object by object, against one built incrementally. If a
migration's DDL and its model disagree, that test says so.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


def table_exists(name: str) -> bool:
    """Whether the table is already present, e.g. because the baseline's `create_all` made it."""
    return sa.inspect(op.get_bind()).has_table(name)


def column_exists(table: str, column: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table(table):
        return False
    return any(col["name"] == column for col in inspector.get_columns(table))


def index_exists(table: str, name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table(table):
        return False
    return any(idx["name"] == name for idx in inspector.get_indexes(table))


def add_column_if_absent(table: str, column: sa.Column) -> None:
    if not column_exists(table, column.name):
        op.add_column(table, column)


def create_index_if_absent(name: str, table: str, columns: list[str], **kwargs) -> None:
    if not index_exists(table, name):
        op.create_index(name, table, columns, **kwargs)


__all__ = [
    "add_column_if_absent",
    "column_exists",
    "create_index_if_absent",
    "index_exists",
    "table_exists",
]
