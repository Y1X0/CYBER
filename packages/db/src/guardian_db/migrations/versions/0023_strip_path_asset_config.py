"""Strip server-side filesystem-path keys from existing asset config (AUD-P1-6 cleanup).

A tenant/staff-controlled asset config could carry keys like `local_path`, `apk_path`, `ipa_path`,
`workspace_path`, `artifact_path` or `image_archive`. A stale scanner image honoured such a key as a
workspace/artifact path and read arbitrary files off the worker, which holds ENCRYPTION_KEY and
JWT_SECRET (AUD-P1-6). The API now refuses these keys on write; this migration removes any that were
stored before that guard existed, so no already-persisted row can feed a path to a worker.

Only top-level keys are stripped (that is where these values live). The number of rows changed is
printed; the removed VALUES are never logged (they may be filesystem paths chosen by a user).

Revision ID: 0023_strip_path_asset_config
Revises: 0022_scan_artifacts
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from guardian_db.migration_utils import table_exists

revision = "0023_strip_path_asset_config"
down_revision = "0022_scan_artifacts"
branch_labels = None
depends_on = None

# Rebuild each affected config as the object of its non-path keys. `LIKE '%\\_path' ESCAPE '\\'`
# matches a key ending in the literal "_path"; `image_archive` is named explicitly. The WHERE clause
# limits the UPDATE to rows that actually carry such a key, so the reported rowcount is the number of
# rows changed.
_STRIP_SQL = r"""
UPDATE assets AS a
SET config = COALESCE(
    (
        SELECT jsonb_object_agg(e.key, e.value)
        FROM jsonb_each(a.config) AS e
        WHERE e.key NOT LIKE '%\_path' ESCAPE '\'
          AND e.key <> 'image_archive'
    ),
    '{}'::jsonb
)
WHERE EXISTS (
    SELECT 1
    FROM jsonb_each(a.config) AS e
    WHERE e.key LIKE '%\_path' ESCAPE '\'
       OR e.key = 'image_archive'
)
"""


def upgrade() -> None:
    if not table_exists("assets"):
        return
    result = op.get_bind().execute(sa.text(_STRIP_SQL))
    # rowcount is the number of asset rows from which at least one path key was removed.
    print(f"0023: stripped filesystem-path keys from {result.rowcount} asset config row(s)")


def downgrade() -> None:
    # Irreversible: the removed keys were a security defect and their values are not retained.
    pass
