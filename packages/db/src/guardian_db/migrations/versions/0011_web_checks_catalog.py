"""web_checks catalog registration

Register the first L3 provider (`web_checks`) in `tool_catalog`. Governance refuses any UNREGISTERED
L3+ provider (`_catalog_block`: a sensitive provider not in the catalog is denied), so the L3
`web_checks` provider must be part of the reproducible deployment state — not a runtime/admin insert.

Additive and idempotent (ON CONFLICT DO NOTHING). No table/column/RLS change; `metadata` is supplied
explicitly (NOT NULL, no server default). No schema change beyond the seed row.

Revision ID: 0011_web_checks_catalog
Revises: 0010_phase_b_governance
Create Date: 2026-08-10
"""

from __future__ import annotations

from alembic import op

revision = "0011_web_checks_catalog"
down_revision = "0010_phase_b_governance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "INSERT INTO tool_catalog (provider_key, version, enabled, metadata) VALUES "
        "('web_checks','1',true,'{}') "
        "ON CONFLICT (provider_key) DO NOTHING"
    )


def downgrade() -> None:
    op.execute("DELETE FROM tool_catalog WHERE provider_key = 'web_checks'")
