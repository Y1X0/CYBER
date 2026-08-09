"""phase B — persistent authorization governance

Additive, reversible. Adds the Phase-B governance tables (platform_grants, campaigns,
campaign_members, approvals, capability_grants, tool_catalog), links campaigns to authorizations and
scans via nullable FKs, applies the existing tenant_isolation RLS to the new tenant-scoped tables,
enables RLS (no app policy) on the global tables, seeds the current platform owner(s) and the three
shipped providers, exposes a SECURITY DEFINER `platform_role()` reader, and makes `audit_log` truly
immutable (blocks UPDATE/DELETE even for the owner via normal DML).

No migration 0001–0009 is touched. Existing behavior (L0–L2 providers) is unchanged: the new columns
are nullable and default to no campaign.

Revision ID: 0010_phase_b_governance
Revises: 0009_phase6c_recon
Create Date: 2026-08-08
"""

from __future__ import annotations

import os

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

import guardian_db.models  # noqa: F401 - populate Base.metadata
from guardian_db.base import Base

revision = "0010_phase_b_governance"
down_revision = "0009_phase6c_recon"
branch_labels = None
depends_on = None

_CUR = "NULLIF(current_setting('app.current_tenant', true), '')::uuid"
_TENANT_TABLES = ("campaigns", "approvals", "capability_grants")
_GLOBAL_TABLES = ("platform_grants", "tool_catalog")

# The Phase-B tables, in FK order (create_all resolves ordering, but this documents intent). Their
# columns, indexes, and CHECK/UNIQUE constraints all live on the models — the single source of truth.
_PHASE_B_TABLES = ("platform_grants", "tool_catalog", "campaigns", "campaign_members",
                   "approvals", "capability_grants")


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)

    # ── Phase-B tables (idempotent; same model-authoritative pattern as 0002/0003/0004/0007).
    # On a fresh DB the baseline create_all already built these from the models, so checkfirst makes
    # this a no-op there; on an incrementally-migrated DB it creates them for real. Every index and
    # CHECK/UNIQUE constraint is defined on the models, so create_all materializes them too — the
    # explicit create_table/create_index that used to live here duplicated the baseline and collided.
    tables = [Base.metadata.tables[name] for name in _PHASE_B_TABLES]
    Base.metadata.create_all(bind=bind, tables=tables, checkfirst=True)

    # ── link executions/authorizations to campaigns (nullable, additive; guarded like 0009) ──
    # These columns are NOT on the models, so the baseline does not add them — add only if missing,
    # and pair each FK with its column so both are existence-safe on a re-run.
    if "campaign_id" not in {c["name"] for c in insp.get_columns("authorizations")}:
        op.add_column("authorizations", sa.Column("campaign_id", sa.Uuid(), nullable=True))
        op.create_foreign_key("fk_authz_campaign", "authorizations", "campaigns",
                              ["campaign_id"], ["id"], ondelete="SET NULL")
    if "campaign_id" not in {c["name"] for c in insp.get_columns("scans")}:
        op.add_column("scans", sa.Column("campaign_id", sa.Uuid(), nullable=True))
        op.create_foreign_key("fk_scan_campaign", "scans", "campaigns",
                              ["campaign_id"], ["id"], ondelete="SET NULL")

    # ── RLS: tenant tables follow the existing tenant_isolation pattern ──
    for t in _TENANT_TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {t} TO guardian_app "
            f"USING (tenant_id = {_CUR}) WITH CHECK (tenant_id = {_CUR})"
        )
    # campaign_members: scoped through its parent campaign (child pattern). _CUR is a fixed literal.
    op.execute("ALTER TABLE campaign_members ENABLE ROW LEVEL SECURITY")
    _cm = f"campaign_id IN (SELECT id FROM campaigns WHERE tenant_id = {_CUR})"  # noqa: S608
    op.execute(
        "CREATE POLICY tenant_isolation ON campaign_members TO guardian_app "
        f"USING ({_cm}) WITH CHECK ({_cm})"
    )
    # Global tables: RLS on with NO app policy ⇒ the app role sees nothing; owner/worker bypass.
    for t in _GLOBAL_TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")

    # ── SECURITY DEFINER reader so the API can check platform authority without table access ──
    op.execute(
        """
        CREATE OR REPLACE FUNCTION platform_role(p_user uuid) RETURNS text
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
          SELECT role FROM platform_grants
          WHERE user_id = p_user AND revoked_at IS NULL
          ORDER BY role LIMIT 1
        $$;
        """
    )
    op.execute("REVOKE ALL ON FUNCTION platform_role(uuid) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION platform_role(uuid) TO guardian_app")

    # ── audit_log immutability: block UPDATE/DELETE even for the owner via normal DML ──
    op.execute(
        """
        CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'audit_log is append-only and cannot be modified';
        END; $$;
        """
    )
    op.execute(
        "CREATE TRIGGER audit_log_no_mutation BEFORE UPDATE OR DELETE ON audit_log "
        "FOR EACH ROW EXECUTE FUNCTION audit_log_immutable()"
    )

    # ── seed: current platform owner(s) from config, and the three shipped providers ──
    owner_ids = [x.strip() for x in os.getenv("GUARDIAN_PLATFORM_OWNER_IDS", "").split(",")
                 if x.strip()]
    if owner_ids:
        op.execute(
            sa.text(
                "INSERT INTO platform_grants (id, user_id, role) "
                "SELECT gen_random_uuid(), u.id, 'platform_owner' FROM users u "
                "WHERE u.id::text = ANY(:ids)"
            ).bindparams(sa.bindparam("ids", value=owner_ids, expanding=False))
        )
    # metadata is NOT NULL with only a Python-side default on the model (no server default), so this
    # raw INSERT supplies it explicitly rather than relying on a DB default.
    op.execute(
        "INSERT INTO tool_catalog (provider_key, version, enabled, metadata) VALUES "
        "('web_tls','1',true,'{}'),('pcap_meta','1',true,'{}'),('dns_posture','1',true,'{}') "
        "ON CONFLICT (provider_key) DO NOTHING"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_mutation ON audit_log")
    op.execute("DROP FUNCTION IF EXISTS audit_log_immutable()")
    op.execute("DROP FUNCTION IF EXISTS platform_role(uuid)")

    bind = op.get_bind()
    insp = inspect(bind)
    if "campaign_id" in {c["name"] for c in insp.get_columns("scans")}:
        op.drop_constraint("fk_scan_campaign", "scans", type_="foreignkey")
        op.drop_column("scans", "campaign_id")
    if "campaign_id" in {c["name"] for c in insp.get_columns("authorizations")}:
        op.drop_constraint("fk_authz_campaign", "authorizations", type_="foreignkey")
        op.drop_column("authorizations", "campaign_id")

    for t in ("approvals", "campaign_members", "capability_grants", "campaigns",
              "tool_catalog", "platform_grants"):
        op.execute(f"DROP TABLE IF EXISTS {t} CASCADE")
