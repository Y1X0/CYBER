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
from sqlalchemy.dialects.postgresql import JSONB

revision = "0010_phase_b_governance"
down_revision = "0009_phase6c_recon"
branch_labels = None
depends_on = None

_CUR = "NULLIF(current_setting('app.current_tenant', true), '')::uuid"
_TENANT_TABLES = ("campaigns", "approvals", "capability_grants")
_GLOBAL_TABLES = ("platform_grants", "tool_catalog")


def _ts_cols() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
    ]


def upgrade() -> None:
    # ── global: platform roles ──
    op.create_table(
        "platform_grants",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("granted_by", sa.Uuid(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        *_ts_cols(),
        sa.CheckConstraint("role IN ('platform_owner','platform_admin')", name="ck_platform_role"),
    )
    op.create_index("uq_platform_grant_active", "platform_grants", ["user_id", "role"],
                    unique=True, postgresql_where=sa.text("revoked_at IS NULL"))

    # ── global: tool catalog (enablement/policy only; primitives stay in code) ──
    op.create_table(
        "tool_catalog",
        sa.Column("provider_key", sa.String(60), primary_key=True),
        sa.Column("version", sa.String(20), server_default="", nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("requires_campaign", sa.Boolean(), nullable=True),
        sa.Column("requires_approval", sa.Boolean(), nullable=True),
        sa.Column("metadata", JSONB(), server_default="{}", nullable=False),
        *_ts_cols(),
    )

    # ── tenant: campaigns ──
    op.create_table(
        "campaigns",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("customer_id", sa.Uuid(), sa.ForeignKey("customers.id"), nullable=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("status", sa.String(20), server_default="draft", nullable=False),
        sa.Column("max_capability_level", sa.Integer(), nullable=False),
        sa.Column("scope", JSONB(), server_default="{}", nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.Uuid(), sa.ForeignKey("users.id"), nullable=True),
        *_ts_cols(),
        sa.CheckConstraint(
            "status IN ('draft','active','suspended','completed','revoked')",
            name="ck_campaign_state"),
    )
    op.create_index("idx_campaigns_tenant_status", "campaigns", ["tenant_id", "status"])

    op.create_table(
        "campaign_members",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("campaign_id", sa.Uuid(),
                  sa.ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("role_in_campaign", sa.String(20), nullable=False),
        *_ts_cols(),
        sa.UniqueConstraint("campaign_id", "user_id", name="uq_campaign_member"),
        sa.CheckConstraint("role_in_campaign IN ('operator','approver','observer')",
                           name="ck_campaign_member_role"),
    )

    # ── tenant: approvals (L3+ only) ──
    op.create_table(
        "approvals",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("campaign_id", sa.Uuid(), sa.ForeignKey("campaigns.id"), nullable=True),
        sa.Column("subject_kind", sa.String(20), nullable=False),
        sa.Column("provider_key", sa.String(60), nullable=True),
        sa.Column("capability_level", sa.Integer(), nullable=False),
        sa.Column("scope_snapshot", JSONB(), server_default="{}", nullable=False),
        sa.Column("requested_by", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("approver_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("reason", sa.Text(), server_default="", nullable=False),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.Uuid(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        *_ts_cols(),
        sa.CheckConstraint("subject_kind IN ('campaign','tool_job')", name="ck_approval_subject"),
        sa.CheckConstraint("capability_level < 4 OR approver_id <> requested_by",
                           name="ck_approval_independent_high"),
    )
    op.create_index("idx_approvals_tenant_campaign", "approvals", ["tenant_id", "campaign_id"])
    op.create_index("idx_approvals_tenant_expires", "approvals", ["tenant_id", "expires_at"])

    # ── tenant: capability grants ──
    op.create_table(
        "capability_grants",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("subject_kind", sa.String(20), nullable=False),
        sa.Column("subject_ref", sa.String(64), nullable=False),
        sa.Column("max_level", sa.Integer(), nullable=False),
        sa.Column("tool_allowlist", JSONB(), nullable=True),
        sa.Column("granted_by", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        *_ts_cols(),
        sa.CheckConstraint("subject_kind IN ('user','role','api_key')", name="ck_grant_subject"),
    )
    op.create_index("idx_capability_grants_tenant_subject", "capability_grants",
                    ["tenant_id", "subject_ref"])

    # ── link executions/authorizations to campaigns (nullable, additive) ──
    op.add_column("authorizations", sa.Column("campaign_id", sa.Uuid(), nullable=True))
    op.create_foreign_key("fk_authz_campaign", "authorizations", "campaigns",
                          ["campaign_id"], ["id"], ondelete="SET NULL")
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
    op.execute(
        "INSERT INTO tool_catalog (provider_key, version, enabled) VALUES "
        "('web_tls','1',true),('pcap_meta','1',true),('dns_posture','1',true) "
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
