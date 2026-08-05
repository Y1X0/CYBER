"""production-readiness sprint — auth bootstrap functions, indexes, asset identity, role password

Closes the pre-Phase-6 hardening items that touch the schema:
  * SECURITY DEFINER auth-lookup functions so the API resolves identity on the RLS app session
    (no second, owner-privileged connection per request). They are owner-owned (bypass RLS),
    parameterized by the JWT-verified user id, and expose only that user's memberships/portal rows.
  * Indexes on tenant_id / child FKs so RLS predicates and list queries stay index-backed as the
    high-volume tables (findings, scans, assets, graph_edges, events, evidence) grow in Phase 6.
  * Asset `last_seen_at` + a partial-unique natural identity, so continuous discovery upserts
    instead of duplicating rows.
  * The guardian_app role password is set from the environment (never a committed literal).

Idempotent throughout (CREATE ... IF NOT EXISTS / OR REPLACE, inspector-guarded column add).

Revision ID: 0006_prod_readiness
Revises: 0005_phase5_rls
Create Date: 2026-08-05
"""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "0006_prod_readiness"
down_revision = "0005_phase5_rls"
branch_labels = None
depends_on = None

_LOCAL_ENVS = {"local", "dev", "development", "test", "ci"}
_PW_OK = re.compile(r"^[A-Za-z0-9_\-!@#%^&*=+.:]{8,128}$")

# name -> DDL body (everything after "CREATE [UNIQUE] INDEX IF NOT EXISTS <name> ")
_INDEXES: list[tuple[str, str]] = [
    ("idx_scans_tenant_created", "ON scans (tenant_id, created_at)"),
    ("idx_scans_tenant_customer", "ON scans (tenant_id, customer_id)"),
    ("idx_customers_tenant", "ON customers (tenant_id)"),
    ("idx_reports_tenant_created", "ON reports (tenant_id, created_at)"),
    ("idx_engagements_tenant_customer", "ON engagements (tenant_id, customer_id)"),
    ("idx_authorizations_asset", "ON authorizations (asset_id)"),
    ("idx_authorizations_tenant", "ON authorizations (tenant_id)"),
    ("idx_remediation_tenant_customer", "ON remediation_items (tenant_id, customer_id)"),
    ("idx_remediation_finding", "ON remediation_items (finding_id)"),
    ("idx_usage_tenant", "ON usage_records (tenant_id)"),
    ("idx_subscriptions_tenant", "ON subscriptions (tenant_id)"),
    ("idx_apikeys_tenant", "ON api_keys (tenant_id)"),
    ("idx_tsc_tenant", "ON tenant_scanner_configs (tenant_id)"),
    ("idx_evidence_finding", "ON evidence_items (finding_id)"),
    ("idx_evidence_tenant", "ON evidence_items (tenant_id)"),
    ("idx_scan_engine_runs_scan", "ON scan_engine_runs (scan_id)"),
    ("idx_finding_events_finding", "ON finding_events (finding_id)"),
    ("idx_report_sections_report", "ON report_sections (report_id)"),
    ("idx_report_approvals_report", "ON report_approvals (report_id)"),
    ("idx_customer_contacts_customer", "ON customer_contacts (customer_id)"),
    ("idx_customer_contacts_user", "ON customer_contacts (user_id)"),
    ("idx_tenant_memberships_user", "ON tenant_memberships (user_id)"),
    ("idx_domain_events_tenant", "ON domain_events (tenant_id, occurred_at)"),
    ("idx_assets_tenant_customer", "ON assets (tenant_id, customer_id)"),
    ("idx_assets_tenant_state_source", "ON assets (tenant_id, state, source)"),
]

_AUTH_FUNCTIONS = """
CREATE OR REPLACE FUNCTION auth_memberships(p_user uuid)
RETURNS TABLE(tenant_id uuid, role text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
AS $$ SELECT tenant_id, role FROM tenant_memberships WHERE user_id = p_user $$;

CREATE OR REPLACE FUNCTION auth_portal(p_user uuid)
RETURNS TABLE(customer_id uuid, tenant_id uuid, role text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
AS $$ SELECT cc.customer_id, c.tenant_id, cc.role
      FROM customer_contacts cc JOIN customers c ON c.id = cc.customer_id
      WHERE cc.user_id = p_user $$;

REVOKE ALL ON FUNCTION auth_memberships(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_portal(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_memberships(uuid) TO guardian_app;
GRANT EXECUTE ON FUNCTION auth_portal(uuid) TO guardian_app;
"""


def _app_role_password() -> str:
    env = (os.environ.get("GUARDIAN_ENV") or "local").lower()
    pw = os.environ.get("GUARDIAN_APP_DB_PASSWORD")
    if not pw:
        if env not in _LOCAL_ENVS:
            raise RuntimeError(
                "GUARDIAN_APP_DB_PASSWORD must be set outside local/dev to secure the guardian_app "
                "role (it must match the password in GUARDIAN_APP_DATABASE_URL)"
            )
        pw = "guardian_app"  # dev-only default, matches the local/CI app URL
    if not _PW_OK.match(pw):
        raise RuntimeError("GUARDIAN_APP_DB_PASSWORD contains unsupported characters")
    return pw


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)

    # 1) asset last_seen_at (guarded)
    if "last_seen_at" not in {c["name"] for c in insp.get_columns("assets")}:
        op.add_column(
            "assets", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True)
        )

    # 2) indexes (idempotent)
    for name, body in _INDEXES:
        op.execute(f"CREATE INDEX IF NOT EXISTS {name} {body}")
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_asset_identity "
        "ON assets (tenant_id, customer_id, kind, identifier) WHERE identifier <> ''"
    )

    # 3) SECURITY DEFINER auth-lookup functions (only where the app role exists)
    if bind.execute(
        sa.text("SELECT 1 FROM pg_roles WHERE rolname = 'guardian_app'")
    ).scalar():
        op.execute(_AUTH_FUNCTIONS)
        # 4) set the app role password from the environment (never a committed literal)
        op.execute(f"ALTER ROLE guardian_app PASSWORD '{_app_role_password()}'")


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS auth_memberships(uuid)")
    op.execute("DROP FUNCTION IF EXISTS auth_portal(uuid)")
    op.execute("DROP INDEX IF EXISTS uq_asset_identity")
    for name, _ in _INDEXES:
        op.execute(f"DROP INDEX IF EXISTS {name}")
    bind = op.get_bind()
    insp = inspect(bind)
    if "last_seen_at" in {c["name"] for c in insp.get_columns("assets")}:
        op.drop_column("assets", "last_seen_at")
