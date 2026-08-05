"""phase 5A — Row-Level Security (tenant isolation hard gate)

Creates a non-owner `guardian_app` role and enables RLS so the API (which connects as guardian_app)
can only ever see rows for `app.current_tenant`. The table owner (`guardian`) and workers bypass RLS
for legitimate cross-tenant operation (a worker scans one tenant's asset; a feed sync updates the
shared KB). This is a hard backstop *underneath* the application-level tenant scoping in the routers.

Tables fall into five scoping shapes:
  * direct       — a `tenant_id` column: USING/CHECK (tenant_id = current)
  * child        — scoped through a parent row (no tenant_id of their own): the FK must resolve to a
                   parent the caller's tenant owns
  * self         — the `tenants` row itself: id = current
  * org          — `policies`, scoped by organization_id
  * append-only  — audit_log/domain_events: SELECT scoped by tenant; INSERT always allowed so
                   pre-tenant-context events (e.g. failed login) can still be recorded

Genuinely global reference data (users, plans, KB, vulns, feeds, scanner_plugins) keeps no RLS — the
app role reads it freely; identity resolution itself runs on the privileged (admin) session.

Idempotent: role creation is guarded; policies are dropped-if-exists then recreated.

Revision ID: 0005_phase5_rls
Revises: 0004_phase5
Create Date: 2026-08-05
"""

from __future__ import annotations

from alembic import op

revision = "0005_phase5_rls"
down_revision = "0004_phase5"
branch_labels = None
depends_on = None

_CUR = "NULLIF(current_setting('app.current_tenant', true), '')::uuid"

# Tables scoped by a direct tenant_id column.
_DIRECT = [
    "tenant_memberships", "customers", "assets", "engagements", "authorizations",
    "scans", "findings", "remediation_items", "reports", "api_keys",
    "usage_records", "subscriptions", "tenant_scanner_configs", "graph_edges", "evidence_items",
]
# Child tables with no tenant_id — scoped by resolving a FK to a parent the tenant owns.
# (table, fk_column, parent_table)
_CHILD = [
    ("customer_contacts", "customer_id", "customers"),
    ("report_sections", "report_id", "reports"),
    ("report_approvals", "report_id", "reports"),
    ("scan_engine_runs", "scan_id", "scans"),
    ("finding_events", "finding_id", "findings"),
]
_SELF = ["tenants"]  # the tenant's own row: id = current
_ORG = ["policies"]  # scoped by organization_id
_APPEND = ["audit_log", "domain_events"]  # scope reads by tenant; always allow inserts

# Every table that gets RLS turned on (used by upgrade/downgrade symmetrically).
_ALL_RLS = (
    _DIRECT + [c[0] for c in _CHILD] + _SELF + _ORG + _APPEND
)


def _policy(table: str, predicate: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
    op.execute(
        f"CREATE POLICY tenant_isolation ON {table} TO guardian_app "
        f"USING ({predicate}) WITH CHECK ({predicate})"
    )


def upgrade() -> None:
    op.execute(
        """
        DO $$ BEGIN
          IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'guardian_app') THEN
            -- No password literal here; it is set from the environment in migration 0006.
            CREATE ROLE guardian_app LOGIN;
          END IF;
        END $$;
        """
    )
    op.execute("GRANT USAGE ON SCHEMA public TO guardian_app")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO guardian_app")
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO guardian_app")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO guardian_app"
    )

    for t in _DIRECT:
        _policy(t, f"tenant_id = {_CUR}")
    for table, fk, parent in _CHILD:
        # Identifiers come from the fixed _CHILD list, not user input — safe DDL interpolation.
        _policy(table, f"{fk} IN (SELECT id FROM {parent} WHERE tenant_id = {_CUR})")  # noqa: S608
    for t in _SELF:
        _policy(t, f"id = {_CUR}")
    for t in _ORG:
        _policy(t, f"organization_id = {_CUR}")

    # Append-only: reads are tenant-scoped, inserts are always permitted (system/pre-auth events
    # may carry a null tenant_id, e.g. a failed login recorded before any tenant context exists).
    for t in _APPEND:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS tenant_read ON {t}")
        op.execute(f"DROP POLICY IF EXISTS tenant_append ON {t}")
        op.execute(
            f"CREATE POLICY tenant_read ON {t} FOR SELECT TO guardian_app "
            f"USING (tenant_id = {_CUR})"
        )
        op.execute(f"CREATE POLICY tenant_append ON {t} FOR INSERT TO guardian_app WITH CHECK (true)")


def downgrade() -> None:
    for t in _DIRECT + [c[0] for c in _CHILD] + _SELF + _ORG:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
    for t in _APPEND:
        op.execute(f"DROP POLICY IF EXISTS tenant_read ON {t}")
        op.execute(f"DROP POLICY IF EXISTS tenant_append ON {t}")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
