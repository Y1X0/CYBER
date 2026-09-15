"""Proof-of-Vulnerability vault — encrypted, per-tenant safe-reproduction evidence.

One row per finding's proof: metadata in the clear (vuln_class, method) for filtering, the proof
body encrypted at rest (`sealed_proof`), and a SHA-256 of the plaintext so tampering with the
ciphertext is detectable on read. Isolated per tenant by Row-Level Security like every other
tenant-owned table — a viewer can only ever reach their own tenant's proofs.

Revision ID: 0020_proof_vault
Revises: 0019_apikey_auth_lookup
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from guardian_db.migration_utils import create_index_if_absent, table_exists

revision = "0020_proof_vault"
down_revision = "0019_apikey_auth_lookup"
branch_labels = None
depends_on = None

_CUR = "NULLIF(current_setting('app.current_tenant', true), '')::uuid"


def upgrade() -> None:
    # Guarded: 0001_baseline builds every registered model, so on an empty database this table
    # already exists. RLS, the index, and the grant run either way.
    if not table_exists("proof_of_vulnerabilities"):
        op.create_table(
            "proof_of_vulnerabilities",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                      server_default=sa.text("gen_random_uuid()")),
            sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"),
                      nullable=False),
            sa.Column("customer_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("customers.id"),
                      nullable=True),
            sa.Column("finding_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("findings.id"),
                      nullable=False),
            sa.Column("vuln_class", sa.String(64), server_default="", nullable=False),
            sa.Column("method", sa.String(40), server_default="", nullable=False),
            sa.Column("safe", sa.Boolean(), server_default=sa.text("true"), nullable=False),
            sa.Column("sealed_proof", sa.Text(), nullable=False),
            sa.Column("content_sha256", sa.String(64), nullable=False),
            sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"),
                      nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.text("now()"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      server_default=sa.text("now()"), nullable=False),
        )

    create_index_if_absent(
        "ix_proof_of_vulnerabilities_finding_id", "proof_of_vulnerabilities", ["finding_id"])

    op.execute("ALTER TABLE proof_of_vulnerabilities ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON proof_of_vulnerabilities TO guardian_app "
        f"USING (tenant_id = {_CUR}) WITH CHECK (tenant_id = {_CUR})"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON proof_of_vulnerabilities TO guardian_app")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS proof_of_vulnerabilities CASCADE")
