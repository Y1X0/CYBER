"""Domain ownership verification (WP-F1).

`Authorization.method` has always had a value `ownership_verified`, and nothing verified ownership.
A human asserted it and the platform believed them. That is the single control standing between a
customer and an active scan of somebody else's domain, and it was a checkbox.

`domain_verifications` is the proof. A customer is issued a random token, publishes it where only
the domain's owner can — a DNS TXT record, or a file under `/.well-known/` on the domain itself —
and Guardian goes and reads it. Only then is an `Authorization` created.

The token is per verification and high entropy, so one customer's proof cannot be replayed for
another's domain, and it expires, so an authorization cannot rest on a record that was removed a
year ago.

Revision ID: 0017_ownership_verification
Revises: 0016_verification
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from guardian_db.migration_utils import create_index_if_absent, table_exists

revision = "0017_ownership_verification"
down_revision = "0016_verification"
branch_labels = None
depends_on = None

_CUR = "NULLIF(current_setting('app.current_tenant', true), '')::uuid"


def upgrade() -> None:
    # Guarded: `0001_baseline` builds every registered model, so on an empty database this table
    # already exists. RLS and the grant below run either way.
    if not table_exists("domain_verifications"):
        _create()

    op.execute("ALTER TABLE domain_verifications ENABLE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON domain_verifications TO guardian_app "
        f"USING (tenant_id = {_CUR}) WITH CHECK (tenant_id = {_CUR})"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON domain_verifications TO guardian_app")


def _create() -> None:
    op.create_table(
        "domain_verifications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"),
                  nullable=False),
        sa.Column("customer_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("customers.id"),
                  nullable=False),
        sa.Column("domain", sa.String(253), nullable=False),
        # dns_txt | http_file
        sa.Column("method", sa.String(20), nullable=False),
        # The secret the customer must publish. Unique across the whole table: a token that could
        # collide is a token that could be replayed against another tenant's domain.
        sa.Column("token", sa.String(80), nullable=False),
        # pending | verified | failed | expired | revoked
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        # A proof is not permanent. An authorization resting on a record removed a year ago is an
        # authorization nobody has re-consented to.
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authorization_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("authorizations.id"), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"),
                  nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("token", name="uq_domain_verification_token"),
    )
    create_index_if_absent("idx_domain_verification_tenant", "domain_verifications",
                           ["tenant_id", "domain"])


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON domain_verifications")
    op.drop_index("idx_domain_verification_tenant", table_name="domain_verifications")
    op.drop_table("domain_verifications")
