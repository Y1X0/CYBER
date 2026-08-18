"""Let an API key authenticate under RLS (WP-G1b).

Authentication has a chicken-and-egg problem with row-level security: the tenant is a *property of
the credential*, so it cannot be known until the credential row has been read, and the credential
row cannot be read until the tenant is bound. The JWT path solved this in migration 0006 with
`auth_memberships` / `auth_portal` — `SECURITY DEFINER` functions that answer exactly one
authentication question and nothing else. The API-key path (WP-G1) was written against a plain
`SELECT ... FROM api_keys`, which returns zero rows under the `guardian_app` role, so a valid key
was refused with "invalid API key" in every RLS-enforced deployment — that is, in production.

`auth_api_key` is the same narrow escape hatch as its two predecessors:

* it takes the key's id, which the caller must already have presented;
* it returns only the columns authentication needs, and the caller still has to pass the
  constant-time digest comparison — the stored digest is an HMAC under a server-side pepper, so
  reading it is not a credential;
* `EXECUTE` is revoked from PUBLIC and granted to `guardian_app` alone.

Everything the request does *after* authentication still runs under RLS with the tenant bound.

Revision ID: 0019_apikey_auth_lookup
Revises: 0018_webhooks
"""

from __future__ import annotations

from alembic import op

revision = "0019_apikey_auth_lookup"
down_revision = "0018_webhooks"
branch_labels = None
depends_on = None

_FUNCTION = """
CREATE OR REPLACE FUNCTION auth_api_key(p_id uuid)
RETURNS TABLE(id uuid, tenant_id uuid, name text, key_hash text, scopes text[],
              expires_at timestamptz, revoked_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
AS $$ SELECT id, tenant_id, name::text, key_hash::text, scopes::text[],
             expires_at, revoked_at
      FROM api_keys WHERE id = p_id $$;

REVOKE ALL ON FUNCTION auth_api_key(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_api_key(uuid) TO guardian_app;
"""


def upgrade() -> None:
    op.execute(_FUNCTION)


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS auth_api_key(uuid)")
