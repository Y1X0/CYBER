"""PostgreSQL TLS enforcement (P1-C) — no live DB.

The database carries envelope-encrypted credentials, customer PII, and the evidence chain, so its
connection must be encrypted in transit outside local/dev — symmetric with the Redis rediss:// rule
(P1-4). libpq/psycopg enforces TLS via the DSN's `sslmode`; only require/verify-ca/verify-full
actually establish TLS (disable/allow/prefer skip it or fall back to plaintext). CI and local/dev use
a plaintext localhost DB and must be unaffected.
"""

from __future__ import annotations

import pytest
from guardian_common.config import Settings, _postgres_enforces_tls
from pydantic import ValidationError

_STRONG = "x" * 40
_OWNER_TLS = "postgresql+psycopg://guardian:guardian@db:5432/guardian?sslmode=verify-full"
_APP_TLS = "postgresql+psycopg://guardian_app:pw@db:5432/guardian?sslmode=verify-full"


def _prod(**over):
    base = dict(
        env="production",
        database_url=_OWNER_TLS, app_database_url=_APP_TLS, redis_url="rediss://:rpw@redis:6379/0",
        jwt_secret=_STRONG, encryption_key=_STRONG, broker_seal_key=_STRONG + "-seal",
        bootstrap_admin_password="a-strong-admin-password",
    )
    base.update(over)
    return Settings(**base)


# ── the sslmode classifier ───────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("mode", ["require", "verify-ca", "verify-full"])
def test_tls_sslmodes_are_accepted(mode):
    assert _postgres_enforces_tls(f"postgresql+psycopg://u:p@h:5432/db?sslmode={mode}") is True


@pytest.mark.parametrize("mode", ["disable", "allow", "prefer"])
def test_non_tls_sslmodes_are_rejected(mode):
    # prefer/allow can silently fall back to plaintext; disable never encrypts.
    assert _postgres_enforces_tls(f"postgresql+psycopg://u:p@h:5432/db?sslmode={mode}") is False


def test_missing_sslmode_is_not_tls():
    assert _postgres_enforces_tls("postgresql+psycopg://u:p@h:5432/db") is False


# ── production config fail-fast ──────────────────────────────────────────────────────────────────
def test_production_rejects_plaintext_database_url():
    with pytest.raises(ValidationError, match="GUARDIAN_DATABASE_URL must enforce TLS"):
        _prod(database_url="postgresql+psycopg://guardian:guardian@db:5432/guardian")


def test_production_rejects_plaintext_app_database_url():
    with pytest.raises(ValidationError, match="GUARDIAN_APP_DATABASE_URL must enforce TLS"):
        _prod(app_database_url="postgresql+psycopg://guardian_app:pw@db:5432/guardian")


def test_production_rejects_sslmode_prefer():
    with pytest.raises(ValidationError, match="must enforce TLS"):
        _prod(database_url="postgresql+psycopg://guardian:guardian@db:5432/guardian?sslmode=prefer")


def test_production_accepts_tls_database_urls():
    s = _prod()
    assert _postgres_enforces_tls(s.database_url) and _postgres_enforces_tls(s.app_database_url)


def test_staging_is_production_grade_for_db_tls():
    with pytest.raises(ValidationError, match="must enforce TLS"):
        _prod(env="staging", database_url="postgresql+psycopg://guardian:guardian@db:5432/guardian")


def test_execution_plane_with_empty_db_url_is_unaffected():
    # The DB-less tool plane has an empty database_url; the TLS check must skip it (no false failure).
    s = _prod(tool_plane=True, database_url="", app_database_url="",
              jwt_secret="", encryption_key="", job_signing_public_key="cHViLWtleQ==")
    assert s.tool_plane is True and s.database_url == ""


@pytest.mark.parametrize("env", ["local", "dev", "development", "test", "ci"])
def test_local_and_dev_allow_plaintext_database(env):
    s = Settings(env=env, database_url="postgresql+psycopg://guardian:guardian@localhost:5432/guardian")
    assert s.database_url.endswith("/guardian")   # no TLS required off production


# ── the actual SQLAlchemy engine carries the TLS sslmode through to the driver ───────────────────
def test_sqlalchemy_engine_preserves_sslmode(monkeypatch):
    # Prove the mechanism is real: a TLS DSN builds an engine whose driver connect args carry sslmode.
    # create_engine does NOT connect here (lazy), so no live TLS server is needed.
    monkeypatch.setenv("GUARDIAN_ENV", "ci")
    from guardian_db import session as db_session

    engine = db_session._make_engine(_OWNER_TLS)
    # SQLAlchemy parses the query string into the URL; psycopg consumes sslmode as a connect arg.
    assert engine.url.query.get("sslmode") == "verify-full"
    cargs = engine.dialect.create_connect_args(engine.url)[1]
    assert cargs.get("sslmode") == "verify-full"
    engine.dispose()
