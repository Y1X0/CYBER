"""Production-invariant fail-fast tests (Prod-Readiness sprint) — no DB required.

These lock in that a misconfiguration which would silently weaken security refuses to start rather
than serving without the backstop: RLS inert (owner-role fallback), or credentials sealed with the
dev sentinel key. Staging is treated as production-grade throughout.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

_STRONG_JWT = "a-strong-secret-value-not-the-sentinel-0123456789"
_STRONG_KEY = "a-strong-encryption-key-0123456789abcdef"
_OWNER_URL = "postgresql+psycopg://guardian:guardian@db:5432/guardian?sslmode=verify-full"
_APP_URL = "postgresql+psycopg://guardian_app:pw@db:5432/guardian?sslmode=verify-full"


def _settings(**over):
    from guardian_common.config import Settings

    base = dict(
        env="production", database_url=_OWNER_URL, app_database_url=_APP_URL,
        redis_url="rediss://db:6379/0",
        jwt_secret=_STRONG_JWT, encryption_key=_STRONG_KEY,
        broker_seal_key=_STRONG_KEY + "-seal",  # P1-A: must be set and distinct from encryption_key
        bootstrap_admin_password="a-strong-admin-password",  # P1-B: default is refused in prod
    )
    base.update(over)
    return Settings(**base)


def test_production_requires_distinct_app_database_url():
    with pytest.raises(ValidationError, match="APP_DATABASE_URL"):
        _settings(app_database_url="")
    with pytest.raises(ValidationError, match="APP_DATABASE_URL"):
        _settings(app_database_url=_OWNER_URL)  # same as owner → RLS inert


def test_production_requires_real_encryption_key():
    with pytest.raises(ValidationError, match="ENCRYPTION_KEY"):
        _settings(encryption_key="")
    with pytest.raises(ValidationError, match="ENCRYPTION_KEY"):
        _settings(encryption_key="dev-only-encryption-key-change-me")  # the sentinel


def test_staging_is_production_grade():
    with pytest.raises(ValidationError):
        _settings(env="staging", app_database_url="")


def test_local_is_permissive():
    # Local/dev may omit everything (dev sentinels are allowed) — no raise.
    from guardian_common.config import Settings

    s = Settings(env="local", app_database_url="", encryption_key="")
    assert s.is_local_or_dev is True


def test_valid_production_config_constructs():
    s = _settings()
    assert not s.is_local_or_dev
    assert s.app_database_url != s.database_url
