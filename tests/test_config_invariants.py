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
        redis_url="rediss://:rpw@db:6379/0",
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


# ── the broker URL Celery will accept ─────────────────────────────────────────────────────────────
#
# Celery refuses to construct a Redis result backend for a `rediss://` URL with no `ssl_cert_reqs`
# and raises at construction, so every worker dies at startup while the API — which only publishes
# and never touches the backend — keeps working. `celery_redis_url` closes that in code so a
# correct-but-incomplete secret cannot take the workers down wherever it is set.
def test_a_tls_broker_url_without_the_parameter_gets_the_verifying_one():
    from guardian_common.config import celery_redis_url

    assert celery_redis_url("rediss://:pw@host:6379/0") == (
        "rediss://:pw@host:6379/0?ssl_cert_reqs=required"
    )


def test_an_existing_choice_is_never_overwritten():
    """The operator said what they wanted. Rewriting it would hide a misconfiguration."""
    from guardian_common.config import celery_redis_url

    for url in (
        "rediss://:pw@host:6379/0?ssl_cert_reqs=CERT_OPTIONAL",
        "rediss://:pw@host:6379/0?ssl_cert_reqs=required&socket_timeout=5",
        "rediss://:pw@host:6379/0?socket_timeout=5&ssl_cert_reqs=CERT_REQUIRED",
    ):
        assert celery_redis_url(url) == url


def test_an_existing_query_is_preserved_and_appended_to():
    from guardian_common.config import celery_redis_url

    assert celery_redis_url("rediss://:pw@host:6379/0?socket_timeout=5") == (
        "rediss://:pw@host:6379/0?socket_timeout=5&ssl_cert_reqs=required"
    )


def test_a_plaintext_broker_url_is_untouched():
    """`redis://` needs no TLS parameter, and adding one would change a working local setup."""
    from guardian_common.config import celery_redis_url

    for url in ("redis://localhost:6379/0", "redis://:pw@host:6379/2?socket_timeout=5", ""):
        assert celery_redis_url(url) == url


def test_a_url_that_will_not_parse_is_handed_on_unchanged():
    """Celery should report a broken URL. Swallowing it here would only move the error."""
    from guardian_common.config import celery_redis_url

    for url in ("not a url at all", "rediss://[oops", "://missing-scheme"):
        assert celery_redis_url(url) == url


def test_the_credentials_survive_normalisation():
    from urllib.parse import urlsplit

    from guardian_common.config import celery_redis_url

    parts = urlsplit(celery_redis_url("rediss://user:s3cret@host:6379/0"))
    assert parts.username == "user"
    assert parts.password == "s3cret"  # noqa: S105 - fixture value, not a real credential


def test_normalising_does_not_change_what_the_production_validator_reads():
    """The validator inspects `settings.redis_url`; normalisation happens at the Celery boundary.

    And a URL that already carries the parameter — an operator who fixed it in the secret instead —
    must still satisfy the TLS and AUTH invariants rather than newly failing them.
    """
    from guardian_common.config import _redis_is_authenticated

    fixed_in_the_secret = "rediss://:pw@host:6379/0?ssl_cert_reqs=required"
    assert fixed_in_the_secret.startswith("rediss://")
    assert _redis_is_authenticated(fixed_in_the_secret)

    settings = _settings(redis_url="rediss://:pw@host:6379/0")
    assert settings.redis_url == "rediss://:pw@host:6379/0"
