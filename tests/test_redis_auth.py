"""Redis authentication requirement (P1-δ) — config fail-fast, no live Redis.

The broker, result backend, and replay-nonce store all derive from GUARDIAN_REDIS_URL. Outside
local/dev the URL must carry AUTH credentials so a compromised execution-plane worker cannot
anonymously read/tamper the queue or the nonce store. local/dev/ci stay runnable without auth.
"""

from __future__ import annotations

import pytest
from guardian_common.config import Settings, _redis_is_authenticated
from pydantic import ValidationError

_STRONG = "x" * 40


def _prod(**over):
    base = dict(
        env="production",
        database_url="postgresql+psycopg://guardian:guardian@db:5432/guardian?sslmode=verify-full",
        app_database_url="postgresql+psycopg://guardian_app:pw@db:5432/guardian?sslmode=verify-full",
        redis_url="rediss://:rpw@redis:6379/0",
        jwt_secret=_STRONG, encryption_key=_STRONG, broker_seal_key=_STRONG + "-seal",
        bootstrap_admin_password="a-strong-admin-password",
    )
    base.update(over)
    return Settings(**base)


# ── the classifier ───────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("url", [
    "redis://:pw@h:6379/0",            # legacy password-only
    "rediss://:pw@h:6379/0",
    "redis://user:pw@h:6379/0",        # ACL user+password
    "rediss://user:strongpw@h:6379/1",
])
def test_authenticated_urls_are_accepted(url):
    assert _redis_is_authenticated(url) is True


@pytest.mark.parametrize("url", [
    "redis://h:6379/0",                # no credentials
    "rediss://h:6379/0",
    "redis://user@h:6379/0",           # username but NO password
])
def test_unauthenticated_urls_are_rejected(url):
    assert _redis_is_authenticated(url) is False


# ── production fail-fast ──────────────────────────────────────────────────────────────────────────
def test_production_rejects_unauthenticated_redis():
    with pytest.raises(ValidationError, match="AUTH credentials"):
        _prod(redis_url="rediss://redis:6379/0")   # TLS but no password


def test_production_rejects_username_without_password():
    with pytest.raises(ValidationError, match="AUTH credentials"):
        _prod(redis_url="rediss://user@redis:6379/0")


def test_production_accepts_authenticated_tls_redis():
    s = _prod(redis_url="rediss://:s3cr3t@redis:6379/0")
    assert _redis_is_authenticated(s.redis_url)


def test_staging_is_production_grade_for_redis_auth():
    with pytest.raises(ValidationError, match="AUTH credentials"):
        _prod(env="staging", redis_url="rediss://redis:6379/0")


def test_tls_is_checked_before_auth():
    # A plaintext URL fails on the TLS rule first (both are required outside local/dev).
    with pytest.raises(ValidationError, match="TLS|rediss://"):
        _prod(redis_url="redis://:pw@redis:6379/0")


@pytest.mark.parametrize("env", ["local", "dev", "development", "test", "ci"])
def test_local_and_dev_allow_unauthenticated_redis(env):
    # Tests and local dev run a passwordless Redis; the auth invariant must not fire there.
    s = Settings(env=env, redis_url="redis://localhost:6379/0")
    assert s.redis_url == "redis://localhost:6379/0"
