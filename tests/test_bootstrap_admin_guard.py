"""Bootstrap-admin credential fail-fast (P1-B) — no DB.

The reference deployment runs `python -m guardian_api.seed` at API startup, which hashes
`bootstrap_admin_password` into an OWNER membership. The publicly-documented default `ChangeMe123!`
must never reach production: startup config fails outside local/dev, and the seed itself fails closed
before any write. local/dev/test/ci keep the convenience default.
"""

from __future__ import annotations

import pytest
from guardian_common.config import _DEFAULT_BOOTSTRAP_PASSWORD, Settings
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


# ── config fail-fast ─────────────────────────────────────────────────────────────────────────────
def test_production_default_bootstrap_password_is_rejected():
    with pytest.raises(ValidationError, match="BOOTSTRAP_ADMIN_PASSWORD must be changed"):
        _prod(bootstrap_admin_password=_DEFAULT_BOOTSTRAP_PASSWORD)


def test_production_strong_bootstrap_password_is_accepted():
    s = _prod(bootstrap_admin_password="a-strong-unique-owner-password")
    assert s.bootstrap_admin_password == "a-strong-unique-owner-password"


def test_staging_is_production_grade_for_bootstrap_password():
    with pytest.raises(ValidationError, match="BOOTSTRAP_ADMIN_PASSWORD must be changed"):
        _prod(env="staging", bootstrap_admin_password=_DEFAULT_BOOTSTRAP_PASSWORD)


@pytest.mark.parametrize("env", ["local", "dev", "development", "test", "ci"])
def test_local_and_dev_keep_the_default_password(env):
    # The dev convenience default must not break local/dev/test/ci startup.
    s = Settings(env=env)
    assert s.bootstrap_admin_password == _DEFAULT_BOOTSTRAP_PASSWORD
    assert s.is_local_or_dev is True


# ── seed fail-closed (defense in depth, no DB touched) ───────────────────────────────────────────
class _FakeSettings:
    log_level = "INFO"
    bootstrap_tenant = "T"
    bootstrap_admin_email = "a@example.com"

    def __init__(self, *, is_local_or_dev, password):  # noqa: ANN001
        self.is_local_or_dev = is_local_or_dev
        self.bootstrap_admin_password = password


def test_seed_refuses_default_owner_credential_in_production(monkeypatch):
    from guardian_api import seed as seed_mod

    monkeypatch.setattr(
        seed_mod, "get_settings",
        lambda: _FakeSettings(is_local_or_dev=False, password=_DEFAULT_BOOTSTRAP_PASSWORD))
    # Fail-closed BEFORE any DB access: session_scope must never be reached.
    monkeypatch.setattr(
        seed_mod, "session_scope",
        lambda: (_ for _ in ()).throw(AssertionError("seed reached the DB with a default password")))
    with pytest.raises(RuntimeError, match="refusing to seed the default bootstrap-admin"):
        seed_mod.seed()


def test_seed_allows_default_owner_credential_in_local(monkeypatch):
    # In local/dev the guard does not fire; the seed proceeds to its DB work (stubbed here).
    from guardian_api import seed as seed_mod

    monkeypatch.setattr(
        seed_mod, "get_settings",
        lambda: _FakeSettings(is_local_or_dev=True, password=_DEFAULT_BOOTSTRAP_PASSWORD))
    reached = {}

    class _Sentinel(RuntimeError):
        pass

    def _boom():
        reached["db"] = True
        raise _Sentinel  # prove we got PAST the guard to the DB step, without a real DB

    monkeypatch.setattr(seed_mod, "session_scope", _boom)
    with pytest.raises(_Sentinel):
        seed_mod.seed()
    assert reached.get("db") is True  # guard did NOT block the local path
