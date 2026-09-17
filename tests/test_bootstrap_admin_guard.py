"""Bootstrap-admin credential fail-fast (P1-B) — no DB.

The reference deployment runs `python -m guardian_api.seed` at API startup, which hashes
`bootstrap_admin_password` into an OWNER membership. The publicly-documented default `ChangeMe123!`
must never reach production: startup config fails outside local/dev, and the seed itself fails closed
before any write. local/dev/test/ci keep the convenience default.
"""

from __future__ import annotations

import base64

import pytest
from guardian_common.config import _DEFAULT_BOOTSTRAP_PASSWORD, Settings
from pydantic import ValidationError

_STRONG = "x" * 40
_SEAL = "s" * 40
_PUB = base64.b64encode(b"u" * 32).decode()  # tool-plane public signing key (verify-only)


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


# ── config fail-fast: the SEEDING plane (API/control plane) rejects the default password ──────────
def test_production_default_bootstrap_password_is_rejected():
    # The API/control plane runs the seed and reads the password, so it must reject the default. It
    # sets none of the worker-plane markers.
    with pytest.raises(ValidationError, match="BOOTSTRAP_ADMIN_PASSWORD must be changed"):
        _prod(bootstrap_admin_password=_DEFAULT_BOOTSTRAP_PASSWORD)


# ── the WORKER planes never seed, so the password check is skipped and not required there ─────────
def test_scanner_worker_does_not_require_a_bootstrap_password():
    # The default-queue scanner worker (the burst worker's role) is DB-bound but never seeds. It must
    # boot in production with the default password untouched — because that seeding credential is not
    # meant to be forwarded into a process that parses untrusted customer files at all.
    s = _prod(scanner_worker=True, bootstrap_admin_password=_DEFAULT_BOOTSTRAP_PASSWORD)
    assert s.scanner_worker is True
    assert s.bootstrap_admin_password == _DEFAULT_BOOTSTRAP_PASSWORD  # accepted, not rejected


def test_tool_plane_does_not_require_a_bootstrap_password():
    s = _prod(
        tool_plane=True, jwt_secret="", encryption_key="", broker_seal_key=_SEAL,
        app_database_url="", job_signing_public_key=_PUB,
        bootstrap_admin_password=_DEFAULT_BOOTSTRAP_PASSWORD,
    )
    assert s.tool_plane is True
    assert s.bootstrap_admin_password == _DEFAULT_BOOTSTRAP_PASSWORD


def test_recon_plane_does_not_require_a_bootstrap_password():
    s = _prod(
        recon_plane=True, jwt_secret="", encryption_key="", app_database_url="",
        bootstrap_admin_password=_DEFAULT_BOOTSTRAP_PASSWORD,
    )
    assert s.recon_plane is True
    assert s.bootstrap_admin_password == _DEFAULT_BOOTSTRAP_PASSWORD


def test_scanner_worker_marker_defaults_false_so_the_api_still_enforces():
    # Guard against the marker silently defaulting True (which would disable the API check): a plain
    # control-plane Settings has scanner_worker False and still rejects the default password.
    assert _prod().scanner_worker is False


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
