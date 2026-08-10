"""Job-signing key boundary (P1-3) — production/tool-plane config is ENFORCED at startup, not merely
unused. No DB. Tests construct Settings with explicit `env="production"` so the production guards are
exercised directly (not only the ci env), and prove the dispatcher fail-closes without its key.
"""

from __future__ import annotations

import base64

import pytest
from guardian_common import job_signing
from guardian_common.config import Settings
from guardian_common.job_signing import JobVerificationError, sign_job
from pydantic import ValidationError

_PRIV = base64.b64encode(b"p" * 32).decode()
_PUB = base64.b64encode(b"u" * 32).decode()
_STRONG = "x" * 40
_SEAL = "s" * 40  # broker-seal key, distinct from the encryption_key master (P1-A)

# A valid production TOOL PLANE under P1-A carries NO JWT secret and NO credential KMS master — only
# the broker-seal key (to unseal jobs / seal evidence) and the public signing key (to verify).
_TOOL_PLANE_SECRETS = dict(jwt_secret="", encryption_key="", broker_seal_key=_SEAL)


def _settings(**over):
    base = dict(
        env="production",
        database_url="postgresql+psycopg://guardian:guardian@db:5432/guardian?sslmode=verify-full",
        app_database_url="postgresql+psycopg://guardian_app:pw@db:5432/guardian?sslmode=verify-full",
        redis_url="rediss://:rpw@redis:6379/0",
        encryption_key=_STRONG, jwt_secret=_STRONG, broker_seal_key=_SEAL,
        bootstrap_admin_password="a-strong-admin-password",  # P1-B: default is refused in prod
        tool_plane=False, job_signing_private_key="", job_signing_public_key="",
    )
    base.update(over)
    return Settings(**base)


# ── the critical boundary: the tool plane can NEVER hold the private key (all envs) ────────────────
def test_tool_plane_with_private_key_is_rejected_even_in_dev():
    with pytest.raises(ValidationError, match="set on the tool plane"):
        Settings(env="local", tool_plane=True, job_signing_private_key=_PRIV)


def test_production_tool_plane_with_private_key_is_rejected():
    with pytest.raises(ValidationError, match="set on the tool plane"):
        _settings(tool_plane=True, job_signing_private_key=_PRIV, job_signing_public_key=_PUB)


# ── production tool plane must carry the public key (fail-fast, not fail-at-first-job) ──────────────
def test_production_tool_plane_without_public_key_is_rejected():
    with pytest.raises(ValidationError, match="PUBLIC_KEY must be set on the tool plane"):
        _settings(tool_plane=True, job_signing_public_key="", **_TOOL_PLANE_SECRETS)


def test_production_tool_plane_with_public_key_only_is_valid():
    s = _settings(tool_plane=True, job_signing_public_key=_PUB, job_signing_private_key="",
                  **_TOOL_PLANE_SECRETS)
    assert s.tool_plane is True and s.job_signing_private_key == ""


# ── the dispatcher (control plane) may hold the private key; the API may hold neither ──────────────
def test_production_dispatcher_with_private_key_is_valid():
    s = _settings(tool_plane=False, job_signing_private_key=_PRIV, job_signing_public_key=_PUB)
    assert s.job_signing_private_key == _PRIV


def test_production_non_signing_service_without_keys_boots():
    # e.g. the API: tool_plane False, no signing keys — must still construct (it never signs/verifies).
    s = _settings(tool_plane=False, job_signing_private_key="", job_signing_public_key="")
    assert s.tool_plane is False


# ── runtime: a production signer with no private key FAILS CLOSED (required key missing) ────────────
def test_production_sign_job_fails_closed_without_private_key(monkeypatch):
    class _Prod:
        env = "production"
        is_local_or_dev = False
        job_signing_private_key = ""
        job_signing_public_key = _PUB

    monkeypatch.setattr(job_signing, "get_settings", lambda: _Prod())
    with pytest.raises(JobVerificationError, match="no job-signing private key"):
        sign_job({"tenant_id": "t", "job_id": "j", "tool_key": "nmap", "scope": {}, "settings": {}})


def test_dev_tool_plane_without_explicit_keys_is_allowed():
    # Dev/test/ci keep the deterministic in-process keypair: a tool plane with NO explicit private key
    # is fine (the boundary check only fires on an explicitly-configured private key).
    s = Settings(env="ci", tool_plane=True, job_signing_private_key="", job_signing_public_key="")
    assert s.tool_plane is True
