"""Burst-worker secret boundary (review Issue 4) — proves the secrets it carries are REQUIRED, and
that the execution planes still refuse them. No DB.

The reviewer flagged the burst worker passing GUARDIAN_JWT_SECRET + GUARDIAN_ENCRYPTION_KEY to the
scanner image as a plane-isolation violation. It is not: that job runs `celery ... --queues default`,
which is the trusted CONTROL PLANE (identical role to `worker-default` in docker-compose) — it
authorizes, decrypts `secret_ref` with the KMS master, and persists. The plane-secret boundary
(P1-A) is enforced by config validation, which REQUIRES the JWT secret + KMS master on the control
plane and FORBIDS them on the DB-less execution planes (tool/recon). Removing them from the burst
worker would make it fail config validation and refuse to boot.

These tests lock that in from both sides: the config invariant, and a static check that the burst
worker does not mark itself an execution plane (so the secrets it carries are the ones it needs).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from guardian_common.config import Settings
from pydantic import ValidationError

_ROOT = Path(__file__).resolve().parents[1]
_STRONG = "x" * 40
_SEAL = "s" * 40


def _settings(**over):
    base = dict(
        env="production",
        database_url="postgresql+psycopg://guardian:guardian@db:5432/guardian?sslmode=verify-full",
        app_database_url="postgresql+psycopg://guardian_app:pw@db:5432/guardian?sslmode=verify-full",
        redis_url="rediss://:rpw@redis:6379/0",
        encryption_key=_STRONG, jwt_secret=_STRONG, broker_seal_key=_SEAL,
        bootstrap_admin_password="a-strong-admin-password",
        tool_plane=False, recon_plane=False,
    )
    base.update(over)
    return Settings(**base)


# ── config invariant: control plane REQUIRES these, execution planes REFUSE them ─────────────────
def test_control_plane_requires_jwt_and_encryption_key():
    # The role the burst worker runs (default queue, no plane marker) must have both to boot.
    s = _settings()
    assert s.jwt_secret == _STRONG and s.encryption_key == _STRONG
    with pytest.raises(ValidationError, match="GUARDIAN_JWT_SECRET must be set"):
        _settings(jwt_secret="change-me-dev-only-do-not-use-in-production")
    with pytest.raises(ValidationError, match="GUARDIAN_ENCRYPTION_KEY must be set"):
        _settings(encryption_key="")


def test_tool_plane_refuses_jwt_and_encryption_key():
    # The DB-less execution plane is where these secrets are forbidden — proving the boundary is
    # real and is NOT what the burst worker runs.
    with pytest.raises(ValidationError, match="JWT_SECRET must NOT be set on the tool/recon"):
        _settings(tool_plane=True, jwt_secret=_STRONG, encryption_key="", broker_seal_key=_SEAL,
                  app_database_url="")
    with pytest.raises(ValidationError, match="ENCRYPTION_KEY .* must NOT be set on the"):
        _settings(tool_plane=True, jwt_secret="", encryption_key=_STRONG, broker_seal_key=_SEAL,
                  app_database_url="")


def test_recon_plane_refuses_the_kms_master():
    with pytest.raises(ValidationError, match="ENCRYPTION_KEY .* must NOT be set on the"):
        _settings(recon_plane=True, jwt_secret="", encryption_key=_STRONG, broker_seal_key=_SEAL,
                  app_database_url="")


# ── static check: the burst worker is the CONTROL plane, so its secret set is the right one ──────
def _consume_step() -> dict:
    wf = yaml.safe_load((_ROOT / ".github/workflows/guardian-burst-worker.yml").read_text())
    steps = wf["jobs"]["drain"]["steps"]
    for step in steps:
        if step.get("name") == "Consume the default queue":
            return step
    raise AssertionError("could not find the 'Consume the default queue' step")


def test_burst_worker_consumes_the_default_control_plane_queue():
    step = _consume_step()
    run = step["run"]
    assert "--queues default" in run                     # control-plane queue, not recon/tools
    assert "--queues recon" not in run and "--queues tools" not in run


def test_burst_worker_is_not_marked_an_execution_plane():
    # If it set GUARDIAN_TOOL_PLANE/RECON_PLANE=true while carrying JWT/ENCRYPTION, config validation
    # would REJECT it. It does not — it is the control plane, so those secrets are required, not a leak.
    step = _consume_step()
    env = step.get("env", {})
    run = step["run"]
    for marker in ("GUARDIAN_TOOL_PLANE", "GUARDIAN_RECON_PLANE"):
        assert str(env.get(marker, "")).lower() != "true"
        assert f"{marker}=true" not in run and f"-e {marker}=true" not in run


def test_burst_worker_only_forwards_control_plane_secrets():
    # The container env is constructed explicitly with `-e` flags. Assert it forwards exactly the
    # control-plane secret set and nothing else secret-shaped (no stray API-only material).
    run = _consume_step()["run"]
    expected = {
        "GUARDIAN_DATABASE_URL", "GUARDIAN_APP_DATABASE_URL", "GUARDIAN_REDIS_URL",
        "GUARDIAN_JWT_SECRET", "GUARDIAN_ENCRYPTION_KEY", "GUARDIAN_BROKER_SEAL_KEY",
    }
    forwarded = {tok for line in run.splitlines() for tok in line.split()
                 if tok.startswith("GUARDIAN_") and tok.isupper()}
    # Every secret-ish var forwarded is one the control-plane worker genuinely needs.
    stray = forwarded - expected - {"GUARDIAN_ENV"}
    assert stray == set(), f"unexpected vars forwarded to the scanner container: {stray}"
