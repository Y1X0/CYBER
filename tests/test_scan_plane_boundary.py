"""ISSUE-3: untrusted engine execution is isolated from the master keys.

Three properties, from three angles:

  * config REFUSES to boot a `scan` plane that carries the KMS master or the JWT secret (mirrors the
    tool/recon execution-plane boundary);
  * the fork sandbox scrubs every GUARDIAN_* secret from the child before running engine code; and
  * an engine round-trips through the scan-plane task using only the broker-seal key and JSON, and a
    finding survives the crossing (so a scan still completes through the new queue).
"""

from __future__ import annotations

import base64
import json
import os

import pytest
from guardian_common.config import Settings
from guardian_core.enums import EngineKey
from guardian_core.findings import RawFinding
from guardian_scanner import sandbox
from guardian_scanner.engines.base import ScanContext
from pydantic import ValidationError

_STRONG = "x" * 40
_SEAL = "s" * 40
_PUB = base64.b64encode(b"u" * 32).decode()


def _prod(**over):
    base = dict(
        env="production",
        database_url="postgresql+psycopg://guardian:guardian@db:5432/guardian?sslmode=verify-full",
        app_database_url="postgresql+psycopg://guardian_app:pw@db:5432/guardian?sslmode=verify-full",
        redis_url="rediss://:rpw@redis:6379/0",
        encryption_key=_STRONG, jwt_secret=_STRONG, broker_seal_key=_SEAL,
        bootstrap_admin_password="a-strong-admin-password",
    )
    base.update(over)
    return Settings(**base)


# A valid production SCAN plane: DB-less, no JWT, no KMS master — only the broker-seal key (to
# unseal its job + sealed creds and seal its findings). Same shape as the tool plane.
_SCAN_PLANE = dict(
    scan_plane=True, jwt_secret="", encryption_key="", broker_seal_key=_SEAL,
    app_database_url="", database_url="",
)


# ── A. config boundary: the scan plane refuses the master keys ────────────────────────────────────
def test_scan_plane_refuses_the_jwt_secret():
    with pytest.raises(ValidationError, match="JWT_SECRET must NOT be set on the tool/recon/scan"):
        _prod(**{**_SCAN_PLANE, "jwt_secret": _STRONG})


def test_scan_plane_refuses_the_kms_master():
    with pytest.raises(ValidationError, match="ENCRYPTION_KEY .* must NOT be set on the"):
        _prod(**{**_SCAN_PLANE, "encryption_key": _STRONG})


def test_valid_scan_plane_boots_with_only_the_seal_key():
    s = _prod(**_SCAN_PLANE)
    assert s.scan_plane is True
    assert s.jwt_secret == "" and s.encryption_key == ""
    assert s.broker_seal_key == _SEAL   # it keeps the seal key — it seals/unseals broker payloads


def test_scan_plane_still_requires_the_seal_key():
    # The scan plane seals its results, so a missing broker-seal key must fail like the tool plane.
    with pytest.raises(ValidationError, match="BROKER_SEAL_KEY must be set"):
        _prod(**{**_SCAN_PLANE, "broker_seal_key": ""})


# ── B. the fork sandbox scrubs GUARDIAN_* from the child (item 4) ──────────────────────────────────
@pytest.mark.skipif(not sandbox.supported(), reason="fork sandbox is POSIX-only")
def test_sandbox_child_has_no_guardian_secrets(monkeypatch):
    monkeypatch.setenv("GUARDIAN_ENCRYPTION_KEY", "super-secret-master")
    monkeypatch.setenv("GUARDIAN_JWT_SECRET", "super-secret-jwt")
    monkeypatch.setenv("GUARDIAN_TEST_CANARY", "should-not-survive")

    def _guardian_env_in_child() -> list[str]:
        return sorted(k for k in os.environ if k.startswith("GUARDIAN_"))

    leaked = sandbox.run_in_sandbox(_guardian_env_in_child, sandbox.policy_for(EngineKey.SECRETS))
    assert leaked == [], f"secrets leaked into the sandbox child: {leaked}"


# ── C. the engine round-trips through the scan plane with only the seal key + JSON ────────────────
_AWS = 'api_key = "AKIAIOSFODNN7EXAMPLE"'


def test_execute_engine_seals_a_json_bundle_the_control_plane_decodes():
    from guardian_scanner import scan_plane

    ctx = ScanContext(scan_id="t", asset_kind="repo", asset_identifier="x", inline_content=_AWS)
    sealed_in = scan_plane.seal_engine_job(EngineKey.SECRETS.value, ctx)
    # The sealed job is opaque — the raw secret and context are not readable without the seal key.
    assert "AKIAIOSFODNN7EXAMPLE" not in sealed_in and "inline_content" not in sealed_in

    sealed_out = scan_plane.execute_engine(sealed_in)
    # The reply is a JSON bundle (no pickle) once unsealed — decodable to RawFindings.
    from guardian_common.crypto import unseal_secret

    bundle = json.loads(unseal_secret(sealed_out))
    assert set(bundle) == {"raws", "health", "inventory"}
    raws = [RawFinding.from_dict(d) for d in bundle["raws"]]
    assert raws, "the secrets engine should have found the planted AWS key"
    assert all(isinstance(r, RawFinding) for r in raws)
    assert all(r.engine == EngineKey.SECRETS for r in raws)
    # Evidence crossing the boundary stays redacted — no raw secret in the JSON.
    assert "AKIAIOSFODNN7EXAMPLE" not in sealed_out


def test_run_engine_offloaded_returns_findings_via_the_scan_queue(monkeypatch):
    # Wire the control-plane dispatch to the real scan-plane task (as a same-process stand-in for the
    # `scan` worker): run_engine_offloaded seals → execute_engine runs + seals → offloaded decodes.
    from guardian_scanner import scan_plane

    class _Result:
        def __init__(self, value):
            self._value = value

        def get(self, timeout=None, **kwargs):  # noqa: ANN001, ANN003
            return self._value

    def _fake_send_task(name, args, queue=None):  # noqa: ANN001
        assert name == "guardian.execute_engine"
        assert queue == scan_plane.SCAN_QUEUE     # routed to the isolated scan plane
        return _Result(scan_plane.execute_engine(args[0]))

    monkeypatch.setattr(scan_plane.celery_app, "send_task", _fake_send_task)

    ctx = ScanContext(scan_id="t", asset_kind="repo", asset_identifier="x", inline_content=_AWS)
    outcome = scan_plane.run_engine_offloaded(EngineKey.SECRETS.value, ctx)
    assert outcome.raws and all(r.engine == EngineKey.SECRETS for r in outcome.raws)
    assert hasattr(outcome.health, "degraded")
    assert isinstance(outcome.inventory, list)
