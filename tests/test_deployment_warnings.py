"""Per-client login limiting is only trusted when the client IP is; the misconfigured state is loud.

`per_client_limiting_enabled` decides whether login may key a limit on the client IP, and
`deployment_warnings` surfaces the production/staging + trusted_proxy_count==0 state (client IP is a
shared proxy value) as an error — logged at startup and served at /health/details.
"""

from __future__ import annotations

import types

import pytest
from fastapi.testclient import TestClient
from guardian_api.deps import get_current_identity
from guardian_api.main import app
from guardian_api.ratelimit import deployment_warnings, per_client_limiting_enabled
from guardian_core.enums import StaffRole


def _settings(*, env, count):
    local = env.lower() in {"local", "dev", "development", "test"}
    return types.SimpleNamespace(
        trusted_proxy_count=count,
        is_local_or_dev=local,
        is_production=env.lower() in {"prod", "production"},
    )


def test_enabled_when_hop_count_configured():
    assert per_client_limiting_enabled(_settings(env="production", count=1)) is True
    assert deployment_warnings(_settings(env="production", count=2)) == []


def test_enabled_on_local_dev_direct_connection():
    assert per_client_limiting_enabled(_settings(env="development", count=0)) is True
    assert deployment_warnings(_settings(env="development", count=0)) == []


def test_disabled_and_warned_in_production_without_a_hop_count():
    s = _settings(env="production", count=0)
    assert per_client_limiting_enabled(s) is False
    warnings = deployment_warnings(s)
    assert len(warnings) == 1
    assert warnings[0]["code"] == "per_client_login_limiting_disabled"
    assert warnings[0]["severity"] == "error"


def test_disabled_and_warned_in_staging_without_a_hop_count():
    # Staging is production-grade (not local/dev), so a shared proxy with count 0 is the same risk.
    s = _settings(env="staging", count=0)
    assert per_client_limiting_enabled(s) is False
    assert deployment_warnings(s)[0]["severity"] == "error"


# ── /health/details is OWNER-only ────────────────────────────────────────────────────────────────
def _identity(role):
    return types.SimpleNamespace(is_machine=False, staff_role=role)


@pytest.fixture
def health_client():
    client = TestClient(app)
    try:
        yield client
    finally:
        app.dependency_overrides.pop(get_current_identity, None)


def test_health_details_forbidden_for_a_non_owner(health_client):
    app.dependency_overrides[get_current_identity] = lambda: _identity(StaffRole.ANALYST.value)
    assert health_client.get("/health/details").status_code == 403


def test_health_details_ok_for_an_owner(health_client):
    app.dependency_overrides[get_current_identity] = lambda: _identity(StaffRole.OWNER.value)
    resp = health_client.get("/health/details")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "guardian-api" and "warnings" in body
