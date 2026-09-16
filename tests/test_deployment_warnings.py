"""Per-client login limiting is only trusted when the client IP is; the misconfigured state is loud.

`per_client_limiting_enabled` decides whether login may key a limit on the client IP, and
`deployment_warnings` surfaces the production/staging + trusted_proxy_count==0 state (client IP is a
shared proxy value) as an error — logged at startup and served at /health/details.
"""

from __future__ import annotations

import types

from guardian_api.ratelimit import deployment_warnings, per_client_limiting_enabled


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
