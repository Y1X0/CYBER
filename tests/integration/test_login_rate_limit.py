"""Login rate limiting over the REAL API (P1-γ). Gated by GUARDIAN_RUN_DB_TESTS=1.

Exercises /api/v1/auth/login through FastAPI's TestClient against the real app + DB: the limiter
returns 429 after the threshold (before Argon2), keys per-IP so a different source is independent, the
429 is identical for existing vs unknown accounts (no enumeration), and a reset restores access.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


@pytest.fixture()
def client_and_limiter(monkeypatch):
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_api.ratelimit import SlidingWindowLimiter
    from guardian_api.routes import auth as auth_route

    lim = SlidingWindowLimiter(3, 60.0)                 # small, deterministic threshold for the test
    monkeypatch.setattr(auth_route, "login_limiter", lambda: lim)
    return TestClient(app), lim


def _login(client, ip, email="nobody@example.com"):
    return client.post("/api/v1/auth/login",
                       headers={"X-Forwarded-For": ip},
                       json={"email": email, "password": "wrong-password"})


def test_login_is_rate_limited_after_threshold(client_and_limiter):
    client, _lim = client_and_limiter
    codes = [_login(client, "203.0.113.7").status_code for _ in range(4)]
    assert codes[:3] == [401, 401, 401]                # first 3 reach the (failing) credential check
    assert codes[3] == 429                             # 4th is rate-limited


def test_rate_limit_sets_retry_after(client_and_limiter):
    client, _lim = client_and_limiter
    for _ in range(3):
        _login(client, "203.0.113.8")
    resp = _login(client, "203.0.113.8")
    assert resp.status_code == 429
    assert int(resp.headers["Retry-After"]) >= 1


def test_limit_is_per_source_ip(client_and_limiter):
    # Distinct accounts isolate the IP dimension (the limiter also caps per-account, by design).
    client, _lim = client_and_limiter
    for _ in range(3):
        _login(client, "203.0.113.9", email="ip9@example.com")
    assert _login(client, "203.0.113.9", email="ip9@example.com").status_code == 429   # IP exhausted
    assert _login(client, "198.51.100.4", email="ip4@example.com").status_code == 401  # other IP ok


def test_429_is_identical_for_known_and_unknown_accounts(client_and_limiter):
    # No user-enumeration signal: the rate-limited response is the same regardless of account.
    client, _lim = client_and_limiter
    for _ in range(3):
        _login(client, "203.0.113.10", email="a@example.com")
    known = _login(client, "203.0.113.10", email="admin@example.com")
    unknown = _login(client, "203.0.113.10", email="ghost@example.com")
    assert known.status_code == unknown.status_code == 429


def test_reset_restores_access(client_and_limiter):
    client, lim = client_and_limiter
    for _ in range(3):
        _login(client, "203.0.113.11")
    assert _login(client, "203.0.113.11").status_code == 429
    lim.reset()
    assert _login(client, "203.0.113.11").status_code == 401     # legitimate login flow works again
