"""Login abuse controls over the REAL API (P1-γ). Gated by GUARDIAN_RUN_DB_TESTS=1.

Exercises /api/v1/auth/login through FastAPI's TestClient against the real app + DB. Login is
DELIBERATELY not rate-limited by client IP or any global counter: behind a shared proxy that would
let one attacker lock out every user (including those with the correct password). The controls are:

  * a per-ACCOUNT limit that returns 429 (before Argon2) — and only ever affects that one account;
  * an Argon2 concurrency limiter that sheds with 503 (covered in the unit suite);
  * an alert-only failed-login breaker that never blocks.

So rotating the account across requests is NOT collectively blocked (that shared-IP lockout was the
DoS), while a single account still locks, and the invalid-credentials response is identical for a
known vs an unknown account (no user enumeration).
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


def _login(client, email="nobody@example.com", ip="203.0.113.7"):
    return client.post("/api/v1/auth/login",
                       headers={"X-Forwarded-For": ip},
                       json={"email": email, "password": "wrong-password"})


def test_a_single_account_is_rate_limited_after_threshold(client_and_limiter):
    client, _lim = client_and_limiter
    codes = [_login(client, email="target@example.com").status_code for _ in range(4)]
    assert codes[:3] == [401, 401, 401]                # first 3 reach the (failing) credential check
    assert codes[3] == 429                             # 4th is rate-limited on the ACCOUNT bucket


def test_rate_limit_sets_retry_after(client_and_limiter):
    client, _lim = client_and_limiter
    for _ in range(3):
        _login(client, email="retry@example.com")
    resp = _login(client, email="retry@example.com")
    assert resp.status_code == 429
    assert int(resp.headers["Retry-After"]) >= 1


def test_rotating_the_account_is_not_collectively_blocked(client_and_limiter):
    # The DoS that used to exist: one source rotating emails filled a shared per-IP bucket and locked
    # everyone out. With no IP/global block, each distinct account has its own fresh bucket, so a
    # rotation of six accounts (one attempt each, under the per-account threshold) is never blocked —
    # no user is denied by another's request pattern.
    client, _lim = client_and_limiter
    codes = [_login(client, email=f"u{i}@example.com", ip=f"{i}.{i}.{i}.{i}").status_code
             for i in range(1, 7)]
    assert codes == [401] * 6                          # never a 429 from a shared limit


def test_one_account_locking_does_not_lock_another(client_and_limiter):
    client, _lim = client_and_limiter
    for _ in range(3):                                 # exhaust ONE account's bucket
        _login(client, email="victim-a@example.com")
    assert _login(client, email="victim-a@example.com").status_code == 429
    # A different account, same source, is unaffected — the block is per-account, not per-source.
    assert _login(client, email="bystander-b@example.com").status_code == 401


def test_invalid_credentials_response_is_identical_for_known_and_unknown(client_and_limiter):
    # No user-enumeration signal below the rate limit: a wrong password is 401 whether or not the
    # account exists (the unknown account still runs a dummy Argon2 verification for constant time).
    client, _lim = client_and_limiter
    known = _login(client, email="admin@example.com")        # seeded by the smoke seed
    unknown = _login(client, email="ghost-does-not-exist@example.com")
    assert known.status_code == unknown.status_code == 401


def test_reset_restores_access(client_and_limiter):
    client, lim = client_and_limiter
    for _ in range(3):
        _login(client, email="reset@example.com")
    assert _login(client, email="reset@example.com").status_code == 429
    lim.reset()
    assert _login(client, email="reset@example.com").status_code == 401   # login flow works again
