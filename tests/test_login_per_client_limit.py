"""Per-client failed-login limit — bounds password spraying without a global lockout.

Once the trusted proxy hop count is configured, the resolved client IP is reliable, so login counts
FAILED logins per client (IPv6 keyed by /64) and refuses a client over the limit BEFORE spending an
Argon2 slot. A blocked client cannot affect a correct login from a DIFFERENT client, so this is a
per-client control, not a global one.

Runs without a database: get_db is overridden with a session that returns a generic active user, and
verify_password is stubbed so a chosen password is the only "correct" one.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from guardian_api import ratelimit
from guardian_api.deps import get_db
from guardian_api.main import app
from guardian_api.ratelimit import SlidingWindowLimiter, client_bucket_key
from guardian_common.config import get_settings

_CORRECT = "correct-horse-battery-staple"
_PROXY = "10.0.0.1"        # the trusted proxy hop appended to X-Forwarded-For


class _FakeUser:
    def __init__(self):
        self.id = uuid.uuid4()
        self.password_hash = "argon2-hash"
        self.status = "active"
        self.email = "user@example.com"
        self.name = "User"


class _Session:
    def query(self, *a, **k):
        return self

    def filter(self, *a, **k):
        return self

    def first(self):
        return _FakeUser()

    def add(self, *a, **k):
        pass

    def commit(self):
        pass


@pytest.fixture
def client(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "trusted_proxy_count", 1)          # client IP is trustworthy → per-client on
    monkeypatch.setattr(s, "auth_rate_limit_per_minute", 100_000)   # keep the ACCOUNT bucket out of the way
    monkeypatch.setattr(s, "global_login_breaker_per_minute", 100_000)
    monkeypatch.setattr(s, "login_failed_per_client_per_minute", 20)
    monkeypatch.setattr(s, "login_argon2_max_concurrency", 8)
    monkeypatch.setattr("guardian_api.routes.auth.verify_password", lambda pw, h: pw == _CORRECT)
    monkeypatch.setattr("guardian_api.routes.auth.verify_dummy", lambda pw: None)
    ratelimit.reset_login_limiter()
    ratelimit.reset_failed_login_breaker()
    ratelimit.reset_argon2_gate()
    app.dependency_overrides[get_db] = lambda: _Session()
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_db, None)
        ratelimit.reset_login_limiter()
        ratelimit.reset_failed_login_breaker()
        ratelimit.reset_argon2_gate()


def _login(client, client_ip, email, password="wrong"):
    return client.post("/api/v1/auth/login",
                       headers={"X-Forwarded-For": f"{client_ip}, {_PROXY}"},
                       json={"email": email, "password": password})


def test_password_spraying_from_one_client_is_blocked_after_the_limit(client):
    # One client, one attempt each on 500 different emails — no single account bucket ever trips, so
    # only the per-client limit (20) can stop it.
    codes = [_login(client, "203.0.113.5", f"user{i}@example.com").status_code for i in range(500)]
    assert codes[:20] == [401] * 20                 # first `limit` failures reach the credential check
    assert set(codes[20:]) == {429}                 # every attempt after the limit is refused
    # And it is refused as a per-client 429, not by exhausting an account.
    assert codes[20] == 429


def test_a_blocked_client_does_not_affect_another_client(client):
    for i in range(25):                             # push client A over the limit
        _login(client, "203.0.113.5", f"user{i}@example.com")
    assert _login(client, "203.0.113.5", "any@example.com").status_code == 429   # A is blocked
    # A different client IP, with the CORRECT password, logs in fine — the block is per-client.
    ok = _login(client, "198.51.100.9", "victim@example.com", password=_CORRECT)
    assert ok.status_code == 200, ok.text
    assert ok.json()["access_token"]


def test_account_still_locks_after_n_failures(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "auth_rate_limit_per_minute", 5)
    ratelimit.reset_login_limiter()
    for _ in range(5):
        assert _login(client, "203.0.113.5", "target@example.com").status_code == 401
    # The 6th trips the ACCOUNT bucket (5) before the per-client bucket (20).
    assert _login(client, "203.0.113.5", "target@example.com").status_code == 429


def test_correct_login_is_not_penalised_by_the_client_bucket(client):
    # A client that only ever succeeds is never blocked: the per-client bucket counts FAILURES only.
    for _ in range(50):
        assert _login(client, "203.0.113.5", "victim@example.com",
                      password=_CORRECT).status_code == 200


# ── IPv6 /64 keying ──────────────────────────────────────────────────────────────────────────────
def test_two_ipv6_addresses_in_the_same_64_share_a_bucket():
    a = client_bucket_key("2001:db8:1:2::1")
    b = client_bucket_key("2001:db8:1:2:aaaa:bbbb:cccc:dddd")
    assert a == b                                   # same /64 → same bucket
    assert a.endswith("/64")
    # A different /64 is a different bucket, and IPv4 is keyed as-is.
    assert client_bucket_key("2001:db8:1:3::1") != a
    assert client_bucket_key("203.0.113.5") == "203.0.113.5"


# ── Issue 4: fail CLOSED for auth keys under a saturated table ────────────────────────────────────
def test_full_table_refuses_a_new_auth_key_but_not_a_best_effort_key(monkeypatch):
    monkeypatch.setattr(ratelimit, "_MAX_KEYS", 3)   # tiny table so we can saturate it deterministically
    lim = SlidingWindowLimiter(5, 60.0)
    # Fill the table with 3 ACTIVE keys (each below its ceiling, so none is evictable as expired).
    for i in range(3):
        assert lim.hit(f"acct:active{i}@example.com", fail_closed=True)[0] is True
    # A brand-new AUTH key now has nowhere to be tracked → it must FAIL CLOSED (refused), not be
    # silently allowed, so filling the table cannot buy an unlimited-guessing window.
    assert lim.hit("acct:new@example.com", fail_closed=True)[0] is False
    assert lim.check("client:203.0.113.9", fail_closed=True)[0] is False
    # A best-effort (non-auth) key stays fail-open so a full table never denies legitimate traffic.
    assert lim.hit("tenant:xyz")[0] is True
