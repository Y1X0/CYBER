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


class _FakeUser:
    def __init__(self):
        self.id = uuid.uuid4()
        self.password_hash = "argon2-hash"
        self.status = "active"
        self.email = "user@example.com"
        self.name = "User"
        self.token_version = 0


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
    # trusted_proxy_count == 1, so the proxy appends the client as the LAST X-Forwarded-For entry:
    # the client is parts[-1], i.e. the value we put here.
    return client.post("/api/v1/auth/login",
                       headers={"X-Forwarded-For": client_ip},
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


def test_attacker_prefix_cannot_pick_a_bucket(client):
    # count=1: an attacker prepends a chosen XFF, the proxy appends their real client, so parts[-1]
    # is their real IP. Two "clients" whose only difference is the prepended spoof share ONE bucket.
    for i in range(25):
        client.post("/api/v1/auth/login",
                    headers={"X-Forwarded-For": f"spoof{i}.0.0.1, 203.0.113.5"},
                    json={"email": f"u{i}@example.com", "password": "wrong"})
    blocked = client.post("/api/v1/auth/login",
                          headers={"X-Forwarded-For": "9.9.9.9, 203.0.113.5"},
                          json={"email": "x@example.com", "password": _CORRECT})
    assert blocked.status_code == 429       # keyed on the real client 203.0.113.5, spoof ignored


def test_malformed_trusted_position_skips_per_client_and_counts(client, monkeypatch):
    # count=1 with a non-IP at parts[-1] ⇒ untrusted ⇒ per-client skipped, so a flood of such
    # requests cannot block a correct login that is also untrusted.
    metric = "guardian_login_client_ip_unresolved_total"
    before = _counter_total(metric)
    for i in range(30):
        r = client.post("/api/v1/auth/login",
                        headers={"X-Forwarded-For": "not-an-ip"},
                        json={"email": f"none{i}@example.com", "password": "wrong"})
        assert r.status_code == 401
    ok = client.post("/api/v1/auth/login",
                     headers={"X-Forwarded-For": "not-an-ip"},
                     json={"email": "victim@example.com", "password": _CORRECT})
    assert ok.status_code == 200, ok.text
    assert _counter_total(metric) - before == 31


def test_no_client_ip_skips_per_client_and_does_not_lock_out(client, monkeypatch):
    # When the client IP cannot be resolved, per-client limiting is SKIPPED (never keyed on a shared
    # placeholder), so a flood of ip=None failures cannot block another ip=None correct login.
    from guardian_api.deps import client_ip

    metric = "guardian_login_client_ip_unresolved_total"
    before = _counter_total(metric)
    app.dependency_overrides[client_ip] = lambda: None
    try:
        for i in range(30):        # 30 distinct accounts so the account bucket never trips either
            r = client.post("/api/v1/auth/login",
                            json={"email": f"none{i}@example.com", "password": "wrong"})
            assert r.status_code == 401
        ok = client.post("/api/v1/auth/login",
                         json={"email": "victim@example.com", "password": _CORRECT})
        assert ok.status_code == 200, ok.text
    finally:
        app.dependency_overrides.pop(client_ip, None)
    assert _counter_total(metric) - before == 31    # every unresolved-IP login is counted


def _counter_total(name: str) -> float:
    from guardian_common.metrics import REGISTRY
    m = REGISTRY._metrics.get(name)
    return sum(m.values.values()) if m else 0.0


# ── IPv6 /64 keying ──────────────────────────────────────────────────────────────────────────────
def test_two_ipv6_addresses_in_the_same_64_share_a_bucket():
    a = client_bucket_key("2001:db8:1:2::1")
    b = client_bucket_key("2001:db8:1:2:aaaa:bbbb:cccc:dddd")
    assert a == b                                   # same /64 → same bucket
    assert a.endswith("/64")
    # A different /64 is a different bucket, and IPv4 is keyed as-is.
    assert client_bucket_key("2001:db8:1:3::1") != a
    assert client_bucket_key("203.0.113.5") == "203.0.113.5"


def test_ipv4_mapped_addresses_key_on_the_embedded_ipv4():
    # Regression: mapped IPv4 used to collapse to ::/64, putting every IPv4 client in one bucket.
    assert client_bucket_key("::ffff:1.2.3.4") == "1.2.3.4"
    assert client_bucket_key("::ffff:5.6.7.8") == "5.6.7.8"
    assert client_bucket_key("::ffff:1.2.3.4") != client_bucket_key("::ffff:5.6.7.8")
    # The mapped form and the plain form of the same IPv4 land in the SAME bucket.
    assert client_bucket_key("::ffff:1.2.3.4") == client_bucket_key("1.2.3.4") == "1.2.3.4"


def test_6to4_and_teredo_unwrap_to_their_ipv4():
    assert client_bucket_key("2002:0102:0304::1") == "1.2.3.4"                      # 6to4 → 1.2.3.4
    assert client_bucket_key("2001:0000:4136:e378:8000:63bf:3fff:fdd2") == "192.0.2.45"  # Teredo client
    # Distinct embedded clients stay distinct, and a real global IPv6 still uses its /64.
    assert client_bucket_key("2002:0506:0708::1") == "5.6.7.8"
    assert client_bucket_key("2001:db8:1:2::1").endswith("/64")


def test_missing_or_unparseable_ip_has_no_bucket():
    # None / garbage must NOT key on a shared placeholder — the caller skips per-client instead.
    assert client_bucket_key(None) is None
    assert client_bucket_key("") is None
    assert client_bucket_key("not-an-ip") is None
    assert client_bucket_key("999.999.999.999") is None


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
