"""Login abuse controls must never deny a correct login to other users (ISSUE 2).

The failing design blocked on a shared key (per-IP, then a global breaker that returned 429), so one
attacker's flood locked out everyone — including users with the correct password. The controls are
now:

  * per-ACCOUNT bucket (bounds brute force against ONE account, never others);
  * an Argon2 concurrency limiter that sheds excess load with a retryable 503 (bounds CPU without
    singling out correct passwords or a shared IP);
  * a failed-login breaker that only ALERTS (metric + log) and never blocks.

These run without a database: `get_db` is overridden with a session that returns a generic active
user, and `verify_password` is stubbed so a chosen password is the only "correct" one.
"""

from __future__ import annotations

import types
import uuid

import pytest
from fastapi.testclient import TestClient
from guardian_api import ratelimit
from guardian_api.deps import get_db
from guardian_api.main import app
from guardian_common.config import get_settings
from guardian_common.metrics import REGISTRY

_CORRECT = "correct-horse-battery-staple"


class _FakeUser:
    def __init__(self):
        self.id = uuid.uuid4()
        self.password_hash = "argon2-hash"
        self.status = "active"
        self.email = "user@example.com"
        self.name = "User"


class _Session:
    """Every lookup returns a generic active user; writes are no-ops."""

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


def _login(client, email, password):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def _counter_total(name: str) -> float:
    metric = REGISTRY._metrics.get(name)
    return sum(metric.values.values()) if metric else 0.0


@pytest.fixture
def client(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "auth_rate_limit_per_minute", 5)
    monkeypatch.setattr(s, "global_login_breaker_per_minute", 300)
    monkeypatch.setattr(s, "login_argon2_max_concurrency", 4)
    monkeypatch.setattr(s, "login_argon2_acquire_timeout_seconds", 2.0)
    # This file covers the case where per-client limiting is OFF (shared proxy / operator-disabled):
    # per-client behavior has its own suite (test_login_per_client_limit.py).
    monkeypatch.setattr(s, "login_failed_per_client_per_minute", 0)
    # A correct password is only ever `_CORRECT`; the Argon2 cost is stubbed out for speed.
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


def test_flood_of_failed_logins_does_not_block_a_correct_login_for_another_account(client):
    # 1000 failed attempts across random accounts (the exact abuse that used to lock everyone out).
    for i in range(1000):
        r = _login(client, f"rand{i}@example.com", "wrong-password")
        assert r.status_code in (401, 429)   # never a 5xx, never a global block
    # A DIFFERENT account with the CORRECT password logs in successfully — not 429, not 503.
    r = _login(client, "victim@example.com", _CORRECT)
    assert r.status_code == 200, r.text
    assert r.json()["access_token"]


def test_account_still_locks_after_n_failures(client):
    # The per-account bucket (auth_rate_limit_per_minute=5) still protects a single account.
    for _ in range(5):
        assert _login(client, "target@example.com", "wrong").status_code == 401
    assert _login(client, "target@example.com", "wrong").status_code == 429


def test_breaker_trips_are_logged_and_never_return_429(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "global_login_breaker_per_minute", 5)
    monkeypatch.setattr(get_settings(), "auth_rate_limit_per_minute", 100_000)  # isolate the breaker
    ratelimit.reset_login_limiter()
    ratelimit.reset_failed_login_breaker()

    before_trip = _counter_total("guardian_login_breaker_tripped_total")
    before_fail = _counter_total("guardian_login_failed_total")

    statuses = [_login(client, f"flood{i}@example.com", "wrong").status_code for i in range(40)]

    assert set(statuses) == {401}                                   # NEVER 429 (or 503)
    assert _counter_total("guardian_login_failed_total") - before_fail == 40
    # Crossing the threshold of 5 fired the alert breaker (metric incremented), without blocking.
    assert _counter_total("guardian_login_breaker_tripped_total") > before_trip


def test_argon2_saturation_sheds_with_503_not_a_lockout(client, monkeypatch):
    # Saturate the single Argon2 slot from the test thread; the request thread cannot acquire one
    # within the (shortened) timeout and is shed with a retryable 503 — not a block on any account.
    monkeypatch.setattr(get_settings(), "login_argon2_max_concurrency", 1)
    monkeypatch.setattr(get_settings(), "login_argon2_acquire_timeout_seconds", 0.1)
    ratelimit.reset_argon2_gate()
    gate = ratelimit._argon2_gate()
    assert gate.acquire()          # hold the only permit
    try:
        r = _login(client, "anyone@example.com", _CORRECT)
        assert r.status_code == 503
        assert r.headers.get("Retry-After")
    finally:
        gate.release()
    # Once the permit is free again, login works — the shed was load-shedding, not a lockout.
    r = _login(client, "victim@example.com", _CORRECT)
    assert r.status_code == 200, r.text


def test_unbounded_concurrency_setting_disables_the_gate(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "login_argon2_max_concurrency", 0)
    ratelimit.reset_argon2_gate()
    # With the gate disabled, a correct login still works (no shedding).
    assert _login(client, "victim@example.com", _CORRECT).status_code == 200


# ── XFF spoof-safety when a hop count is configured ──────────────────────────────────────────────
class _H(dict):
    def get(self, k, d=None):
        return super().get(k.lower(), d)


def _xff_req(xff, peer="10.0.0.1"):
    return types.SimpleNamespace(headers=_H({"x-forwarded-for": xff}),
                                 client=types.SimpleNamespace(host=peer))


def test_xff_cannot_be_spoofed_when_count_configured(monkeypatch):
    from guardian_api.deps import client_ip

    monkeypatch.setattr(get_settings(), "trusted_proxy_count", 1)
    # With 1 trusted hop the client is the entry just before it (parts[-2]). An attacker can only
    # PREPEND entries, which land LEFT of that position — so the result is identical with or without
    # the injected spoof: the source cannot be forged.
    legit = client_ip(_xff_req("203.0.113.9, 172.16.0.1"))
    attacked = client_ip(_xff_req("6.6.6.6, 203.0.113.9, 172.16.0.1"))
    assert legit == attacked == "203.0.113.9"
    assert attacked != "6.6.6.6"


def test_xff_ignored_entirely_when_count_zero(monkeypatch):
    from guardian_api.deps import client_ip

    monkeypatch.setattr(get_settings(), "trusted_proxy_count", 0)
    assert client_ip(_xff_req("6.6.6.6", "10.0.0.1")) == "10.0.0.1"   # socket peer, header ignored


# ── OWNER-only proxy diagnostic reports counts, not client IPs ───────────────────────────────────
def test_proxy_diagnostic_requires_authentication():
    r = TestClient(app).get("/api/v1/auth/proxy-diagnostic")
    assert r.status_code in (401, 403)


def test_proxy_diagnostic_reports_only_the_hop_count(monkeypatch):
    from guardian_api.routes.auth import ProxyDiagnostic, proxy_diagnostic

    monkeypatch.setattr(get_settings(), "trusted_proxy_count", 0)
    req = types.SimpleNamespace(
        headers=_H({"x-forwarded-for": "1.1.1.1, 2.2.2.2, 3.3.3.3"}),
        client=types.SimpleNamespace(host="10.0.0.9"),
    )
    out: ProxyDiagnostic = proxy_diagnostic(request=req, identity=object())
    assert out.xff_entry_count == 3
    dumped = out.model_dump_json()
    for leaked in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
        assert leaked not in dumped
    assert out.socket_peer == "10.0.0.9"
