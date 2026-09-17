"""Sign-up rate limiting keys on a TRUSTED client IP, never a shared placeholder (follow-up).

Sign-up used to key `signup:{client_ip}` unconditionally, so behind a shared proxy (or on a
short/malformed X-Forwarded-For) every sign-up shared one bucket and one source could block everyone.
It now mirrors login: a per-client bucket only when the IP is trustworthy; otherwise the per-client
limit is skipped and an alert-only counter records the untrusted volume.

No real database: get_db returns a session whose user lookup always finds a row, so a request that
clears the rate limit reaches the 409 "address cannot be used" branch right after the gate — 429 vs
409 is exactly the pass/block signal we assert on.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from guardian_api import ratelimit
from guardian_api.deps import get_db
from guardian_api.main import app
from guardian_common.config import get_settings
from guardian_common.metrics import REGISTRY


class _ExistingUser:
    id = uuid.uuid4()


class _Session:
    def query(self, *a, **k):
        return self

    def filter(self, *a, **k):
        return self

    def first(self):
        return _ExistingUser()          # every email looks taken → 409 right after the rate gate

    def add(self, *a, **k):
        pass

    def commit(self):
        pass


def _counter(name: str) -> float:
    m = REGISTRY._metrics.get(name)
    return sum(m.values.values()) if m else 0.0


def _signup(client, xff, i):
    body = {"email": f"u{i}-{uuid.uuid4().hex[:8]}@example.com", "password": "x" * 12,
            "name": "N", "organization": f"org-{i}-{uuid.uuid4().hex[:6]}", "company": "C"}
    headers = {"X-Forwarded-For": xff} if xff is not None else {}
    return client.post("/api/v1/auth/signup", json=body, headers=headers)


@pytest.fixture
def client(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "self_serve_signup", True)
    monkeypatch.setattr(s, "trusted_proxy_count", 1)     # per-client enabled; client = XFF[-1]
    monkeypatch.setattr(s, "auth_rate_limit_per_minute", 5)
    monkeypatch.setattr(s, "global_signup_breaker_per_minute", 100_000)
    ratelimit.reset_login_limiter()
    ratelimit.reset_untrusted_signup_breaker()
    app.dependency_overrides[get_db] = lambda: _Session()
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_db, None)
        ratelimit.reset_login_limiter()
        ratelimit.reset_untrusted_signup_breaker()


def test_untrusted_signups_are_not_blocked_and_are_counted(client):
    # No X-Forwarded-For with trusted_proxy_count=1 ⇒ untrusted (short header). Old code keyed on the
    # shared socket peer and would 429 after the ceiling; now these are skipped + counted, never
    # blocked — so one source cannot deny sign-up to another.
    before = _counter("guardian_signup_untrusted_ip_total")
    codes = [_signup(client, None, i).status_code for i in range(30)]
    assert set(codes) == {409}                 # never 429 — untrusted sign-ups are not blocked
    assert _counter("guardian_signup_untrusted_ip_total") - before == 30


def test_trusted_per_client_isolation_one_client_does_not_block_another(client):
    # Client A sends 10 sign-ups; a DIFFERENT client IP is unaffected (separate per-client bucket).
    for i in range(10):
        _signup(client, "203.0.113.5", i)
    assert _signup(client, "198.51.100.9", 99).status_code == 409     # other client not blocked


def test_trusted_client_is_still_limited_after_the_ceiling(client):
    # The flooding client itself is still bounded (ceiling 5) — but only that client.
    codes = [_signup(client, "203.0.113.5", i).status_code for i in range(6)]
    assert codes[:5] == [409] * 5
    assert codes[5] == 429                       # the 6th from THIS client is rate-limited
    # A different client is still fine at that moment.
    assert _signup(client, "198.51.100.9", 99).status_code == 409


def test_untrusted_signup_does_not_touch_the_counter_when_trusted(client):
    before = _counter("guardian_signup_untrusted_ip_total")
    _signup(client, "203.0.113.5", 1)            # trusted → per-client path, not the untrusted counter
    assert _counter("guardian_signup_untrusted_ip_total") - before == 0
