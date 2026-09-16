"""Login must not be lockable for everyone through a shared proxy IP (ISSUE 2).

Behind a proxy that terminates every connection with GUARDIAN_TRUSTED_PROXY_COUNT unset (Render free
tier), `client_ip()` returns the proxy's IP for every request, so a per-IP hard block would let one
attacker's failed logins lock out ALL users. In that configuration the login endpoint skips the
per-IP block and relies on the per-ACCOUNT limit plus a process-wide breaker.

These run without a database: `get_db` is overridden with a session that finds no user, so a request
that clears rate-limiting reaches the normal 401 "invalid credentials" path, while a rate-limited one
returns 429 — which is exactly what we assert on.
"""

from __future__ import annotations

import types

import pytest
from fastapi.testclient import TestClient
from guardian_api.deps import get_db
from guardian_api.main import app
from guardian_api.ratelimit import reset_login_limiter
from guardian_common.config import get_settings


class _NoUserSession:
    """Minimal stand-in: every user lookup misses, commits are no-ops."""

    def query(self, *a, **k):
        return self

    def filter(self, *a, **k):
        return self

    def first(self):
        return None

    def commit(self):
        pass


def _login(client: TestClient, email: str):
    return client.post("/api/v1/auth/login", json={"email": email, "password": "x" * 12})


@pytest.fixture
def shared_proxy_client(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "env", "production")        # is_production == True
    monkeypatch.setattr(s, "trusted_proxy_count", 0)   # shared-proxy configuration
    monkeypatch.setattr(s, "auth_rate_limit_per_minute", 5)
    monkeypatch.setattr(s, "global_login_breaker_per_minute", 300)
    reset_login_limiter()
    app.dependency_overrides[get_db] = lambda: _NoUserSession()
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_db, None)
        reset_login_limiter()


def test_attacker_cannot_lock_out_a_different_account(shared_proxy_client):
    # One attacker hammers login far past the per-IP ceiling (all sharing the proxy IP).
    for _ in range(60):
        assert _login(shared_proxy_client, "attacker@evil.com").status_code in (401, 429)
    # A different account is unaffected: it clears rate-limiting and reaches the normal 401 path.
    # Before the fix the shared per-IP block would already have made this a 429 (the lockout).
    assert _login(shared_proxy_client, "victim@example.com").status_code == 401


def test_account_still_locks_after_n_failures(shared_proxy_client):
    # The per-account limit still protects an individual account (auth_rate_limit_per_minute=5).
    for _ in range(5):
        assert _login(shared_proxy_client, "target@example.com").status_code == 401
    assert _login(shared_proxy_client, "target@example.com").status_code == 429


def test_global_breaker_throttles_a_distributed_flood(shared_proxy_client, monkeypatch):
    # Distinct accounts, so no per-account bucket ever blocks; only the process-wide breaker can.
    s = get_settings()
    monkeypatch.setattr(s, "auth_rate_limit_per_minute", 10_000)   # keep acct + ip buckets open
    monkeypatch.setattr(s, "global_login_breaker_per_minute", 10)
    reset_login_limiter()
    statuses = [_login(shared_proxy_client, f"user{i}@example.com").status_code for i in range(15)]
    # Before the fix there was no global breaker and the per-IP limit was 10_000, so 15 distinct-
    # account attempts were all 401. Now the breaker trips at 10.
    assert 429 in statuses
    assert statuses[:10] == [401] * 10   # first `limit` attempts pass, then the breaker trips


def test_non_shared_proxy_still_blocks_per_ip(monkeypatch):
    # With a configured hop count (not the shared-proxy case), the precise per-IP block still applies.
    s = get_settings()
    monkeypatch.setattr(s, "env", "production")
    monkeypatch.setattr(s, "trusted_proxy_count", 1)   # a real client IP is derived → not shared
    monkeypatch.setattr(s, "auth_rate_limit_per_minute", 5)
    reset_login_limiter()
    app.dependency_overrides[get_db] = lambda: _NoUserSession()
    try:
        client = TestClient(app)
        # Same client IP (TestClient peer) + XFF so hop-1 parsing yields a stable client → per-IP
        # bucket fills after 5 and blocks regardless of which account is tried.
        headers = {"x-forwarded-for": "203.0.113.7"}
        for _ in range(5):
            client.post("/api/v1/auth/login",
                        json={"email": "a@example.com", "password": "x" * 12}, headers=headers)
        r = client.post("/api/v1/auth/login",
                        json={"email": "b@example.com", "password": "x" * 12}, headers=headers)
        assert r.status_code == 429   # per-IP block active off the shared-proxy path
    finally:
        app.dependency_overrides.pop(get_db, None)
        reset_login_limiter()


# ── XFF spoof-safety when a hop count is configured ──────────────────────────────────────────────
def _req(xff, peer):
    return types.SimpleNamespace(
        headers={"x-forwarded-for": xff} if xff is not None else {},
        client=types.SimpleNamespace(host=peer) if peer else None,
    )


class _H(dict):
    """Case-insensitive header stub matching Starlette's Headers.get()."""

    def get(self, k, d=None):
        return super().get(k.lower(), d)


def _xff_req(xff, peer="10.0.0.1"):
    return types.SimpleNamespace(headers=_H({"x-forwarded-for": xff}),
                                 client=types.SimpleNamespace(host=peer))


def test_xff_cannot_be_spoofed_when_count_configured(monkeypatch):
    from guardian_api.deps import client_ip

    s = get_settings()
    monkeypatch.setattr(s, "trusted_proxy_count", 1)
    # With 1 trusted hop the client is the entry just before it (parts[-2]). An attacker can only
    # PREPEND entries, which land to the LEFT of that position — so the selected IP is identical with
    # or without the injected spoof, i.e. the source cannot be forged.
    legit = client_ip(_xff_req("203.0.113.9, 172.16.0.1"))
    attacked = client_ip(_xff_req("6.6.6.6, 203.0.113.9, 172.16.0.1"))
    assert legit == attacked == "203.0.113.9"
    assert attacked != "6.6.6.6"


def test_xff_ignored_entirely_when_count_zero(monkeypatch):
    from guardian_api.deps import client_ip

    s = get_settings()
    monkeypatch.setattr(s, "trusted_proxy_count", 0)
    req = _req("6.6.6.6", "10.0.0.1")
    assert client_ip(req) == "10.0.0.1"   # socket peer, header ignored (unspoofable)


# ── OWNER-only proxy diagnostic reports counts, not client IPs ───────────────────────────────────
def test_proxy_diagnostic_requires_authentication():
    client = TestClient(app)
    r = client.get("/api/v1/auth/proxy-diagnostic")
    assert r.status_code in (401, 403)   # never open to an unauthenticated caller


def test_proxy_diagnostic_reports_only_the_hop_count(monkeypatch):
    from guardian_api.routes.auth import ProxyDiagnostic, proxy_diagnostic

    monkeypatch.setattr(get_settings(), "trusted_proxy_count", 0)
    req = types.SimpleNamespace(
        headers=_H({"x-forwarded-for": "1.1.1.1, 2.2.2.2, 3.3.3.3"}),
        client=types.SimpleNamespace(host="10.0.0.9"),
    )
    out: ProxyDiagnostic = proxy_diagnostic(request=req, identity=object())
    assert out.xff_entry_count == 3                      # count only
    # The client IP VALUES must not appear anywhere in the serialized diagnostic.
    dumped = out.model_dump_json()
    for leaked in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
        assert leaked not in dumped
    assert out.socket_peer == "10.0.0.9"                 # the infra peer, as designed
