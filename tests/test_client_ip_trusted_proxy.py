"""Trusted client-IP derivation (P1-①) — no network.

X-Forwarded-For is client-spoofable. The rate limiter must key on a trusted IP so an attacker cannot
change their bucket by setting the header. Default (trusted_proxy_count=0) uses the socket peer and
ignores XFF; a configured count N trusts only the last N hops.
"""

from __future__ import annotations

import types

from guardian_api import deps


def _req(peer, xff=None):
    headers = {}
    if xff is not None:
        headers["x-forwarded-for"] = xff
    return types.SimpleNamespace(
        client=types.SimpleNamespace(host=peer) if peer else None,
        headers=headers,
    )


def _with_count(monkeypatch, n):
    monkeypatch.setattr(deps, "get_settings", lambda: types.SimpleNamespace(trusted_proxy_count=n))


# ── default (count=0): socket peer only, XFF ignored ─────────────────────────────────────────────
def test_default_uses_socket_peer_and_ignores_xff(monkeypatch):
    _with_count(monkeypatch, 0)
    # Even with a spoofed XFF, the result is the socket peer — the attacker cannot change the bucket.
    assert deps.client_ip(_req("198.51.100.7", xff="1.2.3.4, 5.6.7.8")) == "198.51.100.7"
    assert deps.client_ip(_req("198.51.100.7", xff="9.9.9.9")) == "198.51.100.7"
    assert deps.client_ip(_req("198.51.100.7")) == "198.51.100.7"


def test_spoofed_xff_never_changes_the_key(monkeypatch):
    _with_count(monkeypatch, 0)
    peer = "203.0.113.50"
    keys = {deps.client_ip(_req(peer, xff=f"{i}.{i}.{i}.{i}")) for i in range(1, 20)}
    assert keys == {peer}                       # one bucket regardless of the header


# ── configured trusted proxies: real client is the hop before the trusted ones ───────────────────
def test_one_trusted_proxy_takes_hop_before_it(monkeypatch):
    _with_count(monkeypatch, 1)
    # our proxy appended the real peer (198.51.100.9) as the last entry; client is parts[-2].
    assert deps.client_ip(_req("10.0.0.1", xff="203.0.113.5, 198.51.100.9")) == "203.0.113.5"


def test_attacker_prepended_xff_is_not_trusted(monkeypatch):
    _with_count(monkeypatch, 1)
    # Attacker sets XFF: "169.254.169.254" — our proxy appends the true peer, so the spoof lands to
    # the LEFT and is never selected; parts[-2] is the attacker's own real client IP.
    ip = deps.client_ip(_req("10.0.0.1", xff="169.254.169.254, 203.0.113.5, 198.51.100.9"))
    assert ip == "203.0.113.5" and ip != "169.254.169.254"


def test_two_trusted_proxies(monkeypatch):
    _with_count(monkeypatch, 2)
    assert deps.client_ip(_req("10.0.0.1", xff="203.0.113.5, 198.51.100.9, 198.51.100.10")) \
        == "203.0.113.5"


def test_short_header_falls_back_to_peer(monkeypatch):
    _with_count(monkeypatch, 2)
    # Fewer entries than expected ⇒ fail-safe to the socket peer, never an attacker-controlled value.
    assert deps.client_ip(_req("10.0.0.1", xff="203.0.113.5")) == "10.0.0.1"


def test_no_client_and_no_header(monkeypatch):
    _with_count(monkeypatch, 0)
    assert deps.client_ip(_req(None)) is None
