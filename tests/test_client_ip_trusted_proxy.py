"""Trusted client-IP derivation (P1-①) — no network.

X-Forwarded-For is client-spoofable. Each trusted proxy APPENDS the address of the peer it received
the connection from, so for `client → P1 → … → PN → app` the header ends `…, client, P1, …, P(N-1)`
and the real client is `parts[-N]` (NOT `parts[-(N+1)]`). Everything to its LEFT is attacker-supplied;
everything to its right is a trusted proxy hop. `resolve_client_ip` also reports whether the value is
trustworthy enough to key a per-client rate limit on: a short or malformed X-Forwarded-For (hop count
misconfigured) yields the socket peer for audit but is marked UNTRUSTED so per-client limiting skips.
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
    assert deps.client_ip(_req("198.51.100.7", xff="1.2.3.4, 5.6.7.8")) == "198.51.100.7"
    assert deps.client_ip(_req("198.51.100.7", xff="9.9.9.9")) == "198.51.100.7"
    assert deps.client_ip(_req("198.51.100.7")) == "198.51.100.7"
    assert deps.resolve_client_ip(_req("198.51.100.7"))[1] is True   # direct connection is trusted


def test_spoofed_xff_never_changes_the_key(monkeypatch):
    _with_count(monkeypatch, 0)
    peer = "203.0.113.50"
    keys = {deps.client_ip(_req(peer, xff=f"{i}.{i}.{i}.{i}")) for i in range(1, 20)}
    assert keys == {peer}                       # one bucket regardless of the header


# ── configured trusted proxies: the client is parts[-n] (the proxy appends the client) ───────────
def test_one_trusted_proxy_takes_the_last_appended_entry(monkeypatch):
    _with_count(monkeypatch, 1)
    # The single proxy appended the client (203.0.113.7) as the LAST entry ⇒ parts[-1].
    ip, trusted = deps.resolve_client_ip(_req("10.0.0.9", xff="203.0.113.7"))
    assert ip == "203.0.113.7" and trusted is True


def test_attacker_prepended_xff_is_not_trusted(monkeypatch):
    _with_count(monkeypatch, 1)
    # Attacker sets XFF "1.1.1.1"; the proxy appends the true client, so the spoof lands to the LEFT
    # and parts[-1] is the attacker's own real client IP.
    ip = deps.client_ip(_req("10.0.0.9", xff="1.1.1.1, 203.0.113.7"))
    assert ip == "203.0.113.7" and ip != "1.1.1.1"


def test_two_trusted_proxies_take_parts_minus_n(monkeypatch):
    _with_count(monkeypatch, 2)
    # client → P1 → P2 → app: XFF = "<attacker>, client, P1"; client = parts[-2].
    assert deps.client_ip(_req("10.0.0.9", xff="a-spoof, 203.0.113.7, 10.1.1.1")) == "203.0.113.7"


def test_distinct_real_clients_get_distinct_buckets(monkeypatch):
    _with_count(monkeypatch, 1)
    a = deps.client_ip(_req("10.0.0.9", xff="203.0.113.7"))
    b = deps.client_ip(_req("10.0.0.9", xff="198.51.100.4"))
    assert a == "203.0.113.7" and b == "198.51.100.4" and a != b


# ── misconfiguration: short / malformed header ⇒ peer for audit, UNTRUSTED for rate limiting ─────
def test_short_header_is_peer_for_audit_but_untrusted(monkeypatch):
    _with_count(monkeypatch, 2)
    ip, trusted = deps.resolve_client_ip(_req("10.0.0.9", xff="203.0.113.7"))   # only 1 entry, need 2
    assert ip == "10.0.0.9"        # audit falls back to the socket peer…
    assert trusted is False        # …but it is NOT keyed on for per-client limiting


def test_missing_header_is_peer_for_audit_but_untrusted(monkeypatch):
    _with_count(monkeypatch, 1)
    ip, trusted = deps.resolve_client_ip(_req("10.0.0.9"))
    assert ip == "10.0.0.9" and trusted is False


def test_malformed_value_at_the_trusted_position_is_untrusted(monkeypatch):
    _with_count(monkeypatch, 1)
    # A non-IP at parts[-1] means the hop count is misconfigured: peer for audit, untrusted.
    ip, trusted = deps.resolve_client_ip(_req("10.0.0.9", xff="not-an-ip"))
    assert ip == "10.0.0.9" and trusted is False
    # But a valid IP at parts[-1] with attacker garbage to the LEFT is still trusted (garbage ignored).
    ip2, trusted2 = deps.resolve_client_ip(_req("10.0.0.9", xff="garbage, 203.0.113.7"))
    assert ip2 == "203.0.113.7" and trusted2 is True


def test_no_client_and_no_header(monkeypatch):
    _with_count(monkeypatch, 0)
    assert deps.client_ip(_req(None)) is None


def test_spoofed_client_cannot_pick_an_arbitrary_bucket(monkeypatch):
    _with_count(monkeypatch, 1)
    # The true client is appended to the RIGHT of anything the attacker sends, so parts[-1] is always
    # their own real client IP (203.0.113.7), never the spoofed 9.9.9.9.
    ip = deps.client_ip(_req("10.0.0.9", xff="9.9.9.9, 203.0.113.7"))
    assert ip == "203.0.113.7" and ip != "9.9.9.9"
