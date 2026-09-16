"""web_checks provider SSRF / DNS-rebinding boundary — no live network.

`_assert_target_public` validated the hostname, but `_fetch_live` then let httpx reconnect BY
HOSTNAME and re-resolve — a validate-then-reconnect TOCTOU. A record that answers public for the
check and rebinds to 169.254.169.254 for the connect defeated it. `_fetch_live` now pins every
connect to a pre-validated public IP via `sandbox._resolve_public_address` (same mechanism as the
DAST engine and discovery web probe), deferring to the sandbox's own egress pin when it is active.
"""

from __future__ import annotations

import socket
import types

import pytest
from guardian_scanner import egress, sandbox
from guardian_scanner.tools.providers import web_checks_provider as wc


def _addrinfo(*ips, port=443):
    return [(0, socket.SOCK_STREAM, 0, "", (ip, port)) for ip in ips]


class _ConnSpy:
    def __init__(self):
        self.addresses: list = []

    def __call__(self, address, *a, **k):
        self.addresses.append(address)
        return types.SimpleNamespace(close=lambda: None)


class _StubClient:
    """Stand-in httpx.Client whose .request() drives socket.create_connection like httpcore would."""

    def __init__(self, **kwargs):
        _StubClient.kwargs = dict(kwargs)

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def request(self, method, url, headers=None):  # noqa: ANN001
        host = url.split("://", 1)[1].split("/", 1)[0].split(":")[0]
        socket.create_connection((host, 443))   # exercises the pin at the real connect point
        return types.SimpleNamespace(status_code=200, headers={}, text="ok", url=url)


# ── the pin ──────────────────────────────────────────────────────────────────────────────────────
def test_pin_connects_to_validated_public_ip(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("93.184.216.34"))
    spy = _ConnSpy()
    monkeypatch.setattr(socket, "create_connection", spy)
    with wc._pinned_egress():
        socket.create_connection(("example.com", 443))
    assert spy.addresses == [("93.184.216.34", 443)]
    assert socket.create_connection is spy   # restored on exit


def test_pin_defers_when_sandbox_allowlist_is_active(monkeypatch):
    # Inside the recon sandbox the allowlist guard already pins; a second pin would hand it an IP it
    # rejects. So the provider's pin must be a no-op while an allowlist is active.
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("93.184.216.34"))
    original = socket.create_connection
    with egress.allowlist(frozenset({"example.com"})), wc._pinned_egress():
        assert socket.create_connection is original   # not patched — defers to the sandbox guard


# ── the TOCTOU: public at check, internal at connect (the reported rebind) ───────────────────────
def test_fetch_live_defeats_rebind_between_check_and_connect(monkeypatch):
    calls = {"n": 0}

    def flipping(*_a, **_k):
        calls["n"] += 1
        return _addrinfo("93.184.216.34") if calls["n"] == 1 else _addrinfo("169.254.169.254")

    real = _ConnSpy()
    monkeypatch.setattr(socket, "getaddrinfo", flipping)
    monkeypatch.setattr(socket, "create_connection", real)
    monkeypatch.setattr("httpx.Client", _StubClient)

    with pytest.raises(wc.EgressBlocked):
        wc._fetch_live("rebind.example", 443, "GET", "/", ())

    assert real.addresses == []   # never connected to the rebinded 169.254.169.254 metadata address


def test_fetch_live_connects_to_pinned_ip_for_a_stable_host(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("93.184.216.34"))
    real = _ConnSpy()
    monkeypatch.setattr(socket, "create_connection", real)
    monkeypatch.setattr("httpx.Client", _StubClient)

    resp = wc._fetch_live("public.example", 443, "GET", "/", ())

    assert resp.status == 200
    assert real.addresses == [("93.184.216.34", 443)]           # connected to the validated IP
    assert _StubClient.kwargs.get("follow_redirects") is False   # redirects still not auto-followed


def test_assert_target_public_still_blocks_a_directly_internal_host(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("169.254.169.254"))
    with pytest.raises(wc.EgressBlocked):
        wc._assert_target_public("metadata.example")


def test_pin_reuses_the_shared_sandbox_resolver():
    assert wc.sandbox._resolve_public_address is sandbox._resolve_public_address
