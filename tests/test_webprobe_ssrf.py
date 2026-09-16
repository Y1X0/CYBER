"""Discovery web-probe SSRF / DNS-rebinding boundary — no live network.

`discovery/webprobe.probe` runs in the PARENT worker process, outside the fork sandbox's egress
pin, and fetches a customer-influenced URL. Its `_is_public_address` guard resolves the host to
check it, but httpx (and `tls_details`) then reconnect BY HOSTNAME and re-resolve — a classic
validate-then-reconnect TOCTOU. A DNS record that answers "public" for the check and then flips to
169.254.169.254 / an internal address for the connection would defeat the check (DNS rebinding).

The fix pins EVERY connect during the fetch to a pre-validated public IP via
`sandbox._resolve_public_address` (the same mechanism the DAST engine uses). These tests prove the
pin connects to the validated IP, blocks internal/metadata targets, defeats a rebind that changes
between the check and the connect, and is torn down afterwards.
"""

from __future__ import annotations

import socket
import types

import pytest
from guardian_scanner import sandbox
from guardian_scanner.discovery import webprobe
from guardian_scanner.discovery.webprobe import _pinned_egress, probe


def _addrinfo(*ips, port=443):
    return [(0, socket.SOCK_STREAM, 0, "", (ip, port)) for ip in ips]


class _ConnSpy:
    def __init__(self):
        self.addresses: list = []

    def __call__(self, address, *a, **k):
        self.addresses.append(address)
        return types.SimpleNamespace(close=lambda: None)  # stand-in socket; no real network


# ── the pin itself ───────────────────────────────────────────────────────────────────────────────
def test_pin_connects_to_validated_public_ip(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("93.184.216.34"))
    spy = _ConnSpy()
    monkeypatch.setattr(socket, "create_connection", spy)
    with _pinned_egress():
        socket.create_connection(("public.example", 443))
    assert spy.addresses == [("93.184.216.34", 443)]  # pinned to the IP, not the hostname


@pytest.mark.parametrize("ip", ["10.0.0.5", "127.0.0.1", "169.254.169.254", "::1", "fe80::1"])
def test_pin_blocks_internal_targets(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo(ip))
    real = _ConnSpy()
    monkeypatch.setattr(socket, "create_connection", real)
    with _pinned_egress(), pytest.raises(PermissionError):
        socket.create_connection(("evil.example", 443))
    assert real.addresses == []  # the real connector was never reached with an internal address


def test_pin_multi_record_rebind_is_blocked(monkeypatch):
    # Host resolves to a public AND an internal address ⇒ refused (defeats a multi-record rebind).
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: _addrinfo("93.184.216.34", "10.1.2.3"))
    monkeypatch.setattr(socket, "create_connection", _ConnSpy())
    with _pinned_egress(), pytest.raises(PermissionError):
        socket.create_connection(("rebind.example", 443))


def test_pin_restores_create_connection():
    original = socket.create_connection
    with _pinned_egress():
        assert socket.create_connection is not original
    assert socket.create_connection is original  # restored on exit


# ── the TOCTOU end-to-end through probe(): check says public, connect rebinds internal ────────────
class _SpyClient:
    """Stand-in httpx.Client whose .get() drives socket.create_connection like httpcore would."""

    def __init__(self, **kwargs):
        _SpyClient.kwargs = dict(kwargs)

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def get(self, url):  # noqa: ANN001
        host = url.split("://", 1)[1].split("/", 1)[0].split(":")[0]
        socket.create_connection((host, 80))  # exercises the pin exactly where the real connect is
        return types.SimpleNamespace(status_code=200, headers={}, text="<html><body>ok</body></html>",
                                     url=url)


def test_probe_defeats_rebind_between_check_and_connect(monkeypatch):
    # getaddrinfo answers PUBLIC for the first lookup (webprobe._is_public_address) and INTERNAL for
    # the next (the pin's connect-time resolution) — the DNS-rebinding attack.
    calls = {"n": 0}

    def flipping_getaddrinfo(*_a, **_k):
        calls["n"] += 1
        return _addrinfo("93.184.216.34") if calls["n"] == 1 else _addrinfo("169.254.169.254")

    real = _ConnSpy()
    monkeypatch.setattr(socket, "getaddrinfo", flipping_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", real)
    monkeypatch.setattr("httpx.Client", _SpyClient)

    obs = probe("http://rebind.example/")

    assert obs.reachable is False
    assert "PermissionError" in obs.error and "internal" in obs.error  # connect refused by the pin
    assert real.addresses == []  # never connected to the rebinded 169.254.169.254 metadata address


def test_probe_connects_to_pinned_ip_for_a_stable_public_host(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("93.184.216.34"))
    real = _ConnSpy()
    monkeypatch.setattr(socket, "create_connection", real)
    monkeypatch.setattr("httpx.Client", _SpyClient)

    obs = probe("http://public.example/")

    assert obs.reachable is True and obs.status == 200
    assert real.addresses == [("93.184.216.34", 80)]  # connected to the validated IP, not the host
    assert _SpyClient.kwargs.get("follow_redirects") is False  # redirects still not auto-followed


def test_probe_refuses_directly_internal_host(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("169.254.169.254"))
    monkeypatch.setattr("httpx.Client", _SpyClient)
    obs = probe("http://169-254-metadata.example/")
    assert obs.reachable is False
    assert "non-public host" in obs.error  # rejected by _is_public_address before any connect


def test_webprobe_reuses_sandbox_validator():
    # The pin must delegate to the shared, audited resolver — not a private re-implementation.
    assert webprobe.sandbox._resolve_public_address is sandbox._resolve_public_address
