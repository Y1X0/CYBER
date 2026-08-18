"""DAST engine SSRF / DNS-rebinding boundaries (P1-②) — no live network.

The DAST live GET runs on the scanner plane without kernel egress isolation, so it must be
rebinding-safe: the connection is PINNED to a pre-validated public IP (via the repo's
sandbox._resolve_public_address), so httpx cannot re-resolve the hostname to an internal address
between check and connect. Private/loopback/link-local/metadata and IPv4-mapped-IPv6 are refused;
redirects are not followed.
"""

from __future__ import annotations

import socket
import types

import pytest
from guardian_scanner import sandbox
from guardian_scanner.engines import dast_engine
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.engines.dast_engine import DastEngine, _pinned_egress


def _ctx(url):
    return ScanContext(scan_id="s", asset_kind="web", asset_identifier=url, asset_config={})


def _addrinfo(*ips):
    return [(0, socket.SOCK_STREAM, 0, "", (ip, 443)) for ip in ips]


class _ConnSpy:
    def __init__(self):
        self.address = None

    def __call__(self, address, *a, **k):
        self.address = address
        return types.SimpleNamespace(close=lambda: None)   # a stand-in socket; no real network


# ── the pin: validates EVERY connect, blocks internal / IPv4-mapped / rebinding / IDN ─────────────
def test_pin_connects_to_the_validated_public_ip(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("93.184.216.34"))
    spy = _ConnSpy()
    monkeypatch.setattr(socket, "create_connection", spy)     # becomes the "real" the pin wraps
    with _pinned_egress():
        socket.create_connection(("public.example", 443))
    assert spy.address == ("93.184.216.34", 443)              # pinned to the IP, not the hostname


@pytest.mark.parametrize("ip", ["10.0.0.5", "127.0.0.1", "169.254.169.254", "192.168.1.1",
                                "::1", "fe80::1"])
def test_pin_blocks_internal_targets(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo(ip))
    monkeypatch.setattr(socket, "create_connection", _ConnSpy())
    with _pinned_egress(), pytest.raises(PermissionError):
        socket.create_connection(("evil.example", 443))


def test_pin_blocks_ipv4_mapped_ipv6_metadata(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: _addrinfo("::ffff:169.254.169.254"))
    monkeypatch.setattr(socket, "create_connection", _ConnSpy())
    with _pinned_egress(), pytest.raises(PermissionError):
        socket.create_connection(("evil.example", 443))


def test_pin_rebinding_multi_record_is_blocked(monkeypatch):
    # Host resolves to a public AND an internal address ⇒ refused (defeats a multi-record rebind).
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: _addrinfo("93.184.216.34", "10.1.2.3"))
    monkeypatch.setattr(socket, "create_connection", _ConnSpy())
    with _pinned_egress(), pytest.raises(PermissionError):
        socket.create_connection(("rebind.example", 443))


def test_pin_validates_idn_punycode_host_not_skipped(monkeypatch):
    # P1-Ⓑ regression: httpcore connects with the IDNA/punycode host; it must be VALIDATED, not
    # passed through on a Unicode-vs-punycode mismatch. An internal punycode target must be refused.
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("169.254.169.254"))
    monkeypatch.setattr(socket, "create_connection", _ConnSpy())
    with _pinned_egress(), pytest.raises(PermissionError):
        socket.create_connection(("xn--bcher-kva.example", 443))   # punycode host → still validated


def test_pin_validates_and_pins_public_punycode_host(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("93.184.216.34"))
    spy = _ConnSpy()
    monkeypatch.setattr(socket, "create_connection", spy)
    with _pinned_egress():
        socket.create_connection(("xn--bcher-kva.example", 443))
    assert spy.address == ("93.184.216.34", 443)              # punycode host validated + pinned


def test_pin_validates_every_host_no_passthrough(monkeypatch):
    # There is NO host-equality gate: ANY host connected during the window is validated (no bypass).
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("10.9.9.9"))
    monkeypatch.setattr(socket, "create_connection", _ConnSpy())
    with _pinned_egress(), pytest.raises(PermissionError):
        socket.create_connection(("anything.example", 8080))


def test_pin_restores_create_connection():
    original = socket.create_connection
    with _pinned_egress():
        assert socket.create_connection is not original
    assert socket.create_connection is original              # restored on exit


# ── engine wiring: pin is applied, redirects not followed, fail-closed on block ──────────────────
class _SpyClient:
    last: dict = {}

    def __init__(self, **kwargs):
        _SpyClient.last = dict(kwargs)

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def get(self, url, headers=None):  # noqa: ANN001
        # `text` is part of the stand-in now: the engine reads the response body since WP-D2,
        # because an injection check has nothing to decide on without it.
        return types.SimpleNamespace(headers={}, cookies=types.SimpleNamespace(jar=[]),
                                     url=url, status_code=200, text="<html><body>hi</body></html>")


def test_engine_pins_and_does_not_follow_redirects(monkeypatch):
    seen = {}

    @dast_engine.contextmanager
    def _fake_pin():
        seen["wrapped"] = True
        yield

    monkeypatch.setattr(dast_engine, "_pinned_egress", _fake_pin)
    monkeypatch.setattr("httpx.Client", _SpyClient)
    findings = list(DastEngine().run(_ctx("https://public.example/")))
    assert seen.get("wrapped") is True                       # the GET is wrapped in the pin
    assert _SpyClient.last.get("follow_redirects") is False   # redirects not followed
    assert _SpyClient.last.get("timeout") == 10.0
    assert any("Content-Security-Policy" in f.title for f in findings)   # public target scanned


def test_engine_fails_closed_when_pin_blocks(monkeypatch):
    """Fail closed means *fail*, not fall silent.

    This used to assert an empty list. An empty list is what the orchestrator records as a clean
    engine run, so a target the pin refused was reported to the customer exactly like a target with
    nothing wrong. Since WP-D2 the engine raises, the run is marked failed, and WP-E2 treats a
    failed engine as `not_checked` rather than as evidence anything was resolved."""
    class _BlockingClient(_SpyClient):
        def get(self, url, headers=None):  # noqa: ANN001
            raise PermissionError("egress denied: resolves to internal address")

    monkeypatch.setattr("httpx.Client", _BlockingClient)
    with pytest.raises(dast_engine.DastScanError, match="could not be reached"):
        list(DastEngine().run(_ctx("http://intranet.example/")))


def test_non_http_scheme_is_ignored(monkeypatch):
    def _forbid(*_a, **_k):
        raise AssertionError("no client for a non-http scheme")

    monkeypatch.setattr("httpx.Client", _forbid)
    assert list(DastEngine().run(_ctx("ftp://public.example/"))) == []


# ── the underlying validator (reused from sandbox) rejects internal, accepts public ──────────────
def test_resolve_public_address_blocks_and_pins(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("93.184.216.34"))
    assert sandbox._resolve_public_address("public.example", 443) == "93.184.216.34"
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("169.254.169.254"))
    with pytest.raises(PermissionError):
        sandbox._resolve_public_address("evil.example", 443)
