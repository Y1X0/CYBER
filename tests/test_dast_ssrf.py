"""DAST engine SSRF boundaries (P1-β) — no live network.

The DAST engine's live GET runs on the scanner plane WITHOUT kernel egress isolation, so it must
self-guard like web_checks/ct_surface: refuse a target resolving to a private/loopback/link-local/
metadata address (DNS-rebinding), and never follow a response-chosen redirect into a new host.
"""

from __future__ import annotations

import pytest
from guardian_scanner.engines import dast_engine
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.engines.dast_engine import (
    DastEngine,
    _assert_target_public,
    _EgressBlocked,
    _is_blocked_ip,
)

_PUBLIC = "93.184.216.34"


def _ctx(url):
    return ScanContext(scan_id="s", asset_kind="web", asset_identifier=url, asset_config={})


def _addrinfo(*ips):
    return [(2, 1, 6, "", (ip, 443)) for ip in ips]


class _SpyClient:
    """Records httpx.Client kwargs and the GET; returns a header-less 200 (⇒ findings)."""

    last: dict = {}

    def __init__(self, **kwargs):
        _SpyClient.last = dict(kwargs)
        _SpyClient.last["constructed"] = True

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def get(self, url, headers=None):  # noqa: ANN001
        _SpyClient.last["get_url"] = url
        import types

        return types.SimpleNamespace(headers={}, cookies=types.SimpleNamespace(jar=[]),
                                     url=url, status_code=200)


def _forbid_client(*_a, **_k):
    raise AssertionError("httpx.Client must NOT be constructed for a blocked target")


# ── the classifier ───────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("ip", ["10.0.0.5", "127.0.0.1", "169.254.169.254", "192.168.1.1",
                                "172.16.0.1", "::1", "fe80::1", "not-an-ip"])
def test_internal_and_metadata_ips_are_blocked(ip):
    assert _is_blocked_ip(ip) is True


@pytest.mark.parametrize("ip", ["93.184.216.34", "1.1.1.1", "8.8.8.8"])
def test_public_ips_are_allowed(ip):
    assert _is_blocked_ip(ip) is False


# ── the guard rejects non-public / rebinding targets, fail-closed ────────────────────────────────
def test_private_target_rejected(monkeypatch):
    monkeypatch.setattr(dast_engine.socket, "getaddrinfo", lambda *a, **k: _addrinfo("10.0.0.5"))
    monkeypatch.setattr("httpx.Client", _forbid_client)
    findings = list(DastEngine().run(_ctx("http://intranet.example/")))
    assert findings == []                      # nothing probed, nothing leaked from the internal host


def test_metadata_endpoint_rejected(monkeypatch):
    monkeypatch.setattr(dast_engine.socket, "getaddrinfo",
                        lambda *a, **k: _addrinfo("169.254.169.254"))
    monkeypatch.setattr("httpx.Client", _forbid_client)
    assert list(DastEngine().run(_ctx("http://169.254.169.254/latest/meta-data/"))) == []


def test_dns_rebinding_any_internal_answer_is_rejected(monkeypatch):
    # A host resolving to BOTH a public and an internal IP must be refused (rebinding defense).
    monkeypatch.setattr(dast_engine.socket, "getaddrinfo",
                        lambda *a, **k: _addrinfo(_PUBLIC, "10.1.2.3"))
    monkeypatch.setattr("httpx.Client", _forbid_client)
    assert list(DastEngine().run(_ctx("https://rebind.example/"))) == []


def test_assert_target_public_raises_on_internal(monkeypatch):
    monkeypatch.setattr(dast_engine.socket, "getaddrinfo", lambda *a, **k: _addrinfo("127.0.0.1"))
    with pytest.raises(_EgressBlocked):
        _assert_target_public("localhost.example")


# ── authorized public target works, and redirects are NOT followed ───────────────────────────────
def test_authorized_public_target_is_scanned(monkeypatch):
    monkeypatch.setattr(dast_engine.socket, "getaddrinfo", lambda *a, **k: _addrinfo(_PUBLIC))
    monkeypatch.setattr("httpx.Client", _SpyClient)
    findings = list(DastEngine().run(_ctx("https://public.example/")))
    # A header-less 200 yields the missing-security-header findings ⇒ the scan actually ran.
    assert any("Content-Security-Policy" in f.title for f in findings)


def test_redirects_are_not_followed_and_timeout_enforced(monkeypatch):
    monkeypatch.setattr(dast_engine.socket, "getaddrinfo", lambda *a, **k: _addrinfo(_PUBLIC))
    monkeypatch.setattr("httpx.Client", _SpyClient)
    list(DastEngine().run(_ctx("https://public.example/")))
    assert _SpyClient.last.get("constructed") is True
    assert _SpyClient.last.get("follow_redirects") is False   # never chase a response Location
    assert _SpyClient.last.get("timeout") == 10.0             # response/timeout bound preserved


def test_non_http_scheme_is_ignored(monkeypatch):
    monkeypatch.setattr("httpx.Client", _forbid_client)
    assert list(DastEngine().run(_ctx("ftp://public.example/"))) == []
