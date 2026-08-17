"""CT discovery source — egress confinement and scope hygiene in the shared module.

The CT fetch is the one place Guardian talks to a third party during passive discovery, so it is
the one place an SSRF could hide. These tests assert the confinement directly against the shared
module, so it stays covered independently of either provider that consumes it.
"""

from __future__ import annotations

import socket

import pytest
from guardian_core.discovery import DiscoveryContext
from guardian_scanner.discovery.providers.ct_provider import CtLogProvider
from guardian_scanner.sources import ct as ct_source


# ── the endpoint is a constant, not an input ──────────────────────────────────────────────────────
def test_domain_rides_in_the_query_string_only():
    url = ct_source.ct_url("evil.com/@attacker.internal")
    assert url.startswith("https://crt.sh/?q=")
    # Percent-encoded, so no separator survives to relocate the host.
    assert "@" not in url.split("?", 1)[1] or "%40" in url


@pytest.mark.parametrize("url", [
    "http://crt.sh/?q=x",                    # wrong scheme
    "https://attacker.example/?q=x",         # wrong host
    "https://crt.sh.attacker.example/?q=x",  # suffix trick
])
def test_disallowed_endpoints_are_refused(url):
    with pytest.raises(ct_source.EgressBlocked):
        ct_source.assert_endpoint_allowed(url)


def test_allowed_endpoint_passes():
    ct_source.assert_endpoint_allowed(ct_source.ct_url("example.com"))


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirects_are_refused(status):
    with pytest.raises(ct_source.EgressBlocked):
        ct_source.ensure_not_redirect(status)


def test_success_status_is_not_a_redirect():
    ct_source.ensure_not_redirect(200)


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "::1", "fe80::1", "not-an-ip",
])
def test_non_public_addresses_are_blocked(ip):
    assert ct_source.is_blocked_ip(ip) is True


def test_public_address_is_allowed():
    assert ct_source.is_blocked_ip("93.184.216.34") is False


def test_ct_host_resolving_to_private_address_is_refused(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(ct_source.EgressBlocked):
        ct_source.assert_ct_host_public()


def test_ct_host_with_no_address_is_refused(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [])
    with pytest.raises(ct_source.EgressBlocked):
        ct_source.assert_ct_host_public()


# ── parsing keeps only sanitized names ────────────────────────────────────────────────────────────
def test_wildcards_are_flattened_and_deduplicated():
    raw = b'[{"name_value":"*.example.com\\nAPI.example.com."},{"common_name":"api.example.com"}]'
    assert ct_source.parse_ct_names(raw) == ["api.example.com", "example.com"]


def test_malformed_payload_yields_nothing():
    assert ct_source.parse_ct_names(b"<html>nope</html>") == []
    assert ct_source.parse_ct_names(b"") == []


# ── scope hygiene: a certificate may list domains that are not the customer's ──────────────────────
def test_foreign_sans_are_dropped():
    snapshot = {"example.com": ["api.example.com", "attacker.com", "evil.example.com.attacker.com"]}
    hosts = ct_source.hosts_for_domain("example.com", allow_live=False, snapshot=snapshot)
    assert hosts == ["api.example.com"]


def test_malformed_domain_never_builds_a_url():
    assert ct_source.hosts_for_domain("not a domain", allow_live=False, snapshot={}) == []
    assert ct_source.hosts_for_domain("", allow_live=False, snapshot={}) == []


def test_offline_mode_opens_no_socket(monkeypatch):
    def _boom(*_a, **_k):
        raise AssertionError("offline CT discovery must not open a socket")

    monkeypatch.setattr(ct_source, "fetch_ct_live", _boom)
    ctx = DiscoveryContext(
        tenant_id="t", run_id="r", seeds={"domains": ["example.com"]},
        settings={"ct": {"example.com": ["api.example.com"]}})
    assets = list(CtLogProvider().collect(ctx))
    assert [a.canonical_key for a in assets] == ["api.example.com"]


def test_live_egress_failure_yields_nothing_rather_than_raising(monkeypatch):
    def _blocked(_domain):
        raise ct_source.EgressBlocked("refused")

    monkeypatch.setattr(ct_source, "fetch_ct_live", _blocked)
    ctx = DiscoveryContext(
        tenant_id="t", run_id="r", seeds={"domains": ["example.com"]},
        settings={"allow_live": True})
    assert list(CtLogProvider().collect(ctx)) == []


def test_seed_domain_itself_is_not_reported_as_a_discovery():
    ctx = DiscoveryContext(
        tenant_id="t", run_id="r", seeds={"domains": ["example.com"]},
        settings={"ct": {"example.com": ["example.com", "api.example.com"]}})
    assert [a.canonical_key for a in CtLogProvider().collect(ctx)] == ["api.example.com"]
