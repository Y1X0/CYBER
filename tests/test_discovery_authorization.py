"""Authorization-gate matcher unit tests (Phase 6C) — pure scope logic, no DB."""

from __future__ import annotations

from guardian_scanner.discovery.authorization import target_matches


def _t(type_, value):
    return {"type": type_, "value": value}


def test_domain_matches_exact_and_subdomain():
    auth = [_t("domain", "example.com")]
    assert target_matches(auth, "example.com")
    assert target_matches(auth, "api.example.com")
    assert target_matches(auth, "API.Example.com")      # case-insensitive
    assert target_matches(auth, "api.example.com:443")  # port stripped
    assert not target_matches(auth, "example.org")
    assert not target_matches(auth, "notexample.com")   # not a subdomain


def test_netblock_contains_ip():
    auth = [_t("netblock", "203.0.113.0/24")]
    assert target_matches(auth, "203.0.113.10")
    assert target_matches(auth, "203.0.113.10:443")
    assert not target_matches(auth, "203.0.114.10")


def test_ip_and_host_exact():
    assert target_matches([_t("ip", "8.8.8.8")], "8.8.8.8")
    assert not target_matches([_t("ip", "8.8.8.8")], "8.8.4.4")
    assert target_matches([_t("host", "vpn.example.com")], "vpn.example.com")


def test_empty_authorization_denies_everything():
    assert not target_matches([], "example.com")
    assert not target_matches([_t("domain", "")], "example.com")
