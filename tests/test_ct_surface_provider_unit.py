"""CtSurfaceProvider unit contract (Provider #4, L1) — passive CT discovery + anti-SSRF.

No DB, no network. Proves, within the ADR-0026 lock, that:
  * the derived level is exactly L1 PASSIVE_NETWORK and needs no approval/campaign;
  * the wire can change neither the CT endpoint nor the target (target comes ONLY from scope);
  * scope isolation holds — only assets AT/under an authorized domain are emitted;
  * anti-SSRF holds — off-host/redirect/private-IP egress is refused, fail-closed;
  * evidence normalizes to assets (a finding is never produced) and leaks no raw CT/secret payload.
"""

from __future__ import annotations

import socket

import pytest
from guardian_core.capability import CapabilityLevel, derive_capability_level
from guardian_core.tool import (
    EffectiveScope,
    ToolJob,
    derive_effective_scope,
    evaluate_tool_policy,
)
from guardian_scanner.tools.providers import ct_surface_provider as ctp
from guardian_scanner.tools.providers.ct_surface_provider import (
    CtSurfaceProvider,
    EgressBlocked,
)


def _job(ct, targets=("example.com",), *, allow_live=False):
    return ToolJob(
        tenant_id="t", job_id="j", tool_key="ct_surface",
        scope=EffectiveScope(targets=tuple(targets), ports=(), protocols=(),
                             network_allowed=True, read_only=True),
        settings={"ct": ct, "allow_live": allow_live},
    )


# ── governance: derived level is L1, no approval ──────────────────────────────────────────────────
def test_capabilities_are_passive_network_no_approval():
    caps = CtSurfaceProvider().capabilities
    assert caps.network is True and caps.active is False and caps.destructive is False
    assert caps.requires_authorization is True and caps.requires_human_approval is False
    assert caps.ports == () and caps.protocols == ()          # never touches the target


def test_derived_level_is_exactly_l1():
    caps = CtSurfaceProvider().capabilities
    assert derive_capability_level(caps) is CapabilityLevel.PASSIVE_NETWORK


def test_policy_gate_allows_with_target_and_needs_no_approval():
    caps = CtSurfaceProvider().capabilities
    scope = derive_effective_scope(["example.com"], ["example.com"], caps, None)
    decision = evaluate_tool_policy(caps, scope)
    assert decision.allowed is True and decision.requires_human_approval is False


# ── the wire cannot change the CT endpoint ────────────────────────────────────────────────────────
def test_ct_endpoint_host_is_fixed_regardless_of_target():
    from urllib.parse import urlsplit
    for evil in ("example.com", "evil.com/@internal", "a.com#@169.254.169.254", "x.com:9/y"):
        assert urlsplit(ctp._ct_url(evil)).hostname == "crt.sh"   # host never moves off the constant


def test_endpoint_allowlist_refuses_off_host_and_plain_http():
    ctp._assert_endpoint_allowed("https://crt.sh/?q=example.com&output=json")   # ok
    for bad in ("http://crt.sh/?q=x", "https://evil.com/?q=x", "https://crt.sh.evil.com/",
                "https://169.254.169.254/"):
        with pytest.raises(EgressBlocked):
            ctp._assert_endpoint_allowed(bad)


# ── the wire cannot change the target (scope-only) + scope isolation ──────────────────────────────
def test_target_comes_only_from_scope_not_settings():
    # A domain present only in the CT snapshot (not in scope) is never enumerated.
    ct = {"authorized.com": ["a.authorized.com"], "secret.com": ["x.secret.com"]}
    hosts = [e.target for e in CtSurfaceProvider().execute(_job(ct, ("authorized.com",)))]
    assert hosts == ["a.authorized.com"]                       # secret.com never consulted


def test_scope_isolation_drops_foreign_sans():
    # A cert for the authorized domain may also list foreign names — those are not our assets.
    ct = {"example.com": ["www.example.com", "attacker.com", "api.example.com"]}
    hosts = sorted(e.target for e in CtSurfaceProvider().execute(_job(ct)))
    assert hosts == ["api.example.com", "www.example.com"]     # attacker.com dropped


def test_malformed_target_builds_no_url_and_yields_nothing():
    ct = {"not a domain/@x": ["y"]}
    assert list(CtSurfaceProvider().execute(_job(ct, ("not a domain/@x",)))) == []


# ── anti-SSRF: private/loopback/link-local/metadata never egress ──────────────────────────────────
@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.5.9", "169.254.169.254",  # incl. cloud metadata
    "::1", "fd00::1", "0.0.0.0", "224.0.0.1", "not-an-ip",
])
def test_blocked_ips_are_refused(ip):
    assert ctp._is_blocked_ip(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
def test_public_ips_are_allowed(ip):
    assert ctp._is_blocked_ip(ip) is False


def test_ct_host_resolving_to_private_is_refused(monkeypatch):
    # DNS-rebinding guard: if the fixed host resolves to a private IP, egress is refused.
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(EgressBlocked):
        ctp._assert_ct_host_public()


def test_ct_host_resolving_to_public_is_allowed(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])
    ctp._assert_ct_host_public()                               # no raise


def test_redirect_is_refused():
    for code in (301, 302, 303, 307, 308):
        with pytest.raises(EgressBlocked):
            ctp._ensure_not_redirect(code)
    ctp._ensure_not_redirect(200)                              # 200 is fine


def test_live_egress_failure_is_fail_closed(monkeypatch):
    # If the hardened fetch refuses egress, the provider emits nothing for that target (no crash).
    def _boom(_domain):
        raise EgressBlocked("blocked")
    monkeypatch.setattr(ctp, "_fetch_ct_live", _boom)
    job = _job({}, ("example.com",), allow_live=True)
    assert list(CtSurfaceProvider().execute(job)) == []


# ── evidence: assets not findings, no raw/secret leakage ──────────────────────────────────────────
def test_discovered_asset_evidence_shape_and_normalize_is_none():
    ct = {"example.com": ["www.example.com", "example.com"]}
    ev = list(CtSurfaceProvider().execute(_job(ct)))
    kinds = {e.kind for e in ev}
    assert kinds == {"discovered_asset"}
    apex = next(e for e in ev if e.target == "example.com")
    sub = next(e for e in ev if e.target == "www.example.com")
    assert apex.data["asset_type"] == "domain" and sub.data["asset_type"] == "subdomain"
    assert all(e.data.get("source") == "ct_log" for e in ev)
    # No raw CT payload / secret keys ever placed in evidence.
    for e in ev:
        assert set(e.data) <= {"host", "parent_domain", "source", "asset_type"}
    assert all(CtSurfaceProvider().normalize(e) is None for e in ev)   # inventory, never a finding


def test_parse_ct_names_flattens_wildcards_and_dedupes():
    raw = b'[{"name_value": "*.example.com\\nwww.example.com"}, {"common_name": "example.com"}]'
    assert ctp._parse_ct_names(raw) == ["example.com", "www.example.com"]


def test_parse_ct_names_on_garbage_returns_empty():
    assert ctp._parse_ct_names(b"not json") == []


def test_execution_is_deterministic():
    ct = {"example.com": ["b.example.com", "a.example.com", "b.example.com"]}
    a = [(e.target, e.kind) for e in CtSurfaceProvider().execute(_job(ct))]
    b = [(e.target, e.kind) for e in CtSurfaceProvider().execute(_job(ct))]
    assert a == b and a == [("a.example.com", "discovered_asset"),
                            ("b.example.com", "discovered_asset")]


def test_validate_rejects_no_target():
    job = ToolJob(tenant_id="t", job_id="j", tool_key="ct_surface",
                  scope=EffectiveScope(targets=(), ports=(), protocols=(),
                                       network_allowed=True, read_only=True), settings={})
    with pytest.raises(ValueError, match="no in-scope target"):
        CtSurfaceProvider().validate(job)
