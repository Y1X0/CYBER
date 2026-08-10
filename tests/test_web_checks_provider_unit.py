"""WebChecksProvider unit contract (Provider #6, L3 SENSITIVE) — curated detection + anti-SSRF.

No DB, no network. Proves: derived level is L3 (campaign+approval gate), targets/ports come only from
scope, anti-SSRF refuses private/loopback/metadata resolution, a redirect is never followed, offline
detection yields one finding per detection, secret-adjacent snippets are redacted, snippets are
bounded (never a full body), and a bad target builds no request.
"""

from __future__ import annotations

import socket

import pytest
from guardian_core.capability import CapabilityLevel, derive_capability_level
from guardian_core.enums import EngineKey
from guardian_core.tool import EffectiveScope, ToolJob
from guardian_scanner.tools.providers import web_checks_provider as wc
from guardian_scanner.tools.providers.web_checks_provider import (
    EgressBlocked,
    WebChecksProvider,
    _assert_target_public,
    _is_blocked_ip,
    _match,
    _redact,
)

_GIT = "[core]\n\trepositoryformatversion = 0\n"
_ENV = "APP_SECRET=supersecrettokenvalue1234567890\nDB_PASSWORD=hunter2\n"


def _job(snapshot, targets=("example.com",), ports=(80, 443), allow_live=False):
    return ToolJob(
        tenant_id="t", job_id="j", tool_key="web_checks",
        scope=EffectiveScope(targets=tuple(targets), ports=tuple(ports), protocols=("http", "https"),
                             network_allowed=True, read_only=True),
        settings={"snapshot": snapshot, "allow_live": allow_live},
    )


# ── governance: derived L3 ─────────────────────────────────────────────────────────────────────────
def test_capabilities_derive_l3_with_human_approval():
    caps = WebChecksProvider().capabilities
    assert caps.network is True and caps.active is True and caps.destructive is False
    assert caps.requires_authorization is True and caps.requires_human_approval is True
    assert derive_capability_level(caps) is CapabilityLevel.SENSITIVE      # L3 ⇒ campaign+approval


# ── anti-SSRF ────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254",
                                "::1", "fd00::1", "0.0.0.0", "not-an-ip"])
def test_blocked_ips_refused(ip):
    assert _is_blocked_ip(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
def test_public_ips_allowed(ip):
    assert _is_blocked_ip(ip) is False


def test_target_resolving_private_is_refused(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(EgressBlocked):
        _assert_target_public("intranet.example.com")


def test_target_resolving_public_is_allowed(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])
    _assert_target_public("example.com")                                  # no raise


def test_live_client_configured_no_redirect_follow():
    # The hardened fetch constructs its client with follow_redirects=False (never a chosen Location).
    import inspect
    src = inspect.getsource(wc._fetch_live)
    assert "follow_redirects=False" in src and "300 <= resp.status_code < 400" in src


# ── matcher + redaction ──────────────────────────────────────────────────────────────────────────
def test_redact_strips_token_like_secrets():
    assert "***" in _redact("APP_SECRET=supersecrettokenvalue1234567890")


def test_match_returns_bounded_snippet_and_redacts_secret_checks():
    git = next(c for c in wc._CHECKS if c.id == "git_config")
    snip = _match(git, _GIT)
    assert snip is not None and len(snip) <= wc._SNIPPET_MAX
    env = next(c for c in wc._CHECKS if c.id == "env_file")
    assert _match(env, _ENV) == "<redacted>"                             # secret-adjacent ⇒ no body
    assert _match(git, "nothing here") is None


# ── offline detection → evidence + finding ─────────────────────────────────────────────────────────
def test_offline_detection_yields_evidence_and_one_finding():
    snap = {"example.com": {"/.git/config": {"status": 200, "body": _GIT}}}
    ev = list(WebChecksProvider().execute(_job(snap, ports=(443,))))
    checks = [e for e in ev if e.kind == "web_check"]
    assert len(checks) == 1 and checks[0].data["check_id"] == "git_config"
    assert checks[0].data["port"] == 443 and "snippet" in checks[0].data
    raw = WebChecksProvider().normalize(checks[0])
    assert raw is not None and raw.engine is EngineKey.WEB_CHECKS
    assert raw.location["rule"] == "web-check-git_config" and raw.base_severity.value == "high"
    scan = next(e for e in ev if e.kind == "web_checks_scan")
    assert scan.data["status"] == "ok" and WebChecksProvider().normalize(scan) is None


def test_env_detection_snippet_is_redacted_no_secret_leak():
    snap = {"example.com": {"/.env": {"status": 200, "body": _ENV}}}
    ev = [e for e in WebChecksProvider().execute(_job(snap, ports=(443,))) if e.kind == "web_check"]
    assert len(ev) == 1 and ev[0].data["snippet"] == "<redacted>"
    assert "hunter2" not in str(ev[0].data) and "supersecret" not in str(ev[0].data)


def test_non_200_is_no_detection():
    snap = {"example.com": {"/.git/config": {"status": 404, "body": _GIT}}}
    ev = [e for e in WebChecksProvider().execute(_job(snap, ports=(443,))) if e.kind == "web_check"]
    assert ev == []


def test_bad_target_builds_no_request():
    snap = {"bad host/@x": {"/.git/config": {"status": 200, "body": _GIT}}}
    assert list(WebChecksProvider().execute(_job(snap, ("bad host/@x",)))) == []


def test_ports_narrowed_to_80_443_only():
    # A scope port outside {80,443} is ignored — the provider never probes it.
    snap = {"example.com": {"/.git/config": {"status": 200, "body": _GIT}}}
    ev = list(WebChecksProvider().execute(_job(snap, ports=(8080, 443))))
    assert {e.data["port"] for e in ev if e.kind == "web_check"} == {443}


def test_validate_rejects_no_target():
    job = ToolJob(tenant_id="t", job_id="j", tool_key="web_checks",
                  scope=EffectiveScope(targets=(), ports=(443,), protocols=("https",),
                                       network_allowed=True, read_only=True), settings={})
    with pytest.raises(ValueError, match="no in-scope target"):
        WebChecksProvider().validate(job)


def test_execution_is_deterministic():
    snap = {"example.com": {"/.git/config": {"status": 200, "body": _GIT},
                            "/server-status": {"status": 200, "body": "Apache Server Status"}}}
    a = [(e.target, e.kind, e.data.get("check_id")) for e in WebChecksProvider().execute(_job(snap))]
    b = [(e.target, e.kind, e.data.get("check_id")) for e in WebChecksProvider().execute(_job(snap))]
    assert a == b
