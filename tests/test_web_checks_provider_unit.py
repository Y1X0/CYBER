"""WebChecksProvider unit contract (Provider #6, L3 SENSITIVE) — templated detection + anti-SSRF.

No DB, no network. Proves: derived level is L3 (campaign+approval gate), targets/ports come only
from scope, anti-SSRF refuses private/loopback/metadata resolution, a redirect is never followed,
offline detection yields one finding per detection, secret-adjacent snippets are redacted, snippets
are bounded (never a full body), and a bad target builds no request.

WP-D1 replaced the six hard-coded `_Check` tuples with nuclei-format templates loaded from
`guardian_scanner/templates/library`. Every property above is unchanged and re-asserted here; what
the tests reference is now a template id rather than a check id.
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
    templates,
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


def _detections(events):
    return [e for e in events if e.kind == "web_check"]


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
    assert "_assert_target_public(host)" in src


def test_the_live_path_asserts_the_target_is_public_before_probing():
    """The template engine is proven against a loopback fixture elsewhere; the production path must
    still refuse loopback, or that fixture becomes a way to reach a customer's internal network."""
    import inspect
    src = inspect.getsource(wc.WebChecksProvider.execute)
    assert "_assert_target_public(host)" in src


# ── template library ─────────────────────────────────────────────────────────────────────────────
def test_the_library_loads_and_nothing_was_silently_dropped():
    loaded = templates()
    assert len(loaded) >= 15
    assert wc._REJECTED == ()


# ── offline detection → evidence + finding ─────────────────────────────────────────────────────────
def test_offline_detection_yields_evidence_and_one_finding():
    snap = {"example.com": {"/.git/config": {"status": 200, "body": _GIT}}}
    ev = list(WebChecksProvider().execute(_job(snap, ports=(443,))))
    checks = _detections(ev)
    assert len(checks) == 1 and checks[0].data["template_id"] == "git-config-exposure"
    assert checks[0].data["port"] == 443 and "snippet" in checks[0].data
    raw = WebChecksProvider().normalize(checks[0])
    assert raw is not None and raw.engine is EngineKey.WEB_CHECKS
    assert raw.location["rule"] == "web-check-git-config-exposure"
    assert raw.base_severity.value == "high"
    # The template's own classification travels to the finding rather than being re-derived.
    assert raw.cwe_id == "CWE-527" and raw.cvss_base == 7.5
    scan = next(e for e in ev if e.kind == "web_checks_scan")
    assert scan.data["status"] == "ok" and WebChecksProvider().normalize(scan) is None


def test_env_detection_snippet_is_redacted_no_secret_leak():
    snap = {"example.com": {"/.env": {"status": 200, "body": _ENV}}}
    ev = _detections(WebChecksProvider().execute(_job(snap, ports=(443,))))
    assert len(ev) == 1 and ev[0].data["snippet"] == "<redacted>"
    assert "hunter2" not in str(ev[0].data) and "supersecret" not in str(ev[0].data)


def test_non_200_is_no_detection():
    snap = {"example.com": {"/.git/config": {"status": 404, "body": _GIT}}}
    assert _detections(WebChecksProvider().execute(_job(snap, ports=(443,)))) == []


def test_bad_target_builds_no_request():
    snap = {"bad host/@x": {"/.git/config": {"status": 200, "body": _GIT}}}
    assert list(WebChecksProvider().execute(_job(snap, ("bad host/@x",)))) == []


def test_ports_narrowed_to_80_443_only():
    # A scope port outside {80,443} is ignored — the provider never probes it.
    snap = {"example.com": {"/.git/config": {"status": 200, "body": _GIT}}}
    ev = _detections(WebChecksProvider().execute(_job(snap, ports=(8080, 443))))
    assert {e.data["port"] for e in ev} == {443}


def test_validate_rejects_no_target():
    job = ToolJob(tenant_id="t", job_id="j", tool_key="web_checks",
                  scope=EffectiveScope(targets=(), ports=(443,), protocols=("https",),
                                       network_allowed=True, read_only=True), settings={})
    with pytest.raises(ValueError, match="no in-scope target"):
        WebChecksProvider().validate(job)


def test_execution_is_deterministic():
    snap = {"example.com": {"/.git/config": {"status": 200, "body": _GIT},
                            "/server-status": {"status": 200, "body": "Apache Server Status"}}}
    a = [(e.target, e.kind, e.data.get("template_id"))
         for e in WebChecksProvider().execute(_job(snap))]
    b = [(e.target, e.kind, e.data.get("template_id"))
         for e in WebChecksProvider().execute(_job(snap))]
    assert a == b
    assert {"git-config-exposure", "apache-server-status"} <= {t for _, _, t in a if t}


def test_a_path_absent_from_the_snapshot_is_a_miss_not_a_match():
    """Offline mode must not invent a response. An unrecorded path is unknown, not clean and not
    vulnerable — inventing either turns a partial snapshot into a fabricated report."""
    assert _detections(WebChecksProvider().execute(_job({"example.com": {}}, ports=(443,)))) == []


def test_extracted_values_reach_the_finding():
    body = _GIT + "\turl = https://git.example.com/app.git\n"
    snap = {"example.com": {"/.git/config": {"status": 200, "body": body}}}
    ev = _detections(WebChecksProvider().execute(_job(snap, ports=(443,))))
    raw = WebChecksProvider().normalize(ev[0])
    assert raw.evidence["extracted"]["remote"] == ["https://git.example.com/app.git"]
    assert raw.evidence["matched_at"] == "https://example.com:443/.git/config"


def test_a_negative_matcher_template_fires_on_a_missing_header():
    """The missing-CSP template is the negative-matcher case end to end."""
    snap = {"example.com": {"/": {"status": 200, "body": "<html></html>",
                                  "headers": {"Server": "nginx"}}}}
    fired = {e.data["template_id"]
             for e in _detections(WebChecksProvider().execute(_job(snap, ports=(443,))))}
    assert "missing-security-headers" in fired

    with_csp = {"example.com": {"/": {"status": 200, "body": "<html></html>",
                                      "headers": {"Content-Security-Policy": "default-src 'self'"}}}}
    fired = {e.data["template_id"]
             for e in _detections(WebChecksProvider().execute(_job(with_csp, ports=(443,))))}
    assert "missing-security-headers" not in fired


def test_an_empty_library_refuses_the_job_rather_than_reporting_a_clean_scan(monkeypatch):
    """Zero templates and zero findings look identical in a report. The job must fail loudly."""
    monkeypatch.setattr(wc, "_LIBRARY", ())
    with pytest.raises(ValueError, match="no usable templates"):
        WebChecksProvider().validate(_job({}))


def test_containment_is_logged_rather_than_silently_returning_no_evidence():
    """A tool killed by a resource limit produced an empty list that downstream code could not tell
    apart from a clean target. The reason now reaches the log."""
    from guardian_scanner import sandbox
    from guardian_scanner.tools.backends import inproc

    recorded = []

    class _Log:
        def error(self, event, **kw):
            recorded.append((event, kw))

    backend = inproc.InprocSandboxBackend()
    original = inproc.log
    inproc.log = _Log()
    try:
        def explode():
            raise sandbox.SandboxViolation("cpu limit exceeded")

        job = _job({}, ports=(443,))
        result = backend.run(job, explode)
    finally:
        inproc.log = original

    assert result == []
    assert recorded and recorded[0][0] == "tool_contained"
    assert "cpu limit" in recorded[0][1]["reason"]
