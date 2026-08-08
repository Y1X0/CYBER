"""WebTlsProvider unit contract (no DB, no network) — offline evidence + deterministic normalize.

Proves the provider is a passive observer: offline it reads a snapshot and opens no socket, its
evidence carries only observed facts, and normalize() derives a finding from evidence deterministically
(expired cert, hostname mismatch) or nothing — a finding is an inference, never the tool's verdict.
"""

from __future__ import annotations

from guardian_core.enums import EngineKey
from guardian_core.tool import EffectiveScope, RawEvidence, ToolJob
from guardian_scanner.tools.providers.web_tls_provider import WebTlsProvider


def _job(targets, snapshot):
    return ToolJob(
        tenant_id="t", job_id="j", tool_key="web_tls",
        scope=EffectiveScope(targets=tuple(targets), ports=(80, 443), protocols=("tls",),
                             network_allowed=True, read_only=True),
        settings={"allow_live": False, "snapshot": snapshot},
    )


def test_capabilities_are_active_network_and_need_approval():
    caps = WebTlsProvider().capabilities
    assert caps.network and caps.active and not caps.destructive
    assert caps.requires_authorization and caps.requires_human_approval
    assert caps.ports == (80, 443)


def test_validate_rejects_empty_scope():
    p = WebTlsProvider()
    import pytest
    with pytest.raises(ValueError):
        p.validate(_job([], {}))


def test_offline_execute_yields_evidence_from_snapshot():
    p = WebTlsProvider()
    snap = {"app.example.com": {
        "tls": {"expired": False, "hostname_verified": True, "not_after": "x"},
        "http": {"port": 80, "status": 200, "server": "nginx"},
    }}
    ev = list(p.execute(_job(["app.example.com"], snap)))
    kinds = sorted(e.kind for e in ev)
    assert kinds == ["http", "tls"]
    assert all(e.tool == "web_tls" and e.target == "app.example.com" for e in ev)
    assert all(e.provenance["mode"] == "offline" for e in ev)


def test_normalize_expired_cert_is_a_finding():
    p = WebTlsProvider()
    raw = p.normalize(RawEvidence(tool="web_tls", execution_id="j", target="app.example.com",
                                  kind="tls", data={"expired": True, "not_after": "2000"}))
    assert raw is not None and raw.engine == EngineKey.WEB_TLS
    assert raw.location["rule"] == "tls-cert-expired"


def test_normalize_hostname_mismatch_is_a_finding():
    p = WebTlsProvider()
    raw = p.normalize(RawEvidence(tool="web_tls", execution_id="j", target="app.example.com",
                                  kind="tls", data={"expired": False, "hostname_verified": False}))
    assert raw is not None and raw.location["rule"] == "tls-hostname-mismatch"


def test_normalize_healthy_cert_and_http_are_not_findings():
    p = WebTlsProvider()
    healthy = RawEvidence(tool="web_tls", execution_id="j", target="h", kind="tls",
                          data={"expired": False, "hostname_verified": True})
    http = RawEvidence(tool="web_tls", execution_id="j", target="h", kind="http",
                       data={"status": 200})
    assert p.normalize(healthy) is None
    assert p.normalize(http) is None
