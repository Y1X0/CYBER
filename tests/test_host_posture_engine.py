"""Host & network posture engine (Phase 2/3) — assesses an authorized local-agent submission.

No scanning happens here: the engine consumes an allowlisted posture report. The load-bearing
properties: an unauthorized report is refused (never assessed), only allowlisted fields are read
(a smuggled secret is dropped/scrubbed), and router/server posture maps to the canonical pipeline.
"""

from __future__ import annotations

import json

import pytest
from guardian_core.enums import EngineKey, Severity
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.engines.host_posture_engine import HostPostureEngine, HostPostureInputError
from guardian_scanner.hostposture.schema import normalize


def _run(report: dict):
    ctx = ScanContext(scan_id="t", asset_kind=report.get("kind", "server_host"),
                      asset_identifier="x", inline_content=json.dumps(report))
    return list(HostPostureEngine().run(ctx))


def _titles(findings):
    return " | ".join(f.title for f in findings)


# ── authorization gate ──────────────────────────────────────────────────────────────────────────
def test_an_unauthorized_report_is_refused():
    with pytest.raises(HostPostureInputError):
        _run({"kind": "server_host", "authorized": False, "server": {}})


def test_a_missing_report_raises():
    ctx = ScanContext(scan_id="t", asset_kind="server_host", asset_identifier="x")
    with pytest.raises(HostPostureInputError):
        list(HostPostureEngine().run(ctx))


# ── network_host (router) ─────────────────────────────────────────────────────────────────────
def test_router_http_management_is_high():
    findings = _run({"kind": "network_host", "authorized": True,
                     "network": {"gateway": "192.168.1.1",
                                 "router": {"mgmt_http": True, "mgmt_https": False}}})
    f = next(x for x in findings if "cleartext HTTP" in x.title)
    assert f.engine == EngineKey.HOST_POSTURE
    assert f.base_severity == Severity.HIGH


def test_router_wan_management_is_critical():
    f = next(x for x in _run({"kind": "network_host", "authorized": True,
                              "network": {"router": {"wan_mgmt": True}}}) if "WAN" in x.title)
    assert f.base_severity == Severity.CRITICAL


def test_upnp_is_flagged():
    assert any("UPnP" in x.title for x in _run(
        {"kind": "network_host", "authorized": True, "network": {"router": {"upnp": True}}}))


def test_telnet_on_a_lan_host_is_high():
    findings = _run({"kind": "network_host", "authorized": True, "network": {"hosts": [
        {"ip": "192.168.1.50", "open_ports": [{"port": 23, "service": "telnet"}]}]}})
    f = next(x for x in findings if "telnet" in x.title)
    assert f.base_severity == Severity.HIGH


def test_a_secure_router_is_clean():
    assert _run({"kind": "network_host", "authorized": True,
                 "network": {"router": {"mgmt_http": False, "mgmt_https": True, "upnp": False}}}) == []


# ── server_host (Linux) ─────────────────────────────────────────────────────────────────────────
def test_ssh_root_login_is_high():
    f = next(x for x in _run({"kind": "server_host", "authorized": True,
                              "server": {"ssh": {"permit_root_login": "yes"}}})
             if "root login" in x.title)
    assert f.base_severity == Severity.HIGH
    assert f.cwe_id == "CWE-250"


def test_ssh_password_auth_is_flagged():
    assert any("password authentication" in x.title.lower() for x in _run(
        {"kind": "server_host", "authorized": True,
         "server": {"ssh": {"password_authentication": "yes"}}}))


def test_eol_os_is_high():
    f = next(x for x in _run({"kind": "server_host", "authorized": True,
                              "server": {"os": {"distro": "ubuntu", "version": "16.04",
                                                "eol": True}}}) if "End-of-life" in x.title)
    assert f.base_severity == Severity.HIGH


def test_exposed_docker_daemon_is_critical():
    f = next(x for x in _run({"kind": "server_host", "authorized": True,
                              "server": {"docker": {"installed": True, "daemon_tcp": True}}})
             if "Docker daemon" in x.title)
    assert f.base_severity == Severity.CRITICAL


def test_privileged_containers_are_high():
    f = next(x for x in _run({"kind": "server_host", "authorized": True,
                              "server": {"docker": {"privileged_containers": 2}}})
             if "Privileged containers" in x.title)
    assert f.base_severity == Severity.HIGH


def test_passwordless_sudo_is_high():
    assert any("Passwordless sudo" in x.title for x in _run(
        {"kind": "server_host", "authorized": True,
         "server": {"users": {"passwordless_sudo": True}}}))


def test_firewall_disabled_is_flagged():
    assert any("firewall" in x.title.lower() for x in _run(
        {"kind": "server_host", "authorized": True, "server": {"firewall": {"enabled": False}}}))


def test_a_hardened_server_is_clean():
    assert _run({"kind": "server_host", "authorized": True, "server": {
        "os": {"distro": "ubuntu", "version": "24.04", "eol": False},
        "firewall": {"enabled": True},
        "ssh": {"permit_root_login": "no", "password_authentication": "no", "protocol": "2"},
        "docker": {"installed": True, "daemon_tcp": False, "privileged_containers": 0},
    }}) == []


# ── allowlist normalizer ────────────────────────────────────────────────────────────────────────
def test_normalize_drops_unknown_keys_and_scrubs_secrets():
    n = normalize({"kind": "server_host", "authorized": True, "hostname": "host",
                   "secret_token": "AKIA" + "I" * 16,           # unknown key -> dropped
                   "server": {"ssh": {"permit_root_login": "yes",
                                      "note": "AKIA" + "I" * 16}}})  # unknown nested -> dropped
    blob = json.dumps(n)
    assert "AKIA" not in blob, "a smuggled secret survived normalization"
    assert "secret_token" not in n
    assert n["server"]["ssh"]["permit_root_login"] == "yes"


def test_supports_and_health():
    e = HostPostureEngine()
    assert e.supports("network_host") and e.supports("server_host")
    assert e.supports("repo") is False
    assert e.health().ok is True
