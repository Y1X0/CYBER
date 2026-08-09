"""NmapProvider + runner unit contract (no DB, no network, no real nmap).

Proves the two hard properties: the scan command is built ONLY from validated authorized IPs/ports
(no injection, no free-form args), and the subprocess runner is bounded (timeout/overflow/kill) and
never raises. Plus safe XML parsing (XXE/malformed fail-closed) and conservative normalization.
"""

from __future__ import annotations

import stat

import pytest
from guardian_core.capability import CapabilityLevel, derive_capability_level
from guardian_core.enums import EngineKey
from guardian_core.tool import EffectiveScope, RawEvidence, ToolJob
from guardian_scanner.tools.nmap_runner import build_nmap_argv, run_nmap
from guardian_scanner.tools.providers.nmap_provider import NmapProvider

_XML_TELNET = (
    b'<?xml version="1.0"?><nmaprun>'
    b'<host><address addr="10.0.0.5" addrtype="ipv4"/><ports>'
    b'<port protocol="tcp" portid="23"><state state="open"/>'
    b'<service name="telnet"/></port>'
    b'<port protocol="tcp" portid="22"><state state="open"/>'
    b'<service name="ssh" product="OpenSSH"/></port>'
    b'<port protocol="tcp" portid="8081"><state state="closed"/></port>'
    b'</ports></host></nmaprun>'
)


def _job(targets=("10.0.0.5",), ports=(22, 23), xml=_XML_TELNET, allow_live=False):
    return ToolJob(
        tenant_id="t", job_id="j", tool_key="nmap",
        scope=EffectiveScope(targets=tuple(targets), ports=tuple(ports), protocols=("tcp",),
                             network_allowed=True, read_only=True),
        settings={"allow_live": allow_live, "xml": xml.decode()})


# ── capability / level ──
def test_nmap_is_l2_active_recon_requiring_approval():
    caps = NmapProvider().capabilities
    assert caps.network and caps.active and not caps.destructive
    assert caps.requires_authorization and caps.requires_human_approval
    assert derive_capability_level(caps) == CapabilityLevel.ACTIVE_RECON


# ── argv isolation ──
def test_argv_is_fixed_connect_scan_no_root_no_dns():
    argv = build_nmap_argv(["10.0.0.5"], (80, 443))
    assert argv[0] == "nmap"
    assert "-sT" in argv and "-Pn" in argv and "-n" in argv         # connect / no-ping / no-DNS
    for banned in ("-sS", "-sU", "-O", "--script", "-A"):
        assert banned not in argv                                    # no raw/UDP/OS/NSE/aggressive
    assert argv[-1] == "10.0.0.5"


def test_argv_rejects_flag_injection_and_hostnames():
    for bad in ["--script=evil", "-oN/tmp/x", "127.0.0.1;rm", "example.com", "$(id)"]:
        with pytest.raises(ValueError):
            build_nmap_argv([bad], (80,))


def test_argv_rejects_empty_or_bad_ports():
    with pytest.raises(ValueError):
        build_nmap_argv(["10.0.0.5"], ())
    with pytest.raises(ValueError):
        build_nmap_argv(["10.0.0.5"], (70000,))


# ── XML parse fail-closed ──
def test_xml_xxe_is_rejected():
    ev = list(NmapProvider().execute(_job(xml=b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun/>')))  # noqa: E501
    assert ev[0].kind == "nmap_scan" and ev[0].data["status"] == "failed"
    assert not [e for e in ev if e.kind == "nmap_service"]


def test_malformed_xml_fails_closed():
    ev = list(NmapProvider().execute(_job(xml=b"<nmaprun><host")))
    assert ev[0].data["status"] == "failed" and ev[0].data["reason"] == "malformed_xml"


# ── evidence + conservative findings ──
def test_open_services_become_evidence_root_first():
    ev = list(NmapProvider().execute(_job()))
    assert ev[0].kind == "nmap_scan" and ev[0].occurred_at == "" and ev[0].data["status"] == "ok"
    services = [e for e in ev if e.kind == "nmap_service"]
    ports = sorted(e.data["port"] for e in services)
    assert ports == [22, 23]                                          # closed 8081 excluded


def test_sensitive_service_is_a_finding_ssh_is_not():
    p = NmapProvider()
    ev = list(p.execute(_job()))
    findings = [p.normalize(e) for e in ev if e.kind == "nmap_service"]
    titles = {f.title for f in findings if f}
    assert "Sensitive service exposed: Telnet" in titles             # 23 → finding
    assert all(f is None or "SSH" not in f.title for f in findings)  # 22 → not a finding
    telnet = next(f for f in findings if f)
    assert telnet.engine == EngineKey.NMAP and telnet.location["rule"] == "exposed-telnet"


def test_normalize_ignores_scan_evidence():
    p = NmapProvider()
    scan_ev = RawEvidence(tool="nmap", execution_id="j", target="x", kind="nmap_scan", data={})
    assert p.normalize(scan_ev) is None


# ── subprocess runner: bounded + kills, never raises (fake binaries, no nmap) ──
def _fake(tmp_path, body):
    p = tmp_path / "fake"
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


def test_runner_not_installed_is_contained():
    assert run_nmap(["/nonexistent/nmap", "-oX", "-"]).status == "not_installed"


def test_runner_timeout_kills_process_group(tmp_path):
    fake = _fake(tmp_path, "sleep 10\n")
    res = run_nmap([fake], wall_seconds=1)
    assert res.status == "timeout"


def test_runner_output_overflow_is_failed(tmp_path):
    fake = _fake(tmp_path, "head -c 100000 /dev/zero\n")
    res = run_nmap([fake], wall_seconds=10, max_output=1000)
    assert res.status == "overflow"


def test_runner_nonzero_exit_is_failed(tmp_path):
    fake = _fake(tmp_path, "exit 3\n")
    res = run_nmap([fake], wall_seconds=10)
    assert res.status == "failed" and res.returncode == 3


def test_runner_ok_returns_stdout(tmp_path):
    fake = _fake(tmp_path, "printf '<nmaprun/>'\n")
    res = run_nmap([fake], wall_seconds=10)
    assert res.status == "ok" and res.xml == b"<nmaprun/>"
