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
from guardian_scanner.tools.providers.nmap_provider import NmapProvider, _parse

# A REAL nmap -oX document header, exactly as nmap emits it — including the bare `<!DOCTYPE nmaprun>`
# line, the xml-stylesheet PI, and a comment — captured from a live scan of scanme.nmap.org. The old
# guard rejected every such document (any `<!DOCTYPE` → malformed); this fixture locks the fix so a
# genuine nmap scan can never be dropped again.
_REAL_NMAP_XML = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<!DOCTYPE nmaprun>\n'
    b'<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>\n'
    b'<!-- Nmap 7.95 scan initiated as: nmap -sT -Pn -n -oX - -p 22,80 45.33.32.156 -->\n'
    b'<nmaprun scanner="nmap" args="nmap -sT -Pn -n -oX - -p 22,80 45.33.32.156" version="7.95">\n'
    b'<host><address addr="45.33.32.156" addrtype="ipv4"/><ports>'
    b'<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>'
    b'<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>'
    b'</ports></host></nmaprun>'
)

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


# ── XML parse: real nmap DOCTYPE accepted, XXE vectors still rejected (fix + regression) ──
def test_parse_accepts_real_nmap_doctype_xml():
    # The exact shape nmap emits — bare `<!DOCTYPE nmaprun>` — must parse to the open services.
    assert b"<!DOCTYPE nmaprun>" in _REAL_NMAP_XML          # fixture really carries the DOCTYPE
    parsed = _parse(_REAL_NMAP_XML)
    assert parsed == [
        ("45.33.32.156", 22, "tcp", "ssh", None, None),
        ("45.33.32.156", 80, "tcp", "http", None, None),
    ]


def test_real_nmap_xml_yields_service_evidence_offline():
    # End-to-end through the provider (offline path feeds the real-shaped XML): open 22/80 surface.
    ev = list(NmapProvider().execute(_job(ports=(22, 80), xml=_REAL_NMAP_XML)))
    assert ev[0].kind == "nmap_scan" and ev[0].data["status"] == "ok"
    ports = sorted(e.data["port"] for e in ev if e.kind == "nmap_service")
    assert ports == [22, 80]


def test_parse_still_rejects_entity_declaration():
    # A billion-laughs / entity-injection payload (internal subset + <!ENTITY>) stays rejected.
    xxe = (b'<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
           b'<nmaprun>&e;</nmaprun>')
    assert _parse(xxe) is None


def test_parse_still_rejects_doctype_internal_subset_without_entity_keyword():
    # Even without the literal <!ENTITY, a DOCTYPE with an internal subset `[...]` is refused.
    assert _parse(b'<!DOCTYPE nmaprun [ <!-- subset --> ]><nmaprun/>') is None


def test_parse_still_rejects_external_dtd_system_and_public():
    assert _parse(b'<!DOCTYPE nmaprun SYSTEM "http://evil.invalid/x.dtd"><nmaprun/>') is None
    assert _parse(b'<!DOCTYPE nmaprun PUBLIC "-//x//DTD//EN" "http://evil.invalid/x.dtd">'
                  b'<nmaprun/>') is None


def test_parse_still_rejects_parameter_entity_doctype():
    assert _parse(b'<!DOCTYPE nmaprun [ %pe; ]><nmaprun/>') is None


def test_xml_xxe_is_rejected():
    ev = list(NmapProvider().execute(_job(xml=b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun/>')))  # noqa: E501
    assert ev[0].kind == "nmap_scan" and ev[0].data["status"] == "failed"
    assert not [e for e in ev if e.kind == "nmap_service"]


def test_scan_evidence_mode_reflects_live_vs_offline():
    # Cosmetic fix: the nmap_scan provenance mode must not be hardcoded "offline" on a live run.
    p = NmapProvider()
    job = _job(ports=(22, 80), xml=_REAL_NMAP_XML)
    offline_ev = list(p.execute(job))
    assert offline_ev[0].kind == "nmap_scan" and offline_ev[0].provenance["mode"] == "offline"
    live_ev = p._scan_evidence(job, status="failed", ports=(22,), reason="x", mode="live")
    assert live_ev.provenance["mode"] == "live"


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
