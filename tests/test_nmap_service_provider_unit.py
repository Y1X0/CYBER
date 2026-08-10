"""NmapServiceProvider unit contract (Provider #5, L2) — service/version identification.

No DB, no network. Proves the bounded `-sV` argv stays argv-isolated (IP-only, no NSE/UDP/OS/free-form,
version-intensity capped at 2), that the derived level is L2 with human approval, that offline XML
parsing yields populated service/product/version, that XXE is rejected, that a bad scan fails closed,
and that the provider forces the uid+nft backend (external_binary) and never mints findings.
"""

from __future__ import annotations

import pytest
from guardian_core.capability import CapabilityLevel, derive_capability_level
from guardian_core.tool import EffectiveScope, ToolJob
from guardian_scanner.tools.nmap_runner import build_nmap_argv
from guardian_scanner.tools.providers.nmap_service_provider import NmapServiceProvider

_XML = (
    b'<?xml version="1.0"?><nmaprun>'
    b'<host><address addr="10.0.0.5" addrtype="ipv4"/>'
    b'<ports><port protocol="tcp" portid="22"><state state="open"/>'
    b'<service name="ssh" product="OpenSSH" version="9.6p1"/></port>'
    b'<port protocol="tcp" portid="443"><state state="open"/>'
    b'<service name="https" product="nginx" version="1.25.3"/></port></ports></host></nmaprun>'
)


def _job(xml=None, targets=("10.0.0.5",), ports=(22, 443), allow_live=False):
    return ToolJob(
        tenant_id="t", job_id="j", tool_key="nmap_service",
        scope=EffectiveScope(targets=tuple(targets), ports=tuple(ports), protocols=("tcp",),
                             network_allowed=True, read_only=True),
        settings={"xml": xml, "allow_live": allow_live},
    )


# ── governance + isolation markers ─────────────────────────────────────────────────────────────────
def test_capabilities_are_l2_active_with_human_approval():
    caps = NmapServiceProvider().capabilities
    assert caps.network is True and caps.active is True and caps.destructive is False
    assert caps.requires_authorization is True and caps.requires_human_approval is True
    assert derive_capability_level(caps) is CapabilityLevel.ACTIVE_RECON


def test_external_binary_marker_present():
    # Forces the uid+nft kernel-isolation backend at execute_tool (proven separately in trust tests).
    assert NmapServiceProvider().external_binary is True


# ── argv isolation: -sV bounded, no NSE/UDP/OS/free-form ───────────────────────────────────────────
def test_version_argv_has_bounded_sv_and_no_dangerous_flags():
    argv = build_nmap_argv(["10.0.0.5"], (22, 443), version_detection=True)
    assert argv[0] == "nmap"
    assert "-sV" in argv
    i = argv.index("--version-intensity")
    assert argv[i + 1] == "2"                      # conservative, capped — never --version-all
    assert "-sT" in argv and "-Pn" in argv and "-n" in argv
    for banned in ("--script", "-sU", "-O", "-sS", "--version-all", "-A"):
        assert banned not in argv                  # no NSE / UDP / OS / SYN / aggressive
    # every non-flag trailing token is a validated IP (targets), never a hostname/flag
    assert argv[-1] == "10.0.0.5"


def test_version_detection_off_by_default_matches_discovery_scan():
    assert "-sV" not in build_nmap_argv(["10.0.0.5"], (443,))   # port-discovery path unchanged


@pytest.mark.parametrize("bad", ["example.com", "10.0.0.5; rm -rf /", "--script=vuln", "-oN/x"])
def test_argv_rejects_non_ip_targets(bad):
    with pytest.raises(ValueError):
        build_nmap_argv([bad], (443,), version_detection=True)


def test_argv_rejects_out_of_range_port():
    with pytest.raises(ValueError):
        build_nmap_argv(["10.0.0.5"], (70000,), version_detection=True)


# ── evidence: populated service/version, evidence-only ─────────────────────────────────────────────
def test_offline_scan_yields_populated_service_version():
    ev = list(NmapServiceProvider().execute(_job(_XML)))
    scan = ev[0]
    assert scan.kind == "nmap_service_scan" and scan.data["status"] == "ok"
    assert scan.data["scan_type"] == "tcp_connect_version" and scan.data["version_intensity"] == 2
    svcs = {e.data["port"]: e for e in ev if e.kind == "nmap_service"}
    assert svcs[22].data["product"] == "OpenSSH" and svcs[22].data["version"] == "9.6p1"
    assert svcs[443].data["product"] == "nginx" and svcs[443].data["version"] == "1.25.3"


def test_service_evidence_is_not_a_finding():
    ev = list(NmapServiceProvider().execute(_job(_XML)))
    assert all(NmapServiceProvider().normalize(e) is None for e in ev)   # evidence-only


def test_scope_narrowing_only_authorized_targets_in_argv():
    # The provider builds argv only from the effective scope — the ip/ports the Control Plane set.
    argv = build_nmap_argv(["10.0.0.5"], (22,), version_detection=True)
    assert argv[-1] == "10.0.0.5" and "9.9.9.9" not in argv
    assert argv[argv.index("-p") + 1] == "22"


# ── XXE + fail-closed ──────────────────────────────────────────────────────────────────────────────
def test_xxe_doctype_is_rejected_fail_closed():
    xxe = b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun></nmaprun>'
    ev = list(NmapServiceProvider().execute(_job(xxe)))
    assert len(ev) == 1 and ev[0].kind == "nmap_service_scan"
    assert ev[0].data["status"] == "failed" and ev[0].data["reason"] == "malformed_xml"


def test_malformed_xml_fails_closed_with_no_service_evidence():
    ev = list(NmapServiceProvider().execute(_job(b"not xml")))
    assert [e.kind for e in ev] == ["nmap_service_scan"]
    assert ev[0].data["status"] == "failed"


def test_validate_rejects_no_target():
    job = ToolJob(tenant_id="t", job_id="j", tool_key="nmap_service",
                  scope=EffectiveScope(targets=(), ports=(443,), protocols=("tcp",),
                                       network_allowed=True, read_only=True), settings={})
    with pytest.raises(ValueError, match="no in-scope target"):
        NmapServiceProvider().validate(job)


def test_execution_is_deterministic():
    a = [(e.target, e.kind) for e in NmapServiceProvider().execute(_job(_XML))]
    b = [(e.target, e.kind) for e in NmapServiceProvider().execute(_job(_XML))]
    assert a == b
