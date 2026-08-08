"""PcapMetaProvider unit contract (no DB, no network) — stdlib parsing, bounds, fail-closed, sha256.

Proves Provider #2 is a passive, offline artifact analyzer: it parses a classic pcap's headers only,
computes the artifact sha256 as the evidence-chain root, derives a finding ONLY from a directly
observed cleartext protocol, and FAILS CLOSED (no flow evidence, no finding) on a bad magic,
truncation, or exceeding the packet bound. It opens no socket and needs no external dependency.
"""

from __future__ import annotations

import base64
import hashlib
import socket
import struct

from guardian_core.enums import EngineKey
from guardian_core.tool import EffectiveScope, ToolJob
from guardian_scanner.tools.providers import pcap_provider as P


# ── tiny pcap builders (classic little-endian, LINKTYPE_ETHERNET) ──
def _eth_ipv4_tcp(src, dst, sport, dport):
    eth = b"\x00" * 12 + b"\x08\x00"
    ip = bytearray(20)
    ip[0] = 0x45
    ip[9] = 6  # TCP
    ip[12:16] = socket.inet_aton(src)
    ip[16:20] = socket.inet_aton(dst)
    tcp = struct.pack(">HH", sport, dport) + b"\x00" * 16
    return eth + bytes(ip) + tcp


def _pcap(records, linktype=1):
    out = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, linktype)
    for ts, pkt in records:
        out += struct.pack("<IIII", ts, 0, len(pkt), len(pkt)) + pkt
    return out


def _job(raw, target="asset-1"):
    return ToolJob(
        tenant_id="t", job_id="j", tool_key="pcap_meta",
        scope=EffectiveScope(targets=(target,), ports=(), protocols=(),
                             network_allowed=False, read_only=True),
        settings={"artifact_b64": base64.b64encode(raw).decode()},
    )


def test_capabilities_are_passive_non_network_no_approval():
    caps = P.PcapMetaProvider().capabilities
    assert caps.network is False and caps.active is False and caps.destructive is False
    assert caps.requires_authorization is True and caps.requires_human_approval is False


def test_scope_for_this_tool_is_network_disabled():
    from guardian_core.tool import derive_effective_scope
    caps = P.PcapMetaProvider().capabilities
    scope = derive_effective_scope(["asset-1"], ["asset-1"], caps, None)
    assert scope.network_allowed is False        # network access is impossible for this tool


def test_valid_pcap_yields_artifact_root_then_cleartext_finding():
    raw = _pcap([(1000, _eth_ipv4_tcp("10.0.0.5", "10.0.0.9", 50000, 80)),
                 (1001, _eth_ipv4_tcp("10.0.0.5", "10.0.0.9", 50000, 80)),
                 (1002, _eth_ipv4_tcp("10.0.0.5", "10.0.0.9", 50001, 443))])  # 443 benign
    ev = list(P.PcapMetaProvider().execute(_job(raw)))

    assert ev[0].kind == "artifact" and ev[0].occurred_at == ""       # root of the chain
    assert ev[0].data["sha256"] == hashlib.sha256(raw).hexdigest()     # correct artifact hash
    assert ev[0].data["status"] == "parsed" and ev[0].data["packet_count"] == 3
    assert "10.0.0.9:80" in ev[0].data["observed_endpoints"]           # observed-only, not probed

    cleartext = [e for e in ev if e.kind == "pcap_cleartext"]
    assert len(cleartext) == 1                                          # 443 not flagged
    assert cleartext[0].data["protocol"] == "HTTP" and cleartext[0].data["observations"] == 2

    raw_finding = P.PcapMetaProvider().normalize(cleartext[0])
    assert raw_finding is not None and raw_finding.engine == EngineKey.PCAP_META
    assert raw_finding.location["rule"] == "cleartext-http"
    assert raw_finding.evidence["artifact_sha256"] == ev[0].data["sha256"]


def test_artifact_evidence_carries_no_payload():
    raw = _pcap([(1, _eth_ipv4_tcp("1.1.1.1", "2.2.2.2", 1234, 80))])
    ev = list(P.PcapMetaProvider().execute(_job(raw)))
    # Only metadata keys — never raw packet bytes / payload.
    for e in ev:
        assert "payload" not in e.data and "raw" not in e.data


def test_bad_magic_fails_closed_no_finding():
    ev = list(P.PcapMetaProvider().execute(_job(b"\x00\x01\x02\x03" + b"\x00" * 40)))
    assert len(ev) == 1 and ev[0].kind == "artifact"
    assert ev[0].data["status"] == "failed"
    assert ev[0].data["reason"] == "bad_magic_or_truncated_global_header"


def test_truncated_record_header_fails_closed():
    raw = _pcap([(1, _eth_ipv4_tcp("1.1.1.1", "2.2.2.2", 1234, 23))])
    ev = list(P.PcapMetaProvider().execute(_job(raw[:24 + 8])))  # cut inside the record header
    assert ev[0].data["status"] == "failed" and ev[0].data["reason"] == "truncated_record_header"
    assert not [e for e in ev if e.kind == "pcap_cleartext"]


def test_truncated_packet_data_fails_closed():
    raw = _pcap([(1, _eth_ipv4_tcp("1.1.1.1", "2.2.2.2", 1234, 21))])
    ev = list(P.PcapMetaProvider().execute(_job(raw[:-5])))       # packet bytes cut short
    assert ev[0].data["status"] == "failed" and ev[0].data["reason"] == "truncated_packet_data"


def test_packet_limit_is_fail_closed_not_partial():
    raw = _pcap([(i, _eth_ipv4_tcp("1.1.1.1", "2.2.2.2", 1000 + i, 80)) for i in range(5)])
    job = _job(raw)
    job.settings["max_packets"] = 2
    ev = list(P.PcapMetaProvider().execute(job))
    assert ev[0].data["status"] == "failed" and ev[0].data["reason"] == "packet_limit_exceeded"
    assert not [e for e in ev if e.kind == "pcap_cleartext"]      # no partial success


def test_oversized_artifact_rejected_by_provider():
    job = _job(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)
    job.settings["max_bytes"] = 10                                # provider-side defensive bound
    ev = list(P.PcapMetaProvider().execute(job))
    assert ev[0].data["status"] == "rejected" and ev[0].data["reason"] == "artifact_exceeds_limit"


def test_pcapng_is_unsupported_fail_closed():
    ev = list(P.PcapMetaProvider().execute(_job(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)))
    assert ev[0].data["status"] == "failed" and ev[0].data["reason"] == "pcapng_unsupported"


def test_benign_capture_yields_no_finding():
    raw = _pcap([(1, _eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 40000, 443))])  # TLS, not cleartext
    ev = list(P.PcapMetaProvider().execute(_job(raw)))
    assert ev[0].data["status"] == "parsed"
    assert all(P.PcapMetaProvider().normalize(e) is None for e in ev)
