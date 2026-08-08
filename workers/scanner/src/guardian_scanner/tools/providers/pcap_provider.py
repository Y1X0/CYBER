"""PCAP header/metadata analysis provider (Framework — second provider, artifact / non-network).

The counterpart to Provider #1: it proves the *untrusted-artifact* branch of the rail —
``Artifact → Sandbox Parser → Evidence → Finding → Graph`` — with **no network at all**. It reads a
classic ``.pcap`` file's structure only: the global header, per-record headers, and just enough of
each frame's L2/L3/L4 *headers* to observe endpoints, ports, and protocol — never payload, never
reassembly, never content extraction. It is a pure `struct` parser (Python stdlib only, no Scapy),
so it opens no socket and pulls in no external dependency.

It is deliberately conservative and forensic:

  * **Chain of custody first.** The first evidence item describes the artifact itself
    (`sha256` of the raw bytes, size, media type) — the root of the tenant's hash chain.
  * **Fail-closed, no partial success.** A bad magic, a truncated header, or exceeding the byte /
    packet bounds fails the whole capture: the artifact descriptor is marked `failed`/`rejected`
    and NO flow evidence and NO finding are produced. A single exotic frame we cannot dissect is
    counted but yields no endpoints — it never fails the capture.
  * **Observation, not discovery.** An endpoint seen inside the capture (`10.0.0.5:22`, …) is
    recorded as an *observed endpoint in evidence only*. The provider NEVER creates an asset, does a
    DNS/reverse-DNS lookup, connects, probes, or scans. It reports what was in the evidence.
  * **Evidence-backed findings only.** `normalize()` derives a finding solely from a directly
    observed cleartext protocol (HTTP/FTP/Telnet/…) on a well-known port — never an inference of
    "compromise" or "exposure" from metadata, never AI.

The framework's execution plane runs `execute()` inside the mandatory sandbox with the network fully
denied (capabilities.network=False), so this file is just the observation.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import socket
import struct
from dataclasses import dataclass, field

from guardian_core.enums import EngineKey, Severity
from guardian_core.findings import RawFinding
from guardian_core.tool import RawEvidence, ToolCapabilities, ToolJob

_MEDIA_TYPE = "application/vnd.tcpdump.pcap"
_MAX_BYTES = 2 * 1024 * 1024          # 2 MB hard cap (mirrors the trusted-plane transport cap)
_MAX_PACKETS = 20_000                 # fail-closed above this — no unbounded loops
_MAX_CLEARTEXT = 500                  # bound distinct cleartext observations emitted as evidence
_MAX_ENDPOINTS_LISTED = 100           # bound the observed-endpoint list recorded in the descriptor

_GLOBAL_HDR = 24
_REC_HDR = 16

# Classic pcap magics → (struct endianness, timestamp divisor). pcapng (0x0a0d0d0a) is unsupported.
_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# Link types we can locate an IP header inside (header-only). Others are counted, not dissected.
_LINKTYPE_ETHERNET, _LINKTYPE_NULL, _LINKTYPE_RAW, _LINKTYPE_LINUX_SLL = 1, 0, 101, 113

# Cleartext services identified from the well-known port ALONE (metadata, never payload).
_CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP", 110: "POP3", 143: "IMAP"}


@dataclass
class _Cleartext:
    server: str
    server_port: int
    client: str
    protocol: str
    l4: str
    first_seen: str
    count: int = 1


@dataclass
class _ParseResult:
    status: str = "parsed"                 # parsed | failed
    reason: str = ""
    linktype: int | None = None
    packet_count: int = 0
    ts_first: str = ""
    ts_last: str = ""
    endpoints: set[str] = field(default_factory=set)
    cleartext: dict[tuple, _Cleartext] = field(default_factory=dict)
    cleartext_truncated: bool = False


def _iso(ts_sec: int, ts_frac: int, divisor: int) -> str:
    try:
        return dt.datetime.fromtimestamp(ts_sec + ts_frac / divisor, dt.UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return f"{ts_sec}.{ts_frac}"


def _ip_header_offset(linktype: int, pkt: bytes) -> int | None:
    """Byte offset of the IP header inside a frame for the link types we support, else None."""
    if linktype == _LINKTYPE_ETHERNET:
        if len(pkt) < 14:
            return None
        ethertype = struct.unpack_from(">H", pkt, 12)[0]
        if ethertype == 0x8100 and len(pkt) >= 18:      # 802.1Q VLAN tag → real type follows
            return 18
        return 14
    if linktype == _LINKTYPE_RAW:
        return 0
    if linktype == _LINKTYPE_NULL:
        return 4
    if linktype == _LINKTYPE_LINUX_SLL:
        return 16
    return None


def _endpoints_and_ports(linktype: int, pkt: bytes):  # noqa: ANN202
    """Best-effort (src_ip, dst_ip, l4, sport, dport) from headers only, or None. Never raises."""
    try:
        off = _ip_header_offset(linktype, pkt)
        if off is None or len(pkt) < off + 1:
            return None
        version = pkt[off] >> 4
        if version == 4:
            if len(pkt) < off + 20:
                return None
            ihl = (pkt[off] & 0x0F) * 4
            proto = pkt[off + 9]
            src = socket.inet_ntop(socket.AF_INET, pkt[off + 12:off + 16])
            dst = socket.inet_ntop(socket.AF_INET, pkt[off + 16:off + 20])
            l4_off = off + ihl
        elif version == 6:
            if len(pkt) < off + 40:
                return None
            proto = pkt[off + 6]                     # first next-header only (no ext-header walk)
            src = socket.inet_ntop(socket.AF_INET6, pkt[off + 8:off + 24])
            dst = socket.inet_ntop(socket.AF_INET6, pkt[off + 24:off + 40])
            l4_off = off + 40
        else:
            return None
        sport = dport = None
        l4 = {6: "tcp", 17: "udp"}.get(proto)
        if l4 and len(pkt) >= l4_off + 4:
            sport, dport = struct.unpack_from(">HH", pkt, l4_off)
        return src, dst, l4, sport, dport
    except (struct.error, ValueError, IndexError):
        return None


def _parse_pcap(raw: bytes, *, max_packets: int) -> _ParseResult:
    """Structural parse. Strict on file structure (fail-closed); lenient on individual frames."""
    r = _ParseResult()
    if raw[:4] == _PCAPNG_MAGIC:
        return _ParseResult(status="failed", reason="pcapng_unsupported")
    magic = _MAGICS.get(raw[:4])
    if magic is None or len(raw) < _GLOBAL_HDR:
        return _ParseResult(status="failed", reason="bad_magic_or_truncated_global_header")
    endian, divisor = magic
    r.linktype = struct.unpack_from(endian + "I", raw, 20)[0]

    offset, n = _GLOBAL_HDR, len(raw)
    while offset < n:
        if offset + _REC_HDR > n:
            return _ParseResult(status="failed", reason="truncated_record_header",
                                linktype=r.linktype)
        ts_sec, ts_frac, incl_len, _orig = struct.unpack_from(endian + "IIII", raw, offset)
        data_start = offset + _REC_HDR
        if incl_len > _MAX_BYTES or data_start + incl_len > n:
            return _ParseResult(status="failed", reason="truncated_packet_data",
                                linktype=r.linktype)
        r.packet_count += 1
        if r.packet_count > max_packets:
            return _ParseResult(status="failed", reason="packet_limit_exceeded",
                                linktype=r.linktype)
        ts = _iso(ts_sec, ts_frac, divisor)
        if not r.ts_first:
            r.ts_first = ts
        r.ts_last = ts

        parsed = _endpoints_and_ports(r.linktype, raw[data_start:data_start + incl_len])
        if parsed is not None:
            _record(r, parsed, ts)
        offset = data_start + incl_len
    return r


def _record(r: _ParseResult, parsed, ts: str) -> None:  # noqa: ANN001
    src, dst, l4, sport, dport = parsed
    if len(r.endpoints) < _MAX_ENDPOINTS_LISTED * 4:     # bound memory; the listed slice is smaller
        if sport is not None:
            r.endpoints.add(f"{src}:{sport}")
        if dport is not None:
            r.endpoints.add(f"{dst}:{dport}")
    if l4 != "tcp" or sport is None:
        return
    # Cleartext identified from the well-known port only; the server is the well-known-port side.
    for server, server_port, client in ((dst, dport, src), (src, sport, dst)):
        proto = _CLEARTEXT_PORTS.get(server_port)
        if proto is None:
            continue
        key = (server, server_port, proto)
        if key in r.cleartext:
            r.cleartext[key].count += 1
        elif len(r.cleartext) < _MAX_CLEARTEXT:
            r.cleartext[key] = _Cleartext(server=server, server_port=server_port, client=client,
                                          protocol=proto, l4="tcp", first_seen=ts)
        else:
            r.cleartext_truncated = True
        break


class PcapMetaProvider:
    """A governed, offline, read-only PCAP header/metadata observer. Never authorizes itself."""

    key = "pcap_meta"
    name = "PCAP Metadata Analyzer"
    version = "1"

    @property
    def capabilities(self) -> ToolCapabilities:
        # Passive artifact analysis: no network, no active touch, not destructive, no approval.
        return ToolCapabilities(
            category="packet_analysis", network=False, active=False, destructive=False,
            requires_authorization=True, requires_human_approval=False,
            supported_targets=("artifact",),
        )

    def validate(self, job: ToolJob) -> None:
        """Reject a malformed job. NOT authorization — the Control Plane anchored the asset."""
        if not (job.settings or {}).get("artifact_b64"):
            raise ValueError("pcap_meta: no artifact provided")

    def _descriptor(self, job: ToolJob, target: str, *, sha: str, size: int,
                    media_type: str, result: _ParseResult | None,
                    status: str, reason: str = "") -> RawEvidence:
        data = {
            "sha256": sha, "size": size, "media_type": media_type, "format": "pcap",
            "status": status, "reason": reason,
        }
        if result is not None:
            listed = sorted(result.endpoints)[:_MAX_ENDPOINTS_LISTED]
            data.update({
                "linktype": result.linktype, "packet_count": result.packet_count,
                "capture_window": [result.ts_first, result.ts_last],
                "observed_endpoint_count": len(result.endpoints),
                "observed_endpoints": listed,
                "cleartext_count": len(result.cleartext),
                "cleartext_truncated": result.cleartext_truncated,
            })
        return RawEvidence(tool=self.key, execution_id=job.job_id, target=target, kind="artifact",
                           data=data, provenance={"mode": "offline", "source": self.key},
                           occurred_at="")  # empty ⇒ sorts first ⇒ the root of the hash chain

    def execute(self, job: ToolJob):  # noqa: ANN201
        """Decode the inline artifact, parse headers under bounds, and yield RawEvidence."""
        settings = job.settings or {}
        target = job.scope.targets[0] if job.scope.targets else "artifact"
        max_bytes = min(int(settings.get("max_bytes") or _MAX_BYTES), _MAX_BYTES)
        max_packets = min(int(settings.get("max_packets") or _MAX_PACKETS), _MAX_PACKETS)
        media_type = settings.get("media_type") or _MEDIA_TYPE

        try:
            raw = base64.b64decode(settings.get("artifact_b64") or "", validate=True)
        except (ValueError, TypeError):
            yield self._descriptor(job, target, sha="", size=0, media_type=media_type,
                                   result=None, status="failed", reason="invalid_encoding")
            return

        sha = hashlib.sha256(raw).hexdigest()
        if len(raw) > max_bytes:                          # fail-closed: too large ⇒ no parse
            yield self._descriptor(job, target, sha=sha, size=len(raw), media_type=media_type,
                                   result=None, status="rejected", reason="artifact_exceeds_limit")
            return

        result = _parse_pcap(raw, max_packets=max_packets)
        yield self._descriptor(job, target, sha=sha, size=len(raw), media_type=media_type,
                               result=result, status=result.status, reason=result.reason)
        if result.status != "parsed":
            return                                        # fail-closed: no flows, no findings

        for obs in result.cleartext.values():
            yield RawEvidence(
                tool=self.key, execution_id=job.job_id, target=target, kind="pcap_cleartext",
                data={"artifact_sha256": sha, "protocol": obs.protocol, "l4": obs.l4,
                      "server": obs.server, "server_port": obs.server_port, "client": obs.client,
                      "observations": obs.count, "first_seen": obs.first_seen,
                      "capture_window": [result.ts_first, result.ts_last]},
                provenance={"mode": "offline", "source": self.key}, occurred_at=obs.first_seen,
            )

    def normalize(self, evidence: RawEvidence) -> RawFinding | None:
        """Derive a finding ONLY from a directly observed cleartext protocol (evidence-backed)."""
        if evidence.kind != "pcap_cleartext":
            return None
        d = evidence.data or {}
        proto = d.get("protocol", "cleartext")
        server, port = d.get("server"), d.get("server_port")
        return RawFinding(
            engine=EngineKey.PCAP_META,
            title=f"Cleartext {proto} traffic observed",
            category="misconfig", base_severity=Severity.MEDIUM, confidence="high",
            cwe_id="CWE-319",
            description=(f"The capture contains {proto} traffic to {server}:{port} over an "
                         f"unencrypted transport, observed from packet metadata."),
            location={"endpoint": server, "port": port, "rule": f"cleartext-{proto.lower()}"},
            evidence={"artifact_sha256": d.get("artifact_sha256"), "protocol": proto,
                      "server": server, "server_port": port, "client": d.get("client"),
                      "observations": d.get("observations"), "window": d.get("capture_window")},
        )
