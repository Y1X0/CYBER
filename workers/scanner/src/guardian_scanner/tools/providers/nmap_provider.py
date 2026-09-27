"""Nmap active network discovery provider (Framework — first active external-binary tool, L2).

Deliberately narrow: an authorization-gated, approval-gated TCP-connect port scan of authorized
IP targets, producing evidence and conservative findings — never exploitation, brute force, fuzzing,
UDP, OS detection, NSE, or a network sweep. Its whole command is built by the Control Plane from the
EffectiveScope (see `nmap_runner.build_nmap_argv`); the provider accepts no free-form arguments.

Offline-first and hermetic: without `settings["allow_live"]` it parses a provided nmap XML snapshot
(so CI needs no nmap and no network); live runs go through the bounded, process-group-isolated
`run_nmap`. Fail-closed: a bad/oversized/timed-out/erroring scan yields a failed/timeout scan
evidence and NO service evidence and NO finding.

It observes, it does not discover the world: open services are recorded as evidence and (for a small
set of sensitive services) derived into findings bound to the authorized asset by the Control
Plane —
the provider never creates IP/Service graph nodes.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET  # noqa: S405 - DTD/entities rejected before parse (see _parse)

from guardian_core.enums import EngineKey, Severity
from guardian_core.findings import RawFinding
from guardian_core.tool import RawEvidence, ToolCapabilities, ToolJob

# The capability's port allowlist (policy can only narrow it). No full-range scanning.
_PORTS = (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443)

# Services that are a finding when found exposed (conservative; not every open port is a finding).
_SENSITIVE = {
    23: ("Telnet", Severity.HIGH), 21: ("FTP", Severity.MEDIUM), 445: ("SMB", Severity.HIGH),
    3389: ("RDP", Severity.HIGH), 3306: ("MySQL", Severity.MEDIUM),
    5432: ("PostgreSQL", Severity.MEDIUM), 25: ("SMTP", Severity.LOW),
}


def _doctype_is_dangerous(xml: bytes) -> bool:
    """True if the XML carries a DOCTYPE that is more than a bare `<!DOCTYPE name>`.

    nmap ALWAYS emits a bare `<!DOCTYPE nmaprun>` (no internal subset, no external DTD), which is
    harmless: ElementTree's expat parser does not fetch external entities, and with no internal
    subset there are no entities to expand. The XXE / entity-expansion vectors are (a) an internal
    subset `[...]` (which can define billion-laughs / recursive entities), (b) an external DTD via
    SYSTEM/PUBLIC, and (c) parameter entities `%`. So a DOCTYPE is dangerous iff its declaration —
    the text between `<!DOCTYPE` and the first `>` — contains any of those markers. The `[` marker
    also fires before any `>` for an internal subset, so scanning to the first `>` is sufficient.
    """
    idx = xml.find(b"<!DOCTYPE")
    if idx == -1:
        return False
    end = xml.find(b">", idx)
    if end == -1:
        return True  # an unterminated DOCTYPE is not a bare declaration — refuse
    decl = xml[idx + len(b"<!DOCTYPE"):end]
    return any(tok in decl for tok in (b"[", b"SYSTEM", b"PUBLIC", b"%"))


def _parse(xml: bytes):  # noqa: ANN202
    """Parse nmap XML → [(ip, port, proto, service, product, version)], or None if malformed.

    XXE / entity-expansion defense without a dependency, applied BEFORE parsing: reject any entity
    declaration outright, and reject a DOCTYPE unless it is a bare `<!DOCTYPE name>` (no internal
    subset, no external SYSTEM/PUBLIC DTD, no parameter entities). This still blocks every XXE
    vector while allowing nmap's own benign `<!DOCTYPE nmaprun>` — without which the parser rejected
    every real nmap scan as malformed.
    """
    if b"<!ENTITY" in xml or _doctype_is_dangerous(xml):
        return None
    try:
        root = ET.fromstring(xml)  # noqa: S314 - entity decls + dangerous DOCTYPEs rejected above
    except ET.ParseError:
        return None
    out = []
    for host in root.findall("host"):
        addr = None
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr")
                break
        if addr is None:
            continue
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            out.append((
                addr, int(port.get("portid")), port.get("protocol") or "tcp",
                (svc.get("name") if svc is not None else None),
                (svc.get("product") if svc is not None else None),
                (svc.get("version") if svc is not None else None),
            ))
    return out


class NmapProvider:
    """A governed, no-root TCP-connect scanner. Never authorizes itself; never sees identity."""

    key = "nmap"
    name = "Nmap TCP Connect Scan"
    version = "1"
    # Trusted marker: spawns an external binary ⇒ the execution plane FORCES the uid+nft kernel
    # isolation backend and never lets a job downgrade it.
    external_binary = True

    @property
    def capabilities(self) -> ToolCapabilities:
        # L2 ACTIVE_RECON: active + network ⇒ authorization + human approval; never destructive.
        return ToolCapabilities(
            category="network_discovery", network=True, active=True, destructive=False,
            requires_authorization=True, requires_human_approval=True,
            supported_targets=("ip",), ports=_PORTS, protocols=("tcp",),
        )

    def validate(self, job: ToolJob) -> None:
        """Reject a malformed job. NOT authorization — the Control Plane already ran the gate."""
        if not job.scope.targets:
            raise ValueError("nmap: no in-scope target")

    def _scan_evidence(self, job, *, status, ports, reason="", mode="offline"):  # noqa: ANN001, ANN202
        return RawEvidence(
            tool=self.key, execution_id=job.job_id, target=",".join(job.scope.targets),
            kind="nmap_scan",
            data={"status": status, "reason": reason, "scan_type": "tcp_connect",
                  "targets": list(job.scope.targets), "ports": list(ports)},
            provenance={"mode": mode, "source": self.key}, occurred_at="")

    def execute(self, job: ToolJob):  # noqa: ANN201
        settings = job.settings or {}
        ports = tuple(job.scope.ports) or _PORTS
        allow_live = bool(settings.get("allow_live"))
        # The provenance mode reflects how the scan ACTUALLY ran, so a live scan's scan-evidence is
        # never mislabeled "offline" (a live failed/ok scan reads "live", matching the service
        # evidence below).
        mode = "live" if allow_live else "offline"

        if allow_live:  # pragma: no cover - real subprocess/network path
            from guardian_scanner.tools.nmap_runner import build_nmap_argv, run_nmap
            try:
                argv = build_nmap_argv(list(job.scope.targets), ports)
            except ValueError as exc:
                yield self._scan_evidence(job, status="failed", ports=ports, reason=str(exc),
                                          mode=mode)
                return
            result = run_nmap(argv)
            if result.status != "ok":
                yield self._scan_evidence(job, status=result.status, ports=ports, mode=mode)
                return
            xml = result.xml
        else:
            raw = settings.get("xml")
            xml = raw.encode() if isinstance(raw, str) else (raw or b"")

        parsed = _parse(xml)
        if parsed is None:
            yield self._scan_evidence(job, status="failed", ports=ports, reason="malformed_xml",
                                      mode=mode)
            return
        yield self._scan_evidence(job, status="ok", ports=ports, mode=mode)
        for ip, port, proto, service, product, version in parsed:
            yield RawEvidence(
                tool=self.key, execution_id=job.job_id, target=ip, kind="nmap_service",
                data={"ip": ip, "port": port, "protocol": proto, "state": "open",
                      "service": service, "product": product, "version": version},
                provenance={"mode": "offline" if not allow_live else "live", "source": self.key},
                occurred_at="")

    def normalize(self, evidence: RawEvidence) -> RawFinding | None:
        """A finding only for a small set of directly observed sensitive exposed services."""
        if evidence.kind != "nmap_service":
            return None
        d = evidence.data or {}
        port = d.get("port")
        spec = _SENSITIVE.get(port)
        if spec is None:
            return None
        label, severity = spec
        ip = d.get("ip")
        return RawFinding(
            engine=EngineKey.NMAP, title=f"Sensitive service exposed: {label}",
            category="exposure", base_severity=severity, confidence="high", cwe_id="CWE-284",
            description=(f"{label} is reachable on {ip}:{port} (open TCP). Exposed management/"
                         f"legacy services widen the attack surface."),
            location={"endpoint": ip, "port": port, "rule": f"exposed-{label.lower()}"},
            evidence={"ip": ip, "port": port, "service": d.get("service"),
                      "product": d.get("product"), "version": d.get("version")})
