"""Nmap service/version identification provider (Framework — Provider #5, L2).

Completes the funnel `IP:Port → Service`: it takes the open ip:ports prior Nmap discovery found and
runs a bounded `nmap -sV --version-intensity 2` to identify the service product/version. It reuses
the Nmap security spine verbatim — the Control Plane builds the ENTIRE argv from authorized IP
targets + in-scope ports (`build_nmap_argv(..., version_detection=True)`; no shell, no free-form
args, no NSE, no UDP/OS), the process is group-isolated and bounded (`run_nmap`), and because it
spawns an external binary (`external_binary = True`) the execution plane FORCES the uid+nft kernel
egress backend (ADR-024) and the job is Ed25519-signed (Phase C).

Deliberately narrow: version detection only, at a fixed conservative intensity — never exploitation,
brute force, fuzzing, NSE, UDP, or OS detection. It is evidence-first: it emits the service/version
as `nmap_service` evidence (the exposure *finding* remains the port-discovery Nmap's job), so this
provider enriches the World Model funnel without duplicating findings.

Offline-first and hermetic: without `settings["allow_live"]` it parses a provided nmap XML snapshot
(reusing the Nmap provider's XXE-hardened parser), so CI needs no nmap and no network. Fail-closed:
a bad/oversized/timed-out/erroring scan yields a failed scan evidence and NO service evidence.
"""

from __future__ import annotations

from guardian_core.findings import RawFinding
from guardian_core.tool import RawEvidence, ToolCapabilities, ToolJob

from guardian_scanner.tools.providers.nmap_provider import _PORTS, _parse


class NmapServiceProvider:
    """A governed, no-root service/version detector (`-sV`). Never authorizes itself."""

    key = "nmap_service"
    name = "Nmap Service/Version Detection"
    version = "1"
    # Spawns an external binary ⇒ the execution plane FORCES the uid+nft kernel isolation backend.
    external_binary = True

    @property
    def capabilities(self) -> ToolCapabilities:
        # L2 ACTIVE_RECON: active + network ⇒ authorization + human approval; never destructive.
        return ToolCapabilities(
            category="service_detection", network=True, active=True, destructive=False,
            requires_authorization=True, requires_human_approval=True,
            supported_targets=("ip",), ports=_PORTS, protocols=("tcp",),
        )

    def validate(self, job: ToolJob) -> None:
        """Reject a malformed job. NOT authorization — the Control Plane already ran the gate."""
        if not job.scope.targets:
            raise ValueError("nmap_service: no in-scope target")

    def _scan_evidence(self, job, *, status, ports, reason=""):  # noqa: ANN001, ANN202
        return RawEvidence(
            tool=self.key, execution_id=job.job_id, target=",".join(job.scope.targets),
            kind="nmap_service_scan",
            data={"status": status, "reason": reason, "scan_type": "tcp_connect_version",
                  "version_intensity": 2, "targets": list(job.scope.targets), "ports": list(ports)},
            provenance={"mode": "offline", "source": self.key}, occurred_at="")

    def execute(self, job: ToolJob):  # noqa: ANN201
        settings = job.settings or {}
        ports = tuple(job.scope.ports) or _PORTS
        allow_live = bool(settings.get("allow_live"))

        if allow_live:  # pragma: no cover - real subprocess/network path
            from guardian_scanner.tools.nmap_runner import build_nmap_argv, run_nmap
            try:
                argv = build_nmap_argv(list(job.scope.targets), ports, version_detection=True)
            except ValueError as exc:
                yield self._scan_evidence(job, status="failed", ports=ports, reason=str(exc))
                return
            result = run_nmap(argv)
            if result.status != "ok":
                yield self._scan_evidence(job, status=result.status, ports=ports)
                return
            xml = result.xml
        else:
            raw = settings.get("xml")
            xml = raw.encode() if isinstance(raw, str) else (raw or b"")

        parsed = _parse(xml)
        if parsed is None:
            yield self._scan_evidence(job, status="failed", ports=ports, reason="malformed_xml")
            return
        yield self._scan_evidence(job, status="ok", ports=ports)
        for ip, port, proto, service, product, version in parsed:
            yield RawEvidence(
                tool=self.key, execution_id=job.job_id, target=ip, kind="nmap_service",
                data={"ip": ip, "port": port, "protocol": proto, "state": "open",
                      "service": service, "product": product, "version": version},
                provenance={"mode": "offline" if not allow_live else "live", "source": self.key},
                occurred_at="")

    def normalize(self, evidence: RawEvidence) -> RawFinding | None:  # noqa: ARG002
        """Evidence-only: service/version enriches the World Model funnel; the exposure finding is
        the port-discovery Nmap's job, so no finding is derived here."""
        return None
