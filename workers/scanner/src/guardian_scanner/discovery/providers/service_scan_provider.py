"""Active service discovery (Phase 6C.2, extended by WP-B2).

The orchestrator owns *what* to probe (authorized targets × a reviewed port catalogue) and turns
evidence into graph nodes/edges. It owns no protocol knowledge: registered `ProtocolProbe` plugins
still handle the ports they claim, and everything else is identified from what the service says
about itself (`discovery/fingerprint`).

**What WP-B2 changed.** Before, "active discovery" meant connecting to 80 and 443, because those
were the two ports a probe happened to register. That answers "is the website up". The services that
actually get an organization compromised are the ones nobody meant to publish — a database on 5432,
an unauthenticated Redis on 6379, SSH on a forgotten jump box — and none of them were ever looked
at. The provider now sweeps a curated port set and identifies what answers, so a service node
carries a product and a version rather than a port number.

Every safety property is unchanged: it probes only `ctx.authorized_targets` (the set the
authorization gate already cleared), never a raw seed; it refuses a target that resolves to a
non-public address; it is bounded in ports, concurrency, rate and wall-clock; and it stays
offline-first, so CI needs no network.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable

from guardian_common.logging import get_logger
from guardian_core.discovery import DiscoveredAsset, DiscoveredEdge, DiscoveryContext
from guardian_core.enums import DiscoverySource, EdgeRelation, NodeType

from guardian_scanner.discovery import fingerprint, webprobe
from guardian_scanner.discovery.ports import (
    SENSITIVE_PORTS,
    TLS_PORTS,
    expected_service,
    resolve_port_set,
)
from guardian_scanner.discovery.portscan import DEFAULT_RATE, OpenPort, SweepResult, sweep
from guardian_scanner.discovery.protocol_registry import probe_for

log = get_logger("guardian.discovery.service_scan")

_TIMEOUT = 4                # seconds per protocol-probe connection, matching pre-6C.2 behaviour
_SWEEP_TIMEOUT = 2.0
_CONCURRENCY = 48
_MAX_TARGETS = 256


class TargetRefused(RuntimeError):
    """A target was refused before any packet was sent (fail-closed)."""


_WEB_SERVICES = frozenset({"http", "https", "http-alt", "https-alt"})


def _is_web(port: int, service: fingerprint.Service) -> bool:
    """Whether an HTTP fetch is worth a second connection on this port.

    Driven by what the service turned out to be, not only by the port: a web application on 8081 is
    the normal case, and a plaintext fetch against a database port is a wasted connection.
    """
    if service.service in _WEB_SERVICES:
        return True
    return expected_service(port) in _WEB_SERVICES


def _web_attributes(host: str, port: int, record: dict) -> dict:
    """Analyse a recorded HTTP response from a snapshot through the production code path."""
    scheme = "https" if port in TLS_PORTS else "http"
    observation = webprobe.analyze(
        record.get("url") or f"{scheme}://{host}:{port}/",
        int(record.get("status", 0)),
        dict(record.get("headers") or {}),
        str(record.get("body") or ""),
        set_cookies=list(record.get("set_cookies") or []),
        redirect_chain=list(record.get("redirect_chain") or []),
        left_scope=bool(record.get("left_scope")),
        tls=record.get("tls"),
    )
    return observation.as_attributes()


def _host_node_type(host: str) -> NodeType:
    try:
        ipaddress.ip_address(host)
        return NodeType.IP_ADDRESS
    except ValueError:
        return NodeType.SUBDOMAIN


def _is_public(host: str) -> bool:
    """Whether every address a host resolves to is publicly routable.

    An authorization covers a customer's internet-facing estate. A hostname that resolves to
    10.0.0.1 or 169.254.169.254 points at our own infrastructure or a cloud metadata service, and
    scanning it on a customer's say-so would make Guardian the pivot.
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return False
    addresses = {info[4][0] for info in infos}
    if not addresses:
        return False
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return False
        if (parsed.is_private or parsed.is_loopback or parsed.is_link_local
                or parsed.is_multicast or parsed.is_reserved or parsed.is_unspecified):
            return False
    return True


class ServiceScanProvider:
    key = "service_scan"
    requires_authorization = True

    def collect(self, ctx: DiscoveryContext) -> Iterable[DiscoveredAsset]:  # noqa: C901
        settings = ctx.settings or {}
        snapshot: dict = settings.get("service_scan", {}) or {}
        allow_live = bool(settings.get("allow_live"))
        allow_probes = bool(settings.get("allow_identification_probes", True))
        ports = resolve_port_set(settings.get("ports", "top"))
        rate = float(settings.get("rate", DEFAULT_RATE))

        for target in list(ctx.authorized_targets)[:_MAX_TARGETS]:
            host = target.split(":")[0]
            host_type = _host_node_type(host)
            host_snap = snapshot.get(host)

            if host_snap is not None:
                observations = list(self._from_snapshot(host, host_snap))
                result = SweepResult(host=host, scanned=len(observations))
            elif not allow_live:
                continue
            else:  # pragma: no cover - network
                if not _is_public(host):
                    log.warning("service_scan_target_refused", host=host,
                                reason="does not resolve to a public address")
                    continue
                result = sweep(host, ports, timeout=_SWEEP_TIMEOUT, concurrency=_CONCURRENCY,
                               rate=rate)
                if result.error:
                    log.warning("service_scan_failed", host=host, error=result.error)
                    continue
                observations = [
                    self._identify(host, open_port, allow_probes=allow_probes)
                    for open_port in result.open_ports
                ]

            for service in observations:
                yield from self._assets(host, host_type, service, ctx, host_snap is not None)

            # A sweep that ran out of time saw less than it was asked to. Recorded on the host node
            # so a later run can tell a shrinking service list from a completed one.
            if result.truncated:
                yield DiscoveredAsset(
                    node_type=host_type, canonical_key=host, source=DiscoverySource.PORT_SCAN,
                    confidence=90, ownership_confidence=90,
                    attributes={"scan_truncated": True, "ports_scanned": result.scanned,
                                "ports_requested": len(ports)},
                )

    # ── identification ───────────────────────────────────────────────────────────────────────────
    def _identify(  # pragma: no cover - network
        self, host: str, open_port: OpenPort, *, allow_probes: bool
    ) -> fingerprint.Service:
        expected = expected_service(open_port.port)
        registered = probe_for(open_port.port)
        if registered is not None:
            # A port a plugin claims stays the plugin's: http/tls keep the behaviour and the
            # evidence shape they had before this package existed.
            evidence = registered.probe(host, open_port.port, timeout=_TIMEOUT,
                                        allow_live=True, snapshot=None)
            if evidence is not None:
                service = fingerprint.identify(open_port.port, open_port.banner, expected=expected)
                service.attributes.update(evidence.attributes)
                service.service = service.service or evidence.protocol
                service.confidence = max(service.confidence, evidence.confidence)
                if _is_web(open_port.port, service):
                    service.attributes.update(self._web(host, open_port.port))
                return service

        service = fingerprint.probe(host, open_port.port, open_port.banner, expected=expected,
                                    allow_probes=allow_probes)
        if _is_web(open_port.port, service):
            # WP-B3: a web service is worth far more than "port open". The technology inventory,
            # the redirect chain and the missing security headers all come from one fetch.
            service.attributes.update(self._web(host, open_port.port))
        return service

    def _web(self, host: str, port: int) -> dict:  # pragma: no cover - network
        scheme = "https" if port in TLS_PORTS else "http"
        observation = webprobe.probe(f"{scheme}://{host}:{port}/")
        return observation.as_attributes()

    def _from_snapshot(self, host: str, host_snap: dict) -> Iterable[fingerprint.Service]:
        """Rebuild observations from a recorded snapshot, so CI exercises the same code path."""
        for raw_port, record in sorted(host_snap.items(), key=lambda kv: int(kv[0])):
            port = int(raw_port)
            if not isinstance(record, dict):
                continue
            banner = str(record.get("banner") or "")
            service = fingerprint.identify(port, banner, expected=expected_service(port))
            for key in ("tls", "missing_tls", "status", "server"):
                if key in record:
                    service.attributes[key] = record[key]
            # A recorded HTTP response goes through the same analysis a live one does, so the
            # technology inventory in CI is produced by the code that produces it in production.
            if isinstance(record.get("http"), dict):
                service.attributes.update(_web_attributes(host, port, record["http"]))
            if record.get("tls") is not None:
                service.service = service.service or "https"
            if banner == "" and record.get("tls") is None and not service.service:
                service.service = expected_service(port)
            yield service

    # ── graph assets ─────────────────────────────────────────────────────────────────────────────
    def _assets(
        self, host: str, host_type: NodeType, service: fingerprint.Service,
        ctx: DiscoveryContext, offline: bool,
    ) -> Iterable[DiscoveredAsset]:
        del ctx
        service_key = f"{host}:{service.port}"
        attributes = {
            "port": service.port,
            "internet_reachable": True,
            "service": service.service or expected_service(service.port),
            "evidence": service.evidence,
            **service.attributes,
        }
        if service.product:
            attributes["product"] = service.product
        if service.version:
            attributes["version"] = service.version
        if service.cpe:
            # The key WP-C3 looks a CVE up by. Present only when the product was actually
            # identified — a fabricated CPE matches nothing and reads as "no vulnerabilities".
            attributes["cpe"] = service.cpe
        if service.banner:
            attributes["banner"] = service.banner[:256]
        if service.port in SENSITIVE_PORTS:
            # Exposure of an administrative interface or a datastore is a finding about the port
            # itself, independent of which version answers on it.
            attributes["sensitive_service"] = SENSITIVE_PORTS[service.port]
        if offline:
            attributes["mode"] = "offline"

        yield DiscoveredAsset(
            node_type=NodeType.SERVICE, canonical_key=service_key,
            source=DiscoverySource.PORT_SCAN, confidence=service.confidence,
            ownership_confidence=90, attributes=attributes,
        )
        yield DiscoveredAsset(
            node_type=host_type, canonical_key=host,
            source=DiscoverySource.PORT_SCAN, confidence=90, ownership_confidence=90,
            edges=[DiscoveredEdge(
                relation=EdgeRelation.HOSTS, dst_type=NodeType.SERVICE,
                dst_key=service_key, confidence=95,
            )],
        )
