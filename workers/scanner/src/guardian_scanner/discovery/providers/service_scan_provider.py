"""Active service-scan provider (Phase 6C) — the platform's first *active* discovery, kept tiny.

Scope is intentionally minimal and stays that way after 6C:
  * only TCP 80 and 443 — no port sweep, no wide scan;
  * connect + (for 443) a TLS handshake to read certificate metadata + a light banner read;
  * NO exploit, NO payloads, NO brute force, NO protocol abuse.

It only ever probes `ctx.authorized_targets` — the set the gate already cleared. It has
no database access (providers are DB-free); the gate and audit live in the task. Live probing runs
inside the Phase-5 worker sandbox (bounded CPU/mem/time, network allowed for the authorized target);
offline it reads a snapshot from `ctx.settings["service_scan"]` for deterministic CI.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from guardian_core.discovery import DiscoveredAsset, DiscoveredEdge, DiscoveryContext
from guardian_core.enums import DiscoverySource, EdgeRelation, NodeType

from guardian_scanner import sandbox

_PORTS = (80, 443)  # fixed and minimal — do not widen without a new, separately-approved milestone
_PROBE_CPU_SECONDS = 5
_PROBE_WALL_SECONDS = 10


def _host_node_type(host: str) -> NodeType:
    try:
        ipaddress.ip_address(host)
        return NodeType.IP_ADDRESS
    except ValueError:
        return NodeType.SUBDOMAIN


def _probe_live(host: str, port: int) -> dict | None:  # pragma: no cover - network, not run in CI
    """Minimal, non-intrusive: TCP connect, TLS cert metadata on 443, a short banner read."""
    import socket
    import ssl

    try:
        with socket.create_connection((host, port), timeout=4) as sock:
            if port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert(binary_form=False) or {}
                    return {"port": port, "tls": {"version": tls.version(), "subject": str(cert)}}
            sock.settimeout(2)
            try:
                banner = sock.recv(256).decode("latin-1", "replace").strip()
            except OSError:
                banner = ""
            return {"port": port, "banner": banner[:256]}
    except OSError:
        return None  # closed / unreachable — not an error, just nothing there


class ServiceScanProvider:
    key = "service_scan"
    requires_authorization = True

    def collect(self, ctx: DiscoveryContext) -> Iterable[DiscoveredAsset]:
        snapshot: dict = ctx.settings.get("service_scan", {})
        allow_live = bool(ctx.settings.get("allow_live"))
        for target in ctx.authorized_targets:  # ONLY pre-authorized targets, never raw seeds
            host = target.split(":")[0]
            host_type = _host_node_type(host)
            for port in _PORTS:
                result = self._probe_one(host, port, snapshot, allow_live)
                if result is None:
                    continue  # closed/unreachable → nothing observed
                service_key = f"{host}:{port}"
                attrs = {"port": port, "internet_reachable": True}
                if "tls" in result:
                    attrs["tls"] = result["tls"]
                    attrs["missing_tls"] = False
                if "banner" in result:
                    attrs["banner"] = result["banner"]
                    attrs["missing_tls"] = port != 443
                # The service node, carrying the evidence we actually observed.
                yield DiscoveredAsset(
                    node_type=NodeType.SERVICE, canonical_key=service_key,
                    source=DiscoverySource.PORT_SCAN, confidence=95, ownership_confidence=90,
                    attributes=attrs,
                )
                # The host --hosts--> service edge (host is the source; it hosts the service).
                yield DiscoveredAsset(
                    node_type=host_type, canonical_key=host,
                    source=DiscoverySource.PORT_SCAN, confidence=90, ownership_confidence=90,
                    edges=[DiscoveredEdge(
                        relation=EdgeRelation.HOSTS, dst_type=NodeType.SERVICE,
                        dst_key=service_key, confidence=95,
                    )],
                )

    def _probe_one(self, host: str, port: int, snapshot: dict, allow_live: bool) -> dict | None:
        host_snap = snapshot.get(host)
        if host_snap is not None:
            return host_snap.get(str(port)) or host_snap.get(port)
        if not allow_live:
            return None
        policy = sandbox.SandboxPolicy(
            cpu_seconds=_PROBE_CPU_SECONDS, wall_seconds=_PROBE_WALL_SECONDS, allow_network=True,
        )
        try:
            return sandbox.run_in_sandbox(lambda: _probe_live(host, port), policy)
        except sandbox.SandboxViolation:
            return None  # bounded-out (timeout/limit) — treat as no result, never crash the run
