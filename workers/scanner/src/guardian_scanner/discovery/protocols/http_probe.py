"""HTTP protocol probe (Phase 6C.2) — reads a light banner on 80. Extracted from service_scan.

Behavior is identical to the pre-6C.2 inline logic: TCP connect + a short banner read; no request is
sent that could act as a payload. Live work runs inside the Phase-5 sandbox; offline it reads the
snapshot.
"""

from __future__ import annotations

from guardian_core.probe import ProbeEvidence

from guardian_scanner import sandbox

_CPU_SECONDS = 5
_WALL_SECONDS = 10


def _banner_live(host: str, port: int, timeout: int) -> str | None:  # pragma: no cover - network
    import socket

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(2)
            try:
                return sock.recv(256).decode("latin-1", "replace").strip()[:256]
            except OSError:
                return ""
    except OSError:
        return None


class HttpProbe:
    key = "http"
    ports = (80,)

    def probe(
        self, host: str, port: int, *, timeout: int, allow_live: bool, snapshot: dict | None
    ) -> ProbeEvidence | None:
        if snapshot is not None:  # offline: the service was observed in the snapshot
            attrs = {"missing_tls": True}
            banner = snapshot.get("banner")
            if banner is not None:
                attrs["banner"] = banner
            return ProbeEvidence("http", port, attrs)
        if not allow_live:
            return None
        policy = sandbox.SandboxPolicy(
            cpu_seconds=_CPU_SECONDS, wall_seconds=_WALL_SECONDS, allow_network=True,
        )
        try:
            banner = sandbox.run_in_sandbox(lambda: _banner_live(host, port, timeout), policy)
        except sandbox.SandboxViolation:
            return None
        if banner is None:
            return None
        return ProbeEvidence("http", port, {"banner": banner, "missing_tls": True})
