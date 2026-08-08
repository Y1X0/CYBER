"""TLS protocol probe (Phase 6C.2) — reads certificate metadata on 443. Extracted from service_scan.

Behavior is identical to the pre-6C.2 inline logic: a TLS handshake to read the certificate; no
verification bypass beyond what's needed to *observe* the cert, no data sent. Live work runs inside
the Phase-5 sandbox; offline it reads the snapshot.
"""

from __future__ import annotations

from guardian_core.probe import ProbeEvidence

from guardian_scanner import sandbox

_CPU_SECONDS = 5
_WALL_SECONDS = 10


def _tls_live(host: str, port: int, timeout: int) -> dict | None:  # pragma: no cover - network
    import socket
    import ssl

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert(binary_form=False) or {}
                return {"version": tls.version(), "subject": str(cert)}
    except OSError:
        return None


class TlsProbe:
    key = "tls"
    ports = (443,)

    def probe(
        self, host: str, port: int, *, timeout: int, allow_live: bool, snapshot: dict | None
    ) -> ProbeEvidence | None:
        if snapshot is not None:  # offline: the service was observed in the snapshot
            tls = snapshot.get("tls")
            attrs = {"missing_tls": False}
            if tls is not None:
                attrs["tls"] = tls
            return ProbeEvidence("tls", port, attrs)
        if not allow_live:
            return None
        policy = sandbox.SandboxPolicy(
            cpu_seconds=_CPU_SECONDS, wall_seconds=_WALL_SECONDS, allow_network=True,
        )
        try:
            tls = sandbox.run_in_sandbox(lambda: _tls_live(host, port, timeout), policy)
        except sandbox.SandboxViolation:
            return None  # bounded-out → no result, never crash
        if tls is None:
            return None
        return ProbeEvidence("tls", port, {"tls": tls, "missing_tls": False})
