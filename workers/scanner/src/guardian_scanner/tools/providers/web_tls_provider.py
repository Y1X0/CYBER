"""Web/TLS read-only tool provider (Security Tool Execution Framework — the first provider).

Deliberately tiny and passive. It OBSERVES an authorized web host and returns evidence — nothing
more. It reuses the 6C.2 TLS/HTTP read logic (a handshake to read the certificate; a light banner /
status read) but not the probes' self-sandboxing: the execution plane (`tools.execution`) already
runs `execute()` inside the mandatory sandbox with egress bound to the job's scope, so the provider
is just the observation.

Strictly out of scope (never here): crawling / directory or content discovery, forms / POST / auth,
fuzzing, payloads, open-redirect probing, port discovery. It only reads: the TLS certificate
(issuer / subject / SAN / expiry / version / hostname verification) and a safe HTTP status + a small
set of non-sensitive response headers, plus the verified IP from the connection it made.

Evidence-first: `execute()` yields `RawEvidence` (the primary truth). `normalize()` derives a
`RawFinding` from a single evidence item deterministically (expired cert, hostname mismatch) — a
finding is an inference from evidence, never the tool's own verdict.

Offline-first & hermetic: when `settings["allow_live"]` is not set, it reads a snapshot from
`settings["snapshot"]` (keyed by host) and opens no socket — so tests and CI are deterministic. Live
work runs only behind `allow_live`, and only ever to the in-scope target the sandbox+egress allow.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from guardian_core.enums import EngineKey, Severity
from guardian_core.findings import RawFinding
from guardian_core.tool import RawEvidence, ToolCapabilities, ToolJob

_TLS_PORT = 443
_HTTP_PORT = 80
_TIMEOUT = 6
# Response headers worth recording — all non-sensitive (never a Set-Cookie / auth header).
_SAFE_HEADERS = ("server", "content-type", "strict-transport-security",
                 "x-frame-options", "content-security-policy")


def _host_of(target: str) -> str:
    return target.split(":", 1)[0].strip()


# ── live reads (reuse 6C.2 socket logic; run inside the framework sandbox, so no self-sandbox) ──
def _tls_live(host: str) -> dict | None:  # pragma: no cover - network
    import socket
    import ssl

    # First a verifying context: success ⇒ hostname verified + not expired (the strong signal).
    verified = True
    try:
        vctx = ssl.create_default_context()
        with socket.create_connection((host, _TLS_PORT), timeout=_TIMEOUT) as sock:
            ip = sock.getpeername()[0]
            with vctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                version = tls.version()
    except ssl.SSLCertVerificationError:
        verified = False
        cert, version, ip = {}, None, None
    except OSError:
        return None
    # If verification failed, observe the cert without verifying (read-only, no data sent).
    if not verified:
        try:
            octx = ssl.create_default_context()
            octx.check_hostname = False
            octx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, _TLS_PORT), timeout=_TIMEOUT) as sock:
                ip = sock.getpeername()[0]
                with octx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert(binary_form=False) or {}
                    version = tls.version()
        except OSError:
            cert, version = {}, None
    return _cert_facts(cert, version=version, resolved_ip=ip, hostname_verified=verified)


def _cert_facts(cert: dict, *, version, resolved_ip, hostname_verified: bool) -> dict:  # noqa: ANN001
    not_after = cert.get("notAfter")
    san = [v for (k, v) in cert.get("subjectAltName", ()) if k == "DNS"]
    subject = _rdn(cert.get("subject"))
    issuer = _rdn(cert.get("issuer"))
    return {
        "port": _TLS_PORT, "tls_version": version, "subject": subject, "issuer": issuer,
        "san": san, "not_after": not_after, "expired": _is_expired(not_after),
        "hostname_verified": hostname_verified, "resolved_ip": resolved_ip,
    }


def _rdn(rdn) -> dict:  # noqa: ANN001
    out: dict[str, str] = {}
    for part in rdn or ():
        for k, v in part:
            out[str(k)] = str(v)
    return out


def _is_expired(not_after: str | None) -> bool:
    if not not_after:
        return False
    try:
        expires = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.UTC)
    except ValueError:
        return False
    return expires < dt.datetime.now(dt.UTC)


def _http_live(host: str) -> dict | None:  # pragma: no cover - network
    import http.client

    try:
        conn = http.client.HTTPConnection(host, _HTTP_PORT, timeout=_TIMEOUT)
        conn.request("HEAD", "/")          # HEAD only — never a body/payload, never a mutation
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders() if k.lower() in _SAFE_HEADERS}
        ip = conn.sock.getpeername()[0] if conn.sock else None
        conn.close()
        return {"port": _HTTP_PORT, "status": resp.status, "server": headers.get("server"),
                "headers": headers, "resolved_ip": ip}
    except OSError:
        return None


class WebTlsProvider:
    """A governed, read-only Web/TLS observer. Declares itself; never authorizes itself."""

    key = "web_tls"
    name = "Web/TLS Read-only"
    version = "1"

    @property
    def capabilities(self) -> ToolCapabilities:
        # network+active ⇒ human approval required (policy gate); never destructive.
        return ToolCapabilities(
            category="web_assessment", network=True, active=True, destructive=False,
            requires_authorization=True, requires_human_approval=True,
            supported_targets=("domain", "subdomain", "host"),
            ports=(_HTTP_PORT, _TLS_PORT), protocols=("http", "https", "tls"),
        )

    def validate(self, job: ToolJob) -> None:
        """Reject a malformed job. NOT authorization — the Control Plane gate already ran."""
        if not job.scope.targets:
            raise ValueError("web_tls: no in-scope target")

    def execute(self, job: ToolJob):  # noqa: ANN201
        """Observe each in-scope host and yield RawEvidence (offline snapshot unless allow_live)."""
        settings = job.settings or {}
        allow_live = bool(settings.get("allow_live"))
        snapshot: dict[str, Any] = settings.get("snapshot") or {}
        for target in job.scope.targets:
            host = _host_of(target)
            if not host:
                continue
            snap = snapshot.get(host) or {}
            occurred = str(snap.get("observed_at") or "")
            mode = "offline" if not allow_live else "live"

            tls = snap.get("tls") if not allow_live else _tls_live(host)
            if tls is not None:
                yield RawEvidence(
                    tool=self.key, execution_id=job.job_id, target=host, kind="tls",
                    data=dict(tls), provenance={"mode": mode, "source": self.key},
                    occurred_at=occurred,
                )
            http = snap.get("http") if not allow_live else _http_live(host)
            if http is not None:
                yield RawEvidence(
                    tool=self.key, execution_id=job.job_id, target=host, kind="http",
                    data=dict(http), provenance={"mode": mode, "source": self.key},
                    occurred_at=occurred,
                )

    def normalize(self, evidence: RawEvidence) -> RawFinding | None:
        """Deterministically derive a finding from ONE evidence item (or None). Never a guess."""
        if evidence.kind != "tls":
            return None
        data = evidence.data or {}
        host = evidence.target
        if data.get("expired"):
            return RawFinding(
                engine=EngineKey.WEB_TLS, title="TLS certificate expired",
                category="misconfig", base_severity=Severity.HIGH, confidence="high",
                cwe_id="CWE-298",
                description=f"The TLS certificate served by {host} is expired.",
                location={"endpoint": host, "port": _TLS_PORT, "rule": "tls-cert-expired"},
                evidence={"not_after": data.get("not_after"), "subject": data.get("subject")},
            )
        if data.get("hostname_verified") is False:
            return RawFinding(
                engine=EngineKey.WEB_TLS, title="TLS certificate hostname mismatch",
                category="misconfig", base_severity=Severity.HIGH, confidence="high",
                cwe_id="CWE-297",
                description=f"The TLS certificate served by {host} does not validate for it.",
                location={"endpoint": host, "port": _TLS_PORT, "rule": "tls-hostname-mismatch"},
                evidence={"san": data.get("san"), "subject": data.get("subject")},
            )
        return None
