"""DAST-lite engine — safe, read-only web assessment (headers, TLS, cookies).

Non-destructive by design: it inspects a single response's security headers, transport, and cookie
flags. No exploitation, no fuzzing. Runs against an offline `http_snapshot` (asset config),
or performs one rate-limited GET in live mode. Active engine → `requires_authorization=True`.
"""

from __future__ import annotations

import socket
from collections.abc import Iterable, Iterator
from contextlib import contextmanager

from guardian_core.enums import EngineKey, Severity
from guardian_core.evidence import Evidence, EvidenceKind
from guardian_core.findings import RawFinding

from guardian_scanner import sandbox
from guardian_scanner.engines.base import EngineHealth, ScanContext


@contextmanager
def _pinned_egress() -> Iterator[None]:
    """Pin EVERY outbound connection made during the enclosed request to a pre-validated PUBLIC IP
    (P1-②/P1-Ⓑ, DNS-rebinding + IDN safe).

    We intercept `socket.create_connection` (the chokepoint httpx/httpcore uses) and, at connect
    time, resolve+validate whatever host it is actually connecting to via the repo's
    `sandbox._resolve_public_address` (blocks private/loopback/link-local/metadata AND
    IPv4-mapped-IPv6, returns ONE validated IP), then connect to THAT IP. There is NO host-equality
    comparison, so a Unicode-vs-IDNA/punycode mismatch cannot slip an unvalidated connection past —
    every connect is validated. No second resolution ⇒ rebinding cannot redirect the socket; TLS
    SNI/Host stay the hostname, so certificate validation is unaffected. The context wraps a single
    GET (follow_redirects=False), so the only connection is the target; an internal target or rebind
    raises PermissionError → the caller fails closed.
    """
    real_create_connection = socket.create_connection

    def _pinned(address, *args, **kwargs):  # noqa: ANN001, ANN202
        host, port = address[0], address[1]
        address = (sandbox._resolve_public_address(host, port), port)  # validate + pin each connect
        return real_create_connection(address, *args, **kwargs)

    socket.create_connection = _pinned  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.create_connection = real_create_connection  # type: ignore[assignment]

# header (lowercased) → (title, severity, cwe)
_REQUIRED_HEADERS = {
    "content-security-policy": ("Missing Content-Security-Policy", Severity.MEDIUM, "CWE-693"),
    "x-content-type-options": ("Missing X-Content-Type-Options: nosniff", Severity.LOW, "CWE-693"),
    "x-frame-options": (
        "Missing clickjacking protection (X-Frame-Options)",
        Severity.MEDIUM,
        "CWE-1021",
    ),
    "referrer-policy": ("Missing Referrer-Policy", Severity.LOW, "CWE-200"),
}
_BANNER_HEADERS = ("server", "x-powered-by", "x-aspnet-version")


class DastEngine:
    key = EngineKey.DAST
    name = "Guardian DAST-lite (headers/TLS/cookies)"
    version = "0.1.0"
    requires_authorization = True
    wants_secrets = True  # consumes target auth material from the encrypted secret_ref

    def supports(self, asset_kind: str) -> bool:
        return asset_kind == "web"

    def health(self) -> EngineHealth:
        return EngineHealth(ok=True, detail="safe header/TLS/cookie checks (snapshot or live GET)")

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        snap = self._load(ctx)
        if snap is None:
            return
        url = snap.get("url", ctx.asset_identifier)
        headers = {k.lower(): v for k, v in (snap.get("headers") or {}).items()}
        is_https = url.startswith("https://")

        if not is_https:
            yield self._f(
                "Site served over plaintext HTTP (no TLS)",
                Severity.HIGH,
                "CWE-319",
                url,
                "Transport is not encrypted.",
            )
        elif "strict-transport-security" not in headers:
            yield self._f(
                "Missing HTTP Strict-Transport-Security (HSTS)",
                Severity.MEDIUM,
                "CWE-319",
                url,
                "HSTS header absent on an HTTPS site.",
            )

        for hdr, (title, sev, cwe) in _REQUIRED_HEADERS.items():
            if hdr not in headers:
                yield self._f(title, sev, cwe, url, f"Response is missing the {hdr} header.")

        for hdr in _BANNER_HEADERS:
            if headers.get(hdr):
                yield self._f(
                    f"Version/banner disclosure via {hdr}",
                    Severity.LOW,
                    "CWE-200",
                    url,
                    f"{hdr}: {headers[hdr]}",
                )

        for cookie in snap.get("cookies", []) or []:
            cname = cookie.get("name", "cookie")
            if not cookie.get("secure"):
                yield self._f(
                    f"Cookie without Secure flag: {cname}",
                    Severity.MEDIUM,
                    "CWE-614",
                    url,
                    "Session cookie can be sent over plaintext.",
                )
            if not cookie.get("httponly"):
                yield self._f(
                    f"Cookie without HttpOnly flag: {cname}",
                    Severity.MEDIUM,
                    "CWE-1004",
                    url,
                    "Cookie is accessible to JavaScript (XSS theft).",
                )
            if not cookie.get("samesite"):
                yield self._f(
                    f"Cookie without SameSite attribute: {cname}",
                    Severity.LOW,
                    "CWE-352",
                    url,
                    "Cookie lacks CSRF-mitigating SameSite.",
                )

    def _load(self, ctx: ScanContext) -> dict | None:
        snap = ctx.asset_config.get("http_snapshot")
        if snap:
            return snap
        # Live mode: ONE hardened GET against the authorized web asset. The DAST engine runs on the
        # scanner plane WITHOUT kernel egress isolation, so it self-guards: every outbound socket
        # is pinned to a validated PUBLIC IP (refusing private/loopback/link-local/metadata +
        # IPv4-mapped-IPv6, rebinding- and IDN-safe), and it NEVER follows a redirect.
        url = ctx.asset_identifier
        if not url.startswith(("http://", "https://")):
            return None
        try:
            import httpx  # noqa: PLC0415

            # Pin every connect to a validated public IP; internal/rebind raises, caught below.
            with _pinned_egress(), httpx.Client(follow_redirects=False, timeout=10.0) as client:
                resp = client.get(url, headers={"user-agent": "guardian-dast"})
            cookies = [
                {
                    "name": c.name,
                    "secure": "secure" in str(c).lower(),
                    "httponly": "httponly" in str(c).lower(),
                    "samesite": None,
                }
                for c in resp.cookies.jar
            ]
            return {"url": str(resp.url), "headers": dict(resp.headers), "cookies": cookies}
        except Exception:  # noqa: BLE001 - network failure degrades to no findings
            return None

    def _f(self, title, sev, cwe, url, detail) -> RawFinding:  # noqa: ANN001
        return RawFinding(
            engine=EngineKey.DAST,
            title=title,
            category="web-misconfig",
            description=detail,
            base_severity=sev,
            confidence="high",
            cwe_id=cwe,
            owasp_ref="A05:2021",
            location={"endpoint": url},
            evidence=Evidence(
                kind=EvidenceKind.HTTP_EXCHANGE, summary=url, detail={"finding": detail}
            ).to_dict(),
            references={"owasp": "A05:2021"},
        )
