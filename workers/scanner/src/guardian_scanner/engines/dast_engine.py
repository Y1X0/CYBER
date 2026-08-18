"""DAST engine — passive posture plus active, safe vulnerability testing (WP-D2).

What this engine used to be was a header/cookie/TLS inspector on a single response. That is worth
having and it is not DAST: it cannot find an injection, because an injection only exists while the
application is running and only answers when something is sent to it. Those checks are kept — they
are cheap and they are correct — and the active scanner from `guardian_scanner.dast` now runs
alongside them.

Two boundaries govern the active half:

* **Authorization.** `requires_authorization = True` has always been declared; the orchestrator
  refuses to run this engine without a valid record. The scanner additionally confines every request
  to the authorized host at the moment the request is made.
* **Egress.** Live requests are pinned to a validated public address at connect time, so a customer
  hostname that resolves to `169.254.169.254` — or rebinds mid-scan — cannot make Guardian fetch its
  own metadata service.

A failure is never a clean result. If the target could not be reached, or the scan stopped on its
budget, the engine says so: it raises when nothing could be scanned at all, and emits the coverage
it achieved when it was partial. An empty finding list and an unreachable application must not look
the same to a customer.
"""

from __future__ import annotations

import socket
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from urllib.parse import urlparse

from guardian_common.logging import get_logger
from guardian_core.enums import EngineKey, Severity
from guardian_core.evidence import Evidence, EvidenceKind
from guardian_core.findings import RawFinding

from guardian_scanner import sandbox
from guardian_scanner.dast.checks import CHECKS
from guardian_scanner.dast.scanner import ActiveScanner, Issue, Response, ScanResult
from guardian_scanner.engines.base import EngineHealth, ScanContext

log = get_logger("guardian.dast.engine")

MAX_BODY_BYTES = 400_000
REQUEST_TIMEOUT = 10.0

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


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
    SNI/Host stay the hostname, so certificate validation is unaffected. Requests are made with
    `follow_redirects=False`, so the only connection is the target; an internal target or rebind
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


class DastScanError(RuntimeError):
    """The application could not be assessed at all.

    Raised rather than returning nothing, because "no findings" is what a customer reads as "we
    looked and it is fine". The orchestrator records the engine run as failed, and WP-E2's
    verification treats a failed engine as *not checked* rather than as evidence of resolution.
    """


class DastEngine:
    key = EngineKey.DAST
    name = "Guardian DAST (passive posture + active injection testing)"
    version = "0.2.0"
    requires_authorization = True
    wants_secrets = True  # consumes target auth material from the encrypted secret_ref

    def supports(self, asset_kind: str) -> bool:
        return asset_kind == "web"

    def health(self) -> EngineHealth:
        return EngineHealth(
            ok=True,
            detail=f"passive header/TLS/cookie checks + {len(CHECKS)} active checks "
                   "(read-only payloads, no timing probes, GET only)",
        )

    # ── entry point ──────────────────────────────────────────────────────────────────────────────
    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        """Everything is collected before anything is returned.

        Deliberately not a generator. The orchestrator persists findings as it consumes them, so a
        generator that yields three findings and *then* raises leaves those three attached to an
        engine run recorded as failed — a scan that is simultaneously "no result" and "some
        results". Raising before the first item means the run is cleanly failed or cleanly complete.
        """
        findings = list(self._passive(ctx))
        findings.extend(self._active(ctx))
        return findings

    # ── passive posture ──────────────────────────────────────────────────────────────────────────
    def _passive(self, ctx: ScanContext) -> Iterable[RawFinding]:
        snap = self._load(ctx)
        if snap is None:
            return
        url = snap.get("url", ctx.asset_identifier)
        headers = {k.lower(): v for k, v in (snap.get("headers") or {}).items()}
        is_https = url.startswith("https://")

        if not is_https:
            yield self._f("Site served over plaintext HTTP (no TLS)", Severity.HIGH, "CWE-319",
                          url, "Transport is not encrypted.")
        elif "strict-transport-security" not in headers:
            yield self._f("Missing HTTP Strict-Transport-Security (HSTS)", Severity.MEDIUM,
                          "CWE-319", url, "HSTS header absent on an HTTPS site.")

        for hdr, (title, sev, cwe) in _REQUIRED_HEADERS.items():
            if hdr not in headers:
                yield self._f(title, sev, cwe, url, f"Response is missing the {hdr} header.")

        for hdr in _BANNER_HEADERS:
            if headers.get(hdr):
                yield self._f(f"Version/banner disclosure via {hdr}", Severity.LOW, "CWE-200",
                              url, f"{hdr}: {headers[hdr]}")

        for cookie in snap.get("cookies", []) or []:
            cname = cookie.get("name", "cookie")
            if not cookie.get("secure"):
                yield self._f(f"Cookie without Secure flag: {cname}", Severity.MEDIUM, "CWE-614",
                              url, "Session cookie can be sent over plaintext.")
            if not cookie.get("httponly"):
                yield self._f(f"Cookie without HttpOnly flag: {cname}", Severity.MEDIUM,
                              "CWE-1004", url, "Cookie is accessible to JavaScript (XSS theft).")
            if not cookie.get("samesite"):
                yield self._f(f"Cookie without SameSite attribute: {cname}", Severity.LOW,
                              "CWE-352", url, "Cookie lacks CSRF-mitigating SameSite.")

    # ── active testing ───────────────────────────────────────────────────────────────────────────
    def _active(self, ctx: ScanContext) -> Iterable[RawFinding]:
        settings = ctx.settings or {}
        if settings.get("dast_active") is False:
            return
        url = ctx.asset_identifier
        if not url.startswith(("http://", "https://")):
            return
        if ctx.asset_config.get("http_snapshot") and not settings.get("dast_live"):
            # An offline snapshot describes one response. Active testing needs a live application,
            # and pretending otherwise would report a clean active scan that never happened.
            return

        host = (urlparse(url).hostname or "").lower()
        if not host:
            return

        scanner = ActiveScanner(
            fetch=self._transport(),
            authorized_hosts={host},
            max_requests=int(settings.get("dast_max_requests", 400)),
            rate_per_second=float(settings.get("dast_rate", 8.0)),
            deadline_seconds=float(settings.get("dast_deadline", 180.0)),
        )
        result = scanner.scan([url],
                              max_pages=int(settings.get("dast_max_pages", 40)),
                              max_depth=int(settings.get("dast_max_depth", 2)))

        if result.requests_made == 0:
            raise DastScanError(
                f"the application at {url} could not be reached: "
                f"{'; '.join(result.errors[:3]) or 'no response'}"
            )

        log.info("dast_active_complete", url=url, requests=result.requests_made,
                 parameters=result.parameters_tested, issues=len(result.issues),
                 degraded=result.degraded)

        for issue in result.issues:
            yield self._issue_finding(issue)
        if result.degraded:
            yield self._coverage_finding(url, result)

    def _transport(self):  # noqa: ANN202
        """A GET that never follows a redirect and never leaves a validated public address."""
        import httpx  # noqa: PLC0415

        def fetch(url: str, headers: dict) -> Response:
            request_headers = {"user-agent": "guardian-dast", **(headers or {})}
            try:
                with _pinned_egress(), httpx.Client(
                    follow_redirects=False, timeout=REQUEST_TIMEOUT
                ) as client:
                    response = client.get(url, headers=request_headers)
            except Exception as exc:  # noqa: BLE001 - reported, never turned into an empty page
                return Response(status=0, headers={}, body="", url=url,
                                error=f"{type(exc).__name__}: {exc}")
            return Response(
                status=response.status_code,
                headers={k.lower(): v for k, v in response.headers.items()},
                body=response.text[:MAX_BODY_BYTES],
                url=str(response.url),
            )

        return fetch

    # ── finding construction ─────────────────────────────────────────────────────────────────────
    def _issue_finding(self, issue: Issue) -> RawFinding:
        check = CHECKS[issue.check_id]
        return RawFinding(
            engine=EngineKey.DAST,
            title=f"{check.title} in `{issue.parameter}`",
            category=check.category,
            description=f"{check.description}\n\nProof: {issue.indicator}",
            base_severity=_SEVERITY.get(check.severity, Severity.MEDIUM),
            confidence=issue.confidence,
            cwe_id=check.cwe,
            owasp_ref=check.owasp,
            location={"endpoint": issue.url, "parameter": issue.parameter, "rule": check.id},
            evidence=Evidence(
                kind=EvidenceKind.HTTP_EXCHANGE,
                summary=f"GET {issue.url} with `{issue.parameter}` set to the probe value "
                        f"→ HTTP {issue.status}",
                detail={
                    "parameter": issue.parameter,
                    # The payload is recorded so the customer can reproduce the request exactly.
                    # Every payload in this catalogue is read-only, which is what makes publishing
                    # it in a report a reasonable thing to do.
                    "payload": issue.payload,
                    "indicator": issue.indicator,
                    "excerpt": issue.excerpt,
                    "remediation": check.remediation,
                },
            ).to_dict(),
            references=check.references,
        )

    def _coverage_finding(self, url: str, result: ScanResult) -> RawFinding:
        """Say out loud that the scan was partial.

        Without this, a budget-limited scan of a large application is reported exactly like a
        complete scan that found nothing — and the customer draws the wrong conclusion from it.
        """
        reasons = []
        if result.budget_exhausted:
            reasons.append(f"the request budget was spent after {result.requests_made} requests")
        if result.deadline_reached:
            reasons.append("the time limit was reached")
        if result.crawl and result.crawl.truncated:
            reasons.append(f"the crawl stopped at {result.crawl.pages_fetched} pages")
        for error in result.errors[:5]:
            reasons.append(f"a request failed: {error}")
        for error in (result.crawl.errors[:5] if result.crawl else []):
            reasons.append(f"a page could not be read: {error}")

        return RawFinding(
            engine=EngineKey.DAST,
            title="Dynamic scan coverage was incomplete",
            category="scan-coverage",
            description=(
                "The active scan did not cover the whole application, so the absence of an "
                "injection finding is not evidence that there is none. "
                + "; ".join(reasons)
            ),
            base_severity=Severity.INFO,
            confidence="high",
            location={"endpoint": url, "rule": "dast-coverage"},
            evidence=Evidence(
                kind=EvidenceKind.HTTP_EXCHANGE,
                summary=f"{result.requests_made} requests, {result.parameters_tested} parameters "
                        f"tested across {result.targets_tested} endpoints",
                detail={
                    "requests_made": result.requests_made,
                    "targets_tested": result.targets_tested,
                    "parameters_tested": result.parameters_tested,
                    "pages_crawled": result.crawl.pages_fetched if result.crawl else 0,
                    "out_of_scope_skipped": len(result.crawl.out_of_scope) if result.crawl else 0,
                    "state_changing_skipped": (
                        len(result.crawl.skipped_dangerous) if result.crawl else 0
                    ),
                    "reasons": reasons,
                },
            ).to_dict(),
            references={},
        )

    # ── snapshot / single response ───────────────────────────────────────────────────────────────
    def _load(self, ctx: ScanContext) -> dict | None:
        snap = ctx.asset_config.get("http_snapshot")
        if snap:
            return snap
        url = ctx.asset_identifier
        if not url.startswith(("http://", "https://")):
            return None
        fetch = self._transport()
        response = fetch(url, {})
        if response.error:
            # Recorded and then re-raised by the active half if nothing at all could be reached.
            # A passive check that cannot see a response has nothing to say, and saying nothing is
            # correct here only because `_active` refuses to stay quiet about the same failure.
            log.warning("dast_passive_fetch_failed", url=url, error=response.error)
            return None
        cookies = [
            {
                "name": name,
                "secure": "secure" in value.lower(),
                "httponly": "httponly" in value.lower(),
                "samesite": "samesite" in value.lower() or None,
            }
            for name, value in _set_cookies(response.headers)
        ]
        return {"url": response.url or url, "headers": response.headers, "cookies": cookies}

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


def _set_cookies(headers: dict) -> list[tuple[str, str]]:
    """`Set-Cookie` values, with the cookie name split out."""
    raw = headers.get("set-cookie", "")
    if not raw:
        return []
    return [(value.split("=", 1)[0].strip(), value) for value in raw.split("\n") if value.strip()]
