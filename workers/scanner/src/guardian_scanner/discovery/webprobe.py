"""Fetch a web service and record what it is (WP-B3).

Discovery's job here is observation, not judgement: this module records what the service returned —
status, title, headers, cookies, the redirect chain, the technologies behind it and its TLS posture
— and leaves "is that a vulnerability" to the engines. Keeping the split means a technology
inventory is available to correlation and reporting even when no rule fired on it.

Redirects are followed manually, one at a time, with a cap and a same-scope rule. The alternative —
handing the client a `follow_redirects=True` — lets the *response* choose the next request, which is
how a scanner ends up fetching a cloud metadata endpoint because a customer's site said to. A
redirect that leaves the authorized host is recorded and not followed.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlparse

from guardian_scanner.discovery.technologies import Technology, fingerprint, page_title

MAX_REDIRECTS = 5
MAX_BODY_BYTES = 300_000
DEFAULT_TIMEOUT = 8.0

# Headers whose absence is worth recording on the asset. Whether an absence is a *finding* is a
# rule's decision (the templated web checks own that); discovery only says what was there.
SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


@dataclass
class WebObservation:
    """One web service as observed. Everything here was seen; nothing is inferred."""

    url: str
    reachable: bool = False
    status: int = 0
    final_url: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    left_scope: bool = False
    title: str = ""
    server: str = ""
    powered_by: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    security_headers_present: list[str] = field(default_factory=list)
    security_headers_missing: list[str] = field(default_factory=list)
    insecure_cookies: list[str] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    tls: dict = field(default_factory=dict)
    error: str = ""

    def as_attributes(self) -> dict:
        """The shape that lands on a discovered SERVICE asset."""
        attributes: dict = {
            "url": self.url,
            "http_status": self.status,
            "title": self.title,
            "security_headers_missing": self.security_headers_missing,
        }
        if self.server:
            attributes["server"] = self.server
        if self.powered_by:
            attributes["powered_by"] = self.powered_by
        if self.final_url and self.final_url != self.url:
            attributes["final_url"] = self.final_url
        if self.redirect_chain:
            attributes["redirect_chain"] = self.redirect_chain
        if self.left_scope:
            attributes["redirect_left_scope"] = True
        if self.insecure_cookies:
            attributes["insecure_cookies"] = self.insecure_cookies
        if self.tls:
            attributes["tls"] = self.tls
        if self.technologies:
            attributes["technologies"] = [
                {"name": t.name, "category": t.category, "version": t.version,
                 "confidence": t.confidence, "evidence": t.evidence, "cpe": t.cpe}
                for t in self.technologies
            ]
            # The CPEs are lifted out so WP-C3 can index them without re-walking the list.
            cpes = [t.cpe for t in self.technologies if t.cpe]
            if cpes:
                attributes["cpes"] = cpes
        if self.error:
            attributes["probe_error"] = self.error
        return attributes


def analyze(
    url: str,
    status: int,
    headers: dict[str, str],
    body: str,
    *,
    set_cookies: list[str] | None = None,
    redirect_chain: list[str] | None = None,
    left_scope: bool = False,
    tls: dict | None = None,
) -> WebObservation:
    """Build an observation from an already-fetched response.

    Separated from the fetch so the same analysis runs against a live response, a recorded snapshot,
    and a test fixture — and so a change to what Guardian concludes never requires a network call to
    verify.
    """
    lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    cookies = list(set_cookies or [])
    joined_cookies = "\n".join(cookies)

    observation = WebObservation(
        url=url,
        reachable=True,
        status=status,
        final_url=(redirect_chain or [url])[-1],
        redirect_chain=list(redirect_chain or []),
        left_scope=left_scope,
        title=page_title(body),
        server=lowered.get("server", "")[:120],
        powered_by=lowered.get("x-powered-by", "")[:120],
        headers=lowered,
        technologies=fingerprint(lowered, body, joined_cookies),
        tls=dict(tls or {}),
    )

    present = [h for h in SECURITY_HEADERS if h in lowered]
    observation.security_headers_present = present
    observation.security_headers_missing = [h for h in SECURITY_HEADERS if h not in lowered]
    observation.insecure_cookies = _insecure_cookies(cookies, url)
    return observation


def _insecure_cookies(set_cookies: list[str], url: str) -> list[str]:
    """Cookie names missing a flag that matters on this scheme.

    `Secure` is only meaningful over HTTPS — demanding it of a plaintext service would report the
    wrong problem, since the transport is the finding there, not the flag.
    """
    https = url.lower().startswith("https://")
    weak: list[str] = []
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip()
        if not name:
            continue
        attributes = raw.lower()
        missing = []
        if "httponly" not in attributes:
            missing.append("HttpOnly")
        if https and "secure" not in attributes:
            missing.append("Secure")
        if "samesite" not in attributes:
            missing.append("SameSite")
        if missing:
            weak.append(f"{name} (missing {', '.join(missing)})")
    return weak


# ── live fetching ─────────────────────────────────────────────────────────────────────────────────
def _is_public_address(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return False
    for info in infos:
        try:
            address = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if (address.is_private or address.is_loopback or address.is_link_local
                or address.is_multicast or address.is_reserved or address.is_unspecified):
            return False
    return bool(infos)


def probe(  # pragma: no cover - network
    url: str, *, timeout: float = DEFAULT_TIMEOUT, allow_offsite_redirects: bool = False
) -> WebObservation:
    """Fetch `url`, following in-scope redirects manually, and analyse the final response."""
    import httpx

    chain: list[str] = []
    left_scope = False
    current = url
    origin_host = (urlparse(url).hostname or "").lower()

    try:
        with httpx.Client(follow_redirects=False, timeout=timeout,
                          headers={"user-agent": "guardian-discovery"}) as client:
            for _hop in range(MAX_REDIRECTS + 1):
                host = (urlparse(current).hostname or "").lower()
                if not host or not _is_public_address(host):
                    return WebObservation(url=url, error=f"refused non-public host {host!r}")

                response = client.get(current)
                chain.append(current)

                if 300 <= response.status_code < 400 and "location" in response.headers:
                    target = str(response.url.join(response.headers["location"]))
                    target_host = (urlparse(target).hostname or "").lower()
                    if target_host != origin_host and not allow_offsite_redirects:
                        # The response chose a host outside the authorized target. Recorded, not
                        # followed: following it is how a scanner is aimed at somebody else.
                        left_scope = True
                        chain.append(target)
                        break
                    current = target
                    continue
                break

        body = response.text[:MAX_BODY_BYTES]
        set_cookies = response.headers.get_list("set-cookie") \
            if hasattr(response.headers, "get_list") else []
        return analyze(
            url, response.status_code, dict(response.headers), body,
            set_cookies=list(set_cookies), redirect_chain=chain, left_scope=left_scope,
            tls=tls_details(urlparse(current).hostname or "", urlparse(current).port or 443)
            if current.lower().startswith("https://") else None,
        )
    except Exception as exc:  # noqa: BLE001 - an unreachable service is a result, not a crash
        return WebObservation(url=url, error=f"{type(exc).__name__}: {exc}"[:200])


def tls_details(host: str, port: int, timeout: float = 5.0) -> dict:  # pragma: no cover - network
    """Certificate and protocol facts. Verification is deliberately off: the point is to *observe*
    an expired or self-signed certificate, and a verifying handshake would refuse to show it."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw, \
                context.wrap_socket(raw, server_hostname=host) as tls:
            certificate = tls.getpeercert() or {}
            return {
                "version": tls.version(),
                "cipher": (tls.cipher() or ("", "", 0))[0],
                "subject": _name(certificate.get("subject")),
                "issuer": _name(certificate.get("issuer")),
                "not_after": certificate.get("notAfter", ""),
                "san": [v for k, v in certificate.get("subjectAltName", ()) if k == "DNS"][:20],
            }
    except (OSError, ssl.SSLError) as exc:
        return {"error": f"{type(exc).__name__}: {exc}"[:120]}


def _name(rdn) -> str:  # noqa: ANN001
    if not rdn:
        return ""
    parts = [f"{k}={v}" for group in rdn for k, v in group]
    return ", ".join(parts)[:200]
