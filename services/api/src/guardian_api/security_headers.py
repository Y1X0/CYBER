"""Baseline HTTP security response headers.

The API previously set no security headers at all (only CORS, metrics, and the body-size limit). A
JSON control-plane API benefits from a conservative, defense-in-depth header set:

  * `X-Content-Type-Options: nosniff` — never let a browser MIME-sniff a JSON response into HTML/JS,
    which is a classic reflected-content XSS vector.
  * `X-Frame-Options: DENY` / `frame-ancestors 'none'` — the API (and its docs) must never be
    framed, closing clickjacking.
  * `Referrer-Policy: no-referrer` — a bearer-token API should not leak URLs (which can carry ids)
    in the Referer header to third parties.
  * `Permissions-Policy` — switch off powerful browser features the API never needs.
  * `Content-Security-Policy: default-src 'none'` — an API response should load nothing; if one is
    ever rendered in a browser it cannot pull scripts, styles, frames, or beacons.

The strict CSP is applied to every response EXCEPT the interactive docs pages (`/docs`, `/redoc`),
whose Swagger-UI / ReDoc HTML loads assets from a CDN and runs inline init — a `default-src 'none'`
policy would blank them. Those two dev-only HTML pages still receive all the other headers; every
JSON API response (including `/openapi.json`) gets the strict policy.

Headers are set with `setdefault`, so an endpoint that deliberately sets its own value always wins.
"""

from __future__ import annotations

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_STRICT_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
# Only the interactive HTML docs need the CDN; exempt just those paths from the strict CSP.
_CSP_EXEMPT_PATHS = frozenset({"/docs", "/redoc"})

_BASELINE_HEADERS = (
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
    ("permissions-policy", "geolocation=(), camera=(), microphone=(), browsing-topics=()"),
)


class SecurityHeadersMiddleware:
    """Attach baseline security headers to every HTTP response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in _BASELINE_HEADERS:
                    headers.setdefault(name, value)
                if path not in _CSP_EXEMPT_PATHS:
                    headers.setdefault("content-security-policy", _STRICT_CSP)
            await send(message)

        await self.app(scope, receive, send_with_headers)
