"""The web SPA ships a strict Content-Security-Policy + hardening headers (Item 1).

The SPA is a static build, so its security headers come from the static host, not the API. Two
sources are asserted here: `apps/web/public/_headers` (the authoritative header set, honoured by
Netlify/Render/Cloudflare static hosts) and the build-only CSP <meta> injected by vite.config.ts
(a fallback for hosts that ignore _headers). These are static-file checks — no build is run.
"""

from __future__ import annotations

from pathlib import Path

_WEB = Path(__file__).resolve().parents[1] / "apps/web"
_HEADERS = (_WEB / "public/_headers").read_text()
_VITE = (_WEB / "vite.config.ts").read_text()


def test_headers_file_sets_a_strict_csp():
    # default-src 'self', no inline scripts, connect-src the API origin (same-origin → 'self'),
    # not framable.
    assert "Content-Security-Policy:" in _HEADERS
    assert "default-src 'self'" in _HEADERS
    assert "script-src 'self'" in _HEADERS and "'unsafe-inline'" not in _HEADERS.split("script-src")[1].split(";")[0]
    assert "connect-src 'self'" in _HEADERS
    assert "frame-ancestors 'none'" in _HEADERS


def test_headers_file_sets_the_supporting_headers():
    for header in ("X-Content-Type-Options: nosniff", "Referrer-Policy: no-referrer",
                   "X-Frame-Options: DENY"):
        assert header in _HEADERS, f"missing {header!r}"


def test_build_injects_a_csp_meta_but_not_in_dev():
    # A build-only vite plugin stamps the CSP into the built index.html; it must be apply:"build" so
    # the dev server (whose HMR needs an inline preamble) is not broken by script-src 'self'.
    assert "Content-Security-Policy" in _VITE
    assert 'apply: "build"' in _VITE
    assert "default-src 'self'" in _VITE and "script-src 'self'" in _VITE


def test_index_html_has_no_inline_script():
    # script-src 'self' forbids inline scripts; the SPA entry must be an external module.
    html = (_WEB / "index.html").read_text()
    # Every <script> tag carries a src= (module entry / assets), never an inline body.
    import re

    for tag in re.findall(r"<script\b[^>]*>", html):
        assert "src=" in tag, f"inline <script> would violate the CSP: {tag!r}"
