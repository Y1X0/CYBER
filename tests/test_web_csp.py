"""The web SPA ships a strict Content-Security-Policy + hardening headers (Item 1).

The SPA is a static build, so its security headers come from the static host, not the API. Two
sources are asserted here: `apps/web/public/_headers` (the authoritative header set, honoured by
Netlify/Render/Cloudflare static hosts) and the build-only CSP <meta> injected by vite.config.ts
(a fallback for hosts that ignore _headers). These are static-file checks — no build is run.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_WEB = _ROOT / "apps/web"
_HEADERS = (_WEB / "public/_headers").read_text()
_VITE = (_WEB / "vite.config.ts").read_text()
_RENDER = (_ROOT / "render.yaml").read_text()

# The exact API origin the SPA talks to (separate origin from the static site).
_API_ORIGIN = "https://guardian-api-s1jd.onrender.com"


def test_headers_file_sets_a_strict_csp():
    # default-src 'self', no inline scripts, connect-src listing the exact API origin, not framable.
    assert "Content-Security-Policy:" in _HEADERS
    assert "default-src 'self'" in _HEADERS
    assert "script-src 'self'" in _HEADERS and "'unsafe-inline'" not in _HEADERS.split("script-src")[1].split(";")[0]
    assert "connect-src 'self'" in _HEADERS
    assert "frame-ancestors 'none'" in _HEADERS


def test_connect_src_lists_the_exact_api_origin_no_wildcard():
    # A separate-origin SPA must be allowed to reach the API — with the EXACT origin, never a
    # wildcard, in both the _headers fallback and the build-time meta.
    for text in (_HEADERS, _VITE):
        assert f"connect-src 'self' {_API_ORIGIN}" in text, "connect-src must list the exact origin"
        assert "connect-src *" not in text, "connect-src must not use a wildcard"


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


def test_render_yaml_sets_host_enforced_headers_for_the_web_site():
    # Render does not read _headers; the authoritative production headers live in render.yaml's
    # `headers:` for the guardian-web static site. Assert the security header set is there, that the
    # CSP names the API origin, and that the SPA is wired to the API cross-origin (VITE_API_BASE +
    # the API's CORS allowlist).
    assert "name: guardian-console" in _RENDER and "runtime: static" in _RENDER
    for header in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
                   "Referrer-Policy", "Permissions-Policy"):
        assert header in _RENDER, f"render.yaml must set {header} on the web site"
    assert "frame-ancestors 'none'" in _RENDER
    assert f"connect-src 'self' {_API_ORIGIN}" in _RENDER
    assert "VITE_API_BASE" in _RENDER and _API_ORIGIN in _RENDER
    assert "GUARDIAN_CORS_ORIGINS" in _RENDER   # API must allow the web origin


def test_index_html_has_no_inline_script():
    # script-src 'self' forbids inline scripts; the SPA entry must be an external module.
    html = (_WEB / "index.html").read_text()
    # Every <script> tag carries a src= (module entry / assets), never an inline body.
    import re

    for tag in re.findall(r"<script\b[^>]*>", html):
        assert "src=" in tag, f"inline <script> would violate the CSP: {tag!r}"
