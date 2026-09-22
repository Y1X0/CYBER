"""Spec-vs-reality probing — undocumented endpoints and unenforced authentication.

Safe, GET-only, bounded. Tested with a fake fetch (no network): the probe finds shadow endpoints
the contract never declared, catches a secured operation that answers an unauthenticated request,
respects the request budget, skips documented paths, and never treats a clean 404 as an endpoint.
"""

from __future__ import annotations

from types import SimpleNamespace

from guardian_core.enums import Severity
from guardian_scanner.apisec import checks
from guardian_scanner.apisec.discovery import probe_surface
from guardian_scanner.apisec.spec import parse

_DOC = {"openapi": "3.0.0", "info": {"title": "t"}, "servers": [{"url": "https://api.x.com"}],
        "paths": {
            "/users/{id}": {"get": {
                "security": [{"K": []}],
                "parameters": [{"name": "id", "in": "path", "required": True, "example": "1",
                                "schema": {"type": "string"}}],
                "responses": {"200": {}}}},
            "/health": {"get": {"responses": {"200": {}}}}}}


def _spec():
    return parse(_DOC)


def _fetch_map(mapping, *, default=404, counter=None):
    def fetch(url, _headers):
        if counter is not None:
            counter.append(url)
        for suffix, status in mapping.items():
            if url.endswith(suffix):
                return SimpleNamespace(status=status, headers={}, body="", error=None)
        return SimpleNamespace(status=default, headers={}, body="", error=None)
    return fetch


def test_undocumented_sensitive_endpoint_is_medium():
    fetch = _fetch_map({"/actuator/env": 200})
    f = next(x for x in probe_surface("https://api.x.com", _spec(), fetch, rate_per_second=0)
             if "actuator/env" in x.title)
    assert f.base_severity == Severity.MEDIUM and f.cwe_id == "CWE-1059"
    assert f.category == "api-inventory"


def test_exposed_documentation_is_low():
    fetch = _fetch_map({"/swagger.json": 200})
    f = next(x for x in probe_surface("https://api.x.com", _spec(), fetch, rate_per_second=0)
             if "documentation exposed" in x.title)
    assert f.base_severity == Severity.LOW


def test_a_protected_undocumented_endpoint_is_downgraded():
    fetch = _fetch_map({"/admin": 401})
    f = next(x for x in probe_surface("https://api.x.com", _spec(), fetch, rate_per_second=0)
             if "/admin" in x.title)
    assert f.base_severity == Severity.LOW  # exists but protected


def test_a_clean_404_is_not_an_endpoint():
    fetch = _fetch_map({}, default=404)
    assert probe_surface("https://api.x.com", _spec(), fetch, rate_per_second=0) == []


def test_secured_get_reachable_without_credentials_is_high():
    fetch = _fetch_map({"/users/1": 200})
    f = next(x for x in probe_surface("https://api.x.com", _spec(), fetch, rate_per_second=0)
             if "without credentials" in x.title)
    assert f.base_severity == Severity.HIGH and f.cwe_id == "CWE-306"
    assert f.category == "api-authorization"


def test_secured_get_that_refuses_unauthenticated_is_not_flagged():
    fetch = _fetch_map({"/users/1": 401})
    assert not any("without credentials" in x.title
                   for x in probe_surface("https://api.x.com", _spec(), fetch, rate_per_second=0))


_CREDENTIAL_HEADERS = {"authorization", "cookie", "x-api-key", "api-key", "x-auth-token",
                       "authentication", "proxy-authorization"}


def test_no_credentials_are_ever_sent():
    seen_headers = []

    def fetch(url, headers):
        seen_headers.append(headers)
        return SimpleNamespace(status=404, headers={}, body="", error=None)

    probe_surface("https://api.x.com", _spec(), fetch, rate_per_second=0)
    # The CORS probe sends one throwaway `Origin` header; nothing here is ever a credential.
    for h in seen_headers:
        keys = {k.lower() for k in h}
        assert not (keys & _CREDENTIAL_HEADERS), "the probe must send no credentials"
        assert keys <= {"origin"}, "the only header the probe may add is a benign Origin"


def test_a_documented_path_is_not_reported_as_undocumented():
    # /health is in the contract; even if it answers, it is not a shadow endpoint. Match the exact
    # URL so /actuator/health (a different, undocumented path) is not caught by this fixture.
    def fetch(url, _headers):
        status = 200 if url == "https://api.x.com/health" else 404
        return SimpleNamespace(status=status, headers={}, body="", error=None)

    findings = probe_surface("https://api.x.com", _spec(), fetch, rate_per_second=0)
    assert not any(x.location.get("endpoint") == "/health" for x in findings)


def test_the_request_budget_is_respected():
    counter: list[str] = []
    fetch = _fetch_map({}, counter=counter)
    probe_surface("https://api.x.com", _spec(), fetch, max_requests=3, rate_per_second=0)
    assert len(counter) == 3


def test_a_non_http_base_makes_no_requests():
    counter: list[str] = []
    fetch = _fetch_map({}, counter=counter)
    assert probe_surface("not-a-url", _spec(), fetch, rate_per_second=0) == []
    assert counter == []


def test_a_transport_error_is_not_an_endpoint():
    def fetch(url, _headers):
        return SimpleNamespace(status=0, headers={}, body="", error="connect failed")

    assert probe_surface("https://api.x.com", _spec(), fetch, rate_per_second=0) == []


# ── CORS + response hygiene (one benign Origin request per reachable GET) ────────────────────────────
def _reaches_api(url):
    return url.endswith(("/users/1", "/health"))


def _cors_fetch(acao_mode=None, *, credentials=False, extra=None):
    """A fetch that answers the two reachable GETs with configurable CORS/hygiene headers."""
    def fetch(url, headers):
        if not _reaches_api(url):
            return SimpleNamespace(status=404, headers={}, body="", error=None)
        h = dict(extra or {})
        if acao_mode == "reflect":
            h["access-control-allow-origin"] = headers.get("origin", "")
        elif acao_mode == "wildcard":
            h["access-control-allow-origin"] = "*"
        elif acao_mode == "null":
            h["access-control-allow-origin"] = "null"
        elif acao_mode == "restricted":
            h["access-control-allow-origin"] = "https://trusted.example.com"
        if credentials:
            h["access-control-allow-credentials"] = "true"
        return SimpleNamespace(status=200, headers=h, body="", error=None)
    return fetch


def _rule(f):
    return (f.location or {}).get("rule", "")


def test_reflected_origin_with_credentials_is_a_high_cors_finding():
    findings = probe_surface("https://api.x.com", _spec(),
                             _cors_fetch("reflect", credentials=True), rate_per_second=0)
    cors = [f for f in findings if _rule(f) == "api-cors-credentialed"]
    assert cors and cors[0].base_severity == Severity.HIGH


def test_reflected_origin_without_credentials_is_a_medium_cors_finding():
    findings = probe_surface("https://api.x.com", _spec(), _cors_fetch("reflect"),
                             rate_per_second=0)
    cors = [f for f in findings if _rule(f) == "api-cors-open"]
    assert cors and cors[0].base_severity == Severity.MEDIUM


def test_plain_wildcard_without_credentials_is_not_a_cors_finding():
    findings = probe_surface("https://api.x.com", _spec(), _cors_fetch("wildcard"),
                             rate_per_second=0)
    assert not any(_rule(f).startswith("api-cors") for f in findings)


def test_a_restricted_allowlist_is_not_a_cors_finding():
    findings = probe_surface("https://api.x.com", _spec(),
                             _cors_fetch("restricted", credentials=True), rate_per_second=0)
    assert not any(_rule(f).startswith("api-cors") for f in findings)


def test_the_cors_probe_sends_only_the_benign_origin():
    seen = []

    def fetch(url, headers):
        seen.append(dict(headers))
        return SimpleNamespace(status=200, headers={}, body="", error=None)

    probe_surface("https://api.x.com", _spec(), fetch, rate_per_second=0)
    origins = [h["origin"] for h in seen if h.get("origin")]
    assert origins and all(o == checks.CORS_PROBE_ORIGIN for o in origins)


def test_missing_hsts_is_reported_once_per_scan():
    findings = probe_surface("https://api.x.com", _spec(), _cors_fetch(None), rate_per_second=0)
    hsts = [f for f in findings if _rule(f) == "api-missing-hsts"]
    assert len(hsts) == 1 and hsts[0].base_severity == Severity.MEDIUM


def test_a_private_response_without_no_store_is_a_cache_finding():
    def fetch(url, _headers):
        if _reaches_api(url):
            return SimpleNamespace(status=200, body='{"email": "a@b.c"}', error=None,
                                   headers={"strict-transport-security": "max-age=1",
                                            "x-content-type-options": "nosniff"})
        return SimpleNamespace(status=404, headers={}, body="", error=None)

    findings = probe_surface("https://api.x.com", _spec(), fetch, rate_per_second=0)
    cache = [f for f in findings if _rule(f) == "api-cache-sensitive"]
    assert len(cache) == 1 and cache[0].base_severity == Severity.MEDIUM


def test_complete_hygiene_headers_produce_no_hygiene_findings():
    good = {"strict-transport-security": "max-age=1", "x-content-type-options": "nosniff",
            "cache-control": "no-store"}
    findings = probe_surface("https://api.x.com", _spec(),
                             _cors_fetch(None, extra=good), rate_per_second=0)
    assert not any(_rule(f) in ("api-missing-hsts", "api-cache-sensitive",
                                "api-missing-content-type-options") for f in findings)


def test_a_404_response_yields_no_hygiene_or_cors_findings():
    def fetch(url, _headers):
        return SimpleNamespace(status=404, headers={"foo": "bar"}, body="", error=None)

    findings = probe_surface("https://api.x.com", _spec(), fetch, rate_per_second=0)
    assert not any(_rule(f).startswith(("api-cors", "api-missing", "api-cache"))
                   for f in findings)
