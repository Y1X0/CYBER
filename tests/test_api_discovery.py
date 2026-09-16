"""Spec-vs-reality probing — undocumented endpoints and unenforced authentication.

Safe, GET-only, bounded. Tested with a fake fetch (no network): the probe finds shadow endpoints
the contract never declared, catches a secured operation that answers an unauthenticated request,
respects the request budget, skips documented paths, and never treats a clean 404 as an endpoint.
"""

from __future__ import annotations

from types import SimpleNamespace

from guardian_core.enums import Severity
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


def test_no_credentials_are_ever_sent():
    seen_headers = []

    def fetch(url, headers):
        seen_headers.append(headers)
        return SimpleNamespace(status=404, headers={}, body="", error=None)

    probe_surface("https://api.x.com", _spec(), fetch, rate_per_second=0)
    assert all(h == {} for h in seen_headers), "the probe must send no credentials"


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
