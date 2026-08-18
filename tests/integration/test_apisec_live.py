"""API authorization testing against a real API (WP-D10).

A small JSON API over real TCP with two tenants and four endpoints: one that checks object
ownership, one that does not, an admin endpoint that checks the caller's role and one that only
hides behind its path, plus a serializer that leaks a password hash.

Both halves have to hold. The broken endpoints must be found — an API scanner that misses BOLA is
not an API scanner — and the correctly-authorized ones must be silent, because a report that says
"broken object level authorization" about a handler that checks ownership is a report the customer
stops believing.
"""

from __future__ import annotations

import contextlib
import http.server
import json
import threading
from urllib.parse import urlparse

import pytest
from guardian_scanner.apisec.scanner import ApiScanner, Principal
from guardian_scanner.apisec.spec import parse
from guardian_scanner.dast.scanner import Response

# tenant → its invoice, and the tokens that identify each caller.
INVOICES = {
    "inv-alpha": {"id": "inv-alpha", "tenant": "alpha", "total": 1000, "notes": "alpha only"},
    "inv-beta": {"id": "inv-beta", "tenant": "beta", "total": 9999, "notes": "beta only"},
}
TOKENS = {"tok-alpha": "alpha", "tok-beta": "beta", "tok-admin": "admin"}

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Fixture"},
    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    "security": [{"bearer": []}],
    "paths": {
        # No ownership check: any valid token retrieves any invoice.
        "/broken/invoices/{invoiceId}": {"get": {
            "operationId": "brokenGetInvoice",
            "parameters": [{"name": "invoiceId", "in": "path", "required": True,
                            "schema": {"type": "string"}}],
            "responses": {"200": {}, "429": {}}}},
        # Ownership checked against the caller's tenant.
        "/safe/invoices/{invoiceId}": {"get": {
            "operationId": "safeGetInvoice",
            "parameters": [{"name": "invoiceId", "in": "path", "required": True,
                            "schema": {"type": "string"}}],
            "responses": {"200": {}}}},
        # Administrative, and only hidden behind its path.
        "/admin/broken/users": {"get": {"operationId": "brokenAdminUsers", "tags": ["admin"],
                                        "responses": {"200": {}}}},
        # Administrative, and it checks the role.
        "/admin/safe/users": {"get": {"operationId": "safeAdminUsers", "tags": ["admin"],
                                      "responses": {"200": {}}}},
        # Declares authentication and does not enforce it.
        "/broken/profile": {"get": {"operationId": "brokenProfile", "responses": {"200": {}}}},
        # Enforces it.
        "/safe/profile": {"get": {"operationId": "safeProfile", "responses": {"200": {}}}},
    },
}


class _Api(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args) -> None:  # noqa: ANN002
        return

    def _tenant(self) -> str | None:
        header = self.headers.get("Authorization", "")
        token = header.split(" ", 1)[-1].strip() if header else ""
        return TOKENS.get(token)

    def _send(self, status: int, payload) -> None:  # noqa: ANN001
        body = json.dumps(payload).encode()
        self.send_response_only(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802, C901, PLR0912
        path = urlparse(self.path).path
        tenant = self._tenant()

        if path.startswith("/broken/invoices/") or path.startswith("/safe/invoices/"):
            if tenant is None:
                return self._send(401, {"error": "unauthorized"})
            invoice = INVOICES.get(path.rsplit("/", 1)[-1])
            if invoice is None:
                return self._send(404, {"error": "not found"})
            # The whole difference between the two endpoints is this one check.
            if path.startswith("/safe/") and invoice["tenant"] != tenant and tenant != "admin":
                return self._send(403, {"error": "forbidden"})
            return self._send(200, invoice)

        if path == "/admin/broken/users":
            if tenant is None:
                return self._send(401, {"error": "unauthorized"})
            # Serializes the whole record, password hash included.
            return self._send(200, {"users": [
                {"id": 1, "email": "ops@example.invalid", "role": "admin",
                 "password_hash": "$2b$12$notarealhashvalue"}]})

        if path == "/admin/safe/users":
            if tenant != "admin":
                return self._send(403, {"error": "forbidden"})
            return self._send(200, {"users": [{"id": 1, "email": "ops@example.invalid"}]})

        if path == "/broken/profile":
            # Declares authentication in the spec; the handler forgot it.
            return self._send(200, {"profile": {"plan": "enterprise", "seats": 40}})

        if path == "/safe/profile":
            if tenant is None:
                return self._send(401, {"error": "unauthorized"})
            return self._send(200, {"profile": {"tenant": tenant}})

        return self._send(404, {"error": "not found"})


@contextlib.contextmanager
def _server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Api)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _transport(seen: list[tuple[str, str]]):
    """A real HTTP client. The engine's own transport pins to a validated public address, which
    refuses loopback by design, so the scanner is driven directly — as WP-B2/B3/D2 were."""
    import httpx

    def fetch(url: str, headers: dict) -> Response:
        seen.append((url, headers.get("Authorization", "")))
        try:
            with httpx.Client(follow_redirects=False, timeout=5.0) as client:
                response = client.get(url, headers=headers or {})
        except Exception as exc:  # noqa: BLE001
            return Response(status=0, headers={}, body="", url=url,
                            error=f"{type(exc).__name__}: {exc}")
        return Response(status=response.status_code,
                        headers={k.lower(): v for k, v in response.headers.items()},
                        body=response.text, url=str(response.url))

    return fetch


@pytest.fixture(scope="module")
def scan():
    with _server() as base:
        seen: list[tuple[str, str]] = []
        principals = [
            Principal(name="alpha", headers={"Authorization": "Bearer tok-alpha"},
                      object_ids={"invoiceId": "inv-alpha"}),
            Principal(name="beta", headers={"Authorization": "Bearer tok-beta"},
                      object_ids={"invoiceId": "inv-beta"}),
            Principal(name="admin", headers={"Authorization": "Bearer tok-admin"},
                      object_ids={"invoiceId": "inv-alpha"}, privileged=True),
        ]
        scanner = ApiScanner(fetch=_transport(seen), spec=parse(SPEC), principals=principals,
                             base_url=base, rate_per_second=0, max_requests=400)
        return {"result": scanner.scan(), "base": base, "requests": seen}


def _fired(scan) -> set[tuple[str, str]]:
    return {(issue.check_id, issue.operation) for issue in scan["result"].issues}


# ── the broken endpoints are found ────────────────────────────────────────────────────────────────
def test_the_endpoint_without_an_ownership_check_is_reported(scan):
    """alpha's credential retrieved beta's invoice."""
    assert ("api-bola", "GET /broken/invoices/{invoiceId}") in _fired(scan)


def test_the_bola_finding_is_proved_by_comparison(scan):
    issue = next(i for i in scan["result"].issues if i.check_id == "api-bola")
    assert issue.confidence == "high"
    assert issue.evidence["matched_owner"] is True
    assert issue.parameter == "invoiceId"


def test_the_admin_endpoint_without_a_role_check_is_reported(scan):
    assert ("api-bfla", "GET /admin/broken/users") in _fired(scan)


def test_the_endpoint_that_forgot_its_authentication_is_reported(scan):
    assert ("api-missing-auth", "GET /broken/profile") in _fired(scan)


def test_the_leaked_password_hash_is_reported_without_the_hash(scan):
    issue = next(i for i in scan["result"].issues if i.check_id == "api-excessive-exposure")
    assert issue.evidence["fields"] == ["password_hash"]
    assert "notarealhash" not in json.dumps(issue.evidence)
    assert "notarealhash" not in issue.indicator


# ── the correct endpoints are silent ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("operation", [
    "GET /safe/invoices/{invoiceId}", "GET /admin/safe/users", "GET /safe/profile",
])
def test_the_correctly_authorized_endpoint_is_not_reported(scan, operation):
    """The safe invoice endpoint differs from the broken one by a single ownership check, which is
    exactly the distinction the scanner has to make."""
    assert not [i for i in scan["result"].issues if i.operation == operation]


def test_nothing_else_was_reported(scan):
    assert {op for _, op in _fired(scan)} == {
        "GET /broken/invoices/{invoiceId}", "GET /admin/broken/users", "GET /broken/profile",
    }


# ── safety, observed on the wire ──────────────────────────────────────────────────────────────────
def test_no_identifier_was_ever_enumerated(scan):
    """Walking `id+1` through a production API means reading real people's records, and reading
    them is the harm rather than the proof of it."""
    requested = {urlparse(url).path.rsplit("/", 1)[-1] for url, _ in scan["requests"]
                 if "/invoices/" in url}
    assert requested <= {"inv-alpha", "inv-beta", "guardian-no-such-object-6f1c"}


def test_every_request_stayed_on_the_target(scan):
    assert scan["requests"]
    assert all(urlparse(url).hostname == "127.0.0.1" for url, _ in scan["requests"])


def test_the_state_changing_operation_was_never_requested(scan):
    """The spec's POST operation is inventoried and not called."""
    assert not any("/pay" in url for url, _ in scan["requests"])


def test_the_scan_reports_what_it_could_not_test(scan):
    result = scan["result"]
    assert result.bola_pairs_tested >= 2
    assert result.operations_tested >= 5


def test_bola_cannot_be_tested_with_one_principal_and_says_so():
    """Reporting an API clean of a class that was never tested is the failure this avoids."""
    with _server() as base:
        scanner = ApiScanner(
            fetch=_transport([]), spec=parse(SPEC), base_url=base, rate_per_second=0,
            principals=[Principal(name="alpha", headers={"Authorization": "Bearer tok-alpha"},
                                  object_ids={"invoiceId": "inv-alpha"})],
        )
        result = scanner.scan()
    assert any("two principals" in note for note in result.untested)
    assert not [i for i in result.issues if i.check_id == "api-bola"]
    assert result.degraded is True
