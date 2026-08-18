"""API authorization testing (WP-D10), without a network.

The verdict functions are where this package earns its keep. A BOLA scanner that reports every 200
is worse than no scanner, because an API answers 200 for a great many reasons that are not a
vulnerability: the endpoint is meant to be public, the object genuinely belongs to the caller, the
response is an empty list, or the service returns its error document with a 200 status.

So most of what follows is the *negative* case.
"""

from __future__ import annotations

import json

import pytest
from guardian_scanner.apisec import checks
from guardian_scanner.apisec.spec import Operation, Parameter, build_url, parse

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Billing"},
    "servers": [{"url": "https://api.example.com/v1"}],
    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    "security": [{"bearer": []}],
    "paths": {
        "/invoices/{invoiceId}": {
            "get": {
                "operationId": "getInvoice",
                "parameters": [{"name": "invoiceId", "in": "path", "required": True,
                                "schema": {"type": "string"}}],
                "responses": {"200": {}, "429": {}},
            }
        },
        "/invoices": {
            "get": {
                "operationId": "listInvoices",
                "parameters": [{"name": "page", "in": "query", "schema": {"type": "integer"}}],
                "responses": {"200": {}},
            }
        },
        "/admin/users": {
            "get": {"operationId": "adminListUsers", "tags": ["admin"], "responses": {"200": {}}}
        },
        "/health": {"get": {"operationId": "health", "security": [], "responses": {"200": {}}}},
        "/invoices/{invoiceId}/pay": {
            "post": {"operationId": "payInvoice", "responses": {"200": {}}}
        },
    },
}


# ── spec parsing ──────────────────────────────────────────────────────────────────────────────────
def test_the_operations_are_enumerated_with_their_security():
    spec = parse(SPEC)
    labels = {op.label for op in spec.operations}
    assert "GET /invoices/{invoiceId}" in labels
    assert "POST /invoices/{invoiceId}/pay" in labels

    invoice = next(op for op in spec.operations if op.operation_id == "getInvoice")
    assert invoice.security == ("bearer",)
    health = next(op for op in spec.operations if op.operation_id == "health")
    assert health.security == ()
    assert health.security_declared is True


def test_object_identifier_parameters_are_recognized():
    spec = parse(SPEC)
    invoice = next(op for op in spec.operations if op.operation_id == "getInvoice")
    assert [p.name for p in invoice.object_ids] == ["invoiceId"]


@pytest.mark.parametrize("name", ["id", "user_id", "accountId", "uuid", "customer", "orderId"])
def test_identifier_shaped_names_are_object_ids(name):
    assert Parameter(name=name, where="path").is_object_id is True


@pytest.mark.parametrize("name", ["page", "limit", "offset", "cursor", "sort", "q", "fields"])
def test_pagination_parameters_are_not(name):
    """Testing them spends the request budget and finds nothing."""
    assert Parameter(name=name, where="query").is_object_id is False


def test_an_administrative_operation_is_recognized_from_the_document():
    spec = parse(SPEC)
    admin = next(op for op in spec.operations if op.operation_id == "adminListUsers")
    assert admin.privileged is True
    assert next(op for op in spec.operations if op.operation_id == "getInvoice").privileged is False


def test_a_swagger_2_document_is_read_too():
    document = {"swagger": "2.0", "host": "api.example.com", "basePath": "/v1",
                "schemes": ["https"], "securityDefinitions": {"key": {"type": "apiKey"}},
                "paths": {"/x": {"get": {"responses": {"200": {}}}}}}
    spec = parse(document)
    assert spec.servers == ("https://api.example.com/v1",)
    assert spec.schemes


def test_a_referenced_parameter_is_resolved():
    document = {
        "openapi": "3.0.0",
        "components": {"parameters": {"UserId": {"name": "userId", "in": "path",
                                                 "required": True, "schema": {"type": "string"}}}},
        "paths": {"/users/{userId}": {
            "get": {"parameters": [{"$ref": "#/components/parameters/UserId"}],
                    "responses": {"200": {}}}}},
    }
    operation = parse(document).operations[0]
    assert [p.name for p in operation.object_ids] == ["userId"]


def test_a_url_is_built_only_when_every_template_is_filled():
    operation = Operation(method="get", path="/invoices/{invoiceId}",
                          parameters=(Parameter("invoiceId", "path", True),))
    assert build_url("https://api.example.com/v1", operation, {"invoiceId": "42"}) == \
        "https://api.example.com/v1/invoices/42"
    # An unfilled template reaches a 404 handler at best and a wildcard route at worst.
    assert build_url("https://api.example.com/v1", operation, {}) == ""


def test_identifiers_are_escaped_into_the_path():
    operation = Operation(method="get", path="/files/{name}",
                          parameters=(Parameter("name", "path", True),))
    assert build_url("https://api.example.com", operation, {"name": "../../etc/passwd"}) == \
        "https://api.example.com/files/..%2F..%2Fetc%2Fpasswd"


# ── what a response means ─────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(("status", "body"), [
    (401, ""), (403, ""), (404, ""), (302, ""), (500, ""),
    (200, '{"error": "Unauthorized"}'),
    (200, '{"message": "Access denied"}'),
    (200, "<html>Please log in to continue</html>"),
])
def test_a_refusal_is_recognized_however_it_is_spelled(status, body):
    """A service that returns its error document with a 200 status is common enough that ignoring
    it makes the whole check useless."""
    assert checks.looks_like_denial(status, body) is True


@pytest.mark.parametrize("body", ["", "[]", "{}", "null", '{"data": null}', '{"items": []}'])
def test_an_empty_response_is_not_a_disclosure(body):
    """This is what a correctly-authorized API returns when the caller may see nothing."""
    assert checks.substantive(body) is False


def test_a_real_payload_is_substantive():
    assert checks.substantive('{"id": 42, "total": 1999, "customer": "acme"}') is True


# ── BOLA ──────────────────────────────────────────────────────────────────────────────────────────
OWNER_BODY = '{"id": "inv-2", "customer": "beta-corp", "total": 4200}'


def test_reading_another_principals_object_is_reported():
    verdict = checks.evaluate_bola(attacker_status=200, attacker_body=OWNER_BODY,
                                   owner_status=200, owner_body=OWNER_BODY)
    assert verdict.fired is True
    assert verdict.confidence == "high"
    assert verdict.evidence["matched_owner"] is True


def test_a_refusal_is_not_reported():
    for status in (401, 403, 404):
        assert checks.evaluate_bola(attacker_status=status, attacker_body="",
                                    owner_status=200, owner_body=OWNER_BODY).fired is False


def test_a_different_body_than_the_owner_receives_is_not_reported():
    """The endpoint answered, but not with the object — a filtered view, an empty result, or the
    caller's own record. None of those is a disclosure."""
    verdict = checks.evaluate_bola(
        attacker_status=200, attacker_body='{"id": "inv-1", "customer": "alpha-corp"}',
        owner_status=200, owner_body=OWNER_BODY)
    assert verdict.fired is False


def test_an_api_that_answers_the_same_for_a_nonexistent_id_is_not_reported():
    """Without the control request, an API that returns a generic object for every identifier looks
    like BOLA on every endpoint."""
    generic = '{"status": "ok", "data": {"placeholder": true}}'
    assert checks.evaluate_bola(attacker_status=200, attacker_body=generic,
                                control_status=200, control_body=generic).fired is False


def test_without_a_second_credential_the_finding_is_reported_with_lower_confidence():
    verdict = checks.evaluate_bola(attacker_status=200, attacker_body=OWNER_BODY)
    assert verdict.fired is True
    assert verdict.confidence == "medium"


# ── unauthenticated access ────────────────────────────────────────────────────────────────────────
def test_the_same_response_without_a_credential_is_reported():
    body = '{"invoices": [{"id": 1}]}'
    verdict = checks.evaluate_unauthenticated(status=200, body=body, authenticated_status=200,
                                              authenticated_body=body)
    assert verdict.fired is True
    assert verdict.confidence == "high"


def test_a_401_without_a_credential_is_the_correct_behaviour():
    assert checks.evaluate_unauthenticated(status=401, body='{"error": "unauthorized"}',
                                           authenticated_status=200,
                                           authenticated_body="{}").fired is False


# ── BFLA ──────────────────────────────────────────────────────────────────────────────────────────
def test_an_admin_endpoint_answering_a_normal_user_is_reported():
    body = '{"users": [{"id": 1, "role": "admin"}]}'
    verdict = checks.evaluate_bfla(status=200, body=body, privileged_status=200,
                                   privileged_body=body)
    assert verdict.fired is True
    assert verdict.confidence == "high"


def test_an_admin_endpoint_that_refuses_is_not():
    assert checks.evaluate_bfla(status=403, body="").fired is False


# ── excessive data exposure ───────────────────────────────────────────────────────────────────────
def test_sensitive_fields_in_a_response_are_reported_by_name_only():
    body = json.dumps({"id": 1, "email": "a@b.c", "password_hash": "$2b$12$abcdefg",
                       "profile": {"ssn": "123-45-6789"}})
    verdict = checks.evaluate_exposure(body)
    assert verdict.fired is True
    assert set(verdict.evidence["fields"]) == {"password_hash", "ssn"}
    # The finding is that the hash was in the payload; quoting it would put it in the report.
    assert "$2b$12$abcdefg" not in json.dumps(verdict.evidence)
    assert "123-45-6789" not in json.dumps(verdict.evidence)


def test_an_ordinary_payload_is_not_reported():
    assert checks.evaluate_exposure('{"id": 1, "name": "Acme", "total": 100}').fired is False


def test_a_null_sensitive_field_is_not_reported():
    """A serializer that includes the key with a null value has not disclosed anything."""
    assert checks.evaluate_exposure('{"id": 1, "password_hash": null}').fired is False


def test_a_non_json_response_is_not_scanned_for_fields():
    assert checks.evaluate_exposure("<html><body>password</body></html>").fired is False
