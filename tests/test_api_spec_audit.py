"""Deep static OpenAPI analysis — the contract read closely, no network.

These are the checks the first-order review does not make: the quality of the security schemes
themselves, whether they are actually applied, sensitive fields the response schema promises to
return, and unbounded collections. All pure: a document in, findings out.
"""

from __future__ import annotations

from guardian_core.enums import EngineKey, Severity
from guardian_scanner.apisec.spec import parse
from guardian_scanner.apisec.spec_audit import audit_spec


def _audit(doc: dict):
    return audit_spec(doc, parse(doc))


def _titles(findings):
    return " | ".join(f.title for f in findings)


def _one(findings, needle):
    return next(f for f in findings if needle in f.title)


_BASE = {"openapi": "3.0.0", "info": {"title": "t"}, "servers": [{"url": "https://api.acme.com"}]}


def test_api_key_in_query_is_flagged():
    doc = {**_BASE, "components": {"securitySchemes": {
        "K": {"type": "apiKey", "in": "query", "name": "api_key"}}},
        "paths": {"/x": {"get": {"security": [{"K": []}], "responses": {"200": {}}}}}}
    f = _one(_audit(doc), "API key passed in the URL")
    assert f.base_severity == Severity.MEDIUM and f.cwe_id == "CWE-598"
    assert f.engine == EngineKey.API


def test_basic_auth_is_flagged():
    doc = {**_BASE, "components": {"securitySchemes": {
        "B": {"type": "http", "scheme": "basic"}}},
        "paths": {"/x": {"get": {"security": [{"B": []}], "responses": {"200": {}}}}}}
    assert any("Basic authentication" in x.title for x in _audit(doc))


def test_oauth_implicit_flow_is_flagged():
    doc = {**_BASE, "components": {"securitySchemes": {
        "O": {"type": "oauth2", "flows": {"implicit": {"authorizationUrl": "https://a/x"}}}}},
        "paths": {"/x": {"get": {"security": [{"O": []}], "responses": {"200": {}}}}}}
    assert any("implicit flow" in x.title for x in _audit(doc))


def test_oauth_cleartext_endpoint_is_high():
    doc = {**_BASE, "components": {"securitySchemes": {
        "O": {"type": "oauth2", "flows": {"authorizationCode": {
            "authorizationUrl": "http://a/x", "tokenUrl": "http://a/t"}}}}},
        "paths": {"/x": {"get": {"security": [{"O": []}], "responses": {"200": {}}}}}}
    f = _one(_audit(doc), "OAuth endpoint over cleartext")
    assert f.base_severity == Severity.HIGH and f.cwe_id == "CWE-319"


def test_all_schemes_unreferenced_is_high():
    doc = {**_BASE, "components": {"securitySchemes": {"A": {"type": "http", "scheme": "bearer"}}},
           "paths": {"/x": {"get": {"responses": {"200": {}}}}}}  # no op references A, no global
    f = _one(_audit(doc), "Declared security schemes are never applied")
    assert f.base_severity == Severity.HIGH and f.cwe_id == "CWE-1220"


def test_partially_unreferenced_scheme_is_low():
    doc = {**_BASE, "components": {"securitySchemes": {
        "Used": {"type": "http", "scheme": "bearer"},
        "Unused": {"type": "http", "scheme": "bearer"}}},
        "paths": {"/x": {"get": {"security": [{"Used": []}], "responses": {"200": {}}}}}}
    f = _one(_audit(doc), "Unused security scheme")
    assert f.base_severity == Severity.LOW and "Unused" in f.title


def test_opt_out_of_global_security_is_high():
    doc = {**_BASE, "security": [{"G": []}],
           "components": {"securitySchemes": {"G": {"type": "http", "scheme": "bearer"}}},
           "paths": {"/public": {"get": {"security": [], "responses": {"200": {}}}}}}
    f = _one(_audit(doc), "opts out of global authentication")
    assert f.base_severity == Severity.HIGH and f.cwe_id == "CWE-306"


def test_secured_op_without_401_403_is_flagged():
    doc = {**_BASE, "components": {"securitySchemes": {"G": {"type": "http", "scheme": "bearer"}}},
           "paths": {"/x": {"get": {"security": [{"G": []}], "responses": {"200": {}}}}}}
    assert any("documents no 401/403" in x.title for x in _audit(doc))


def test_sensitive_field_in_response_is_flagged_by_name_only():
    doc = {**_BASE,
           "components": {"schemas": {"U": {"type": "object", "properties": {
               "id": {"type": "string"}, "password": {"type": "string"}}}}},
           "paths": {"/u": {"get": {"responses": {"200": {"content": {"application/json": {
               "schema": {"$ref": "#/components/schemas/U"}}}}}}}}}
    f = _one(_audit(doc), "sensitive field 'password'")
    assert f.base_severity == Severity.MEDIUM and f.cwe_id == "CWE-213"


def test_sensitive_field_through_array_items_and_ref():
    doc = {**_BASE,
           "components": {"schemas": {"U": {"type": "object", "properties": {
               "token": {"type": "string"}}}}},
           "paths": {"/u": {"get": {"responses": {"200": {"content": {"application/json": {
               "schema": {"type": "array", "items": {"$ref": "#/components/schemas/U"}}}}}}}}}}
    assert any("sensitive field 'token'" in x.title for x in _audit(doc))


def test_ordinary_response_schema_is_not_flagged():
    doc = {**_BASE, "paths": {"/u": {"get": {"responses": {"200": {"content": {
        "application/json": {"schema": {"type": "object", "properties": {
            "id": {"type": "string"}, "email": {"type": "string"}}}}}}}}}}}
    assert not any("sensitive field" in x.title for x in _audit(doc))


def test_collection_without_pagination_is_flagged():
    doc = {**_BASE, "paths": {"/users": {"get": {"responses": {"200": {}}}}}}
    assert any("without pagination controls" in x.title for x in _audit(doc))


def test_collection_with_limit_is_not_flagged():
    doc = {**_BASE, "paths": {"/users": {"get": {
        "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer"}}],
        "responses": {"200": {}}}}}}
    assert not any("without pagination" in x.title for x in _audit(doc))


def test_cyclic_schema_ref_terminates():
    doc = {**_BASE,
           "components": {"schemas": {"Node": {"type": "object", "properties": {
               "child": {"$ref": "#/components/schemas/Node"}, "secret": {"type": "string"}}}}},
           "paths": {"/n": {"get": {"responses": {"200": {"content": {"application/json": {
               "schema": {"$ref": "#/components/schemas/Node"}}}}}}}}}
    # Must not infinite-loop, and must still find the sensitive field.
    assert any("sensitive field 'secret'" in x.title for x in _audit(doc))


def test_placeholder_server_url_is_info():
    doc = {**_BASE, "servers": [{"url": "https://your-api.example.com"}],
           "paths": {"/x": {"get": {"responses": {"200": {}}}}}}
    f = _one(_audit(doc), "placeholder or template")
    assert f.base_severity == Severity.INFO


def test_a_clean_contract_produces_no_audit_findings():
    doc = {"openapi": "3.0.0", "info": {"title": "t"},
           "servers": [{"url": "https://api.acme.com"}],
           "components": {"securitySchemes": {"Bearer": {"type": "http", "scheme": "bearer"}}},
           "security": [{"Bearer": []}],
           "paths": {"/orders/{id}": {"get": {
               "parameters": [{"name": "id", "in": "path", "required": True,
                               "schema": {"type": "string"}}],
               "responses": {"200": {}, "401": {}, "403": {}}}}}}
    assert _audit(doc) == [], _titles(_audit(doc))
