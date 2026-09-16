"""Deep static analysis of an OpenAPI document — the contract, read closely (no network).

The API engine already does the first-order contract review (no auth scheme, plaintext server, an
operation with no security requirement, no documented rate limit). This is the *deep* pass: it reads
the security schemes themselves, cross-checks which are actually used, and walks the response
schemas for fields no client should receive. It is pure and offline — a document in, findings out —
and adds
to the engine's existing static review rather than replacing it.

Nothing here probes a live service; every finding is derived from the document. The active
spec-vs-behavior and undocumented-endpoint checks live in `discovery.py`.
"""

from __future__ import annotations

from guardian_core.enums import EngineKey, Severity
from guardian_core.evidence import Evidence, EvidenceKind
from guardian_core.findings import RawFinding

from guardian_scanner.apisec.spec import Spec

# Field names in a response schema that a client should almost never receive — the spec-level shape
# of "excessive data exposure" (OWASP API3): the document itself says the API returns them.
_SENSITIVE_FIELDS = {
    "password", "passwd", "pwd", "secret", "client_secret", "token", "access_token",
    "refresh_token", "id_token", "api_key", "apikey", "private_key", "privatekey", "secret_key",
    "ssn", "social_security", "socialsecuritynumber", "credit_card", "card_number", "cardnumber",
    "cvv", "cvc", "pin", "session_id", "sessionid", "password_hash", "salt", "otp_secret",
}
# Collection-style path leaves that should carry pagination/limit controls.
_COLLECTION_LIMIT_PARAMS = {"limit", "per_page", "perpage", "page_size", "pagesize", "count",
                           "top", "first", "max", "size"}


def audit_spec(document: dict, spec: Spec) -> list[RawFinding]:
    """Deep static findings for an OpenAPI/Swagger document. Bounded and side-effect free."""
    out: list[RawFinding] = []
    out.extend(_scheme_findings(spec))
    out.extend(_unreferenced_schemes(spec))
    out.extend(_operation_findings(document, spec))
    out.extend(_exposure_findings(document, spec))
    out.extend(_server_findings(spec))
    return out


# ── security scheme quality ─────────────────────────────────────────────────────────────────────
def _scheme_findings(spec: Spec) -> list[RawFinding]:
    out: list[RawFinding] = []
    for name, scheme in (spec.schemes or {}).items():
        if not isinstance(scheme, dict):
            continue
        stype = str(scheme.get("type") or "").lower()
        if stype == "apikey" and str(scheme.get("in") or "").lower() == "query":
            out.append(_f(
                f"API key passed in the URL query string: scheme '{name}'", Severity.MEDIUM,
                "CWE-598", "API8:2023", f"scheme:{name}",
                "The security scheme sends the API key as a query parameter. Query strings are "
                "logged by servers, proxies and browser history, so the key leaks into places it "
                "should never be. Send the key in a header (or Authorization) instead."))
        if stype in ("http", "basic") and str(scheme.get("scheme") or stype).lower() == "basic":
            out.append(_f(
                f"HTTP Basic authentication: scheme '{name}'", Severity.LOW, "CWE-522",
                "API2:2023", f"scheme:{name}",
                "Basic auth sends a reversible base64 credential on every request. Prefer bearer "
                "tokens with a short lifetime; if Basic is required, ensure TLS everywhere and "
                "rotate credentials."))
        flows = scheme.get("flows") if isinstance(scheme.get("flows"), dict) else {}
        if stype == "oauth2" and "implicit" in flows:
            out.append(_f(
                f"OAuth2 implicit flow declared: scheme '{name}'", Severity.MEDIUM, "CWE-522",
                "API2:2023", f"scheme:{name}",
                "The implicit flow returns the access token in the URL fragment and is deprecated "
                "by OAuth 2.1. Use the authorization-code flow with PKCE."))
        # OAuth/OIDC endpoints served over cleartext.
        for flow in (flows.values() if isinstance(flows, dict) else []):
            if not isinstance(flow, dict):
                continue
            for key in ("authorizationUrl", "tokenUrl", "refreshUrl"):
                url = str(flow.get(key) or "")
                if url.startswith("http://"):
                    out.append(_f(
                        f"OAuth endpoint over cleartext HTTP: {key} in '{name}'", Severity.HIGH,
                        "CWE-319", "API2:2023", f"scheme:{name}",
                        f"The {key} ({url}) uses http://. Tokens and codes would traverse the "
                        "network unencrypted. Use https://."))
        if stype == "openidconnect":
            url = str(scheme.get("openIdConnectUrl") or "")
            if url.startswith("http://"):
                out.append(_f(
                    f"OIDC discovery over cleartext HTTP: scheme '{name}'", Severity.HIGH,
                    "CWE-319", "API2:2023", f"scheme:{name}",
                    f"The OpenID Connect discovery URL ({url}) uses http://. Use https://."))
    return out


def _unreferenced_schemes(spec: Spec) -> list[RawFinding]:
    """Security schemes defined but referenced by no operation and no global requirement.

    A declared-but-unused scheme is a strong signal that authentication is documented but not
    actually applied — the schemes exist for show while operations run open.
    """
    if not spec.schemes:
        return []
    used: set[str] = set(spec.global_security)
    for op in spec.operations:
        used.update(op.security)
    unreferenced = sorted(set(spec.schemes) - used)
    if unreferenced and len(unreferenced) == len(spec.schemes):
        # Every declared scheme is unused — the whole API's declared auth is not wired to anything.
        return [_f(
            "Declared security schemes are never applied", Severity.HIGH, "CWE-1220", "API2:2023",
            "spec", "The document declares security scheme(s) "
            f"({', '.join(unreferenced)}) but no operation and no global `security` requirement "
            "references any of them. Authentication is documented but not enforced by the "
            "contract. Add a global `security` requirement or per-operation `security`.")]
    if unreferenced:
        return [_f(
            f"Unused security scheme(s): {', '.join(unreferenced)}", Severity.LOW, "CWE-1220",
            "API2:2023", "spec",
            "These security schemes are declared but referenced by no operation. Remove them or "
            "apply them, so the contract reflects what is enforced.")]
    return []


# ── per-operation deep checks ───────────────────────────────────────────────────────────────────
def _operation_findings(document: dict, spec: Spec) -> list[RawFinding]:
    out: list[RawFinding] = []
    raw_paths = document.get("paths") or {}
    for op in spec.operations:
        # An operation that explicitly opts OUT of a global security requirement (`security: []`).
        raw_op = _raw_operation(raw_paths, op.path, op.method)
        if (op.security_declared and not op.security and spec.global_security
                and isinstance(raw_op, dict) and isinstance(raw_op.get("security"), list)
                and len(raw_op.get("security")) == 0):
            out.append(_f(
                f"Operation opts out of global authentication: {op.label}", Severity.HIGH,
                "CWE-306", "API2:2023", op.label,
                "The API declares a global security requirement, but this operation overrides it "
                "with an empty `security: []`, making it public. Confirm this endpoint is meant to "
                "be unauthenticated; if not, remove the override."))
        # A secured operation that documents no 401/403 response — the contract is inconsistent
        # about its own auth, and clients cannot handle the rejection they should expect.
        if op.security and op.responses and not ({"401", "403"} & set(op.responses)):
            out.append(_f(
                f"Secured operation documents no 401/403 response: {op.label}", Severity.LOW,
                "CWE-703", "API2:2023", op.label,
                "The operation requires authentication but its documented responses include "
                "neither 401 nor 403. Document the unauthorized/forbidden responses so the "
                "contract matches enforcement."))
        # A collection GET with no pagination/limit control — unbounded result sets.
        if op.method == "get" and _looks_like_collection(op.path):
            names = {p.name.lower() for p in op.parameters}
            if not (names & _COLLECTION_LIMIT_PARAMS):
                out.append(_f(
                    f"Collection endpoint without pagination controls: {op.label}", Severity.LOW,
                    "CWE-770", "API4:2023", op.label,
                    "This collection endpoint declares no limit/page-size parameter, so a client "
                    "can request an unbounded result set. Add pagination with a bounded default "
                    "and maximum."))
    return out


# ── excessive data exposure (response schemas) ──────────────────────────────────────────────────
def _exposure_findings(document: dict, spec: Spec) -> list[RawFinding]:
    components = document.get("components") or {}
    raw_paths = document.get("paths") or {}
    seen: set[tuple[str, str]] = set()
    out: list[RawFinding] = []
    for op in spec.operations:
        raw_op = _raw_operation(raw_paths, op.path, op.method)
        if not isinstance(raw_op, dict):
            continue
        for status, resp in (raw_op.get("responses") or {}).items():
            if not str(status).startswith("2") or not isinstance(resp, dict):
                continue
            schema = _response_schema(resp, document)
            fields = _sensitive_fields_in(schema, components, depth=0, visited=set())
            for field in sorted(fields):
                key = (op.label, field)
                if key in seen:
                    continue
                seen.add(key)
                out.append(_f(
                    f"Response may expose sensitive field '{field}': {op.label}", Severity.MEDIUM,
                    "CWE-213", "API3:2023", op.label,
                    f"The documented {status} response schema for {op.label} includes a field "
                    f"named '{field}', which clients should not receive. Serialize responses from "
                    "an explicit allowlist and never return credential/PII fields."))
    return out


def _server_findings(spec: Spec) -> list[RawFinding]:
    out: list[RawFinding] = []
    for server in spec.servers:
        low = server.lower()
        if "{" in server or "example.com" in low or "localhost" in low or "your-" in low:
            out.append(_f(
                f"Server URL is a placeholder or template: {server}", Severity.INFO, "CWE-1059",
                "API8:2023", server,
                "The documented server URL contains an unresolved template variable or an example "
                "host. Ensure the published contract points at the real base URL."))
    return out


# ── schema walking ──────────────────────────────────────────────────────────────────────────────
def _response_schema(resp: dict, document: dict) -> dict:
    content = resp.get("content")
    if isinstance(content, dict):
        for media in content.values():
            if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                return media["schema"]
    if isinstance(resp.get("schema"), dict):   # Swagger 2
        return resp["schema"]
    return {}


def _sensitive_fields_in(schema: dict, components: dict, *, depth: int,
                         visited: set[str]) -> set[str]:
    """Property names in a response schema that match the sensitive set. Bounded and cycle-safe."""
    if depth > 8 or not isinstance(schema, dict):
        return set()
    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref in visited:
            return set()
        visited = visited | {ref}
        resolved = _resolve_ref(ref, components)
        return _sensitive_fields_in(resolved, components, depth=depth + 1, visited=visited)
    found: set[str] = set()
    props = schema.get("properties")
    if isinstance(props, dict):
        for pname, pschema in props.items():
            if str(pname).lower() in _SENSITIVE_FIELDS:
                found.add(str(pname))
            if isinstance(pschema, dict):
                found |= _sensitive_fields_in(pschema, components, depth=depth + 1, visited=visited)
    for key in ("items", "additionalProperties"):
        if isinstance(schema.get(key), dict):
            found |= _sensitive_fields_in(schema[key], components, depth=depth + 1, visited=visited)
    for key in ("allOf", "oneOf", "anyOf"):
        for sub in (schema.get(key) or []):
            if isinstance(sub, dict):
                found |= _sensitive_fields_in(sub, components, depth=depth + 1, visited=visited)
    return found


def _resolve_ref(ref: str, components: dict) -> dict:
    if not ref.startswith("#/"):
        return {}
    node: object = {"components": components}
    for part in ref[2:].split("/"):
        if not isinstance(node, dict):
            return {}
        node = node.get(part)
    return node if isinstance(node, dict) else {}


def _raw_operation(raw_paths: dict, path: str, method: str) -> dict | None:
    item = raw_paths.get(path)
    if not isinstance(item, dict):
        return None
    op = item.get(method) or item.get(method.lower())
    return op if isinstance(op, dict) else None


def _looks_like_collection(path: str) -> bool:
    """A GET whose last path segment is a plain (non-templated) noun — e.g. /users, /v1/orders."""
    segs = [s for s in path.split("/") if s]
    if not segs:
        return False
    last = segs[-1]
    return "{" not in last and not last.startswith("{") and last.isalpha() and last.endswith("s")


def _f(title: str, severity: Severity, cwe: str, owasp: str, loc: str, detail: str) -> RawFinding:
    return RawFinding(
        engine=EngineKey.API,
        title=title[:300],
        category="api-misconfig",
        description=detail,
        base_severity=severity,
        confidence="medium",
        cwe_id=cwe,
        owasp_ref=owasp,
        location={"endpoint": loc, "rule": "api-spec-audit"},
        evidence=Evidence(kind=EvidenceKind.CONFIG, summary=loc,
                          detail={"finding": detail}).to_dict(),
        references={"owasp_api": "https://owasp.org/API-Security/"},
    )


__all__ = ["audit_spec"]
