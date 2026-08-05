"""API engine — endpoint security review from an OpenAPI/Swagger spec.

Statically reviews the API contract for missing authentication, missing rate limiting, insecure
transport, and unvalidated input. The spec is provided (asset config `openapi_spec` or inline JSON);
optional safe active probing is a later add behind this engine. Active → needs authorization.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from guardian_core.enums import EngineKey, Severity
from guardian_core.evidence import Evidence, EvidenceKind
from guardian_core.findings import RawFinding

from guardian_scanner.engines.base import EngineHealth, ScanContext

_METHODS = {"get", "post", "put", "patch", "delete"}


class ApiEngine:
    key = EngineKey.API
    name = "Guardian API (OpenAPI security review)"
    version = "0.1.0"
    requires_authorization = True

    def supports(self, asset_kind: str) -> bool:
        return asset_kind == "api"

    def health(self) -> EngineHealth:
        return EngineHealth(ok=True, detail="OpenAPI static review")

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        spec = self._load(ctx)
        if not spec:
            return

        schemes = (spec.get("components", {}) or {}).get("securitySchemes", {})
        global_security = spec.get("security")
        if not schemes:
            yield self._f(
                "API defines no authentication scheme",
                Severity.HIGH,
                "CWE-306",
                "spec",
                "No securitySchemes declared in the OpenAPI document.",
            )

        for server in spec.get("servers", []) or []:
            if str(server.get("url", "")).startswith("http://"):
                yield self._f(
                    "API served over plaintext HTTP",
                    Severity.MEDIUM,
                    "CWE-319",
                    server.get("url", "server"),
                    "A server uses an http:// URL.",
                )

        documents_rate_limit = False
        for path, item in (spec.get("paths", {}) or {}).items():
            if not isinstance(item, dict):
                continue
            for method, op in item.items():
                if method.lower() not in _METHODS or not isinstance(op, dict):
                    continue
                loc = f"{method.upper()} {path}"
                op_security = op.get("security", global_security)
                if not op_security:
                    yield self._f(
                        f"Endpoint without authentication: {loc}",
                        Severity.HIGH,
                        "CWE-306",
                        loc,
                        "Operation has no security requirement.",
                    )
                if "429" in (op.get("responses", {}) or {}):
                    documents_rate_limit = True
                for param in op.get("parameters", []) or []:
                    if isinstance(param, dict) and "schema" not in param and "content" not in param:
                        yield self._f(
                            f"Input parameter without validation schema: {loc} "
                            f"({param.get('name')})",
                            Severity.LOW,
                            "CWE-20",
                            loc,
                            "Parameter declares no schema for validation.",
                        )

        if spec.get("paths") and not documents_rate_limit:
            yield self._f(
                "No rate limiting documented (no 429 responses)",
                Severity.MEDIUM,
                "CWE-770",
                "spec",
                "No operation documents a 429 Too Many Requests.",
            )

    def _load(self, ctx: ScanContext) -> dict | None:
        spec = ctx.asset_config.get("openapi_spec")
        if spec:
            return spec
        if ctx.inline_content:
            try:
                return json.loads(ctx.inline_content)
            except ValueError:
                return None
        return None

    def _f(self, title, sev, cwe, loc, detail) -> RawFinding:  # noqa: ANN001
        return RawFinding(
            engine=EngineKey.API,
            title=title,
            category="api-misconfig",
            description=detail,
            base_severity=sev,
            confidence="medium",
            cwe_id=cwe,
            owasp_ref="API-security",
            location={"endpoint": loc},
            evidence=Evidence(
                kind=EvidenceKind.CONFIG, summary=loc, detail={"finding": detail}
            ).to_dict(),
            references={"owasp_api": "https://owasp.org/API-Security/"},
        )
