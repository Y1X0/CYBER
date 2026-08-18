"""API engine — contract review plus live authorization testing (WP-D10).

The static half reviews the OpenAPI document: no declared authentication scheme, a plaintext server
URL, an operation with no security requirement, no documented rate limiting. Worth saying, and it
is contract review rather than security testing.

The active half is the package. Broken object level authorization is the first item on the OWASP API
Security list and it cannot be seen in a document: `GET /invoices/{id}` looks the same whether the
handler checks ownership or not. Finding out means asking for somebody else's invoice with your own
credential, which needs two logins and the identifiers each of them owns — supplied through the
asset's secret config, never guessed, and never enumerated.

Runs only when principals are configured. When they are not, the engine says so as a finding rather
than reporting an API clean of a class it never tested.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from guardian_common.logging import get_logger
from guardian_core.enums import EngineKey, Severity
from guardian_core.evidence import Evidence, EvidenceKind
from guardian_core.findings import RawFinding

from guardian_scanner.apisec.scanner import ApiScanner, ApiScanResult, Issue, Principal
from guardian_scanner.apisec.spec import Spec, parse
from guardian_scanner.engines.base import EngineHealth, ScanContext

log = get_logger("guardian.apisec.engine")

MAX_BODY_BYTES = 200_000
REQUEST_TIMEOUT = 10.0

_METHODS = {"get", "post", "put", "patch", "delete"}

_CHECK_META = {
    "api-bola": (
        "Broken object level authorization", Severity.CRITICAL, "CWE-639", "API1:2023",
        "One principal's credential retrieved another principal's object. Every record of this "
        "type is readable by any authenticated user who can name its identifier.",
        "Authorize on the object, not just on the session: check that the authenticated principal "
        "owns or is entitled to the specific record before returning it.",
    ),
    "api-bfla": (
        "Broken function level authorization", Severity.HIGH, "CWE-285", "API5:2023",
        "An administrative operation answered an unprivileged credential.",
        "Check the caller's role in the handler. Route-level separation is not enforcement.",
    ),
    "api-missing-auth": (
        "Endpoint reachable without authentication", Severity.HIGH, "CWE-306", "API2:2023",
        "The specification requires a credential for this operation and the running service does "
        "not.",
        "Apply the authentication middleware to this route, and test it from an unauthenticated "
        "client.",
    ),
    "api-excessive-exposure": (
        "Excessive data exposure in the response", Severity.HIGH, "CWE-213", "API3:2023",
        "The response carries fields no client needs, which are exactly the fields an attacker "
        "wants.",
        "Serialize responses from an explicit allowlist of fields rather than dumping the model.",
    ),
}


class ApiEngine:
    key = EngineKey.API
    name = "Guardian API (contract review + authorization testing)"
    version = "0.2.0"
    requires_authorization = True
    wants_secrets = True  # consumes API credentials from the encrypted secret_ref

    def supports(self, asset_kind: str) -> bool:
        return asset_kind == "api"

    def health(self) -> EngineHealth:
        return EngineHealth(
            ok=True,
            detail="OpenAPI contract review; live BOLA/BFLA/authentication testing when "
                   "principals are configured (GET and HEAD only)",
        )

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        document = self._load(ctx)
        if not document:
            return []
        spec = parse(document)
        findings = list(self._static(document, spec))
        findings.extend(self._active(ctx, spec))
        return findings

    # ── contract review ──────────────────────────────────────────────────────────────────────────
    def _static(self, document: dict, spec: Spec) -> Iterable[RawFinding]:
        if not spec.schemes:
            yield self._f("API defines no authentication scheme", Severity.HIGH, "CWE-306",
                          "spec", "No securitySchemes declared in the OpenAPI document.")

        for server in spec.servers:
            if server.startswith("http://"):
                yield self._f("API served over plaintext HTTP", Severity.MEDIUM, "CWE-319",
                              server, "A server uses an http:// URL.")

        documents_rate_limit = False
        for operation in spec.operations:
            if operation.method not in _METHODS:
                continue
            if not operation.security:
                yield self._f(f"Endpoint without authentication: {operation.label}", Severity.HIGH,
                              "CWE-306", operation.label, "Operation has no security requirement.")
            if "429" in operation.responses:
                documents_rate_limit = True
            for parameter in operation.parameters:
                if not parameter.schema_type and parameter.where in ("query", "path"):
                    yield self._f(
                        f"Input parameter without validation schema: {operation.label} "
                        f"({parameter.name})", Severity.LOW, "CWE-20", operation.label,
                        "Parameter declares no schema for validation.")

        if spec.operations and not documents_rate_limit:
            yield self._f("No rate limiting documented (no 429 responses)", Severity.MEDIUM,
                          "CWE-770", "spec", "No operation documents a 429 Too Many Requests.")
        del document

    # ── live authorization testing ───────────────────────────────────────────────────────────────
    def _active(self, ctx: ScanContext, spec: Spec) -> Iterable[RawFinding]:
        principals = self._principals(ctx)
        base = ctx.asset_identifier if ctx.asset_identifier.startswith(("http://", "https://")) \
            else (spec.servers[0] if spec.servers else "")
        if not principals or not base:
            if spec.operations:
                yield self._not_tested(spec, base)
            return

        settings = ctx.settings or {}
        scanner = ApiScanner(
            fetch=self._transport(), spec=spec, principals=principals, base_url=base,
            max_requests=int(settings.get("api_max_requests", 300)),
            rate_per_second=float(settings.get("api_rate", 8.0)),
            deadline_seconds=float(settings.get("api_deadline", 120.0)),
        )
        result = scanner.scan()
        log.info("apisec_scan_complete", base=base, requests=result.requests_made,
                 operations=result.operations_tested, bola_pairs=result.bola_pairs_tested,
                 issues=len(result.issues))

        for issue in result.issues:
            yield self._issue_finding(issue)
        if result.degraded:
            yield self._coverage_finding(base, result)

    def _principals(self, ctx: ScanContext) -> list[Principal]:
        """Logins and owned identifiers, from the asset's decrypted secret config.

        They live in `secret_config` because they are credentials: in-memory for the run, never
        persisted, never logged, and never written into a finding.
        """
        raw = (ctx.secret_config or {}).get("api_principals") or []
        principals: list[Principal] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            principals.append(Principal(
                name=str(entry.get("name") or f"principal-{len(principals) + 1}"),
                headers={str(k): str(v) for k, v in (entry.get("headers") or {}).items()},
                object_ids={str(k): str(v) for k, v in (entry.get("object_ids") or {}).items()},
                privileged=bool(entry.get("privileged")),
            ))
        return principals

    def _transport(self):  # noqa: ANN202
        import httpx  # noqa: PLC0415

        from guardian_scanner.dast.scanner import Response  # noqa: PLC0415
        from guardian_scanner.engines.dast_engine import _pinned_egress  # noqa: PLC0415

        def fetch(url: str, headers: dict) -> Response:
            try:
                with _pinned_egress(), httpx.Client(
                    follow_redirects=False, timeout=REQUEST_TIMEOUT
                ) as client:
                    response = client.get(
                        url, headers={"user-agent": "guardian-api", **(headers or {})}
                    )
            except Exception as exc:  # noqa: BLE001 - reported, never an empty page
                return Response(status=0, headers={}, body="", url=url,
                                error=f"{type(exc).__name__}: {exc}")
            return Response(
                status=response.status_code,
                headers={k.lower(): v for k, v in response.headers.items()},
                body=response.text[:MAX_BODY_BYTES], url=str(response.url),
            )

        return fetch

    # ── findings ─────────────────────────────────────────────────────────────────────────────────
    def _issue_finding(self, issue: Issue) -> RawFinding:
        title, severity, cwe, owasp, description, remediation = _CHECK_META[issue.check_id]
        subject = f" via `{issue.parameter}`" if issue.parameter else ""
        return RawFinding(
            engine=EngineKey.API,
            title=f"{title}: {issue.operation}{subject}",
            category="api-authorization" if issue.check_id in ("api-bola", "api-bfla",
                                                               "api-missing-auth")
            else "api-misconfig",
            description=f"{description}\n\nProof: {issue.indicator}\n\n"
                        f"Remediation: {remediation}",
            base_severity=severity,
            confidence=issue.confidence,
            cwe_id=cwe,
            owasp_ref=owasp,
            location={"endpoint": issue.operation, "url": issue.url, "rule": issue.check_id,
                      "parameter": issue.parameter},
            evidence=Evidence(
                kind=EvidenceKind.HTTP_EXCHANGE,
                summary=f"{issue.operation} → HTTP {issue.status}"
                        + (f" as {issue.principal}" if issue.principal else ""),
                # Digests, field names, sizes and status codes. Never another principal's data:
                # the finding is that it was readable, and quoting it would republish it.
                detail={"principal": issue.principal, "parameter": issue.parameter,
                        "status": issue.status, **issue.evidence},
            ).to_dict(),
            references={"owasp_api": "https://owasp.org/API-Security/"},
        )

    def _not_tested(self, spec: Spec, base: str) -> RawFinding:
        """Say that authorization was not tested, rather than implying it passed."""
        return RawFinding(
            engine=EngineKey.API,
            title="API authorization was not tested",
            category="scan-coverage",
            description=(
                "Object- and function-level authorization are the top two entries on the OWASP API "
                "Security list, and neither is visible in a specification: the same document "
                "describes an endpoint that checks ownership and one that does not. Testing them "
                "requires two logins and the identifiers each one owns.\n\n"
                + ("No base URL is configured for this API." if not base else
                   "No API principals are configured for this asset.")
            ),
            base_severity=Severity.INFO,
            confidence="high",
            location={"endpoint": base or "spec", "rule": "api-authz-untested"},
            evidence=Evidence(
                kind=EvidenceKind.CONFIG,
                summary=f"{len(spec.operations)} operations reviewed statically; 0 tested live",
                detail={"operations": len(spec.operations),
                        "object_id_operations": sum(1 for o in spec.operations if o.object_ids)},
            ).to_dict(),
            references={"owasp_api": "https://owasp.org/API-Security/"},
        )

    def _coverage_finding(self, base: str, result: ApiScanResult) -> RawFinding:
        reasons = list(result.untested)
        if result.budget_exhausted:
            reasons.append(f"the request budget was spent after {result.requests_made} requests")
        if result.deadline_reached:
            reasons.append("the time limit was reached")
        reasons.extend(f"a request failed: {error}" for error in result.errors[:5])
        return RawFinding(
            engine=EngineKey.API,
            title="API authorization testing was incomplete",
            category="scan-coverage",
            description="Part of the API was not tested, so the absence of an authorization "
                        "finding is not evidence that there is none.\n\n" + "; ".join(reasons),
            base_severity=Severity.INFO,
            confidence="high",
            location={"endpoint": base, "rule": "api-coverage"},
            evidence=Evidence(
                kind=EvidenceKind.HTTP_EXCHANGE,
                summary=f"{result.requests_made} requests across {result.operations_tested} "
                        f"operations; {result.bola_pairs_tested} object-authorization pairs",
                detail={"requests": result.requests_made,
                        "operations_tested": result.operations_tested,
                        "bola_pairs_tested": result.bola_pairs_tested, "reasons": reasons},
            ).to_dict(),
            references={},
        )

    # ── input ────────────────────────────────────────────────────────────────────────────────────
    def _load(self, ctx: ScanContext) -> dict | None:
        spec = (ctx.asset_config or {}).get("openapi_spec")
        if spec:
            return spec if isinstance(spec, dict) else self._parse(str(spec))
        if ctx.inline_content:
            return self._parse(ctx.inline_content)
        return None

    def _parse(self, text: str) -> dict | None:
        try:
            parsed = json.loads(text)
        except ValueError:
            try:
                import yaml  # noqa: PLC0415

                parsed = yaml.safe_load(text)
            except Exception as exc:  # noqa: BLE001
                log.warning("openapi_unreadable", error=str(exc)[:200])
                return None
        return parsed if isinstance(parsed, dict) else None

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
