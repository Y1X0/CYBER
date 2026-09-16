"""Spec-vs-reality probing — undocumented endpoints and authentication that the document promised.

Two safe, GET-only checks the static review cannot make because they compare the contract to the
running service:

  * **Undocumented / shadow endpoints.** A small, curated wordlist of endpoints that commonly exist
    but are absent from the spec (framework actuators, metrics, admin/debug surfaces, exposed API
    documentation). One reachable that the document never declared is "improper inventory
    management" (OWASP API9) — the endpoints an attacker finds and the defender forgot.
  * **Authentication the spec promised but the service does not enforce.** For an operation the
    document marks as secured, an *unauthenticated* GET that returns 2xx means the credential the
    contract requires is not actually checked (OWASP API2 / CWE-306). This needs no principals — it
    is the absence of auth, not another user's data — so it complements the principal-gated BOLA/
    BFLA tester rather than duplicating it.

Strict safety model, identical to the rest of the API engine: **GET only**, never a state-changing
method; a fixed request budget, a per-request rate limit and an overall deadline; bounded, non
-destructive, and it only requests paths the caller is authorized to assess. Nothing here guesses
identifiers or enumerates data.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from guardian_core.enums import EngineKey, Severity
from guardian_core.evidence import Evidence, EvidenceKind
from guardian_core.findings import RawFinding

from guardian_scanner.apisec.spec import Spec, build_url

# Curated, safe wordlist. Each is (path, kind, severity-if-reachable). No parameters, no bodies,
# nothing destructive — GET only. `sensitive` endpoints, if live and undeclared, matter more.
_WORDLIST: tuple[tuple[str, str, Severity], ...] = (
    ("openapi.json", "docs", Severity.LOW),
    ("swagger.json", "docs", Severity.LOW),
    ("v2/api-docs", "docs", Severity.LOW),
    ("api-docs", "docs", Severity.LOW),
    ("swagger-ui.html", "docs", Severity.LOW),
    ("swagger-ui/", "docs", Severity.LOW),
    ("redoc", "docs", Severity.LOW),
    (".well-known/openapi.json", "docs", Severity.LOW),
    ("actuator", "sensitive", Severity.MEDIUM),
    ("actuator/health", "ops", Severity.LOW),
    ("actuator/env", "sensitive", Severity.MEDIUM),
    ("actuator/mappings", "sensitive", Severity.MEDIUM),
    ("actuator/heapdump", "sensitive", Severity.MEDIUM),
    ("metrics", "ops", Severity.LOW),
    ("health", "ops", Severity.LOW),
    ("healthz", "ops", Severity.LOW),
    ("status", "ops", Severity.LOW),
    ("debug", "sensitive", Severity.MEDIUM),
    ("admin", "sensitive", Severity.MEDIUM),
    ("internal", "sensitive", Severity.MEDIUM),
    ("console", "sensitive", Severity.MEDIUM),
    ("graphql", "ops", Severity.LOW),
    ("graphiql", "sensitive", Severity.MEDIUM),
)

# Statuses that mean "this route exists" (as opposed to a clean 404/connection failure).
_EXISTS = {200, 201, 202, 203, 204, 206, 301, 302, 303, 307, 308, 401, 403, 405, 500, 503}
_PROTECTED = {401, 403}


@dataclass
class _Budget:
    max_requests: int
    rate_per_second: float
    deadline_seconds: float
    _made: int = 0
    _start: float = 0.0

    def start(self) -> None:
        self._start = time.monotonic()

    def spend(self) -> bool:
        """True while another request is allowed; enforces count, rate and deadline."""
        if self._made >= self.max_requests:
            return False
        if time.monotonic() - self._start > self.deadline_seconds:
            return False
        if self._made and self.rate_per_second > 0:
            time.sleep(1.0 / self.rate_per_second)
        self._made += 1
        return True


def probe_surface(
    base_url: str,
    spec: Spec,
    fetch: Callable[[str, dict], object],
    *,
    max_requests: int = 40,
    rate_per_second: float = 8.0,
    deadline_seconds: float = 60.0,
) -> list[RawFinding]:
    """Safe GET-only probing for undocumented endpoints and unenforced authentication."""
    if not base_url.startswith(("http://", "https://")):
        return []
    budget = _Budget(max_requests=max_requests, rate_per_second=rate_per_second,
                     deadline_seconds=deadline_seconds)
    budget.start()
    out: list[RawFinding] = []
    out.extend(_undocumented(base_url, spec, fetch, budget))
    out.extend(_unenforced_auth(base_url, spec, fetch, budget))
    return out


def _documented_paths(spec: Spec) -> set[str]:
    return {op.path.strip("/").lower() for op in spec.operations}


def _undocumented(base_url: str, spec: Spec, fetch, budget: _Budget) -> list[RawFinding]:  # noqa: ANN001
    documented = _documented_paths(spec)
    root = base_url.rstrip("/")
    out: list[RawFinding] = []
    for path, kind, sev in _WORDLIST:
        if path.strip("/").lower() in documented:
            continue  # the document declares it — not a shadow endpoint
        if not budget.spend():
            break
        resp = fetch(f"{root}/{path}", {})
        status = int(getattr(resp, "status", 0) or 0)
        if getattr(resp, "error", None) or status not in _EXISTS:
            continue
        protected = status in _PROTECTED
        if kind == "docs":
            title = f"API documentation exposed: /{path}"
            desc = (f"/{path} is reachable (HTTP {status}) and is not part of the reviewed "
                    "contract. Exposed API documentation hands an attacker the full endpoint "
                    "inventory. Restrict it to trusted networks or authenticated users.")
        else:
            title = f"Undocumented endpoint reachable: /{path}"
            desc = (f"/{path} responds (HTTP {status}) but appears in no part of the OpenAPI "
                    "contract — an unmanaged endpoint (improper inventory). "
                    + ("It is protected (auth required), but should still be documented or "
                       "removed." if protected else "Confirm it is intended to be exposed; "
                       "framework actuator/debug/admin surfaces should not be reachable in "
                       "production."))
        out.append(_f(title, sev if not protected else Severity.LOW, "CWE-1059", "API9:2023",
                      f"/{path}", desc, status))
    return out


def _unenforced_auth(base_url: str, spec: Spec, fetch, budget: _Budget) -> list[RawFinding]:  # noqa: ANN001
    """A secured GET that answers 2xx to an unauthenticated request is not actually secured."""
    out: list[RawFinding] = []
    probed = 0
    for op in spec.operations:
        if op.method != "get" or not op.security:
            continue
        if probed >= 15:
            break
        values = {p.name: p.example for p in op.parameters if p.where == "path" and p.example}
        url = build_url(base_url, op, values)
        if not url:
            continue  # cannot build a concrete URL without inventing an identifier — skip safely
        if not budget.spend():
            break
        probed += 1
        resp = fetch(url, {})  # deliberately NO credentials
        status = int(getattr(resp, "status", 0) or 0)
        if getattr(resp, "error", None):
            continue
        if 200 <= status < 300:
            out.append(_f(
                f"Documented as authenticated but reachable without credentials: {op.label}",
                Severity.HIGH, "CWE-306", "API2:2023", op.label,
                f"The contract requires authentication for {op.label}, but an unauthenticated "
                f"request returned HTTP {status}. The credential the document promises is not "
                "enforced. Apply the authentication middleware to this route and verify from an "
                "unauthenticated client.", status))
    return out


def _f(title: str, severity: Severity, cwe: str, owasp: str, loc: str, detail: str,
       status: int) -> RawFinding:
    category = ("api-authorization" if cwe == "CWE-306" else "api-inventory")
    return RawFinding(
        engine=EngineKey.API,
        title=title[:300],
        category=category,
        description=detail,
        base_severity=severity,
        confidence="high" if cwe == "CWE-306" else "medium",
        cwe_id=cwe,
        owasp_ref=owasp,
        location={"endpoint": loc, "rule": "api-surface-probe", "status": status},
        evidence=Evidence(
            kind=EvidenceKind.HTTP_EXCHANGE,
            summary=f"{loc} → HTTP {status}",
            detail={"status": status, "rule": "api-surface-probe"},
        ).to_dict(),
        references={"owasp_api": "https://owasp.org/API-Security/"},
    )


__all__ = ["probe_surface"]
