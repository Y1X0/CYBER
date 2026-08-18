"""Driving the authorization tests against a live API (WP-D10).

The scanner needs something no static tool needs: **principals**. A BOLA test is one principal's
credential against another principal's object, so the customer supplies at least two logins and,
for each, the identifiers of objects that belong to it. Without a second principal the scanner still
runs the unauthenticated and exposure checks and says plainly that it could not test BOLA — which is
better than silently reporting an API clean of a class it never looked for.

Safety follows WP-D2: GET and HEAD only, in-scope only, bounded by requests and wall clock. One rule
is specific to this package and matters more than the rest — **identifiers are never enumerated**.
The scanner asks for the objects the customer named and nothing else, because walking `id+1` through
a production API means reading real people's records, and reading them is the harm rather than the
proof of it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

from guardian_common.logging import get_logger

from guardian_scanner.apisec import checks
from guardian_scanner.apisec.spec import Operation, Spec, build_url
from guardian_scanner.dast.scanner import Budget, Response

log = get_logger("guardian.apisec")

DEFAULT_MAX_REQUESTS = 300
DEFAULT_RATE_PER_SECOND = 8.0
DEFAULT_DEADLINE_SECONDS = 120.0
NONEXISTENT_ID = "guardian-no-such-object-6f1c"


@dataclass
class Principal:
    """One login, and what it legitimately owns."""

    name: str
    headers: dict = field(default_factory=dict)
    # parameter name → identifier this principal owns, e.g. {"id": "42", "accountId": "acc-7"}
    object_ids: dict = field(default_factory=dict)
    privileged: bool = False

    def value_for(self, parameter_name: str) -> str | None:
        return self.object_ids.get(parameter_name)


@dataclass
class Issue:
    check_id: str
    operation: str
    url: str
    parameter: str
    indicator: str
    confidence: str
    status: int
    principal: str = ""
    evidence: dict = field(default_factory=dict)


@dataclass
class ApiScanResult:
    issues: list[Issue] = field(default_factory=list)
    requests_made: int = 0
    operations_tested: int = 0
    bola_pairs_tested: int = 0
    errors: list[str] = field(default_factory=list)
    # Set when the inputs could not support a class of test. Reported, never left implicit.
    untested: list[str] = field(default_factory=list)
    budget_exhausted: bool = False
    deadline_reached: bool = False

    @property
    def degraded(self) -> bool:
        return bool(self.errors or self.untested or self.budget_exhausted or self.deadline_reached)


class ApiScanner:
    def __init__(
        self, *, fetch, spec: Spec, principals: list[Principal],  # noqa: ANN001
        base_url: str = "", max_requests: int = DEFAULT_MAX_REQUESTS,
        rate_per_second: float = DEFAULT_RATE_PER_SECOND,
        deadline_seconds: float = DEFAULT_DEADLINE_SECONDS,
        clock=time.monotonic, sleep=time.sleep,  # noqa: ANN001
    ) -> None:
        self._fetch = fetch
        self._spec = spec
        self._principals = principals
        self._base = (base_url or (spec.servers[0] if spec.servers else "")).rstrip("/")
        host = (urlparse(self._base).hostname or "").lower()
        self._hosts = frozenset({host}) if host else frozenset()
        self._budget = Budget(max_requests=max_requests, rate_per_second=rate_per_second,
                              deadline_seconds=deadline_seconds, clock=clock, sleep=sleep)
        self.result = ApiScanResult()

    # ── transport ────────────────────────────────────────────────────────────────────────────────
    def _request(self, url: str, headers: dict | None = None) -> Response | None:
        if not url:
            return None
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in ("http", "https") or not self._hosts or (
            host not in self._hosts and not host.endswith("." + next(iter(self._hosts)))
        ):
            self.result.errors.append(f"refused out-of-scope request: {url[:200]}")
            log.warning("apisec_out_of_scope_refused", url=url[:200])
            return None
        if not self._budget.take():
            self.result.budget_exhausted = self._budget.exhausted
            self.result.deadline_reached = self._budget.expired
            return None
        try:
            response = self._fetch(url, headers or {})
        except Exception as exc:  # noqa: BLE001 - one failure must not end the scan
            self.result.errors.append(f"{url[:120]}: {type(exc).__name__}: {exc}")
            return None
        if response is None or response.error:
            self.result.errors.append(
                f"{url[:120]}: {response.error if response else 'no response'}")
            return None
        self.result.requests_made += 1
        return response

    # ── the scan ─────────────────────────────────────────────────────────────────────────────────
    def scan(self) -> ApiScanResult:
        if not self._base:
            self.result.errors.append("the specification declares no server URL and none was given")
            return self.result
        if len(self._principals) < 2:
            self.result.untested.append(
                "object-level authorization was not tested: it needs two principals and the "
                "identifiers each of them owns, and fewer than two were supplied"
            )

        testable = [op for op in self._spec.operations if op.method in ("get", "head")]
        for operation in testable:
            self._test_operation(operation)
            if self._budget.exhausted or self._budget.expired:
                self.result.budget_exhausted = self._budget.exhausted
                self.result.deadline_reached = self._budget.expired
                break

        skipped = len(self._spec.operations) - len(testable)
        if skipped:
            self.result.untested.append(
                f"{skipped} operation(s) use a state-changing method and were not requested"
            )
        return self.result

    def _test_operation(self, operation: Operation) -> None:
        primary = self._principals[0] if self._principals else Principal("anonymous")
        values = self._values(operation, primary)
        url = build_url(self._base, operation, values)
        if not url:
            # A path template with no supplied identifier. Requesting `/users/{id}` literally tests
            # a 404 handler.
            return

        self.result.operations_tested += 1
        authenticated = self._request(url, primary.headers)
        if authenticated is None:
            return

        self._check_unauthenticated(operation, url, authenticated)
        self._check_exposure(operation, url, authenticated, primary)
        self._check_bola(operation)
        self._check_bfla(operation)

    def _values(self, operation: Operation, principal: Principal) -> dict[str, str]:
        values: dict[str, str] = {}
        for parameter in operation.parameters:
            if parameter.where not in ("path", "query"):
                continue
            supplied = principal.value_for(parameter.name)
            if supplied is not None:
                values[parameter.name] = str(supplied)
            elif parameter.example:
                values[parameter.name] = parameter.example
            elif parameter.where == "query" and not parameter.required:
                continue
        return values

    def _record(self, check_id: str, operation: Operation, url: str, parameter: str,
                verdict: checks.Verdict, status: int, principal: str = "") -> None:
        self.result.issues.append(Issue(
            check_id=check_id, operation=operation.label, url=url, parameter=parameter,
            indicator=verdict.indicator, confidence=verdict.confidence, status=status,
            principal=principal, evidence=verdict.evidence or {},
        ))

    # ── checks ───────────────────────────────────────────────────────────────────────────────────
    def _check_unauthenticated(self, operation: Operation, url: str,
                               authenticated: Response) -> None:
        if not operation.security and not operation.security_declared:
            # The document never claimed this endpoint was protected. Whether it should be is a
            # design question, and the static review already raises it.
            return
        anonymous = self._request(url, {})
        if anonymous is None:
            return
        verdict = checks.evaluate_unauthenticated(
            status=anonymous.status, body=anonymous.body,
            authenticated_status=authenticated.status, authenticated_body=authenticated.body,
        )
        if verdict.fired:
            self._record("api-missing-auth", operation, url, "", verdict, anonymous.status)

    def _check_exposure(self, operation: Operation, url: str, response: Response,
                        principal: Principal) -> None:
        verdict = checks.evaluate_exposure(response.body)
        if verdict.fired:
            self._record("api-excessive-exposure", operation, url, "", verdict, response.status,
                         principal.name)

    def _check_bola(self, operation: Operation) -> None:
        if len(self._principals) < 2:
            return
        attacker, owner = self._principals[0], self._principals[1]

        for parameter in operation.object_ids:
            owned = owner.value_for(parameter.name)
            if owned is None:
                continue

            values = self._values(operation, attacker)
            values[parameter.name] = str(owned)
            url = build_url(self._base, operation, values)
            if not url:
                continue

            self.result.bola_pairs_tested += 1
            attacker_response = self._request(url, attacker.headers)
            if attacker_response is None:
                continue
            if checks.looks_like_denial(attacker_response.status, attacker_response.body):
                continue  # refused, as it should be — no further requests needed

            owner_response = self._request(url, owner.headers)
            control_values = dict(values)
            control_values[parameter.name] = NONEXISTENT_ID
            control_url = build_url(self._base, operation, control_values)
            control_response = self._request(control_url, attacker.headers) if control_url else None

            verdict = checks.evaluate_bola(
                attacker_status=attacker_response.status, attacker_body=attacker_response.body,
                owner_status=owner_response.status if owner_response else None,
                owner_body=owner_response.body if owner_response else None,
                control_status=control_response.status if control_response else None,
                control_body=control_response.body if control_response else None,
            )
            if verdict.fired:
                self._record("api-bola", operation, url, parameter.name, verdict,
                             attacker_response.status, attacker.name)

    def _check_bfla(self, operation: Operation) -> None:
        if not operation.privileged:
            return
        unprivileged = next((p for p in self._principals if not p.privileged), None)
        privileged = next((p for p in self._principals if p.privileged), None)
        if unprivileged is None:
            return

        values = self._values(operation, unprivileged)
        url = build_url(self._base, operation, values)
        if not url:
            return
        response = self._request(url, unprivileged.headers)
        if response is None:
            return
        privileged_response = (
            self._request(url, privileged.headers) if privileged is not None else None
        )
        verdict = checks.evaluate_bfla(
            status=response.status, body=response.body,
            privileged_status=privileged_response.status if privileged_response else None,
            privileged_body=privileged_response.body if privileged_response else None,
        )
        if verdict.fired:
            self._record("api-bfla", operation, url, "", verdict, response.status,
                         unprivileged.name)


__all__ = ["ApiScanResult", "ApiScanner", "Issue", "Principal"]
