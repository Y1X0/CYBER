"""Drive the checks against a live application, safely (WP-D2).

This is the loop that decides *what request to make next*, and every safety property of the package
is enforced here rather than trusted to the caller:

* **scope** — every URL is re-checked against the authorized hosts immediately before the request,
  including after a redirect, because the target of a request is not the target the crawler queued;
* **budget** — a hard request ceiling and a wall-clock deadline, so an application with an infinite
  URL space cannot turn a scan into a flood;
* **rate** — a minimum interval between requests to one host;
* **method** — GET only. A form declaring POST is inventoried and never submitted.

Failures are recorded, never converted into "no findings". A scan that could not reach the
application must not be indistinguishable from a scan of an application with nothing wrong: the
result carries `errors` and `degraded`, and the engine surfaces them.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from guardian_common.logging import get_logger

from guardian_scanner.dast import checks as c
from guardian_scanner.dast.crawl import CrawlResult, Param, Target, crawl, normalize, same_scope

log = get_logger("guardian.dast")

DEFAULT_MAX_REQUESTS = 400
DEFAULT_RATE_PER_SECOND = 8.0
DEFAULT_DEADLINE_SECONDS = 180.0
MAX_PARAMS_PER_TARGET = 12
MAX_BODY_BYTES = 400_000


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict
    body: str
    url: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass
class Issue:
    """One confirmed finding, with the request that produced it."""

    check_id: str
    url: str
    parameter: str
    payload: str
    indicator: str
    excerpt: str
    confidence: str
    status: int


@dataclass
class ScanResult:
    issues: list[Issue] = field(default_factory=list)
    requests_made: int = 0
    targets_tested: int = 0
    parameters_tested: int = 0
    crawl: CrawlResult | None = None
    budget_exhausted: bool = False
    deadline_reached: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def degraded(self) -> bool:
        """Whether this scan covered less than it was asked to.

        A truncated scan that reports `completed` is the failure mode this whole package exists to
        avoid — a customer reads "no findings" as "nothing is wrong" rather than "we stopped early".
        """
        return bool(self.errors) or self.budget_exhausted or self.deadline_reached or bool(
            self.crawl and (self.crawl.truncated or self.crawl.errors)
        )


class Budget:
    """Requests, rate and wall clock, in one place so no call site can forget one."""

    def __init__(self, *, max_requests: int, rate_per_second: float, deadline_seconds: float,
                 clock=time.monotonic, sleep=time.sleep) -> None:  # noqa: ANN001
        self.max_requests = max_requests
        self._interval = 1.0 / rate_per_second if rate_per_second > 0 else 0.0
        self._deadline = clock() + deadline_seconds
        self._clock = clock
        self._sleep = sleep
        # None, not 0.0: a clock that legitimately reads 0.0 on the first request would make
        # `if self._last` false and skip the rate limit for the request after it.
        self._last: float | None = None
        self.spent = 0
        self.exhausted = False
        self.expired = False

    def take(self) -> bool:
        """Claim one request, waiting for the rate limit. False when the scan must stop."""
        if self.spent >= self.max_requests:
            self.exhausted = True
            return False
        now = self._clock()
        if now >= self._deadline:
            self.expired = True
            return False
        if self._interval and self._last is not None:
            wait = self._last + self._interval - now
            if wait > 0:
                self._sleep(wait)
        self._last = self._clock()
        self.spent += 1
        return True


def new_marker() -> str:
    """A token identifying this scan in a customer's logs and in reflected output."""
    return f"{c.MARKER_STEM}{secrets.token_hex(4)}"


def with_param(url: str, name: str, value: str) -> str:
    """Replace one query parameter, leaving the rest of the URL alone."""
    parsed = urlparse(url)
    params = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k != name]
    params.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(params)))


def form_url(target: Target, name: str, value: str) -> str:
    """A GET form submission with one field replaced.

    Only ever called for `method == "GET"` forms: a POST form is inventoried and left alone.
    """
    url = target.url
    for param in target.params:
        url = with_param(url, param.name, param.value or "1")
    return with_param(url, name, value)


class ActiveScanner:
    """Runs the catalogue against one application.

    `fetch` is injected: `(url, headers) -> Response`. Keeping the transport out means the loop —
    scope, budget, ordering, and every verdict — is testable without a network, and that the engine
    can supply a transport that carries its own egress pinning.
    """

    def __init__(
        self, *, fetch, authorized_hosts: set[str] | frozenset[str],  # noqa: ANN001
        max_requests: int = DEFAULT_MAX_REQUESTS,
        rate_per_second: float = DEFAULT_RATE_PER_SECOND,
        deadline_seconds: float = DEFAULT_DEADLINE_SECONDS,
        clock=time.monotonic, sleep=time.sleep,  # noqa: ANN001
    ) -> None:
        self._fetch = fetch
        self._hosts = frozenset(h.lower().rstrip(".") for h in authorized_hosts)
        self._budget = Budget(max_requests=max_requests, rate_per_second=rate_per_second,
                              deadline_seconds=deadline_seconds, clock=clock, sleep=sleep)
        self.result = ScanResult()
        self._marker = new_marker()
        self._cors_seen: set[str] = set()
        self._csrf_seen: set[str] = set()
        # Set-Cookie values observed across every response (crawl + checks). Used by the CSRF check
        # to decide whether the session has a SameSite fallback — never a request of its own.
        self._cookies_seen: list[str] = []
        # Whether an XSS marker was submitted through a *form* field. Persistence (stored XSS) is
        # only possible via a submission, so the re-fetch pass runs only when this is true.
        self._xss_submitted_via_form = False

    # ── transport ────────────────────────────────────────────────────────────────────────────────
    def _request(self, url: str, headers: dict | None = None) -> Response | None:
        """One request, or None when it must not or could not be made.

        The scope check is here, at the last possible moment, rather than only in the crawler.
        Anything that builds a URL — a payload, a form action, a redirect — goes through this
        function, so there is exactly one place that can send a packet and exactly one check.
        """
        if not same_scope(url, self._hosts):
            self.result.errors.append(f"refused out-of-scope request: {url[:200]}")
            log.warning("dast_out_of_scope_refused", url=url[:200])
            return None
        if not self._budget.take():
            self.result.budget_exhausted = self._budget.exhausted
            self.result.deadline_reached = self._budget.expired
            return None
        try:
            response = self._fetch(url, headers or {})
        except Exception as exc:  # noqa: BLE001 - one failed request must not end the scan
            self.result.errors.append(f"{url[:120]}: {type(exc).__name__}: {exc}")
            return None
        if response is None or response.error:
            self.result.errors.append(
                f"{url[:120]}: {response.error if response else 'no response'}"
            )
            return None
        # Counted only when a response actually came back. The budget already counted the attempt;
        # this number answers "how much of the application did we see", and an attempt that failed
        # saw none of it — which is what lets the engine tell "unreachable" from "clean".
        self.result.requests_made += 1
        # Passively observe Set-Cookie from every response — the CSRF check reads these to decide
        # whether the session has a SameSite fallback. No extra request is ever made for this.
        set_cookie = response.headers.get("set-cookie")
        if set_cookie:
            self._cookies_seen.append(str(set_cookie))
        return response

    # ── the scan ─────────────────────────────────────────────────────────────────────────────────
    def scan(self, seeds: list[str], *, max_pages: int = 40, max_depth: int = 2) -> ScanResult:
        def crawl_fetch(url: str):  # noqa: ANN202
            response = self._request(url)
            if response is None:
                raise RuntimeError("request refused or failed")
            return response.status, response.headers, response.body

        self.result.crawl = crawl(
            seeds, fetch=crawl_fetch, authorized_hosts=self._hosts,
            max_pages=max_pages, max_depth=max_depth,
        )

        # Passive, request-free: a session identifier sitting in any crawled URL.
        self._check_session_urls()

        seen: set[tuple[str, str]] = set()
        for target in self.result.crawl.targets:
            if target.method != "GET":
                # A POST form's action is not requested at all — not even the once-per-endpoint
                # CORS probe. A bare GET to `/transfer` submits nothing, but it is still traffic
                # aimed at an endpoint whose whole purpose is to change something, and the
                # discipline is worth more than the coverage. The CSRF check inspects the form the
                # crawler already parsed and the cookies already seen; it sends nothing.
                self._check_csrf(target)
                continue
            self._check_cors(target)
            if not target.testable:
                continue
            self.result.targets_tested += 1
            for param in target.params[:MAX_PARAMS_PER_TARGET]:
                key = (normalize(target.url), param.name)
                if key in seen:
                    continue
                seen.add(key)
                self.result.parameters_tested += 1
                self._test_parameter(target, param)
                if self._stopped():
                    return self.result
        # Stored XSS: only after a marker was actually submitted through a form, re-fetch the
        # crawled pages (plain GET, no payload) and see whether the marker persisted.
        self._check_stored_xss()
        return self.result

    def _stopped(self) -> bool:
        if self._budget.exhausted or self._budget.expired:
            self.result.budget_exhausted = self._budget.exhausted
            self.result.deadline_reached = self._budget.expired
            return True
        return False

    def _url_for(self, target: Target, param: Param, value: str) -> str:
        """The URL that submits `value` in `param`.

        A form field is not a query parameter: sending only the field under test would drop the
        others, and most applications answer a half-submitted form with a validation page that never
        reaches the code being tested. `form_url` fills the rest in with their declared defaults.
        """
        if param.where == "form":
            return form_url(target, param.name, value)
        return with_param(target.url, param.name, value)

    def _test_parameter(self, target: Target, param: Param) -> None:
        baseline = self._request(self._url_for(target, param, param.value or "1"))
        if baseline is None:
            return

        self._test_xss(target, param)
        self._test_sql(target, param, baseline)
        self._test_traversal(target, param)
        self._test_ssti(target, param)
        self._test_command(target, param)
        self._test_redirect(target, param)

    def _record(self, check_id: str, target: Target, param: Param, probe: c.Probe,
                verdict: c.Verdict, status: int) -> None:
        self.result.issues.append(Issue(
            check_id=check_id, url=target.url, parameter=param.name, payload=probe.payload,
            indicator=verdict.indicator, excerpt=verdict.excerpt[:400],
            confidence=verdict.confidence, status=status,
        ))

    # ── individual checks ────────────────────────────────────────────────────────────────────────
    def _test_xss(self, target: Target, param: Param) -> None:
        for probe in c.xss_probes(self._marker):
            response = self._request(self._url_for(target, param, probe.payload))
            if response is None:
                return
            # Submitting the marker through a form field is what could persist it; note that so the
            # stored-XSS re-fetch pass runs. (Query-parameter reflection cannot persist.)
            if param.where == "form":
                self._xss_submitted_via_form = True
            verdict = c.evaluate_xss(self._marker, probe.payload, response.body,
                                     str(response.headers.get("content-type", "")))
            if verdict.fired:
                self._record("xss-reflected", target, param, probe, verdict, response.status)
                return

    def _test_sql(self, target: Target, param: Param, baseline: Response) -> None:
        for probe in c.sql_error_probes():
            response = self._request(self._url_for(target, param, probe.payload))
            if response is None:
                return
            verdict = c.evaluate_sql_error(response.body)
            if verdict.fired:
                self._record("sqli-error", target, param, probe, verdict, response.status)
                return

        true_probe, false_probe = c.sql_boolean_probes(param.value or "1")
        true_response = self._request(self._url_for(target, param, true_probe.payload))
        false_response = self._request(self._url_for(target, param, false_probe.payload))
        if true_response is None or false_response is None:
            return
        verdict = c.evaluate_sql_boolean(
            baseline.body, true_response.body, false_response.body,
            true_status=true_response.status, false_status=false_response.status,
        )
        if verdict.fired:
            self._record("sqli-boolean", target, param, true_probe, verdict, true_response.status)

    def _test_traversal(self, target: Target, param: Param) -> None:
        for probe in c.traversal_probes():
            response = self._request(self._url_for(target, param, probe.payload))
            if response is None:
                return
            verdict = c.evaluate_traversal(response.body)
            if verdict.fired:
                self._record("path-traversal", target, param, probe, verdict, response.status)
                return

    def _test_ssti(self, target: Target, param: Param) -> None:
        for probe in c.ssti_probes():
            response = self._request(self._url_for(target, param, probe.payload))
            if response is None:
                return
            verdict = c.evaluate_ssti(response.body)
            if verdict.fired:
                self._record("ssti", target, param, probe, verdict, response.status)
                return

    def _test_command(self, target: Target, param: Param) -> None:
        for probe in c.command_probes(self._marker):
            response = self._request(self._url_for(target, param, probe.payload))
            if response is None:
                return
            verdict = c.evaluate_command(self._marker, probe.payload, response.body)
            if verdict.fired:
                self._record("command-injection", target, param, probe, verdict, response.status)
                return

    def _test_redirect(self, target: Target, param: Param) -> None:
        for probe in c.redirect_probes():
            response = self._request(self._url_for(target, param, probe.payload))
            if response is None:
                return
            verdict = c.evaluate_redirect(response.status,
                                          str(response.headers.get("location", "")))
            if verdict.fired:
                self._record("open-redirect", target, param, probe, verdict, response.status)
                return

    def _test_cors(self, target: Target) -> None:
        response = self._request(target.url, {"origin": c.CORS_ORIGIN})
        if response is None:
            return
        verdict = c.evaluate_cors(response.headers)
        if verdict.fired:
            self._record("cors-misconfig", target, Param(name="Origin", where="header"),
                         c.Probe(payload=c.CORS_ORIGIN, label="origin"), verdict, response.status)

    def _check_cors(self, target: Target) -> None:
        # Once per URL, not once per parameter: CORS is a property of the endpoint.
        key = normalize(target.url)
        if key in self._cors_seen:
            return
        self._cors_seen.add(key)
        self._test_cors(target)

    def _check_csrf(self, target: Target) -> None:
        """A state-changing POST form without an anti-CSRF token, on a session with no SameSite
        fallback. Inspects the form the crawler already parsed and the cookies already observed —
        it makes NO request, so the POST is never submitted.
        """
        key = normalize(target.url)
        if key in self._csrf_seen:
            return
        self._csrf_seen.add(key)
        verdict = c.evaluate_csrf(target.method, [p.name for p in target.params],
                                  self._cookies_seen)
        if verdict.fired:
            self._record("csrf-missing-token", target, Param(name="form", where="form"),
                         c.Probe(payload="", label="post-form"), verdict, 0)

    def _check_session_urls(self) -> None:
        """A session identifier in a crawled URL. Request-free — it reads URLs already gathered.
        Reported once (it is a site-wide design issue, not a per-URL one)."""
        for target in (self.result.crawl.targets if self.result.crawl else []):
            verdict = c.evaluate_session_in_url(target.url)
            if verdict.fired:
                self._record("session-id-in-url", target, Param(name="(url)", where="query"),
                             c.Probe(payload="", label="url"), verdict, 0)
                return

    def _check_stored_xss(self) -> None:
        """Persistence: re-fetch each crawled GET page (plain, no payload) and see whether the
        marker submitted earlier through a form now renders unescaped — i.e. it was stored and is
        served to other visitors. Runs only after a form submission that could persist it, and
        stays within the request budget.
        """
        if not self._xss_submitted_via_form:
            return
        seen: set[str] = set()
        for target in (self.result.crawl.targets if self.result.crawl else []):
            if target.method != "GET":
                continue
            key = normalize(target.url)
            if key in seen:
                continue
            seen.add(key)
            response = self._request(target.url)
            if response is None:
                if self._stopped():
                    return
                continue
            verdict = c.evaluate_xss(self._marker, "", response.body,
                                     str(response.headers.get("content-type", "")))
            if verdict.fired:
                self._record("xss-stored", target, Param(name="(stored)", where="query"),
                             c.Probe(payload=self._marker, label="persisted-marker"),
                             verdict, response.status)


__all__ = [
    "ActiveScanner",
    "Budget",
    "Issue",
    "Response",
    "ScanResult",
    "form_url",
    "new_marker",
    "with_param",
]
