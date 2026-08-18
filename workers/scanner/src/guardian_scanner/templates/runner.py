"""Evaluate a validated template against a response (WP-D1).

Matching is pure: it takes a status, headers and a body, and returns whether the template fired and
what it extracted. Nothing here opens a socket. The fetch is injected, which is what lets the same
code run against a live target, against a recorded snapshot in CI, and against a local server in a
test — and, more importantly, keeps the egress policy (authorized host, public address, no
redirects, size caps) in one place instead of being re-implemented per call site.

Evidence is bounded and redacted here rather than at the reporting layer. A template that matches an
exposed `.env` has, by definition, just read a credential; the snippet must never carry it out.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from guardian_scanner.templates.model import Detection, Extractor, Matcher, Request, Template

SNIPPET_MAX = 120
MAX_EXTRACTED_VALUES = 5
MAX_EXTRACTED_LENGTH = 120
# Long token-like runs are redacted out of every snippet: base64/hex secrets look exactly like this
# and a matched region is the most likely place in a response for one to appear.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_=-]{20,}")
_INTERPOLATION_RE = re.compile(r"\{\{([^}]*)\}\}")


@dataclass(frozen=True)
class Response:
    """What the runner needs from a fetch, independent of the client that produced it."""

    status: int
    headers: dict[str, str]
    body: str

    @property
    def header_block(self) -> str:
        return "\n".join(f"{k}: {v}" for k, v in self.headers.items())

    def part(self, which: str) -> str:
        if which == "header":
            return self.header_block
        if which == "status":
            return str(self.status)
        if which == "all":
            return f"{self.status}\n{self.header_block}\n{self.body}"
        return self.body


Fetch = Callable[[str, str, tuple[tuple[str, str], ...]], Response]
"""(method, path, headers) -> Response. Raises on a refused or failed request."""


def redact(text: str) -> str:
    return _TOKEN_RE.sub("***", text)


def substitute(value: str, *, base_url: str, hostname: str) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1).strip()
        if name in {"BaseURL", "RootURL"}:
            return base_url
        if name in {"Hostname", "Host"}:
            return hostname
        return ""      # the loader has already refused anything else
    return _INTERPOLATION_RE.sub(replace, value)


# ── matching ──────────────────────────────────────────────────────────────────────────────────────
def _terms_hit(matcher: Matcher, response: Response) -> bool:
    haystack = response.part(matcher.part)
    if matcher.case_insensitive:
        haystack = haystack.lower()

    if matcher.type == "status":
        return response.status in matcher.status
    if matcher.type == "size":
        return len(response.body) in matcher.sizes
    if matcher.type == "word":
        words = [w.lower() for w in matcher.words] if matcher.case_insensitive else matcher.words
        hits = [w in haystack for w in words]
    else:  # regex
        flags = re.IGNORECASE if matcher.case_insensitive else 0
        hits = [re.search(p, haystack, flags) is not None for p in matcher.regexes]

    return all(hits) if matcher.condition == "and" else any(hits)


def matcher_hits(matcher: Matcher, response: Response) -> bool:
    """Whether this matcher is satisfied, with `negative` applied last."""
    hit = _terms_hit(matcher, response)
    return not hit if matcher.negative else hit


def _snippet(request: Request, response: Response, template: Template) -> str:
    """A short, redacted excerpt of what matched — never a body."""
    if template.redact_evidence:
        return "<redacted>"
    for matcher in request.matchers:
        if matcher.negative:
            continue
        haystack = response.part(matcher.part)
        flags = re.IGNORECASE if matcher.case_insensitive else 0
        found = None
        if matcher.type == "word":
            for word in matcher.words:
                index = haystack.lower().find(word.lower()) if matcher.case_insensitive \
                    else haystack.find(word)
                if index >= 0:
                    found = index
                    break
        elif matcher.type == "regex":
            for pattern in matcher.regexes:
                hit = re.search(pattern, haystack, flags)
                if hit is not None:
                    found = hit.start()
                    break
        if found is not None:
            return redact(haystack[found : found + SNIPPET_MAX].strip())
    return ""


def _extract(extractor: Extractor, response: Response) -> tuple[str, ...]:
    values: list[str] = []
    if extractor.type == "kval":
        lowered = {k.lower().replace("-", "_"): v for k, v in response.headers.items()}
        for key in extractor.kval:
            value = lowered.get(key.lower().replace("-", "_"))
            if value:
                values.append(value)
    else:
        haystack = response.part(extractor.part)
        for pattern in extractor.regexes:
            for match in re.finditer(pattern, haystack):
                try:
                    values.append(match.group(extractor.group))
                except (IndexError, re.error):
                    continue
                if len(values) >= MAX_EXTRACTED_VALUES:
                    break
            if len(values) >= MAX_EXTRACTED_VALUES:
                break
    return tuple(
        redact(v)[:MAX_EXTRACTED_LENGTH] for v in values[:MAX_EXTRACTED_VALUES] if v
    )


def evaluate(
    template: Template, request: Request, response: Response
) -> tuple[bool, str, dict[str, tuple[str, ...]], str]:
    """Return (fired, snippet, extracted, matcher_name) for one request/response pair."""
    results = [matcher_hits(m, response) for m in request.matchers]
    fired = all(results) if request.matchers_condition == "and" else any(results)
    if not fired:
        return False, "", {}, ""

    extracted: dict[str, tuple[str, ...]] = {}
    for index, extractor in enumerate(request.extractors):
        if extractor.internal:
            continue
        values = _extract(extractor, response)
        if values:
            extracted[extractor.name or f"extract-{index}"] = values

    name = next(
        (m.name for m, hit in zip(request.matchers, results, strict=True) if hit and m.name), ""
    )
    return True, _snippet(request, response, template), extracted, name


# ── execution ─────────────────────────────────────────────────────────────────────────────────────
def run_template(
    template: Template, *, host: str, port: int, fetch: Fetch, stop_at_first: bool = True
) -> list[Detection]:
    """Run every request in a template against one target, via the injected fetch.

    A failed fetch ends this template against this target rather than the whole scan: one 500 or one
    connection reset must not silence the remaining checks, and it must not be reported as a clean
    result either — the caller sees an empty list and the provider records the probe outcome.
    """
    scheme = "https" if port == 443 else "http"
    base_url = f"{scheme}://{host}:{port}"
    detections: list[Detection] = []

    for request in template.requests:
        path = substitute(request.path, base_url="", hostname=host) or "/"
        headers = tuple(
            (k, substitute(v, base_url=base_url, hostname=host)) for k, v in request.headers
        )
        try:
            response = fetch(request.method, path, headers)
        except Exception:  # noqa: BLE001 - a refused or failed probe is not a finding
            return detections

        fired, snippet, extracted, matcher_name = evaluate(template, request, response)
        if fired:
            detections.append(
                Detection(
                    template=template, target=host, port=port, path=path,
                    status=response.status, matched_at=f"{base_url}{path}",
                    snippet=snippet, extracted=extracted, matcher_name=matcher_name,
                )
            )
            if stop_at_first:
                break
    return detections
