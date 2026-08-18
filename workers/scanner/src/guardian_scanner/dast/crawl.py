"""Find the application's attack surface (WP-D2).

An active check needs somewhere to inject. That means knowing the application's URLs and, more
importantly, its **parameters** — the query strings and form fields that reach server-side code. A
scanner that only tests the one URL it was given tests the front page and reports the site clean.

Parsing is done with `html.parser` from the standard library rather than a DOM library, because the
input is attacker-controlled markup from a customer's application and the smallest parser that can
do the job is the right one to point at it.

Scope is enforced here, before a URL is ever queued. Everything that leaves the authorized host is
dropped and counted, so "we did not test that" is visible rather than silent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse, urlunparse

from guardian_common.logging import get_logger

log = get_logger("guardian.dast.crawl")

MAX_URL_LENGTH = 2_000

# Paths that change state or end the session. A crawler that follows them logs itself out halfway
# through the scan and then reports the rest of the application as unreachable — and on an
# application without CSRF protection, a GET to one of these is a destructive request.
_DANGEROUS_PATH = re.compile(
    r"(?i)(?:^|/)(?:logout|signout|sign-out|log-out|delete|destroy|remove|drop|purge|reset|"
    r"deactivate|unsubscribe|revoke|shutdown|restart)(?:/|$|\?)"
)

# Extensions with no server-side parameters worth testing. Fetching them burns the request budget.
_STATIC_SUFFIXES = (
    ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff",
    ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".mp3", ".pdf", ".zip", ".gz", ".tar",
)


@dataclass(frozen=True)
class Param:
    """One injectable input."""

    name: str
    value: str = ""
    # "query" | "form"
    where: str = "query"


@dataclass(frozen=True)
class Target:
    """A request the scanner may make, and the inputs it can vary.

    `method` is only ever GET here. A form declaring POST is *recorded* — knowing an application has
    a POST endpoint is useful to a report — but never submitted: submitting an unknown POST is how a
    scanner creates users, sends email, or charges a card.
    """

    url: str
    method: str = "GET"
    params: tuple[Param, ...] = ()

    @property
    def testable(self) -> bool:
        return self.method == "GET" and bool(self.params)


@dataclass
class CrawlResult:
    targets: list[Target] = field(default_factory=list)
    # Kept rather than discarded: a scanner that silently drops out-of-scope links looks identical
    # to one that found nothing there.
    out_of_scope: list[str] = field(default_factory=list)
    skipped_dangerous: list[str] = field(default_factory=list)
    pages_fetched: int = 0
    truncated: bool = False
    errors: list[str] = field(default_factory=list)


def normalize(url: str) -> str:
    """Canonical form for dedup: no fragment, sorted query, default port dropped."""
    url, _ = urldefrag(url.strip())
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    port = parsed.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    query = "&".join(f"{k}={v}" for k, v in sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    path = parsed.path or "/"
    return urlunparse((scheme, host, path, "", query, ""))


def same_scope(url: str, authorized_hosts: frozenset[str] | set[str]) -> bool:
    """Whether a URL is inside the authorized scope.

    Host equality, plus subdomains of an authorized host — an authorization for `example.com` covers
    `app.example.com` for the same reason WP-F1's ownership proof does: whoever controls the zone
    controls the names in it. A lookalike suffix (`notexample.com`) is a different owner.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return False
    return any(host == allowed or host.endswith("." + allowed) for allowed in authorized_hosts)


def is_static(url: str) -> bool:
    return urlparse(url).path.lower().endswith(_STATIC_SUFFIXES)


def is_dangerous(url: str) -> bool:
    parsed = urlparse(url)
    return bool(_DANGEROUS_PATH.search(parsed.path)) or bool(_DANGEROUS_PATH.search(parsed.query))


class _Extractor(HTMLParser):
    """Links and forms out of one page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and attributes.get("href"):
            self.links.append(attributes["href"])
        elif tag == "form":
            self._form = {
                "action": attributes.get("action", ""),
                "method": (attributes.get("method") or "GET").upper(),
                "fields": [],
            }
        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = attributes.get("name")
            if not name:
                return
            if attributes.get("type", "").lower() in ("submit", "button", "image", "reset"):
                return
            self._form["fields"].append((name, attributes.get("value", "")))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def close(self) -> None:  # pragma: no cover - trivial
        super().close()
        if self._form is not None:  # an unclosed <form> still describes a real endpoint
            self.forms.append(self._form)
            self._form = None


def extract(base_url: str, body: str) -> tuple[list[str], list[Target]]:
    """(absolute links, form targets) from one page."""
    parser = _Extractor()
    try:
        parser.feed(body)
        parser.close()
    except Exception as exc:  # noqa: BLE001 - malformed markup is normal on a real site
        # Not silent, but not fatal either: whatever parsed before the error is still real attack
        # surface, and a page that broke the parser is worth knowing about when coverage is
        # questioned later.
        log.debug("dast_html_parse_incomplete", url=base_url[:200], error=str(exc)[:200])

    links = [urljoin(base_url, href) for href in parser.links
             if not href.lower().startswith(("javascript:", "mailto:", "tel:", "data:"))]

    forms: list[Target] = []
    for form in parser.forms:
        action = urljoin(base_url, form["action"] or base_url)
        params = tuple(Param(name=name, value=value, where="form")
                       for name, value in form["fields"])
        forms.append(Target(url=normalize(action), method=form["method"], params=params))
    return links, forms


def target_for(url: str) -> Target:
    """A GET target with its query parameters as the injectable inputs."""
    parsed = urlparse(url)
    params = tuple(Param(name=k, value=v, where="query")
                   for k, v in parse_qsl(parsed.query, keep_blank_values=True))
    return Target(url=normalize(url), method="GET", params=params)


def crawl(
    seeds: list[str],
    *,
    fetch,  # noqa: ANN001 - (url) -> (status, headers, body); injected so this is testable offline
    authorized_hosts: frozenset[str] | set[str],
    max_pages: int = 60,
    max_depth: int = 3,
) -> CrawlResult:
    """Breadth-first within scope, bounded by pages and depth.

    Breadth-first rather than depth-first because a bounded depth-first crawl spends its budget in
    one branch of a site — pagination, typically — and never reaches the other sections.
    """
    result = CrawlResult()
    seen: set[str] = set()
    queue: list[tuple[str, int]] = []

    for seed in seeds:
        normalized = normalize(seed)
        if not same_scope(normalized, authorized_hosts):
            result.out_of_scope.append(normalized)
            continue
        queue.append((normalized, 0))
        seen.add(normalized)

    while queue:
        if result.pages_fetched >= max_pages:
            result.truncated = True
            break
        url, depth = queue.pop(0)

        try:
            status, headers, body = fetch(url)
        except Exception as exc:  # noqa: BLE001 - one unreachable page must not end the crawl
            # Recorded, never swallowed: a page the scanner could not read is a page it did not
            # test, and the report has to be able to say so.
            result.errors.append(f"{url}: {type(exc).__name__}: {exc}")
            continue

        result.pages_fetched += 1
        result.targets.append(target_for(url))

        content_type = str(headers.get("content-type", "")).lower() if headers else ""
        if depth >= max_depth or "html" not in content_type:
            continue

        links, forms = extract(url, body or "")
        for form in forms:
            if not same_scope(form.url, authorized_hosts):
                result.out_of_scope.append(form.url)
                continue
            result.targets.append(form)

        for link in links:
            if len(link) > MAX_URL_LENGTH:
                continue
            candidate = normalize(link)
            if candidate in seen:
                continue
            if not same_scope(candidate, authorized_hosts):
                result.out_of_scope.append(candidate)
                seen.add(candidate)
                continue
            if is_dangerous(candidate):
                result.skipped_dangerous.append(candidate)
                seen.add(candidate)
                continue
            if is_static(candidate):
                seen.add(candidate)
                continue
            seen.add(candidate)
            queue.append((candidate, depth + 1))

    return result


__all__ = [
    "CrawlResult",
    "Param",
    "Target",
    "crawl",
    "extract",
    "is_dangerous",
    "is_static",
    "normalize",
    "same_scope",
    "target_for",
]
