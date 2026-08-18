"""Parse and *refuse* nuclei templates (WP-D1).

This module is the safety boundary of the whole template engine, and it is written as a
deny-by-default validator rather than a parser with checks bolted on: an unknown key is a rejection,
not something to ignore. The nuclei template language is far larger than detection — it can execute
JavaScript, evaluate DSL expressions, replay raw HTTP, fuzz with payload sets, and call out to an
external interaction server. Guardian runs templates against systems a customer authorized us to
*look at*, so every one of those capabilities is refused here, by name and by shape.

The original design decision (recorded in `web_checks_provider`) was "Path B — no Nuclei", on the
grounds that a remote, auto-updating template feed is an unreviewable code path pointed at a
customer's production systems. That reasoning is preserved, not discarded: templates are loaded
from files committed to this repository, never fetched at scan time, and git review remains their
integrity boundary. What changes is that the check format is now the ecosystem's format, so the
MIT-licensed corpus can be adopted template by template after review instead of hand-written.

Rejections are values, not exceptions to swallow: `load_directory` returns what it refused and why,
so a template silently dropping out of a scan is impossible to miss.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from guardian_scanner.templates.model import (
    SEVERITY_BY_NAME,
    Classification,
    Extractor,
    Matcher,
    Request,
    Template,
)

MAX_TEMPLATE_BYTES = 64_000
MAX_REQUESTS_PER_TEMPLATE = 4
MAX_MATCHERS_PER_REQUEST = 12
MAX_REGEX_LENGTH = 400

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,80}$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")
_ALLOWED_METHODS = frozenset({"GET", "HEAD"})
_ALLOWED_MATCHER_TYPES = frozenset({"status", "word", "regex", "size"})
_ALLOWED_EXTRACTOR_TYPES = frozenset({"regex", "kval"})
_ALLOWED_PARTS = frozenset({"body", "header", "all", "status"})

_ALLOWED_TOP_LEVEL = frozenset({"id", "info", "http", "requests"})
_ALLOWED_INFO = frozenset(
    {"name", "author", "severity", "description", "remediation", "reference", "tags",
     "classification", "metadata", "impact"}
)
_ALLOWED_REQUEST_KEYS = frozenset(
    {"method", "path", "headers", "matchers", "extractors", "matchers-condition",
     "stop-at-first-match", "max-size", "redirects", "host-redirects"}
)

# Everything structural — other protocol blocks (`network`, `dns`, `ssl`, `code`, `javascript`,
# `headless`, `file`), `flow`, `variables`, `self-contained`, and per-request `raw`, `payloads`,
# `attack`, `fuzzing`, `unsafe`, `race`, `pipeline` — is refused by the key allowlists below rather
# than by string matching, which is both stricter and immune to a description that happens to use
# the word. What remains here is the one capability that can hide inside a *value* (a path, a
# header, a matcher word) and so would slip past a key check: the out-of-band interaction server.
_FORBIDDEN_TEXT: tuple[tuple[re.Pattern[str], str], ...] = (
    # No trailing word boundary: the constructs in the wild are `interactsh-url`,
    # `{{interactsh_url}}` and `oast_url`, and `_` is a word character — so `\binteractsh\b` would
    # miss the exact spellings this is meant to catch.
    (re.compile(r"\binteractsh", re.IGNORECASE), "out-of-band interaction callbacks"),
    (re.compile(r"\boast(\b|_)", re.IGNORECASE), "out-of-band interaction callbacks"),
    (re.compile(r"\bcollaborator", re.IGNORECASE), "out-of-band interaction callbacks"),
)

# `{{BaseURL}}` is the only interpolation a path may contain. Anything else is either a variable
# (refused above) or a helper function, which is expression evaluation by another name.
_INTERPOLATION_RE = re.compile(r"\{\{([^}]*)\}\}")
_ALLOWED_INTERPOLATIONS = frozenset({"BaseURL", "RootURL", "Hostname", "Host"})

_SECRET_HINTS = ("env", "credential", "secret", "token", "password", "aws", "id_rsa", "private-key")


class TemplateRejected(ValueError):
    """A template was refused. The message names the construct and why it is not allowed."""


@dataclass(frozen=True)
class Rejection:
    source: str
    reason: str


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list | tuple):
        return tuple(str(v) for v in value)
    return ()


def _check_interpolations(where: str, value: str) -> None:
    for found in _INTERPOLATION_RE.findall(value):
        name = found.strip()
        if name not in _ALLOWED_INTERPOLATIONS:
            raise TemplateRejected(
                f"{where}: interpolation {{{{{name}}}}} is not allowed — only "
                f"{sorted(_ALLOWED_INTERPOLATIONS)} may appear, everything else is an expression"
            )


def _compile(pattern: str, where: str) -> str:
    if len(pattern) > MAX_REGEX_LENGTH:
        raise TemplateRejected(f"{where}: regex longer than {MAX_REGEX_LENGTH} characters")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise TemplateRejected(f"{where}: regex does not compile ({exc})") from exc
    return pattern


def _parse_matcher(raw: Any, where: str) -> Matcher:
    if not isinstance(raw, dict):
        raise TemplateRejected(f"{where}: matcher must be a mapping")
    kind = _text(raw.get("type")).lower()
    if kind not in _ALLOWED_MATCHER_TYPES:
        raise TemplateRejected(
            f"{where}: matcher type {kind!r} is not allowed — supported types are "
            f"{sorted(_ALLOWED_MATCHER_TYPES)}; `dsl` in particular is expression evaluation"
        )
    part = _text(raw.get("part") or "body").lower()
    if part not in _ALLOWED_PARTS:
        raise TemplateRejected(f"{where}: matcher part {part!r} is not allowed")

    words = _as_tuple(raw.get("words"))
    regexes = tuple(_compile(p, where) for p in _as_tuple(raw.get("regex")))
    # Nuclei interpolates matcher terms too, so they are checked with the same rule as paths and
    # headers. A helper function reached through a matcher word is still expression evaluation.
    for term in (*words, *regexes):
        _check_interpolations(where, term)
    status = tuple(int(s) for s in _as_tuple(raw.get("status")) if str(s).lstrip("-").isdigit())
    sizes = tuple(int(s) for s in _as_tuple(raw.get("size")) if str(s).lstrip("-").isdigit())

    if kind == "word" and not words:
        raise TemplateRejected(f"{where}: word matcher has no words")
    if kind == "regex" and not regexes:
        raise TemplateRejected(f"{where}: regex matcher has no patterns")
    if kind == "status" and not status:
        raise TemplateRejected(f"{where}: status matcher has no status codes")
    if kind == "size" and not sizes:
        raise TemplateRejected(f"{where}: size matcher has no sizes")

    condition = _text(raw.get("condition") or "or").lower()
    if condition not in {"and", "or"}:
        raise TemplateRejected(f"{where}: matcher condition {condition!r} is not and/or")

    return Matcher(
        type=kind, part=part, words=words, regexes=regexes, status=status, sizes=sizes,
        condition=condition, negative=bool(raw.get("negative")),
        case_insensitive=bool(raw.get("case-insensitive")), name=_text(raw.get("name")),
    )


def _parse_extractor(raw: Any, where: str) -> Extractor:
    if not isinstance(raw, dict):
        raise TemplateRejected(f"{where}: extractor must be a mapping")
    kind = _text(raw.get("type")).lower()
    if kind not in _ALLOWED_EXTRACTOR_TYPES:
        raise TemplateRejected(
            f"{where}: extractor type {kind!r} is not allowed — supported types are "
            f"{sorted(_ALLOWED_EXTRACTOR_TYPES)}"
        )
    part = _text(raw.get("part") or "body").lower()
    if part not in _ALLOWED_PARTS:
        raise TemplateRejected(f"{where}: extractor part {part!r} is not allowed")
    regexes = tuple(_compile(p, where) for p in _as_tuple(raw.get("regex")))
    kval = _as_tuple(raw.get("kval"))
    if kind == "regex" and not regexes:
        raise TemplateRejected(f"{where}: regex extractor has no patterns")
    if kind == "kval" and not kval:
        raise TemplateRejected(f"{where}: kval extractor has no keys")
    return Extractor(
        type=kind, name=_text(raw.get("name")), part=part, regexes=regexes,
        group=int(raw.get("group") or 0), kval=kval, internal=bool(raw.get("internal")),
    )


def _parse_request(raw: Any, index: int) -> Request:
    where = f"request[{index}]"
    if not isinstance(raw, dict):
        raise TemplateRejected(f"{where}: must be a mapping")

    unknown = set(raw) - _ALLOWED_REQUEST_KEYS
    if unknown:
        raise TemplateRejected(
            f"{where}: unsupported keys {sorted(unknown)} — the validator denies by default, so a "
            "construct it does not model cannot be executed"
        )
    if raw.get("redirects") or raw.get("host-redirects"):
        raise TemplateRejected(
            f"{where}: redirects are not followed — a response must never choose the next target"
        )

    method = _text(raw.get("method") or "GET").upper()
    if method not in _ALLOWED_METHODS:
        raise TemplateRejected(
            f"{where}: method {method!r} is not allowed — detection reads, it does not write, so "
            f"only {sorted(_ALLOWED_METHODS)} may be sent"
        )

    paths = _as_tuple(raw.get("path"))
    if len(paths) != 1:
        raise TemplateRejected(f"{where}: exactly one path is required, got {len(paths)}")
    path = paths[0]
    _check_interpolations(where, path)
    relative = _INTERPOLATION_RE.sub("", path)
    if not relative:
        relative = "/"
    if not relative.startswith("/"):
        relative = "/" + relative
    if not _PATH_RE.match(relative) or ".." in relative:
        raise TemplateRejected(f"{where}: path {relative!r} is not a plain absolute path")

    headers_raw = raw.get("headers") or {}
    if not isinstance(headers_raw, dict):
        raise TemplateRejected(f"{where}: headers must be a mapping")
    headers = []
    for key, value in headers_raw.items():
        text = str(value)
        _check_interpolations(f"{where}.headers.{key}", text)
        if "\n" in text or "\r" in text:
            raise TemplateRejected(f"{where}: header {key!r} contains a newline")
        headers.append((str(key), text))

    matchers = raw.get("matchers") or []
    if not isinstance(matchers, list) or not matchers:
        raise TemplateRejected(f"{where}: at least one matcher is required")
    if len(matchers) > MAX_MATCHERS_PER_REQUEST:
        raise TemplateRejected(f"{where}: more than {MAX_MATCHERS_PER_REQUEST} matchers")

    condition = _text(raw.get("matchers-condition") or "and").lower()
    if condition not in {"and", "or"}:
        raise TemplateRejected(f"{where}: matchers-condition {condition!r} is not and/or")

    return Request(
        method=method,
        path=relative,
        headers=tuple(headers),
        matchers=tuple(_parse_matcher(m, f"{where}.matchers[{i}]") for i, m in enumerate(matchers)),
        extractors=tuple(
            _parse_extractor(e, f"{where}.extractors[{i}]")
            for i, e in enumerate(raw.get("extractors") or [])
        ),
        matchers_condition=condition,
    )


def _parse_classification(raw: Any) -> Classification:
    if not isinstance(raw, dict):
        return Classification()
    score = raw.get("cvss-score")
    try:
        cvss = float(score) if score is not None else None
    except (TypeError, ValueError):
        cvss = None
    return Classification(
        cve_ids=tuple(v.upper() for v in _as_tuple(raw.get("cve-id"))),
        cwe_ids=tuple(v.upper() for v in _as_tuple(raw.get("cwe-id"))),
        cvss_score=cvss,
        cvss_metrics=_text(raw.get("cvss-metrics")),
    )


def load_template(text: str, source: str = "<memory>") -> Template:
    """Parse one template, or raise `TemplateRejected` naming the construct that is not allowed."""
    if len(text) > MAX_TEMPLATE_BYTES:
        raise TemplateRejected(f"{source}: template larger than {MAX_TEMPLATE_BYTES} bytes")

    for pattern, why in _FORBIDDEN_TEXT:
        found = pattern.search(text)
        if found is not None:
            raise TemplateRejected(f"{source}: refused — {why} (matched {found.group(0)!r})")

    try:
        # safe_load, never load: a template is untrusted input even when it is committed, and
        # `yaml.load` would construct arbitrary Python objects from it.
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise TemplateRejected(f"{source}: not valid YAML ({exc})") from exc
    if not isinstance(doc, dict):
        raise TemplateRejected(f"{source}: template must be a mapping")

    unknown = set(doc) - _ALLOWED_TOP_LEVEL
    if unknown:
        raise TemplateRejected(f"{source}: unsupported top-level keys {sorted(unknown)}")

    template_id = _text(doc.get("id")).strip()
    if not _ID_RE.match(template_id):
        raise TemplateRejected(f"{source}: id {template_id!r} is missing or malformed")

    info = doc.get("info") or {}
    if not isinstance(info, dict):
        raise TemplateRejected(f"{source}: info must be a mapping")
    unknown_info = set(info) - _ALLOWED_INFO
    if unknown_info:
        raise TemplateRejected(f"{source}: unsupported info keys {sorted(unknown_info)}")

    severity_name = _text(info.get("severity") or "info").lower()
    if severity_name not in SEVERITY_BY_NAME:
        raise TemplateRejected(f"{source}: unknown severity {severity_name!r}")

    raw_requests = doc.get("http") or doc.get("requests") or []
    if not isinstance(raw_requests, list) or not raw_requests:
        raise TemplateRejected(f"{source}: template has no http request")
    if len(raw_requests) > MAX_REQUESTS_PER_TEMPLATE:
        raise TemplateRejected(f"{source}: more than {MAX_REQUESTS_PER_TEMPLATE} requests")

    tags = tuple(
        t.strip().lower() for t in ",".join(_as_tuple(info.get("tags"))).split(",") if t.strip()
    )
    name = _text(info.get("name")) or template_id
    redact = any(hint in f"{template_id} {name} {' '.join(tags)}".lower() for hint in _SECRET_HINTS)

    return Template(
        id=template_id,
        name=name,
        severity=SEVERITY_BY_NAME[severity_name],
        requests=tuple(_parse_request(r, i) for i, r in enumerate(raw_requests)),
        author=", ".join(_as_tuple(info.get("author"))),
        description=_text(info.get("description")).strip(),
        remediation=_text(info.get("remediation")).strip(),
        tags=tags,
        reference=_as_tuple(info.get("reference")),
        classification=_parse_classification(info.get("classification")),
        redact_evidence=redact,
        source=source,
    )


def load_directory(path: str | Path) -> tuple[tuple[Template, ...], tuple[Rejection, ...]]:
    """Load every `*.yaml` under `path`. Returns the accepted templates and the refusals.

    Refusals are returned rather than logged and forgotten. A template that quietly stops loading
    is a check that silently stops running, and the customer sees a clean report either way.
    """
    root = Path(path)
    accepted: list[Template] = []
    rejected: list[Rejection] = []
    seen: set[str] = set()
    for file in sorted(root.rglob("*.yaml")):
        try:
            text = file.read_text(encoding="utf-8")
        except OSError as exc:
            rejected.append(Rejection(source=str(file), reason=f"unreadable: {exc}"))
            continue
        try:
            template = load_template(text, source=file.name)
        except TemplateRejected as exc:
            rejected.append(Rejection(source=str(file), reason=str(exc)))
            continue
        if template.id in seen:
            rejected.append(Rejection(source=str(file), reason=f"duplicate id {template.id!r}"))
            continue
        seen.add(template.id)
        accepted.append(template)
    return tuple(accepted), tuple(rejected)


def library_path() -> Path:
    """The source-controlled template library that ships with the scanner."""
    return Path(__file__).resolve().parent / "library"
