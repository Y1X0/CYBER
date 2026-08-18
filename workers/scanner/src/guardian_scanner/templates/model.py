"""The validated, executable form of a nuclei template (WP-D1).

A template that reaches this module has already been through `loader.load_template`, which is the
only place a template's safety is decided. Everything here is therefore assumed safe to execute:
the request is a GET or HEAD against a path the template author wrote, the matchers are pure
predicates over a response, and there is nothing left that can evaluate an expression, follow a
redirect, or reach a host the scope did not name.

Keeping the parsed form separate from the YAML is what makes that guarantee checkable. If matchers
were evaluated straight out of the raw dict, every new template field would be a new way to smuggle
behaviour past the validator.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from guardian_core.enums import Severity

SEVERITY_BY_NAME: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


@dataclass(frozen=True)
class Matcher:
    """One predicate over a response.

    `part` selects what the predicate reads: the body, the raw header block, the status line, or
    everything concatenated. `negative` inverts it — which is how a template asserts an *absence*,
    e.g. "the page loads and does NOT contain the login form".
    """

    type: str                      # "status" | "word" | "regex" | "size"
    part: str = "body"             # "body" | "header" | "all" | "status"
    words: tuple[str, ...] = ()
    regexes: tuple[str, ...] = ()
    status: tuple[int, ...] = ()
    sizes: tuple[int, ...] = ()
    condition: str = "or"          # how this matcher's own terms combine
    negative: bool = False
    case_insensitive: bool = False
    name: str = ""


@dataclass(frozen=True)
class Extractor:
    """A value pulled out of a matching response, for the finding's evidence."""

    type: str                      # "regex" | "kval"
    name: str = ""
    part: str = "body"
    regexes: tuple[str, ...] = ()
    group: int = 0
    kval: tuple[str, ...] = ()
    internal: bool = False


@dataclass(frozen=True)
class Request:
    """One HTTP probe. Only the method and path vary; everything else is fixed by policy."""

    method: str                    # "GET" | "HEAD"
    path: str                      # relative, always beginning at the target root
    headers: tuple[tuple[str, str], ...] = ()
    matchers: tuple[Matcher, ...] = ()
    extractors: tuple[Extractor, ...] = ()
    matchers_condition: str = "and"


@dataclass(frozen=True)
class Classification:
    cve_ids: tuple[str, ...] = ()
    cwe_ids: tuple[str, ...] = ()
    cvss_score: float | None = None
    cvss_metrics: str = ""


@dataclass(frozen=True)
class Template:
    """A safe, executable detection template."""

    id: str
    name: str
    severity: Severity
    requests: tuple[Request, ...]
    author: str = ""
    description: str = ""
    remediation: str = ""
    tags: tuple[str, ...] = ()
    reference: tuple[str, ...] = ()
    classification: Classification = field(default_factory=Classification)
    # Set when the template's own text says its evidence may contain credential material, so the
    # runner emits a redaction marker instead of a snippet.
    redact_evidence: bool = False
    source: str = ""               # file the template was loaded from, for provenance


@dataclass
class Detection:
    """A template that fired against one target."""

    template: Template
    target: str
    port: int
    path: str
    status: int
    matched_at: str
    snippet: str = ""
    extracted: dict[str, tuple[str, ...]] = field(default_factory=dict)
    matcher_name: str = ""
