"""The active checks, and what counts as proof (WP-D2).

Each check is a payload plus a decision about the response. The decision is the part that matters:
"the payload appeared in the page" is not a cross-site scripting vulnerability, and a scanner that
reports it as one produces a backlog nobody reads.

Everything here is pure — payload in, verdict out — so each rule is tested against the exact
responses that must and must not trigger it, without a network.

**Nothing in this module changes state.** SQL probes are boolean and error based; command-injection
probes echo a marker; there are no timing payloads, because a check whose signal is "the server got
slower" is indistinguishable from a check that caused a denial of service.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

# A per-scan random marker is appended by the scanner; this is the recognizable stem.
MARKER_STEM = "gdn"


@dataclass(frozen=True)
class Probe:
    """One request to make: the value to put in the parameter, and a label for the evidence."""

    payload: str
    label: str


@dataclass(frozen=True)
class Verdict:
    """What a response proved, if anything."""

    fired: bool
    indicator: str = ""
    # The exact substring of the response that decided it, for the evidence trail. Bounded.
    excerpt: str = ""
    confidence: str = "medium"


NO = Verdict(False)


@dataclass(frozen=True)
class Check:
    """A vulnerability class the scanner can test for."""

    id: str
    title: str
    category: str
    cwe: str
    owasp: str
    severity: str
    description: str
    remediation: str
    # Every check gets the marker so payloads are attributable to this scan in a customer's logs.
    probes: tuple[Probe, ...] = ()
    references: dict = field(default_factory=dict)


# ── reflected XSS ─────────────────────────────────────────────────────────────────────────────────
# The payload is inert: it is not a script, it does not call anything, and it renders as text in a
# browser. It exists to answer one question — does the application escape `<`, `>`, `"` and `'` —
# because an application that does not is one where a real payload would execute.
_XSS_PROBE = "\"'><{marker}>"

_SCRIPT_BLOCK = re.compile(r"(?is)<script\b[^>]*>(.*?)</script>")


def xss_probes(marker: str) -> tuple[Probe, ...]:
    return (Probe(payload=_XSS_PROBE.format(marker=marker), label="html-context"),)


def evaluate_xss(marker: str, payload: str, body: str, content_type: str) -> Verdict:
    """Reflected, *and* in a context where it would execute.

    Three ways this is wrong if done naively:

    * the marker appears but every dangerous character was escaped — the application is doing its
      job, and reporting it teaches the customer to ignore the scanner;
    * the response is not HTML — a marker echoed into `application/json` is not an XSS sink, it is
      an API returning what it was given;
    * the marker appears only inside an HTML comment or a text node with its brackets encoded.
    """
    if not body or marker not in body:
        return NO
    if "html" not in (content_type or "").lower():
        return NO

    # The response must contain the *unescaped* form. `html.escape` of the payload is exactly what
    # a correctly-behaving application produces, and finding that instead proves the opposite of a
    # finding — the marker is present because the application safely displayed it as text.
    raw = f"<{marker}>"
    if raw not in body:
        return NO
    del payload  # only the injected tag decides; the rest of the payload is context

    index = body.find(raw)
    excerpt = body[max(0, index - 60): index + len(raw) + 60]

    # Landing inside a <script> block is worth saying explicitly: there the injection does not even
    # need a tag, it only needs to break the surrounding string literal.
    in_script = any(raw in block for block in _SCRIPT_BLOCK.findall(body))
    where = " inside a <script> block" if in_script else ""
    return Verdict(
        True,
        indicator=f"the payload was reflected unescaped as <{marker}>{where}",
        excerpt=excerpt,
        confidence="high",
    )


# ── SQL injection ─────────────────────────────────────────────────────────────────────────────────
# Error-based and boolean-based only. No stacked statements, no `DROP`, no `WAITFOR`/`SLEEP`.
_SQL_ERRORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PostgreSQL", re.compile(r"(?i)\b(?:PSQLException|PG::\w+Error|unterminated quoted string|"
                              r"syntax error at or near|invalid input syntax for (?:type )?\w+)")),
    ("MySQL", re.compile(r"(?i)(?:You have an error in your SQL syntax|"
                         r"warning:\s*mysqli?_|MySqlException|com\.mysql\.jdbc)")),
    ("SQLite", re.compile(r"(?i)(?:SQLite3?::|sqlite3\.OperationalError|"
                          r"unrecognized token:|SQLITE_ERROR)")),
    ("Oracle", re.compile(r"(?i)(?:ORA-\d{5}|quoted string not properly terminated)")),
    ("SQL Server", re.compile(r"(?i)(?:Unclosed quotation mark after the character string|"
                              r"Microsoft OLE DB Provider for SQL Server|"
                              r"System\.Data\.SqlClient\.SqlException)")),
    ("generic", re.compile(r"(?i)(?:SQLSTATE\[\w+\]|sqlalchemy\.exc\.\w*(?:Programming|Operational)"
                           r"Error|psycopg2?\.errors\.\w+)")),
)


def sql_error_probes() -> tuple[Probe, ...]:
    # A lone quote. It cannot modify anything; it either breaks a concatenated query or it does not.
    return (Probe(payload="'", label="single-quote"),)


def sql_boolean_probes(value: str) -> tuple[Probe, Probe]:
    """A pair whose responses must differ only if the parameter reaches SQL.

    Both are read-only and both leave the result set unchanged in a parameterized application: `1=1`
    and `1=2` appended to a *value* are just strings. Reaching an interpreter is what makes them
    behave differently.
    """
    return (
        Probe(payload=f"{value}' AND '1'='1", label="true-branch"),
        Probe(payload=f"{value}' AND '1'='2", label="false-branch"),
    )


def evaluate_sql_error(body: str) -> Verdict:
    for engine, pattern in _SQL_ERRORS:
        match = pattern.search(body or "")
        if match:
            start = max(0, match.start() - 40)
            return Verdict(
                True,
                indicator=f"the response contained a {engine} error raised by the injected quote",
                excerpt=(body or "")[start: match.end() + 80],
                confidence="high",
            )
    return NO


def evaluate_sql_boolean(
    baseline: str, true_body: str, false_body: str, *, true_status: int, false_status: int,
) -> Verdict:
    """Differential: the true branch must match the baseline and the false branch must not.

    Requiring *both* halves is what separates an injection from an application that is simply
    unstable. A page with a timestamp or a rotating banner differs from itself on every request; it
    fails this test, correctly, because the true branch will not match the baseline either.
    """
    if not baseline or not true_body or false_body is None:
        return NO
    if true_body == false_body:
        return NO
    if _similar(baseline, true_body) and not _similar(baseline, false_body):
        return Verdict(
            True,
            indicator=(f"`AND '1'='1` returned the original page (HTTP {true_status}) while "
                       f"`AND '1'='2` did not (HTTP {false_status}) — the parameter is evaluated "
                       "as SQL"),
            excerpt=(f"baseline {len(baseline)}B / true {len(true_body)}B / "
                     f"false {len(false_body)}B"),
            confidence="high",
        )
    return NO


def _similar(left: str, right: str) -> bool:
    """Cheap structural comparison: identical, or within 2% in length and sharing their prefix.

    Deliberately not a fuzzy text ratio. A near-miss threshold is how a differential check starts
    reporting every dynamic page on the site.
    """
    if left == right:
        return True
    if not left or not right:
        return False
    longer = max(len(left), len(right))
    if abs(len(left) - len(right)) > max(16, longer * 0.02):
        return False
    head = min(200, len(left), len(right))
    return left[:head] == right[:head]


# ── path traversal ────────────────────────────────────────────────────────────────────────────────
_TRAVERSAL_SIGNATURES = (
    ("/etc/passwd", re.compile(r"root:[x*]?:0:0:")),
    ("Windows hosts file", re.compile(r"(?i)#\s*Copyright \(c\) \d+ Microsoft Corp")),
    ("PHP source", re.compile(r"<\?php\s")),
)


def traversal_probes() -> tuple[Probe, ...]:
    return (
        Probe(payload="../../../../etc/passwd", label="relative"),
        Probe(payload="....//....//....//etc/passwd", label="filtered-relative"),
        Probe(payload="%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", label="encoded"),
    )


def evaluate_traversal(body: str) -> Verdict:
    """A file the application had no business returning.

    Matched on file *content*, not on the payload being echoed. `/etc/passwd` appearing in an error
    message proves the path was rejected; `root:x:0:0:` proves it was read.
    """
    for name, pattern in _TRAVERSAL_SIGNATURES:
        match = pattern.search(body or "")
        if match:
            return Verdict(
                True,
                indicator=f"the response contained the contents of {name}",
                excerpt=(body or "")[match.start(): match.start() + 120],
                confidence="high",
            )
    return NO


# ── server-side template injection ────────────────────────────────────────────────────────────────
def ssti_probes() -> tuple[Probe, ...]:
    # Arithmetic only. It computes a number and touches nothing.
    return (
        Probe(payload="${7*191}", label="el"),
        Probe(payload="{{7*191}}", label="jinja-twig"),
        Probe(payload="<%= 7*191 %>", label="erb"),
    )


def evaluate_ssti(body: str) -> Verdict:
    """The server evaluated the expression.

    `7*191` rather than `7*7`: a page containing `1337` by coincidence is a great deal less likely
    than one containing `49`, and a false positive here claims remote code execution.
    """
    if "1337" in (body or ""):
        index = body.find("1337")
        return Verdict(
            True,
            indicator="the template expression was evaluated server-side (7*191 returned 1337)",
            excerpt=body[max(0, index - 60): index + 64],
            confidence="high",
        )
    return NO


# ── OS command injection ──────────────────────────────────────────────────────────────────────────
def command_probes(marker: str) -> tuple[Probe, ...]:
    """`echo` and nothing else.

    The command executed reads no file, writes nothing and contacts nothing; its entire effect is to
    print a string the scanner already knows. That is the whole point: proving a shell is reachable
    does not require doing anything with it.
    """
    return (
        Probe(payload=f";echo {marker}", label="semicolon"),
        Probe(payload=f"|echo {marker}", label="pipe"),
        Probe(payload=f"$(echo {marker})", label="subshell"),
        Probe(payload=f"`echo {marker}`", label="backtick"),
    )


def evaluate_command(marker: str, payload: str, body: str) -> Verdict:
    """The marker came back *without* the shell syntax around it — i.e. a shell ran the echo.

    If the raw payload is echoed verbatim the application simply reflected the input, which is at
    most an XSS question and definitely not command execution.
    """
    if not body or marker not in body:
        return NO
    if payload in body:
        return NO
    index = body.find(marker)
    return Verdict(
        True,
        indicator="the injected `echo` was executed by a shell and its output returned",
        excerpt=body[max(0, index - 60): index + len(marker) + 60],
        confidence="high",
    )


# ── open redirect ─────────────────────────────────────────────────────────────────────────────────
REDIRECT_HOST = "guardian-redirect-check.invalid"


def redirect_probes() -> tuple[Probe, ...]:
    # `.invalid` is reserved by RFC 2606 and can never resolve, so even a followed redirect reaches
    # nobody. The check is whether the application was willing, not whether the trip completed.
    return (
        Probe(payload=f"https://{REDIRECT_HOST}/", label="absolute"),
        Probe(payload=f"//{REDIRECT_HOST}/", label="scheme-relative"),
    )


def evaluate_redirect(status: int, location: str) -> Verdict:
    """A 3xx pointing at a host the parameter named."""
    if not (300 <= status < 400) or not location:
        return NO
    host = (urlparse(location if "//" in location else f"//{location}").hostname or "").lower()
    if host == REDIRECT_HOST:
        return Verdict(
            True,
            indicator=f"the parameter controlled the redirect target (Location: {location[:120]})",
            excerpt=location[:200],
            confidence="high",
        )
    return NO


# ── CORS misconfiguration ─────────────────────────────────────────────────────────────────────────
CORS_ORIGIN = "https://guardian-cors-check.invalid"


def evaluate_cors(headers: dict) -> Verdict:
    """Reflecting an arbitrary Origin *with credentials* is what makes CORS a vulnerability.

    Either half alone is a design decision: a public API may reflect any origin, and a same-origin
    app may allow credentials. Together they let any site read authenticated responses.
    """
    lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    allow_origin = lowered.get("access-control-allow-origin", "")
    credentials = lowered.get("access-control-allow-credentials", "").lower() == "true"
    if allow_origin.rstrip("/") == CORS_ORIGIN and credentials:
        return Verdict(
            True,
            indicator="the application reflected an arbitrary Origin and allowed credentials",
            excerpt=f"Access-Control-Allow-Origin: {allow_origin}; "
                    f"Access-Control-Allow-Credentials: true",
            confidence="high",
        )
    if allow_origin == "*" and credentials:
        # Browsers refuse this combination, so it is a misconfiguration rather than an exposure.
        return Verdict(
            True,
            indicator="`Access-Control-Allow-Origin: *` is combined with credentials, which every "
                      "browser rejects — the intended sharing does not work",
            excerpt="Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
            confidence="medium",
        )
    return NO


# ── the catalogue ─────────────────────────────────────────────────────────────────────────────────
CHECKS: dict[str, Check] = {
    "xss-reflected": Check(
        id="xss-reflected",
        title="Reflected cross-site scripting",
        category="injection",
        cwe="CWE-79",
        owasp="A03:2021",
        severity="high",
        description="A request parameter is reflected into the HTML response without escaping, so "
                    "an attacker who controls it controls markup in the victim's browser.",
        remediation="Escape output for its context (HTML body, attribute, JavaScript) and set a "
                    "Content-Security-Policy that forbids inline script.",
        references={"owasp": "A03:2021", "cwe": "CWE-79"},
    ),
    "sqli-error": Check(
        id="sqli-error",
        title="SQL injection (database error)",
        category="injection",
        cwe="CWE-89",
        owasp="A03:2021",
        severity="critical",
        description="A single quote in a request parameter produced a database error, which means "
                    "the parameter is concatenated into a SQL statement rather than bound to it.",
        remediation="Use parameterized queries. Never build SQL by string concatenation, and do "
                    "not return database errors to the client.",
        references={"owasp": "A03:2021", "cwe": "CWE-89"},
    ),
    "sqli-boolean": Check(
        id="sqli-boolean",
        title="SQL injection (boolean-based)",
        category="injection",
        cwe="CWE-89",
        owasp="A03:2021",
        severity="critical",
        description="A true and a false SQL condition injected into the same parameter produced "
                    "different responses, so the parameter is evaluated as SQL.",
        remediation="Use parameterized queries.",
        references={"owasp": "A03:2021", "cwe": "CWE-89"},
    ),
    "path-traversal": Check(
        id="path-traversal",
        title="Path traversal",
        category="injection",
        cwe="CWE-22",
        owasp="A01:2021",
        severity="critical",
        description="A request parameter is used to build a filesystem path, and a traversal "
                    "sequence returned the contents of a file outside the intended directory.",
        remediation="Resolve the path and verify it is inside the intended directory; prefer an "
                    "identifier mapped to a file server-side over a client-supplied path.",
        references={"owasp": "A01:2021", "cwe": "CWE-22"},
    ),
    "ssti": Check(
        id="ssti",
        title="Server-side template injection",
        category="injection",
        cwe="CWE-1336",
        owasp="A03:2021",
        severity="critical",
        description="A request parameter is rendered as a template expression, so the server "
                    "evaluates what the client sends. This usually escalates to code execution.",
        remediation="Never pass user input as a template; pass it as a *value* to a "
                    "fixed template.",
        references={"owasp": "A03:2021", "cwe": "CWE-1336"},
    ),
    "command-injection": Check(
        id="command-injection",
        title="OS command injection",
        category="injection",
        cwe="CWE-78",
        owasp="A03:2021",
        severity="critical",
        description="A request parameter reaches a shell: an injected `echo` was executed and its "
                    "output returned in the response.",
        remediation="Do not build shell command lines from input. Invoke the binary directly with "
                    "an argument list and no shell.",
        references={"owasp": "A03:2021", "cwe": "CWE-78"},
    ),
    "open-redirect": Check(
        id="open-redirect",
        title="Open redirect",
        category="web-misconfig",
        cwe="CWE-601",
        owasp="A01:2021",
        severity="medium",
        description="A request parameter controls the target of a redirect, so the application can "
                    "be used to send users to an attacker's site under its own domain.",
        remediation="Redirect only to a server-side allowlist, or to paths relative to the "
                    "application's own origin.",
        references={"owasp": "A01:2021", "cwe": "CWE-601"},
    ),
    "cors-misconfig": Check(
        id="cors-misconfig",
        title="Permissive CORS with credentials",
        category="web-misconfig",
        cwe="CWE-942",
        owasp="A05:2021",
        severity="high",
        description="The application reflects an arbitrary Origin and allows credentials, so any "
                    "website can read authenticated responses on a visitor's behalf.",
        remediation="Reflect only origins from a server-side allowlist, and never combine a "
                    "wildcard origin with credentials.",
        references={"owasp": "A05:2021", "cwe": "CWE-942"},
    ),
}


__all__ = [
    "CHECKS",
    "CORS_ORIGIN",
    "MARKER_STEM",
    "REDIRECT_HOST",
    "Check",
    "Probe",
    "Verdict",
    "command_probes",
    "evaluate_command",
    "evaluate_cors",
    "evaluate_redirect",
    "evaluate_sql_boolean",
    "evaluate_sql_error",
    "evaluate_ssti",
    "evaluate_traversal",
    "evaluate_xss",
    "redirect_probes",
    "sql_boolean_probes",
    "sql_error_probes",
    "ssti_probes",
    "traversal_probes",
    "xss_probes",
]
