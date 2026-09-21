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
from urllib.parse import parse_qsl, urlparse

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


# ── cross-site request forgery (CSRF) ─────────────────────────────────────────────────────────────
# A hidden field whose name marks it as a synchronizer / anti-CSRF token. Framework conventions:
# Django `csrfmiddlewaretoken`, Rails `authenticity_token`, .NET `__RequestVerificationToken`, plus
# the generic csrf/xsrf/_token/nonce forms.
_CSRF_FIELD = re.compile(
    r"(?i)(?:csrf|xsrf|_token|authenticity_token|__requestverificationtoken|"
    r"anti[-_]?forgery|verification[-_]?token|nonce)"
)


def samesite_protective(set_cookie: str) -> bool:
    """A cookie declaring SameSite=Strict or SameSite=Lax — a real CSRF mitigation. `SameSite=None`,
    or no SameSite at all, provides none, and is treated as unprotective by both the CSRF check and
    the passive cookie posture check."""
    match = re.search(r"(?i)\bsamesite\s*=\s*(strict|lax|none)\b", set_cookie or "")
    return bool(match) and match.group(1).lower() in ("strict", "lax")


def evaluate_csrf(method: str, field_names, cookies_observed) -> Verdict:
    """A state-changing (POST) form with no anti-CSRF token, on a session that has no SameSite
    fallback — so a page on another origin can forge the request and the browser attaches the
    session cookie. Detected purely from the crawled form and the cookies already seen; nothing is
    submitted (a POST form is never sent — see the scanner).

    Deliberately conservative to stay low-false-positive: it fires only when a session actually
    exists (a cookie was observed) AND that cookie carries no SameSite=Strict/Lax. A tokenless POST
    on an app with no cookies (an unauthenticated search, or the login form itself) is not flagged:
    there is no session for a forged request to ride.
    """
    if (method or "").upper() != "POST":
        return NO
    names = [n for n in (field_names or ()) if n]
    if any(_CSRF_FIELD.search(n) for n in names):
        return NO
    cookies = [c for c in (cookies_observed or []) if c]
    if not cookies:
        return NO
    if any(samesite_protective(c) for c in cookies):
        return NO
    return Verdict(
        True,
        indicator="a state-changing POST form carries no anti-CSRF token and the session cookie "
                  "has no SameSite=Strict/Lax fallback",
        excerpt=f"form fields: {', '.join(names)[:200]}",
        confidence="medium",
    )


# ── session identifier exposed in the URL ─────────────────────────────────────────────────────────
# Names that carry a session / authentication token. In a URL these leak into server logs, the
# Referer header, browser history and shared links (CWE-598 / CWE-200). The common-word names
# (`sid`, `session`) are reported at lower confidence because they are sometimes something else.
SESSION_URL_PARAMS: tuple[str, ...] = (
    "jsessionid", "phpsessid", "aspsessionid", "asp.net_sessionid", "cfid", "cftoken",
    "sessionid", "session_id", "sessiontoken", "session_token", "auth_token", "access_token",
    "sid", "session", "sessid",
)
_LOW_CONFIDENCE_SESSION = frozenset({"sid", "session", "cfid", "cftoken"})


def evaluate_session_in_url(url: str) -> Verdict:
    """A session identifier is present in the URL — as a query parameter, or as a `;name=` matrix
    parameter in the path (e.g. `/page;jsessionid=…`)."""
    parsed = urlparse(url or "")
    query_names = {k.lower() for k, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    # A `;name=value` matrix parameter lands in urlparse().params (not the path); e.g. jsessionid.
    matrix = (parsed.params or "").lower()
    path = parsed.path.lower()
    for name in SESSION_URL_PARAMS:
        if name in query_names or f"{name}=" in matrix or f";{name}=" in path:
            return Verdict(
                True,
                indicator=f"the URL carries a session identifier (`{name}`), which leaks into "
                          "logs, the Referer header, browser history and shared links",
                excerpt=url[:200],
                confidence="medium" if name in _LOW_CONFIDENCE_SESSION else "high",
            )
    return NO


# ── time-based blind SQL injection ────────────────────────────────────────────────────────────────
# The module's other SQL checks are error- and boolean-based on purpose (no timing). This one is the
# deliberate, bounded exception the operator asked for: a CAPPED sleep, non-stacked, read-only, and
# only ever confirmed — never reported on a single slow response, which could be jitter or a load
# spike. The scanner sends a control (no sleep), a base sleep, and — only if the base actually
# delayed — a double-sleep confirmation; this evaluator fires only when the induced delay tracks the
# injected sleep proportionally, which a flaky network cannot fake.
TIME_BLIND_SECONDS = 5


def time_blind_probes(value: str, seconds: int) -> tuple[Probe, ...]:
    """One base-sleep payload per dialect/context. `pg_sleep` is wrapped in a scalar subquery and
    `SLEEP` in a boolean context — both non-stacked and read-only (they change nothing; they only
    make a reachable database pause). The scanner sends the 2x confirmation only after a base
    probe delays.
    """
    v = value or "1"
    # This SELECT…PG_SLEEP string is an attack payload SENT TO THE TARGET to prove its parameter
    # reaches SQL — it is never a query Guardian itself executes, so S608 does not apply.
    pg_sleep = (
        f"{v}' AND {seconds}=(SELECT {seconds} FROM PG_SLEEP({seconds}))-- -"  # noqa: S608
    )
    return (
        Probe(payload=f"{v}' AND SLEEP({seconds})-- -", label="mysql-single-quote"),
        Probe(payload=f"{v} AND SLEEP({seconds})", label="mysql-numeric"),
        Probe(payload=pg_sleep, label="postgres-single-quote"),
    )


def evaluate_time_blind(seconds: int, control_ms: float, base_ms: float,
                        confirm_ms: float) -> Verdict:
    """Fire only on a delay that is present, large enough, and *proportional* to the injected sleep.

    * ``control_ms`` — a benign request, to establish the normal latency floor.
    * ``base_ms`` — a ``SLEEP(seconds)`` payload.
    * ``confirm_ms`` — a ``SLEEP(2*seconds)`` payload, sent only because the base already delayed.

    The base must clear the control by most of one sleep, and doubling the sleep must roughly double
    the *induced* delay (delay above control). A constant added latency, a slow endpoint, or random
    jitter fails the proportionality test — that is what keeps a timing check from crying wolf.
    """
    base_target = seconds * 1000.0
    induced_base = base_ms - control_ms
    induced_confirm = confirm_ms - control_ms
    if induced_base < base_target * 0.6:
        return NO
    if induced_confirm < base_target * 1.4:
        return NO
    # Doubling the sleep must scale the induced delay by at least ~1.6× (rules out fixed latency).
    if induced_confirm < induced_base * 1.6:
        return NO
    return Verdict(
        True,
        indicator=(f"a SLEEP({seconds}s) payload delayed the response by "
                   f"{induced_base / 1000:.1f}s and SLEEP({seconds * 2}s) by "
                   f"{induced_confirm / 1000:.1f}s — the delay tracks the injected sleep, so the "
                   "parameter reaches SQL"),
        excerpt=(f"control {control_ms:.0f}ms / sleep(t) {base_ms:.0f}ms / "
                 f"sleep(2t) {confirm_ms:.0f}ms"),
        confidence="high",
    )


# ── exposed sensitive paths ───────────────────────────────────────────────────────────────────────
# A fixed, tiny list of well-known sensitive paths — NOT a wordlist, NOT brute-forcing. Each fires
# only on a positive *content* signal, never on a bare 200 (a SPA that answers every path with its
# index page must not light this up). GET only; reads what the server already serves.
_EXPOSED_PATHS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (".git/HEAD", "a Git repository (.git/HEAD)", re.compile(r"(?m)^ref:\s+refs/")),
    (".git/config", "a Git repository (.git/config)",
     re.compile(r"(?s)\[core\].*repositoryformatversion")),
    (".env", "a dotenv secrets file (.env)",
     re.compile(r"(?m)^\s*(?:APP_KEY|APP_SECRET|DB_(?:PASSWORD|HOST|USERNAME)|"
                r"SECRET_KEY|AWS_(?:SECRET_)?ACCESS_KEY|DATABASE_URL)\s*=")),
    (".DS_Store", "a macOS .DS_Store directory index", re.compile(r"Bud1")),
    ("server-status", "the Apache mod_status page (/server-status)",
     re.compile(r"(?i)Apache Server Status|Server uptime:")),
    ("backup.sql", "a database backup (backup.sql)",
     re.compile(r"(?i)(?:CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)")),
)


def exposed_path_specs() -> tuple[str, ...]:
    """The paths to probe (relative to the site root), in order."""
    return tuple(path for path, _label, _sig in _EXPOSED_PATHS)


def evaluate_exposed_path(path: str, status: int, body: str) -> Verdict:
    """Fire only when the path returned 200 AND its body matches that path's content signature."""
    if status != 200 or not body:
        return NO
    for candidate, label, signature in _EXPOSED_PATHS:
        if candidate != path:
            continue
        match = signature.search(body)
        if match:
            return Verdict(
                True,
                indicator=f"the server returned {label} at /{path}",
                excerpt=body[max(0, match.start() - 20): match.start() + 120],
                confidence="high",
            )
    return NO


# ── GraphQL introspection exposed ─────────────────────────────────────────────────────────────────
# A read-only introspection query sent over GET (`?query={__schema...}`). If the server answers with
# the schema, introspection is enabled — an information-disclosure that hands an attacker the full
# API shape. Nothing is mutated; a server that only accepts POST simply 400s and is not flagged.
GRAPHQL_ENDPOINTS: tuple[str, ...] = ("graphql", "api/graphql", "v1/graphql", "query")
GRAPHQL_INTROSPECTION_QUERY = "{__schema{queryType{name}}}"


def evaluate_graphql_introspection(status: int, content_type: str, body: str) -> Verdict:
    """Fire when a JSON response returns the introspection schema (`data.__schema.queryType`)."""
    if not body:
        return NO
    ctype = (content_type or "").lower()
    if "json" not in ctype and not body.lstrip().startswith("{"):
        return NO
    # A real introspection response carries the schema under `data`; an error response does not.
    if '"__schema"' in body and '"queryType"' in body and '"data"' in body:
        index = body.find('"__schema"')
        return Verdict(
            True,
            indicator="GraphQL introspection is enabled — the server returned its schema, exposing "
                      "every type, query and mutation the API defines",
            excerpt=body[max(0, index - 20): index + 160],
            confidence="high",
        )
    return NO


# ── host header injection ─────────────────────────────────────────────────────────────────────────
# A benign alternate Host header (a reserved `.invalid` name that resolves to nobody). If the app
# echoes it into a redirect Location or into an absolute link in the body, the Host header is
# trusted — the seed of password-reset poisoning and web-cache poisoning. No account action is
# taken; the check is only whether the value comes back.
HOST_HEADER_MARKER = "guardian-hostcheck.invalid"


def evaluate_host_header_injection(status: int, location: str, body: str) -> Verdict:
    """Fire when the injected Host is reflected into the redirect target or an absolute URL."""
    marker = HOST_HEADER_MARKER
    loc = location or ""
    if marker in loc:
        return Verdict(
            True,
            indicator=f"the Host header was reflected into the redirect target (Location: "
                      f"{loc[:120]})",
            excerpt=loc[:200],
            confidence="high",
        )
    # Only an absolute reference to the injected host counts — a bare mention in text does not let
    # an attacker redirect anyone. Require it inside a URL (scheme-prefixed or protocol-relative).
    for needle in (f"https://{marker}", f"http://{marker}", f"//{marker}"):
        if body and needle in body:
            index = body.find(needle)
            return Verdict(
                True,
                indicator="the Host header was reflected into an absolute URL in the response "
                          "body, so it controls links the page generates",
                excerpt=body[max(0, index - 40): index + 80],
                confidence="medium",
            )
    return NO


# ── extended banner / version disclosure ──────────────────────────────────────────────────────────
# NOTE ON security.txt: deliberately NOT implemented here — Guardian already flags a missing
# RFC 9116 security.txt via the `security-txt-missing` web-checks template. Re-adding it in the DAST
# engine would double-report. Only the new half of the request — banner/version disclosure beyond
# the Server header — is implemented below.
#
# Version/banner-leaking response headers BEYOND the three the passive posture check already covers
# (server, x-powered-by, x-aspnet-version). Each present header is a small information leak.
_EXTENDED_BANNER_HEADERS: tuple[str, ...] = (
    "x-aspnetmvc-version", "x-generator", "x-drupal-dynamic-cache", "x-runtime", "x-version",
    "x-backend-server", "x-served-by", "x-application-version", "x-nginx-version", "via",
)


def evaluate_banner_disclosure_extended(headers: dict) -> tuple[Verdict, ...]:
    """One verdict per extra disclosing header present. Excludes the three the passive check already
    reports, so there is no double-counting."""
    lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    out: list[Verdict] = []
    for name in _EXTENDED_BANNER_HEADERS:
        value = lowered.get(name)
        if value:
            out.append(Verdict(
                True,
                indicator=f"the `{name}` response header discloses software/version information",
                excerpt=f"{name}: {value}"[:200],
                confidence="high",
            ))
    return tuple(out)


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
    "csrf-missing-token": Check(
        id="csrf-missing-token",
        title="Cross-site request forgery (no anti-CSRF token)",
        category="web-misconfig",
        cwe="CWE-352",
        owasp="A01:2021",
        severity="high",
        description="A state-changing POST form has no anti-CSRF (synchronizer) token, and the "
                    "session cookie carries no SameSite=Strict/Lax fallback, so a page on another "
                    "site can forge the request in a logged-in victim's browser.",
        remediation="Add a per-session anti-CSRF token to state-changing forms and verify it "
                    "server-side; set session cookies SameSite=Lax or Strict as defence in depth.",
        references={"owasp": "A01:2021", "cwe": "CWE-352"},
    ),
    "session-id-in-url": Check(
        id="session-id-in-url",
        title="Session identifier exposed in URL",
        category="web-misconfig",
        cwe="CWE-598",
        owasp="A07:2021",
        severity="medium",
        description="A session or authentication identifier appears in the URL, where it leaks "
                    "into server logs, the Referer header, browser history and shared links — any "
                    "of which lets someone replay the session.",
        remediation="Carry the session in a cookie with Secure/HttpOnly/SameSite; never place a "
                    "session or token in the URL.",
        references={"owasp": "A07:2021", "cwe": "CWE-598"},
    ),
    "xss-stored": Check(
        id="xss-stored",
        title="Stored cross-site scripting",
        category="injection",
        cwe="CWE-79",
        owasp="A03:2021",
        severity="high",
        description="A value submitted through a form was persisted and later returned unescaped "
                    "on another page, so an attacker's markup runs in every visitor's browser, "
                    "not only their own.",
        remediation="Escape output for its context on every page that renders stored data, and set "
                    "a Content-Security-Policy that forbids inline script.",
        references={"owasp": "A03:2021", "cwe": "CWE-79"},
    ),
    "sqli-time-blind": Check(
        id="sqli-time-blind",
        title="Blind SQL injection (time-based)",
        category="injection",
        cwe="CWE-89",
        owasp="A03:2021",
        severity="high",
        description="A capped, read-only SLEEP payload made the response take proportionally "
                    "longer than a control request, and doubling the sleep doubled the delay — so "
                    "the parameter reaches SQL even though the page shows no error or content "
                    "difference.",
        remediation="Use parameterized queries. Never concatenate request input into SQL.",
        references={"owasp": "A03:2021", "cwe": "CWE-89"},
    ),
    "exposed-sensitive-path": Check(
        id="exposed-sensitive-path",
        title="Exposed sensitive file or path",
        category="web-misconfig",
        cwe="CWE-538",
        owasp="A05:2021",
        severity="medium",
        description="A well-known sensitive path (e.g. .git/, .env, .DS_Store, a database backup, "
                    "or the Apache server-status page) is served to anonymous requests, leaking "
                    "source, secrets, or internal state.",
        remediation="Block access to VCS directories, dotfiles, backups and status endpoints at "
                    "the web server, and never deploy them to the document root.",
        references={"owasp": "A05:2021", "cwe": "CWE-538"},
    ),
    "graphql-introspection": Check(
        id="graphql-introspection",
        title="GraphQL introspection enabled",
        category="web-misconfig",
        cwe="CWE-200",
        owasp="A05:2021",
        severity="medium",
        description="The GraphQL endpoint answers an introspection query, returning its full "
                    "schema — every type, query and mutation — which hands an attacker a complete "
                    "map of the API's attack surface.",
        remediation="Disable introspection in production, or restrict it to authenticated internal "
                    "callers.",
        references={"owasp": "A05:2021", "cwe": "CWE-200"},
    ),
    "host-header-injection": Check(
        id="host-header-injection",
        title="Host header injection",
        category="web-misconfig",
        cwe="CWE-20",
        owasp="A03:2021",
        severity="medium",
        description="The application reflects an attacker-supplied Host header into a redirect or "
                    "into absolute links it generates, which enables password-reset poisoning and "
                    "web-cache poisoning.",
        remediation="Validate the Host header against an allowlist of expected hostnames, and "
                    "build absolute URLs from a configured canonical host, not the request Host.",
        references={"owasp": "A03:2021", "cwe": "CWE-20"},
    ),
    "banner-disclosure-extended": Check(
        id="banner-disclosure-extended",
        title="Version/banner disclosure in response headers",
        category="web-misconfig",
        cwe="CWE-200",
        owasp="A05:2021",
        severity="low",
        description="A response header beyond the usual Server banner (e.g. X-Generator, "
                    "X-Runtime, X-AspNetMvc-Version, Via) discloses the software or version in "
                    "use, helping an attacker match the target to known vulnerabilities.",
        remediation="Strip version-identifying response headers at the web server or application "
                    "framework.",
        references={"owasp": "A05:2021", "cwe": "CWE-200"},
    ),
}


__all__ = [
    "CHECKS",
    "CORS_ORIGIN",
    "GRAPHQL_ENDPOINTS",
    "GRAPHQL_INTROSPECTION_QUERY",
    "HOST_HEADER_MARKER",
    "MARKER_STEM",
    "REDIRECT_HOST",
    "SESSION_URL_PARAMS",
    "TIME_BLIND_SECONDS",
    "Check",
    "Probe",
    "Verdict",
    "command_probes",
    "evaluate_banner_disclosure_extended",
    "evaluate_command",
    "evaluate_cors",
    "evaluate_csrf",
    "evaluate_exposed_path",
    "evaluate_graphql_introspection",
    "evaluate_host_header_injection",
    "evaluate_redirect",
    "evaluate_session_in_url",
    "evaluate_sql_boolean",
    "evaluate_sql_error",
    "evaluate_ssti",
    "evaluate_time_blind",
    "evaluate_traversal",
    "evaluate_xss",
    "exposed_path_specs",
    "redirect_probes",
    "samesite_protective",
    "sql_boolean_probes",
    "sql_error_probes",
    "ssti_probes",
    "time_blind_probes",
    "traversal_probes",
    "xss_probes",
]
