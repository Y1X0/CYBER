"""What counts as a source, a sink, and a sanitizer (WP-D4).

Kept as data rather than code so adding a framework is a table edit, and so the same catalogue can
be asserted against in tests without executing the analyser.

**Sanitizers are per vulnerability class, not global.** `html.escape` makes a value safe to place in
a page and does nothing whatsoever for a shell command; `shlex.quote` is the reverse. A scanner that
treats "was sanitized" as one boolean will happily clear a command injection because the developer
remembered to HTML-escape, which is precisely the mistake that gets a product uninstalled. Each
sanitizer therefore declares the CWE classes it actually neutralizes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from guardian_core.enums import Severity

# ── vulnerability classes ─────────────────────────────────────────────────────────────────────────
CWE_CODE_INJECTION = "CWE-95"
CWE_COMMAND_INJECTION = "CWE-78"
CWE_SQL_INJECTION = "CWE-89"
CWE_PATH_TRAVERSAL = "CWE-22"
CWE_DESERIALIZATION = "CWE-502"
CWE_SSRF = "CWE-918"
CWE_OPEN_REDIRECT = "CWE-601"
CWE_SSTI = "CWE-1336"
CWE_XSS = "CWE-79"
CWE_LOG_INJECTION = "CWE-117"

# Everything a type coercion protects against: the result is an int/float/bool/UUID, so there is no
# string left for an injection payload to live in.
_ALL_CLASSES = frozenset(
    {
        CWE_CODE_INJECTION,
        CWE_COMMAND_INJECTION,
        CWE_SQL_INJECTION,
        CWE_PATH_TRAVERSAL,
        CWE_DESERIALIZATION,
        CWE_SSRF,
        CWE_OPEN_REDIRECT,
        CWE_SSTI,
        CWE_XSS,
        CWE_LOG_INJECTION,
    }
)


@dataclass(frozen=True)
class Sink:
    """A call that turns attacker-controlled data into an action."""

    id: str
    title: str
    cwe: str
    owasp: str
    severity: Severity
    # Fully-qualified callables, resolved through the module's import aliases.
    dotted: tuple[str, ...] = ()
    # Bare method names, matched on the attribute alone because the receiver's type is unknown
    # (`cursor.execute`, `db.raw`). Lower confidence than a resolved dotted name.
    methods: tuple[str, ...] = ()
    # Argument positions that carry the dangerous value; empty means "any argument".
    positions: tuple[int, ...] = ()
    keywords: tuple[str, ...] = ()
    # Some sinks are only dangerous in a particular configuration, e.g. subprocess with shell=True.
    requires_kwarg: tuple[str, str] | None = None
    remediation: str = ""


SINKS: tuple[Sink, ...] = (
    Sink(
        id="taint-code-exec",
        title="Attacker-controlled data reaches a code evaluator",
        cwe=CWE_CODE_INJECTION,
        owasp="A03:2021",
        severity=Severity.CRITICAL,
        dotted=("eval", "exec", "compile", "builtins.eval", "builtins.exec"),
        positions=(0,),
        remediation="Parse the value instead of evaluating it; there is no safe way to eval input.",
    ),
    Sink(
        id="taint-shell-command",
        title="Attacker-controlled data reaches a shell",
        cwe=CWE_COMMAND_INJECTION,
        owasp="A03:2021",
        severity=Severity.CRITICAL,
        dotted=("os.system", "os.popen", "commands.getoutput", "popen2.popen2"),
        positions=(0,),
        remediation="Pass an argument list to subprocess without a shell, or quote with"
                    " shlex.quote.",
    ),
    Sink(
        id="taint-subprocess-shell",
        title="Attacker-controlled data reaches subprocess with shell=True",
        cwe=CWE_COMMAND_INJECTION,
        owasp="A03:2021",
        severity=Severity.CRITICAL,
        dotted=(
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
        ),
        positions=(0,),
        requires_kwarg=("shell", "True"),
        remediation="Drop shell=True and pass argv as a list.",
    ),
    Sink(
        id="taint-subprocess-argv",
        title="Attacker-controlled data reaches the program name of a subprocess",
        cwe=CWE_COMMAND_INJECTION,
        owasp="A03:2021",
        severity=Severity.HIGH,
        dotted=("subprocess.run", "subprocess.call", "subprocess.Popen", "os.execv", "os.execve"),
        positions=(0,),
        remediation="Choose the executable from a fixed allowlist rather than from the request.",
    ),
    Sink(
        id="taint-sql",
        title="Attacker-controlled data reaches a SQL statement",
        cwe=CWE_SQL_INJECTION,
        owasp="A03:2021",
        severity=Severity.CRITICAL,
        dotted=("sqlalchemy.text",),
        methods=("execute", "executemany", "executescript", "raw"),
        positions=(0,),
        remediation="Use bound parameters; string-building a query is never made safe by escaping.",
    ),
    Sink(
        id="taint-deserialization",
        title="Attacker-controlled data is deserialized",
        cwe=CWE_DESERIALIZATION,
        owasp="A08:2021",
        severity=Severity.CRITICAL,
        dotted=(
            "pickle.load",
            "pickle.loads",
            "cPickle.loads",
            "marshal.loads",
            "dill.loads",
            "shelve.open",
            "yaml.load",
            "yaml.unsafe_load",
            "yaml.full_load",
        ),
        positions=(0,),
        remediation="Deserializing untrusted data is remote code execution;"
                    " use JSON or yaml.safe_load.",
    ),
    Sink(
        id="taint-path",
        title="Attacker-controlled data reaches a filesystem path",
        cwe=CWE_PATH_TRAVERSAL,
        owasp="A01:2021",
        severity=Severity.HIGH,
        dotted=("open", "io.open", "os.remove", "os.unlink", "os.rename", "shutil.rmtree",
                "shutil.copy", "shutil.move", "pathlib.Path"),
        methods=("send_file", "send_from_directory"),
        positions=(0,),
        remediation="Resolve the path and confirm it stays inside the intended root before"
                    " opening.",
    ),
    Sink(
        id="taint-ssrf",
        title="Attacker-controlled data reaches an outbound request URL",
        cwe=CWE_SSRF,
        owasp="A10:2021",
        severity=Severity.HIGH,
        dotted=(
            "requests.get", "requests.post", "requests.put", "requests.delete", "requests.head",
            "requests.patch", "requests.request",
            "httpx.get", "httpx.post", "httpx.request", "httpx.stream",
            "urllib.request.urlopen", "urllib.request.urlretrieve",
        ),
        positions=(0,),
        keywords=("url",),
        remediation="Allowlist the host, refuse redirects, and reject non-public addresses.",
    ),
    Sink(
        id="taint-open-redirect",
        title="Attacker-controlled data reaches a redirect target",
        cwe=CWE_OPEN_REDIRECT,
        owasp="A01:2021",
        severity=Severity.MEDIUM,
        dotted=("flask.redirect", "redirect", "django.shortcuts.redirect"),
        positions=(0,),
        remediation="Redirect to a path chosen from a fixed map, never to a URL taken from input.",
    ),
    Sink(
        id="taint-ssti",
        title="Attacker-controlled data reaches a template compiler",
        cwe=CWE_SSTI,
        owasp="A03:2021",
        severity=Severity.CRITICAL,
        dotted=("flask.render_template_string", "render_template_string",
                "jinja2.Template", "jinja2.Environment.from_string"),
        positions=(0,),
        remediation="Render a fixed template and pass the value as context, never as the template.",
    ),
    Sink(
        id="taint-xss",
        title="Attacker-controlled data is marked as trusted markup",
        cwe=CWE_XSS,
        owasp="A03:2021",
        severity=Severity.HIGH,
        dotted=("markupsafe.Markup", "flask.Markup", "Markup",
                "django.utils.safestring.mark_safe", "mark_safe"),
        positions=(0,),
        remediation="Let the template escape the value; mark_safe/Markup disables that protection.",
    ),
)


@dataclass(frozen=True)
class Sanitizer:
    """A call whose result is safe — for the named classes only."""

    id: str
    dotted: tuple[str, ...]
    neutralizes: frozenset[str]
    methods: tuple[str, ...] = ()
    note: str = ""


SANITIZERS: tuple[Sanitizer, ...] = (
    Sanitizer(
        id="coerce",
        dotted=("int", "float", "bool", "len", "uuid.UUID", "ipaddress.ip_address"),
        neutralizes=_ALL_CLASSES,
        note="the result is not a string, so there is nothing left to inject into",
    ),
    Sanitizer(
        id="shell-quote",
        dotted=("shlex.quote", "pipes.quote"),
        neutralizes=frozenset({CWE_COMMAND_INJECTION}),
        note="safe as one shell word; does nothing for SQL, paths or markup",
    ),
    Sanitizer(
        id="html-escape",
        dotted=("html.escape", "cgi.escape", "markupsafe.escape", "bleach.clean"),
        neutralizes=frozenset({CWE_XSS}),
        note="safe in markup only — an HTML-escaped value is still a live shell payload",
    ),
    Sanitizer(
        id="url-quote",
        dotted=("urllib.parse.quote", "urllib.parse.quote_plus"),
        neutralizes=frozenset({CWE_OPEN_REDIRECT}),
        note="percent-encoding is not an SSRF control; the host is still attacker-chosen",
    ),
    Sanitizer(
        id="basename",
        dotted=("os.path.basename",),
        neutralizes=frozenset({CWE_PATH_TRAVERSAL}),
        note="strips directory components, so ../ cannot escape",
    ),
    Sanitizer(
        id="regex-escape",
        dotted=("re.escape",),
        neutralizes=frozenset({CWE_CODE_INJECTION}),
        note="only protects the regex compiler itself",
    ),
)

_BY_DOTTED: dict[str, Sanitizer] = {}
for _s in SANITIZERS:
    for _d in _s.dotted:
        _BY_DOTTED[_d] = _s


def sanitizer_for(dotted: str | None) -> Sanitizer | None:
    return _BY_DOTTED.get(dotted) if dotted else None


# ── sources ───────────────────────────────────────────────────────────────────────────────────────
# Attribute paths that are attacker-controlled the moment they are read. The base name is matched
# loosely (`request`, `req`) because the object is usually a framework global rather than an import.
REQUEST_OBJECTS: frozenset[str] = frozenset({"request", "req", "self.request"})
REQUEST_ATTRIBUTES: frozenset[str] = frozenset(
    {
        "args", "form", "json", "data", "values", "cookies", "headers", "files", "query_params",
        "GET", "POST", "COOKIES", "META", "body", "path", "path_params", "url", "full_path",
        "query_string", "stream", "get_json", "get_data", "remote_addr", "referrer", "user_agent",
    }
)

# Fully-resolved callables/attributes that yield untrusted input directly.
SOURCE_DOTTED: frozenset[str] = frozenset(
    {
        "input", "sys.argv", "sys.stdin",
        "flask.request", "starlette.requests.Request",
    }
)

# Decorators that make every parameter of the function attacker-controlled: it is a route handler,
# so its arguments come off the wire.
ROUTE_DECORATOR_ATTRS: frozenset[str] = frozenset(
    {"route", "get", "post", "put", "patch", "delete", "head", "options", "websocket",
     "middleware", "api_route"}
)


@dataclass
class SourceHit:
    """Where a value entered the program from outside."""

    kind: str  # "request" | "route-parameter" | "stdin" | "argv"
    label: str
    line: int
    detail: dict = field(default_factory=dict)
