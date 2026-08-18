"""The DAST scanner against a real, deliberately vulnerable application (WP-D2).

Everything in `test_dast_checks.py` and `test_dast_scanner.py` runs on constructed strings. This
runs over real TCP against a real HTTP server built for the purpose: a small application with six
planted flaws and four safe endpoints that look like them.

The fixture is local and controlled. Nothing here touches a public target — an active scanner
pointed at somebody else's site is the thing the whole authorization gate exists to prevent.

What it has to prove is both halves:

* every planted flaw is found — a scanner that misses them is decoration;
* **none of the safe endpoints is reported** — the safe endpoints are the ones that escape, bind,
  validate and allowlist correctly, and a scanner that flags them produces a report the customer
  learns to ignore.
"""

from __future__ import annotations

import contextlib
import html
import http.server
import threading
from urllib.parse import parse_qs, urlparse

import pytest
from guardian_scanner.dast.scanner import ActiveScanner, Response

PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


class _VulnerableApp(http.server.BaseHTTPRequestHandler):
    """Six planted flaws, four correct implementations of the same features."""

    def log_message(self, *_args) -> None:  # noqa: ANN002 - silence the test server
        return

    def do_GET(self) -> None:  # noqa: N802, C901, PLR0912 - a router is a router
        parsed = urlparse(self.path)
        query = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        path = parsed.path
        status, headers, body = 200, {"Content-Type": "text/html; charset=utf-8"}, ""

        if path == "/":
            body = (
                '<html><body>'
                '<a href="/search?q=shoes">search</a>'
                '<a href="/item?id=1">item</a>'
                '<a href="/file?name=readme.txt">file</a>'
                '<a href="/greet?name=world">greet</a>'
                '<a href="/ping?host=localhost">ping</a>'
                '<a href="/go?next=/home">go</a>'
                '<a href="/safe-search?q=shoes">safe search</a>'
                '<a href="/safe-item?id=1">safe item</a>'
                '<a href="/safe-file?name=readme.txt">safe file</a>'
                '<a href="/safe-go?next=/home">safe go</a>'
                '<a href="/logout">logout</a>'
                '<form action="/find" method="get"><input name="term" value="x"></form>'
                '<form action="/transfer" method="post"><input name="amount"></form>'
                '</body></html>'
            )

        # ── planted: reflected XSS (no escaping) ────────────────────────────────────────────────
        elif path in ("/search", "/find"):
            value = query.get("q", query.get("term", ""))
            body = f"<html><body>Results for {value}</body></html>"

        # ── planted: SQL injection (string-concatenated query, error leaked) ────────────────────
        elif path == "/item":
            value = query.get("id", "")
            if "'" in value:
                status = 500
                body = ("<html><body>sqlite3.OperationalError: unrecognized token: \"'\""
                        "</body></html>")
            else:
                body = f"<html><body>Item {html.escape(value)}</body></html>"

        # ── planted: path traversal (path joined from input) ────────────────────────────────────
        elif path == "/file":
            name = query.get("name", "")
            body = PASSWD if "etc/passwd" in name.replace("%2f", "/") else \
                "<html><body>readme contents</body></html>"

        # ── planted: template injection (input rendered as a template) ──────────────────────────
        elif path == "/greet":
            name = query.get("name", "")
            rendered = name
            for opener, closer in (("{{", "}}"), ("${", "}"), ("<%=", "%>")):
                if opener in name and closer in name:
                    expression = name.split(opener, 1)[1].rsplit(closer, 1)[0].strip()
                    with contextlib.suppress(Exception):
                        left, right = expression.split("*")
                        rendered = str(int(left.strip()) * int(right.strip()))
            body = f"<html><body>Hello {rendered}</body></html>"

        # ── planted: command injection (input concatenated into a shell command) ────────────────
        elif path == "/ping":
            host = query.get("host", "")
            # The fixture emulates a shell rather than running one: the flaw under test is the
            # scanner's ability to *recognize* executed output, and a test that spawns a real shell
            # to prove it is a test that spawns a real shell.
            echoed = ""
            for separator in (";", "|", "$(", "`"):
                if separator in host:
                    tail = host.split(separator, 1)[1].strip("()`")
                    if tail.startswith("echo "):
                        echoed = tail[5:].strip()
            body = f"<html><body>PING {html.escape(host.split(';')[0])} {echoed}</body></html>"

        # ── planted: open redirect (unvalidated `next`) ─────────────────────────────────────────
        elif path == "/go":
            status, headers = 302, {"Location": query.get("next", "/")}

        # ── planted: CORS reflecting any origin with credentials ───────────────────────────────
        elif path == "/api/data":
            origin = self.headers.get("Origin", "")
            headers = {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }
            body = '{"ok": true}'

        # ── correct implementations of the same four features ───────────────────────────────────
        elif path == "/safe-search":
            body = f"<html><body>Results for {html.escape(query.get('q', ''))}</body></html>"
        elif path == "/safe-item":
            value = query.get("id", "")
            body = (f"<html><body>Item {html.escape(value)}</body></html>" if value.isdigit()
                    else "<html><body>No such item</body></html>")
        elif path == "/safe-file":
            name = query.get("name", "")
            body = ("<html><body>readme contents</body></html>" if name == "readme.txt"
                    else "<html><body>Not allowed</body></html>")
        elif path == "/safe-go":
            target = query.get("next", "/")
            # `startswith("/")` alone is NOT enough — `//evil.example/` is a scheme-relative URL
            # and every browser treats it as absolute. The first version of this fixture had
            # exactly that bug, and the scanner reported it, correctly.
            safe = target.startswith("/") and not target.startswith("//")
            status, headers = 302, {"Location": target if safe else "/"}

        elif path == "/logout":
            body = "<html><body>you should not be here</body></html>"
        else:
            status, body = 404, "<html><body>not found</body></html>"

        payload = body.encode()
        self.send_response_only(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@contextlib.contextmanager
def _server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _VulnerableApp)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _transport(seen: list[str] | None = None):
    """A real HTTP client over a real socket.

    The engine's transport pins every connection to a validated *public* address, which by design
    refuses loopback — so this drives the scanner directly, exactly as WP-B2 and WP-B3 were
    live-verified against local listeners. The pinning itself is covered by `test_dast_ssrf.py`.
    """
    import httpx

    def fetch(url: str, headers: dict) -> Response:
        if seen is not None:
            seen.append(url)
        try:
            with httpx.Client(follow_redirects=False, timeout=5.0) as client:
                response = client.get(url, headers={"user-agent": "guardian-dast", **headers})
        except Exception as exc:  # noqa: BLE001
            return Response(status=0, headers={}, body="", url=url,
                            error=f"{type(exc).__name__}: {exc}")
        return Response(
            status=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()},
            body=response.text, url=str(response.url),
        )

    return fetch


@pytest.fixture(scope="module")
def scan():
    with _server() as base:
        seen: list[str] = []
        scanner = ActiveScanner(
            fetch=_transport(seen), authorized_hosts={"127.0.0.1"},
            max_requests=1500, rate_per_second=0, deadline_seconds=120,
        )
        result = scanner.scan([f"{base}/", f"{base}/api/data"], max_pages=40, max_depth=2)
        return {"result": result, "base": base, "requests": seen}


def _fired(scan) -> set[tuple[str, str]]:
    return {(issue.check_id, urlparse(issue.url).path) for issue in scan["result"].issues}


# ── every planted flaw is found ───────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(("check", "path"), [
    ("xss-reflected", "/search"),
    ("xss-reflected", "/find"),
    ("sqli-error", "/item"),
    ("path-traversal", "/file"),
    ("ssti", "/greet"),
    ("command-injection", "/ping"),
    ("open-redirect", "/go"),
    ("cors-misconfig", "/api/data"),
])
def test_the_planted_flaw_is_found(scan, check, path):
    assert (check, path) in _fired(scan)


# ── nothing is reported on the correct implementations ────────────────────────────────────────────
@pytest.mark.parametrize("path", ["/safe-search", "/safe-item", "/safe-file", "/safe-go"])
def test_the_safe_endpoint_is_not_reported(scan, path):
    """These escape, validate, bind and allowlist correctly. A scanner that flags them is a scanner
    the customer learns to ignore."""
    assert not [issue for issue in scan["result"].issues if urlparse(issue.url).path == path]


def test_the_scan_reports_no_false_positives_at_all(scan):
    reported = {path for _, path in _fired(scan)}
    assert reported <= {"/search", "/find", "/item", "/file", "/greet", "/ping", "/go",
                        "/api/data"}


# ── evidence ──────────────────────────────────────────────────────────────────────────────────────
def test_every_issue_carries_the_request_that_proved_it(scan):
    for issue in scan["result"].issues:
        assert issue.parameter
        assert issue.payload
        assert issue.indicator
        assert issue.confidence in ("high", "medium", "low")


def test_the_evidence_quotes_what_the_application_actually_returned(scan):
    traversal = next(i for i in scan["result"].issues if i.check_id == "path-traversal")
    assert "root:" in traversal.excerpt

    ssti = next(i for i in scan["result"].issues if i.check_id == "ssti")
    assert "1337" in ssti.excerpt


# ── safety, observed on the wire ──────────────────────────────────────────────────────────────────
def test_the_state_changing_endpoint_was_never_requested(scan):
    """`/logout` is linked from the index. It must not appear in the traffic."""
    assert not any(urlparse(url).path == "/logout" for url in scan["requests"])


def test_the_post_form_was_never_submitted(scan):
    assert not any(urlparse(url).path == "/transfer" for url in scan["requests"])


def test_every_request_stayed_on_the_authorized_host(scan):
    assert scan["requests"]
    assert all(urlparse(url).hostname == "127.0.0.1" for url in scan["requests"])


def test_every_request_was_a_get(scan):
    """There is no other verb in the package: the transport only issues GET."""
    assert scan["result"].requests_made == len(scan["requests"])


def test_the_scan_completed_within_its_budget(scan):
    result = scan["result"]
    assert result.requests_made < 1500
    assert result.budget_exhausted is False
    assert result.deadline_reached is False
