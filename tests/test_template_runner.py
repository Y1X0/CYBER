"""Template execution: matcher semantics, redaction, and a live run (WP-D1).

The last test in this file is the one that matters. It starts a real HTTP server on loopback that
serves the artefacts the shipped templates look for — an exposed `.git/config`, a readable `.env`, a
directory index, a Spring actuator — and runs the actual library against it over a real socket. That
is the difference between "the matcher unit-tests pass" and "the engine detects things".

The server is bound to 127.0.0.1 and created by this test. Nothing outside the machine is contacted,
which is also why the run goes through the runner's injected fetch rather than the provider: the
provider's SSRF guard refuses loopback by design, and that refusal is asserted in
`test_web_checks_provider_unit.py` rather than weakened here.
"""

from __future__ import annotations

import http.server
import threading

import httpx
import pytest
from guardian_scanner.templates import load_template, run_template
from guardian_scanner.templates.loader import library_path, load_directory
from guardian_scanner.templates.model import Matcher
from guardian_scanner.templates.runner import Response, matcher_hits, redact, substitute

GIT_CONFIG = "[core]\n\trepositoryformatversion = 0\n\turl = https://git.example.com/app.git\n"
ENV_FILE = "APP_SECRET=supersecrettokenvalue1234567890\nDB_PASSWORD=hunter2\n"


def _response(status=200, body="", headers=None) -> Response:
    return Response(status=status, headers=headers or {}, body=body)


# ── matcher semantics ─────────────────────────────────────────────────────────────────────────────
def test_word_matcher_condition_and_requires_every_word():
    matcher = Matcher(type="word", words=("alpha", "beta"), condition="and")
    assert matcher_hits(matcher, _response(body="alpha and beta")) is True
    assert matcher_hits(matcher, _response(body="alpha only")) is False


def test_word_matcher_condition_or_requires_one():
    matcher = Matcher(type="word", words=("alpha", "beta"), condition="or")
    assert matcher_hits(matcher, _response(body="beta only")) is True
    assert matcher_hits(matcher, _response(body="neither")) is False


def test_negative_matcher_asserts_an_absence():
    """The header-missing case: a matcher has to be able to say "this was NOT present"."""
    matcher = Matcher(type="word", part="header", words=("content-security-policy",), negative=True)
    assert matcher_hits(matcher, _response(headers={"server": "nginx"})) is True
    assert matcher_hits(matcher, _response(headers={"content-security-policy": "default-src"})) \
        is False


def test_status_and_size_matchers():
    assert matcher_hits(Matcher(type="status", status=(200, 302)), _response(status=302)) is True
    assert matcher_hits(Matcher(type="status", status=(200,)), _response(status=404)) is False
    assert matcher_hits(Matcher(type="size", sizes=(5,)), _response(body="12345")) is True


def test_case_insensitive_matching():
    matcher = Matcher(type="word", words=("Index Of /",), case_insensitive=True)
    assert matcher_hits(matcher, _response(body="<h1>index of /</h1>")) is True


def test_part_selects_what_is_read():
    matcher = Matcher(type="word", part="header", words=("nginx",))
    assert matcher_hits(matcher, _response(body="nginx", headers={})) is False
    assert matcher_hits(matcher, _response(body="", headers={"server": "nginx"})) is True


# ── matchers-condition across matchers ────────────────────────────────────────────────────────────
def _two_matcher_template(condition: str) -> str:
    return f"""
id: two-matcher-check
info:
  name: Two matchers
  severity: info
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/x"
    matchers-condition: {condition}
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "present"
"""


def test_matchers_condition_and_requires_both():
    template = load_template(_two_matcher_template("and"))
    fired = run_template(template, host="h", port=443,
                         fetch=lambda *_: _response(200, "present"))
    assert len(fired) == 1
    assert run_template(template, host="h", port=443,
                        fetch=lambda *_: _response(404, "present")) == []


def test_matchers_condition_or_requires_either():
    template = load_template(_two_matcher_template("or"))
    assert run_template(template, host="h", port=443,
                        fetch=lambda *_: _response(404, "present")) != []


# ── evidence discipline ───────────────────────────────────────────────────────────────────────────
def test_token_like_values_are_redacted():
    assert "supersecrettokenvalue1234567890" not in redact(ENV_FILE)
    assert "***" in redact(ENV_FILE)


def test_a_secret_adjacent_template_emits_no_snippet_at_all():
    loaded, _ = load_directory(library_path())
    env_template = next(t for t in loaded if t.id == "env-file-exposure")
    detections = run_template(env_template, host="h", port=443,
                              fetch=lambda *_: _response(200, ENV_FILE))
    assert len(detections) == 1
    assert detections[0].snippet == "<redacted>"
    assert "hunter2" not in str(detections[0])


def test_snippets_are_bounded():
    loaded, _ = load_directory(library_path())
    git = next(t for t in loaded if t.id == "git-config-exposure")
    detections = run_template(git, host="h", port=443,
                              fetch=lambda *_: _response(200, GIT_CONFIG + "x" * 5000))
    assert len(detections[0].snippet) <= 130


def test_extractors_pull_named_values():
    loaded, _ = load_directory(library_path())
    git = next(t for t in loaded if t.id == "git-config-exposure")
    detections = run_template(git, host="h", port=443, fetch=lambda *_: _response(200, GIT_CONFIG))
    assert detections[0].extracted["remote"] == ("https://git.example.com/app.git",)


def test_a_failed_fetch_is_not_a_detection():
    """A connection reset must not be reported as a finding, and must not raise into the scan."""
    loaded, _ = load_directory(library_path())
    git = next(t for t in loaded if t.id == "git-config-exposure")

    def boom(*_args):
        raise ConnectionResetError("refused")

    assert run_template(git, host="h", port=443, fetch=boom) == []


def test_base_url_substitution():
    assert substitute("{{BaseURL}}/x", base_url="https://h:443", hostname="h") == "https://h:443/x"
    assert substitute("{{Hostname}}", base_url="", hostname="h.example") == "h.example"


# ── a real HTTP server ────────────────────────────────────────────────────────────────────────────
class _Fixture(http.server.BaseHTTPRequestHandler):
    """Serves exactly the artefacts the shipped templates look for, and nothing else."""

    ROUTES: dict[str, tuple[int, str, dict[str, str]]] = {
        "/.git/config": (200, GIT_CONFIG, {}),
        "/.git/HEAD": (200, "ref: refs/heads/main\n", {}),
        "/.env": (200, ENV_FILE, {}),
        "/": (200, "<html><head><title>Index of /</title></head><body>Index of /</body></html>",
              {"Server": "nginx/1.24.0"}),
        "/server-status": (200, "<h1>Apache Server Status for fixture</h1>", {}),
        "/actuator": (200, '{"_links":{"self":{"href":"/actuator"}}}',
                      {"Content-Type": "application/json"}),
        "/metrics": (200, "# HELP http_requests_total Total\n# TYPE http_requests_total counter\n",
                     {}),
        # Present but NOT vulnerable: the template requires a phpinfo() banner, and this is a
        # perfectly ordinary page at the same path. A scanner that fires on the path alone is
        # reporting a URL, not a finding.
        "/phpinfo.php": (200, "<html><body>Nothing to see</body></html>", {}),
    }

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's interface
        status, body, headers = self.ROUTES.get(self.path, (404, "not found", {}))
        payload = body.encode()
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):  # keep the test output readable
        return


@pytest.fixture(scope="module")
def fixture_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _live_fetch(port: int):
    """A plain fetch against the local fixture.

    The provider's hardened fetch refuses loopback, which is correct and is asserted separately.
    Template semantics and egress policy are different layers, and proving one must not require
    loosening the other.
    """
    client = httpx.Client(follow_redirects=False, timeout=5)

    def fetch(method: str, path: str, headers: tuple[tuple[str, str], ...]) -> Response:
        resp = client.request(method, f"http://127.0.0.1:{port}{path}", headers=dict(headers))
        return Response(status=resp.status_code,
                        headers={k.lower(): v for k, v in resp.headers.items()},
                        body=resp.text)

    return fetch


def test_the_library_detects_real_exposures_over_a_real_socket(fixture_server):
    port = fixture_server
    loaded, rejected = load_directory(library_path())
    assert rejected == ()
    fetch = _live_fetch(port)

    fired = {
        detection.template.id
        for template in loaded
        for detection in run_template(template, host="127.0.0.1", port=port, fetch=fetch)
    }

    assert {
        "git-config-exposure",
        "git-head-exposure",
        "env-file-exposure",
        "directory-listing",
        "apache-server-status",
        "spring-actuator-exposure",
        "prometheus-metrics-exposure",
        "missing-security-headers",   # the fixture sends no CSP
    } <= fired


def test_a_present_but_harmless_path_is_not_reported(fixture_server):
    """`/phpinfo.php` exists on the fixture and returns 200 with an ordinary page. Reporting it
    would mean the engine is matching on paths rather than on evidence."""
    loaded, _ = load_directory(library_path())
    phpinfo = next(t for t in loaded if t.id == "phpinfo-exposure")
    assert run_template(phpinfo, host="127.0.0.1", port=fixture_server,
                        fetch=_live_fetch(fixture_server)) == []


def test_absent_paths_produce_nothing(fixture_server):
    """Every 404 route must stay silent — otherwise a scan of an empty server produces findings."""
    loaded, _ = load_directory(library_path())
    fetch = _live_fetch(fixture_server)
    absent = [t for t in loaded
              if t.id in {"backup-archive-exposure", "docker-compose-exposure",
                          "elasticsearch-open", "jenkins-unauthenticated",
                          "wordpress-debug-log", "svn-entries-exposure", "swagger-ui-exposure"}]
    assert absent
    for template in absent:
        assert run_template(template, host="127.0.0.1", port=fixture_server, fetch=fetch) == []
