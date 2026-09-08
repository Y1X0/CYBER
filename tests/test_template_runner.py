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

        # ── batch 1 ──────────────────────────────────────────────────────────────────────────────
        "/.hg/hgrc": (200, "[paths]\ndefault = https://hg.example.com/app\n", {}),
        "/dump.sql": (200, "-- MySQL dump 10.13\nCREATE TABLE users (id int);\n", {}),
        "/phpmyadmin/": (200, '<form><input name="pma_username" /></form>', {}),
        "/.npmrc": (200, "//registry.npmjs.org/:_authToken=npm_liveTokenValue1234567890\n", {}),
        "/crossdomain.xml": (
            200,
            '<?xml version="1.0"?><cross-domain-policy>'
            '<allow-access-from domain="*" /></cross-domain-policy>',
            {"Content-Type": "text/xml"}),

        # Decoys: the path exists and returns 200, but the artefact is not the vulnerable one.
        # Each of these is the false positive its template is written to avoid.
        "/.bzr/branch-format": (200, "<html><body>Bazaar is a version control system</body></html>",
                                {}),
        "/db.sql": (200, "<html><body>File not found, sorry</body></html>", {}),
        "/adminer.php": (200, "<html><body>We use Adminer to manage the database</body></html>",
                         {}),
        "/.pypirc": (200, "[distutils]\nindex-servers =\n    pypi\n", {}),
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
        "hg-bzr-metadata-exposure",
        "backup-archive-exposure",     # via /dump.sql, which the template gained in batch 1
        "database-admin-console-exposure",
        "credential-file-exposure",
        "crossdomain-wildcard",
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
    # `backup-archive-exposure` left this set in batch 1: the fixture now serves a real dump at
    # /dump.sql, so its paths are no longer all absent and it is asserted positively above instead.
    absent = [t for t in loaded
              if t.id in {"docker-compose-exposure",
                          "elasticsearch-open", "jenkins-unauthenticated",
                          "wordpress-debug-log", "svn-entries-exposure", "swagger-ui-exposure"}]
    assert absent
    for template in absent:
        assert run_template(template, host="127.0.0.1", port=fixture_server, fetch=fetch) == []


# ── batch 1: one positive and one negative per template ───────────────────────────────────────────
#
# The negative half is the point. Every template here probes a path that plenty of hosts answer with
# 200 — a soft-404, a documentation page, a config file with no secret in it — so "the path exists"
# and "the finding is real" are different claims. Each decoy below is the specific false positive
# its template was written to refuse, served at the very path the template asks for.
def test_batch1_hg_metadata_fires_and_a_page_mentioning_bazaar_does_not(fixture_server):
    """/.hg/hgrc is a real INI; /.bzr/branch-format is an HTML page that says the word Bazaar.

    The template matches `^Bazaar` anchored at the start of the body, so prose cannot satisfy it.
    Firing there would mean the check reads paths rather than content.
    """
    loaded, _ = load_directory(library_path())
    template = next(t for t in loaded if t.id == "hg-bzr-metadata-exposure")
    detections = run_template(template, host="127.0.0.1", port=fixture_server,
                              fetch=_live_fetch(fixture_server), stop_at_first=False)
    assert [d.path for d in detections] == ["/.hg/hgrc"]


def test_batch1_sql_dump_fires_on_sql_and_not_on_a_soft_404(fixture_server):
    """/dump.sql carries a real dump; /db.sql returns 200 with an HTML "not found" page.

    Soft 404s are the dominant false positive for filename probes: the status says 200 and the body
    says otherwise. The body is what decides.
    """
    loaded, _ = load_directory(library_path())
    template = next(t for t in loaded if t.id == "backup-archive-exposure")
    detections = run_template(template, host="127.0.0.1", port=fixture_server,
                              fetch=_live_fetch(fixture_server), stop_at_first=False)
    paths = [d.path for d in detections]
    assert "/dump.sql" in paths
    assert "/db.sql" not in paths


def test_batch1_admin_console_fires_on_a_login_form_not_on_a_mention(fixture_server):
    """/phpmyadmin/ serves the login input; /adminer.php merely names the product in prose.

    Matching the product name would report every page that documents its own tooling.
    """
    loaded, _ = load_directory(library_path())
    template = next(t for t in loaded if t.id == "database-admin-console-exposure")
    detections = run_template(template, host="127.0.0.1", port=fixture_server,
                              fetch=_live_fetch(fixture_server), stop_at_first=False)
    paths = [d.path for d in detections]
    assert "/phpmyadmin/" in paths
    assert "/adminer.php" not in paths


def test_batch1_credential_file_fires_on_a_token_not_on_bare_config(fixture_server):
    """/.npmrc carries an _authToken; /.pypirc has an index-servers stanza and no password.

    A dotfile without a credential in it is configuration, not a credential exposure.
    """
    loaded, _ = load_directory(library_path())
    template = next(t for t in loaded if t.id == "credential-file-exposure")
    detections = run_template(template, host="127.0.0.1", port=fixture_server,
                              fetch=_live_fetch(fixture_server), stop_at_first=False)
    paths = [d.path for d in detections]
    assert "/.npmrc" in paths
    assert "/.pypirc" not in paths


def test_batch1_credential_evidence_is_redacted_in_full(fixture_server):
    """The npm token is in the fixture body. It must not reach the finding."""
    loaded, _ = load_directory(library_path())
    template = next(t for t in loaded if t.id == "credential-file-exposure")
    assert template.redact_evidence is True
    detections = run_template(template, host="127.0.0.1", port=fixture_server,
                              fetch=_live_fetch(fixture_server))
    assert detections
    for detection in detections:
        assert detection.snippet == "<redacted>"
        assert "npm_liveTokenValue" not in detection.snippet


def test_batch1_crossdomain_fires_on_the_wildcard_only():
    """A policy naming specific domains is correct configuration and must stay silent.

    Served from memory rather than the fixture because the distinction is one attribute value, and
    the two policies cannot both live at /crossdomain.xml.
    """
    loaded, _ = load_directory(library_path())
    template = next(t for t in loaded if t.id == "crossdomain-wildcard")

    def serve(body: str):
        def fetch(_method, _path, _headers):
            return Response(status=200, headers={"content-type": "text/xml"}, body=body)
        return fetch

    wildcard = '<cross-domain-policy><allow-access-from domain="*" /></cross-domain-policy>'
    specific = ('<cross-domain-policy><allow-access-from domain="app.example.com" />'
                '</cross-domain-policy>')
    assert run_template(template, host="h", port=443, fetch=serve(wildcard))
    assert run_template(template, host="h", port=443, fetch=serve(specific)) == []
