"""What counts as proof of a web vulnerability (WP-D2).

Every test here is one of two questions, and the second is the one that decides whether the scanner
is usable:

* does the check fire on the response a vulnerable application actually returns?
* does it stay silent on the response a *correct* application returns?

A scanner that reports reflected XSS whenever its payload appears in the page — escaped, in a JSON
body, in an error message — produces a backlog nobody reads, and a backlog nobody reads is
indistinguishable from no scanner at all.
"""

from __future__ import annotations

import pytest
from guardian_scanner.dast import checks as c

MARKER = "gdn1a2b3c4d"
HTML = "text/html; charset=utf-8"


# ── reflected XSS ─────────────────────────────────────────────────────────────────────────────────
def test_an_unescaped_reflection_in_html_fires():
    body = f"<html><body>You searched for <{MARKER}></body></html>"
    verdict = c.evaluate_xss(MARKER, f"\"'><{MARKER}>", body, HTML)
    assert verdict.fired is True
    assert verdict.confidence == "high"
    assert MARKER in verdict.excerpt


def test_an_escaped_reflection_does_not_fire():
    """The application escaped the payload. That is it working, and reporting it teaches the
    customer to ignore the scanner."""
    body = f"<html><body>You searched for &lt;{MARKER}&gt;</body></html>"
    assert c.evaluate_xss(MARKER, f"\"'><{MARKER}>", body, HTML).fired is False


def test_a_reflection_in_json_does_not_fire():
    """An API returning what it was given is not an HTML injection sink."""
    body = f'{{"query": "<{MARKER}>", "results": []}}'
    assert c.evaluate_xss(MARKER, f"<{MARKER}>", body, "application/json").fired is False


def test_a_response_without_the_marker_does_not_fire():
    assert c.evaluate_xss(MARKER, "x", "<html>nothing here</html>", HTML).fired is False


def test_a_reflection_inside_a_script_block_is_called_out():
    body = f'<html><script>var q = "<{MARKER}>";</script></html>'
    verdict = c.evaluate_xss(MARKER, f"<{MARKER}>", body, HTML)
    assert verdict.fired is True
    assert "script" in verdict.indicator


def test_the_xss_payload_is_inert():
    """It is not a script and it calls nothing. It answers one question — does the application
    escape angle brackets — because an application that does not is one where a real payload
    would run."""
    payload = c.xss_probes(MARKER)[0].payload
    for dangerous in ("<script", "onerror", "javascript:", "alert(", "fetch(", "document."):
        assert dangerous not in payload.lower()


# ── SQL injection ─────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("body", [
    "django.db.utils.ProgrammingError: syntax error at or near \"'\"",
    "You have an error in your SQL syntax; check the manual",
    "Warning: mysqli_query(): You have an error",
    "sqlite3.OperationalError: unrecognized token: \"'\"",
    "ORA-01756: quoted string not properly terminated",
    "Unclosed quotation mark after the character string ''.",
    "SQLSTATE[42000]: Syntax error or access violation",
])
def test_a_database_error_fires(body):
    verdict = c.evaluate_sql_error(body)
    assert verdict.fired is True
    assert verdict.confidence == "high"


@pytest.mark.parametrize("body", [
    "<html><body>No results found for '</body></html>",
    "Error: invalid input",
    "500 Internal Server Error",
    "",
])
def test_an_ordinary_error_page_does_not_fire(body):
    """A generic 500 is not evidence of SQL injection — every application has them."""
    assert c.evaluate_sql_error(body).fired is False


def test_the_sql_payloads_change_nothing():
    """Read-only by construction: no stacked statements, no DDL, no timing."""
    payloads = [p.payload for p in c.sql_error_probes()]
    payloads += [p.payload for p in c.sql_boolean_probes("1")]
    for payload in payloads:
        lowered = payload.lower()
        for dangerous in (";", "drop", "delete", "insert", "update ", "truncate", "sleep",
                          "waitfor", "benchmark", "pg_sleep", "--", "/*"):
            assert dangerous not in lowered, payload


def test_a_true_false_pair_that_differs_correctly_fires():
    baseline = "<html><body>" + "user record " * 40 + "</body></html>"
    false_page = "<html><body>no results</body></html>"
    verdict = c.evaluate_sql_boolean(baseline, baseline, false_page,
                                     true_status=200, false_status=200)
    assert verdict.fired is True


def test_a_stable_page_that_ignores_both_branches_does_not_fire():
    page = "<html><body>static</body></html>"
    assert c.evaluate_sql_boolean(page, page, page, true_status=200, false_status=200).fired is False


def test_a_page_that_differs_from_itself_does_not_fire():
    """A rotating banner or a timestamp makes every response different. Requiring the *true* branch
    to match the baseline is what keeps that from being reported as an injection."""
    baseline = "<html><body>hello 12:00:01</body></html>"
    true_page = "<html><body>hello 12:00:02 and a much longer tail of content here</body></html>"
    false_page = "<html><body>hello 12:00:03 plus different content entirely, longer still</body>"
    assert c.evaluate_sql_boolean(baseline, true_page, false_page,
                                  true_status=200, false_status=200).fired is False


# ── path traversal ────────────────────────────────────────────────────────────────────────────────
def test_the_contents_of_etc_passwd_fires():
    body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    assert c.evaluate_traversal(body).fired is True


def test_an_error_message_naming_the_file_does_not_fire():
    """`/etc/passwd` in an error proves the path was *rejected*. `root:x:0:0:` proves it was read."""
    body = "Error: file not found: ../../../../etc/passwd"
    assert c.evaluate_traversal(body).fired is False


def test_the_traversal_payloads_only_read():
    for probe in c.traversal_probes():
        assert "etc" in probe.payload or "%2e" in probe.payload
        assert ";" not in probe.payload and "|" not in probe.payload


# ── template injection ────────────────────────────────────────────────────────────────────────────
def test_an_evaluated_expression_fires():
    assert c.evaluate_ssti("<html><body>1337</body></html>").fired is True


def test_an_unevaluated_expression_does_not_fire():
    assert c.evaluate_ssti("<html><body>{{7*191}}</body></html>").fired is False


def test_the_ssti_probe_only_does_arithmetic():
    """`7*191` rather than `7*7`: a page containing 1337 by coincidence is far less likely than one
    containing 49, and this check claims code execution."""
    for probe in c.ssti_probes():
        assert "7*191" in probe.payload
        for dangerous in ("import", "__", "os.", "system", "exec", "eval", "popen"):
            assert dangerous not in probe.payload


# ── command injection ─────────────────────────────────────────────────────────────────────────────
def test_an_executed_echo_fires():
    body = f"<html><body>ping output for {MARKER}</body></html>"
    assert c.evaluate_command(MARKER, f";echo {MARKER}", body).fired is True


def test_a_reflected_payload_does_not_fire():
    """If the whole payload comes back verbatim, the application echoed the input. Nothing ran."""
    body = f"<html><body>host not found: ;echo {MARKER}</body></html>"
    assert c.evaluate_command(MARKER, f";echo {MARKER}", body).fired is False


def test_the_command_payloads_only_echo():
    """Proving a shell is reachable does not require doing anything with it."""
    for probe in c.command_probes(MARKER):
        assert "echo" in probe.payload
        for dangerous in ("rm ", "curl", "wget", "nc ", "bash -i", "sleep", "cat /", "/dev/tcp",
                          ">", "chmod", "kill"):
            assert dangerous not in probe.payload


# ── open redirect ─────────────────────────────────────────────────────────────────────────────────
def test_a_redirect_to_the_probe_host_fires():
    verdict = c.evaluate_redirect(302, f"https://{c.REDIRECT_HOST}/")
    assert verdict.fired is True


def test_a_redirect_elsewhere_does_not_fire():
    assert c.evaluate_redirect(302, "https://app.example.com/login").fired is False


def test_a_200_does_not_fire():
    assert c.evaluate_redirect(200, f"https://{c.REDIRECT_HOST}/").fired is False


def test_the_redirect_probe_can_never_reach_anyone():
    """`.invalid` is reserved by RFC 2606 and cannot resolve, so even a followed redirect goes
    nowhere. The check is whether the application was willing."""
    assert c.REDIRECT_HOST.endswith(".invalid")


# ── CORS ──────────────────────────────────────────────────────────────────────────────────────────
def test_a_reflected_origin_with_credentials_fires():
    verdict = c.evaluate_cors({
        "Access-Control-Allow-Origin": c.CORS_ORIGIN,
        "Access-Control-Allow-Credentials": "true",
    })
    assert verdict.fired is True


def test_a_reflected_origin_without_credentials_does_not_fire():
    """A public API reflecting any origin is a design decision, not a vulnerability. It becomes one
    when credentials are allowed too."""
    assert c.evaluate_cors({"Access-Control-Allow-Origin": c.CORS_ORIGIN}).fired is False


def test_a_fixed_allowlisted_origin_does_not_fire():
    assert c.evaluate_cors({
        "Access-Control-Allow-Origin": "https://app.example.com",
        "Access-Control-Allow-Credentials": "true",
    }).fired is False


def test_a_wildcard_with_credentials_is_reported_as_a_misconfiguration():
    verdict = c.evaluate_cors({
        "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true",
    })
    assert verdict.fired is True
    assert verdict.confidence == "medium"


# ── CSRF ────────────────────────────────────────────────────────────────────────────────────────
_INSECURE_COOKIE = "session=abc; Path=/; HttpOnly"
_SAMESITE_COOKIE = "session=abc; Path=/; HttpOnly; SameSite=Lax"


def test_a_post_form_with_no_token_and_no_samesite_fires():
    verdict = c.evaluate_csrf("POST", ["amount", "to"], [_INSECURE_COOKIE])
    assert verdict.fired is True
    assert verdict.confidence == "medium"


def test_a_post_form_with_an_anti_csrf_token_does_not_fire():
    for token in ("csrfmiddlewaretoken", "authenticity_token", "__RequestVerificationToken",
                  "_token", "xsrf_token"):
        assert c.evaluate_csrf("POST", ["amount", token], [_INSECURE_COOKIE]).fired is False


def test_a_post_form_does_not_fire_when_the_cookie_is_samesite_protective():
    """SameSite=Strict/Lax is a real CSRF mitigation even without a token."""
    assert c.evaluate_csrf("POST", ["amount"], [_SAMESITE_COOKIE]).fired is False


def test_samesite_none_is_not_protective():
    assert c.samesite_protective("session=abc; SameSite=None") is False
    assert c.evaluate_csrf("POST", ["amount"], ["session=abc; SameSite=None"]).fired is True


def test_a_get_form_is_not_a_csrf_finding():
    assert c.evaluate_csrf("GET", ["q"], [_INSECURE_COOKIE]).fired is False


def test_a_tokenless_post_with_no_cookies_does_not_fire():
    """No session cookie means no session for a forged request to ride — low-false-positive."""
    assert c.evaluate_csrf("POST", ["email"], []).fired is False


# ── session identifier in the URL ─────────────────────────────────────────────────────────────────
def test_a_jsessionid_in_the_query_fires():
    verdict = c.evaluate_session_in_url("https://app.example.com/a?jsessionid=9F3A")
    assert verdict.fired is True and verdict.confidence == "high"


def test_a_jsessionid_matrix_param_in_the_path_fires():
    assert c.evaluate_session_in_url("https://app.example.com/page;jsessionid=9F3A").fired is True


def test_a_common_word_session_param_fires_at_lower_confidence():
    assert c.evaluate_session_in_url("https://app.example.com/x?sid=1").confidence == "medium"


def test_a_url_with_no_session_identifier_does_not_fire():
    assert c.evaluate_session_in_url("https://app.example.com/search?q=shoes&page=2").fired is False


# ── the catalogue ─────────────────────────────────────────────────────────────────────────────────
def test_every_check_carries_what_a_report_needs():
    for check in c.CHECKS.values():
        assert check.cwe.startswith("CWE-")
        assert check.owasp
        assert check.severity in ("critical", "high", "medium", "low", "info")
        assert len(check.description) > 40
        assert len(check.remediation) > 20


# ── BATCH 1 ─────────────────────────────────────────────────────────────────────────────────────────
# Time-based blind SQLi, exposed sensitive paths, GraphQL introspection, host-header injection,
# extended banner disclosure. Pure evaluators — numeric timings and recorded responses, no network.

# ── time-based blind SQLi ──
def test_time_blind_fires_on_a_proportional_delay():
    # control ~100ms; SLEEP(5) ~5.1s; SLEEP(10) ~10.1s — the delay tracks the sleep.
    v = c.evaluate_time_blind(5, control_ms=100, base_ms=5150, confirm_ms=10150)
    assert v.fired and v.confidence == "high"


def test_time_blind_does_not_fire_without_a_delay():
    assert c.evaluate_time_blind(5, control_ms=100, base_ms=160, confirm_ms=180).fired is False


def test_time_blind_does_not_fire_on_a_delay_that_is_not_proportional():
    # A fixed added latency (or a one-off spike): the base delayed, but doubling the sleep did NOT
    # roughly double the induced delay — so it is jitter/latency, not injection.
    assert c.evaluate_time_blind(5, control_ms=100, base_ms=8000, confirm_ms=9000).fired is False


def test_time_blind_does_not_fire_when_the_endpoint_is_just_slow():
    assert c.evaluate_time_blind(5, control_ms=6000, base_ms=6100, confirm_ms=6200).fired is False


def test_time_blind_probes_scale_consistently_when_the_sleep_is_doubled():
    # The scanner builds the 2x confirmation by regenerating the probes with a doubled sleep, so the
    # payload stays internally consistent — every occurrence of the sleep scales together.
    _mysql, _numeric, pg5 = c.time_blind_probes("1", 5)
    _mysql2, _numeric2, pg10 = c.time_blind_probes("1", 10)
    assert "SLEEP(5)" in _mysql.payload and "SLEEP(10)" in _mysql2.payload
    assert "10=(SELECT 10 FROM PG_SLEEP(10))" in pg10.payload
    assert "5=(SELECT 5 FROM PG_SLEEP(5))" in pg5.payload


# ── exposed sensitive paths ──
def test_exposed_git_head_fires_on_the_content_signature():
    assert c.evaluate_exposed_path(".git/HEAD", 200, "ref: refs/heads/main\n").fired is True


def test_exposed_dotenv_fires_on_env_keys():
    body = "APP_KEY=base64:abc\nDB_PASSWORD=hunter2\n"
    assert c.evaluate_exposed_path(".env", 200, body).fired is True


def test_exposed_server_status_fires():
    assert c.evaluate_exposed_path("server-status", 200, "Apache Server Status for host").fired


def test_exposed_path_does_not_fire_on_a_200_spa_fallback():
    # A single-page app answers every path with its index; a bare 200 must not light this up.
    assert c.evaluate_exposed_path(".git/HEAD", 200, "<!doctype html><html>app</html>").fired is False


def test_exposed_path_does_not_fire_on_a_404():
    assert c.evaluate_exposed_path(".env", 404, "APP_KEY=x").fired is False


# ── GraphQL introspection ──
def test_graphql_introspection_fires_on_a_schema_response():
    body = '{"data":{"__schema":{"queryType":{"name":"Query"}}}}'
    assert c.evaluate_graphql_introspection(200, "application/json", body).fired is True


def test_graphql_introspection_does_not_fire_when_disabled():
    body = '{"errors":[{"message":"introspection is disabled"}]}'
    assert c.evaluate_graphql_introspection(200, "application/json", body).fired is False


def test_graphql_introspection_does_not_fire_on_html():
    body = "<html><body>__schema queryType data</body></html>"
    assert c.evaluate_graphql_introspection(200, "text/html", body).fired is False


# ── host-header injection ──
def test_host_header_fires_when_reflected_into_the_redirect():
    v = c.evaluate_host_header_injection(302, f"https://{c.HOST_HEADER_MARKER}/login", "")
    assert v.fired and v.confidence == "high"


def test_host_header_fires_when_reflected_into_an_absolute_link():
    body = f'<link rel="canonical" href="https://{c.HOST_HEADER_MARKER}/home">'
    assert c.evaluate_host_header_injection(200, "", body).fired is True


def test_host_header_does_not_fire_on_a_bare_mention():
    # The marker echoed in plain text (not inside a URL) cannot redirect anyone.
    body = f"Unknown host {c.HOST_HEADER_MARKER} was ignored."
    assert c.evaluate_host_header_injection(200, "", body).fired is False


def test_host_header_does_not_fire_when_absent():
    assert c.evaluate_host_header_injection(200, "/home", "<html>ok</html>").fired is False


# ── extended banner disclosure ──
def test_extended_banner_reports_each_disclosing_header():
    verdicts = c.evaluate_banner_disclosure_extended({"X-Runtime": "12ms", "Via": "1.1 varnish"})
    assert len(verdicts) == 2


def test_extended_banner_excludes_the_headers_the_passive_check_already_covers():
    # server / x-powered-by / x-aspnet-version are reported by the passive posture check, not here.
    assert c.evaluate_banner_disclosure_extended(
        {"Server": "nginx", "X-Powered-By": "PHP/8"}) == ()
