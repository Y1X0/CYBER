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


# ── the catalogue ─────────────────────────────────────────────────────────────────────────────────
def test_every_check_carries_what_a_report_needs():
    for check in c.CHECKS.values():
        assert check.cwe.startswith("CWE-")
        assert check.owasp
        assert check.severity in ("critical", "high", "medium", "low", "info")
        assert len(check.description) > 40
        assert len(check.remediation) > 20
