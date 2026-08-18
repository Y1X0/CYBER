"""The template validator is a safety boundary, so these are refusal tests (WP-D1).

Guardian runs these templates against systems a customer authorized us to *look at*. The nuclei
template language can do considerably more than look: evaluate expressions, replay raw HTTP, fuzz
with payload sets, drive a headless browser, and call an out-of-band interaction server. Each of
those is a way for a reviewed-looking YAML file to become an action nobody approved.

So the validator denies by default, and the tests below assert the denials rather than the
acceptances. A parser that is merely permissive would pass every test about what it accepts.
"""

from __future__ import annotations

import pytest
from guardian_scanner.templates.loader import (
    TemplateRejected,
    library_path,
    load_directory,
    load_template,
)

MINIMAL = """
id: example-check
info:
  name: Example
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/example"
    matchers:
      - type: word
        words:
          - "hello"
"""


def _with(extra: str, *, body: str = MINIMAL) -> str:
    return body + extra


# ── the baseline parses ───────────────────────────────────────────────────────────────────────────
def test_a_minimal_template_loads():
    template = load_template(MINIMAL)
    assert template.id == "example-check"
    assert template.severity.value == "medium"
    assert template.requests[0].method == "GET"
    assert template.requests[0].path == "/example"
    assert template.requests[0].matchers[0].words == ("hello",)


def test_classification_is_carried_through():
    template = load_template(
        MINIMAL.replace(
            "  severity: medium",
            "  severity: high\n"
            "  classification:\n"
            "    cve-id: CVE-2021-44228\n"
            "    cwe-id: CWE-502\n"
            "    cvss-score: 10.0",
        )
    )
    assert template.classification.cve_ids == ("CVE-2021-44228",)
    assert template.classification.cwe_ids == ("CWE-502",)
    assert template.classification.cvss_score == 10.0


# ── refusals: capabilities that are not "look at it" ──────────────────────────────────────────────
def test_dsl_matchers_are_refused():
    """`dsl` is expression evaluation. It is the single most powerful construct in the language."""
    bad = MINIMAL.replace('      - type: word\n        words:\n          - "hello"',
                          '      - type: dsl\n        dsl:\n          - "len(body) > 10"')
    with pytest.raises(TemplateRejected, match="dsl"):
        load_template(bad)


def test_out_of_band_callbacks_are_refused():
    for marker in ("interactsh-url", "{{interactsh_url}}", "oast", "collaborator"):
        bad = MINIMAL.replace('          - "hello"', f'          - "{marker}"')
        with pytest.raises(TemplateRejected, match="out-of-band"):
            load_template(bad)


def test_payload_sets_and_attack_modes_are_refused():
    """A payload set turns detection into fuzzing or credential brute force."""
    for extra in ("    payloads:\n      user:\n        - admin\n",
                  "    attack: clusterbomb\n",
                  "    fuzzing:\n      - part: query\n"):
        with pytest.raises(TemplateRejected, match="unsupported keys"):
            load_template(_with(extra))


def test_raw_requests_are_refused():
    with pytest.raises(TemplateRejected, match="unsupported keys"):
        load_template(_with('    raw:\n      - "GET / HTTP/1.1"\n'))


def test_unsafe_mode_is_refused():
    with pytest.raises(TemplateRejected, match="unsupported keys"):
        load_template(_with("    unsafe: true\n"))


def test_race_and_pipeline_are_refused():
    for extra in ("    race: true\n", "    pipeline: true\n"):
        with pytest.raises(TemplateRejected, match="unsupported keys"):
            load_template(_with(extra))


def test_redirect_following_is_refused():
    """A response must never choose the next target — that is SSRF with extra steps."""
    with pytest.raises(TemplateRejected, match="redirects"):
        load_template(_with("    redirects: true\n"))
    with pytest.raises(TemplateRejected, match="redirects"):
        load_template(_with("    host-redirects: true\n"))


@pytest.mark.parametrize("protocol", ["network", "dns", "ssl", "code", "javascript", "headless",
                                      "file", "flow", "variables", "self-contained"])
def test_every_other_protocol_and_scripting_block_is_refused(protocol):
    with pytest.raises(TemplateRejected, match="unsupported top-level keys"):
        load_template(MINIMAL + f"\n{protocol}: true\n")


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def test_only_read_methods_are_allowed(method):
    """Detection reads. A scanner that writes has changed the customer's system, not observed it."""
    with pytest.raises(TemplateRejected, match="method"):
        load_template(MINIMAL.replace("method: GET", f"method: {method}"))


def test_helper_interpolation_is_refused():
    """`{{BaseURL}}` is a substitution; `{{rand_base(5)}}` is a function call."""
    bad = MINIMAL.replace('"{{BaseURL}}/example"', '"{{BaseURL}}/{{rand_base(5)}}"')
    with pytest.raises(TemplateRejected, match="interpolation"):
        load_template(bad)


def test_interpolation_inside_a_matcher_word_is_refused():
    bad = MINIMAL.replace('          - "hello"', '          - "{{md5(body)}}"')
    with pytest.raises(TemplateRejected, match="interpolation"):
        load_template(bad)


def test_path_traversal_in_a_template_path_is_refused():
    bad = MINIMAL.replace('"{{BaseURL}}/example"', '"{{BaseURL}}/../../etc/passwd"')
    with pytest.raises(TemplateRejected, match="plain absolute path"):
        load_template(bad)


def test_a_header_with_a_newline_is_refused():
    """CRLF in a header value is request splitting."""
    bad = MINIMAL.replace(
        '    matchers:',
        '    headers:\n      X-Test: "a\\r\\nInjected: 1"\n    matchers:',
    )
    with pytest.raises(TemplateRejected, match="newline"):
        load_template(bad)


# ── refusals: malformed rather than dangerous ─────────────────────────────────────────────────────
def test_yaml_is_parsed_safely():
    """`yaml.load` would construct arbitrary Python objects from a template file."""
    bad = MINIMAL.replace('          - "hello"', "          - !!python/object/apply:os.system ['id']")
    with pytest.raises(TemplateRejected):
        load_template(bad)


def test_a_template_with_no_matcher_is_refused():
    """A template that matches nothing would report on every response it received."""
    bad = MINIMAL.split("    matchers:")[0]
    with pytest.raises(TemplateRejected, match="at least one matcher"):
        load_template(bad)


def test_a_template_with_no_request_is_refused():
    with pytest.raises(TemplateRejected, match="no http request"):
        load_template("id: nothing-here\ninfo:\n  name: X\n  severity: info\n")


def test_a_malformed_id_is_refused():
    with pytest.raises(TemplateRejected, match="id"):
        load_template(MINIMAL.replace("id: example-check", "id: 'Bad ID!'"))


def test_an_uncompilable_regex_is_refused():
    bad = MINIMAL.replace('      - type: word\n        words:\n          - "hello"',
                          '      - type: regex\n        regex:\n          - "([unclosed"')
    with pytest.raises(TemplateRejected, match="does not compile"):
        load_template(bad)


def test_an_oversized_template_is_refused():
    with pytest.raises(TemplateRejected, match="larger than"):
        load_template(MINIMAL + "\n# " + "x" * 70_000)


def test_an_unknown_severity_is_refused():
    with pytest.raises(TemplateRejected, match="severity"):
        load_template(MINIMAL.replace("severity: medium", "severity: catastrophic"))


# ── the shipped library ───────────────────────────────────────────────────────────────────────────
def test_every_shipped_template_passes_its_own_validator():
    loaded, rejected = load_directory(library_path())
    assert rejected == (), f"shipped templates must be valid: {rejected}"
    assert len(loaded) >= 15


def test_shipped_template_ids_are_unique_and_well_formed():
    loaded, _ = load_directory(library_path())
    ids = [t.id for t in loaded]
    assert len(ids) == len(set(ids))
    assert all(t.name and t.description for t in loaded)


def test_shipped_templates_only_probe_read_methods():
    loaded, _ = load_directory(library_path())
    assert {r.method for t in loaded for r in t.requests} <= {"GET", "HEAD"}


def test_secret_adjacent_templates_are_marked_for_redaction():
    """An `.env` template has, by definition, just read a credential when it matches."""
    loaded, _ = load_directory(library_path())
    by_id = {t.id: t for t in loaded}
    assert by_id["env-file-exposure"].redact_evidence is True
    assert by_id["directory-listing"].redact_evidence is False


def test_a_rejected_template_is_reported_rather_than_skipped(tmp_path):
    """A check that silently stops running produces a clean report — the worst failure mode here."""
    (tmp_path / "good.yaml").write_text(MINIMAL)
    (tmp_path / "bad.yaml").write_text(MINIMAL.replace("method: GET", "method: POST"))
    loaded, rejected = load_directory(tmp_path)
    assert [t.id for t in loaded] == ["example-check"]
    assert len(rejected) == 1
    assert "method" in rejected[0].reason


def test_duplicate_ids_are_rejected(tmp_path):
    (tmp_path / "a.yaml").write_text(MINIMAL)
    (tmp_path / "b.yaml").write_text(MINIMAL)
    loaded, rejected = load_directory(tmp_path)
    assert len(loaded) == 1
    assert "duplicate" in rejected[0].reason
