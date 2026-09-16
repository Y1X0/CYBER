"""The single source of truth for plain-language results.

The same function feeds the console (via the API), the report and the remediation ticket, so what it
returns is what a person reads everywhere. It must explain a known CWE plainly, fall back sensibly
when there is no mapping, and never fabricate a location — the specifics come from the finding.
"""

from __future__ import annotations

from types import SimpleNamespace

from guardian_core.finding_explain import explain_finding


def _f(**over):
    base = {"cwe_id": None, "category": None, "severity": "high", "title": "x",
            "description": "", "evidence": {}}
    base.update(over)
    return SimpleNamespace(**base)


def test_a_known_cwe_is_explained_plainly():
    e = explain_finding(_f(cwe_id="CWE-306", title="Missing Authentication"))
    assert "without any credentials" in e.what_it_means.lower()
    assert "require authentication" in e.what_to_do.lower()
    assert e.why_it_matters


def test_category_fallback_when_no_cwe():
    e = explain_finding(_f(category="vuln-dep"))
    assert "dependency" in e.what_it_means.lower()
    assert "upgrade" in e.what_to_do.lower()


def test_description_and_its_remediation_are_used_as_a_last_resort():
    e = explain_finding(_f(
        category="other",
        description="The server exposes its version banner. Remediation: hide the Server header."))
    assert "version banner" in e.what_it_means
    assert "hide the Server header" in e.what_to_do


def test_severity_drives_why_it_matters_with_no_mapping():
    e = explain_finding(_f(severity="critical"))
    assert "critical" in e.why_it_matters.lower()


def test_location_is_composed_from_evidence_never_bare():
    assert explain_finding(_f(evidence={"endpoint": "GET /api/users"})).where == "Endpoint GET /api/users"
    assert explain_finding(_f(evidence={"file": "config/settings.py", "line": "12"})).where \
        == "File config/settings.py:12"
    assert explain_finding(_f(evidence={"package": "flask", "version": "2.0.1"})).where \
        == "Component flask@2.0.1"
    assert explain_finding(_f(evidence={})).where == ""


def test_it_reads_a_dict_too():
    e = explain_finding({"cwe_id": "CWE-798", "severity": "critical", "title": "secret",
                         "evidence": {}})
    assert "token" in e.what_it_means.lower() or "password" in e.what_it_means.lower()


def test_to_dict_exposes_the_fields_the_api_returns():
    d = explain_finding(_f(cwe_id="CWE-319")).to_dict()
    assert set(d) == {"what_it_means", "why_it_matters", "what_to_do", "where"}
