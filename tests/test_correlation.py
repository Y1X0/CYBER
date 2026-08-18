"""Cross-engine correlation rules (WP-E1).

Nine engines report on the same estate, and until this package nothing joined their answers. The
report was therefore both repetitive and incomplete: three engines can find one hardcoded credential
and a customer saw three criticals for one problem, while the two findings that together mean *the
credential is already retrievable* sat in different sections with nothing saying so.

The rules are pure functions over findings, so they are tested here without a database. What matters
in each case is the discrimination — a rule that groups too eagerly merges two real problems into
one and hides the second, which is worse than not grouping at all.
"""

from __future__ import annotations

import uuid

import pytest
from guardian_core.enums import Severity
from guardian_scanner.correlation import (
    correlate,
    group_exposed_repository_secret,
    group_injection_corroborated,
    group_same_cve_on_asset,
    group_same_secret,
    group_shipped_and_running,
)

CUSTOMER = uuid.uuid4()
OTHER_CUSTOMER = uuid.uuid4()
ASSET = uuid.uuid4()
OTHER_ASSET = uuid.uuid4()


class FakeFinding:
    """A finding as the rules see it. The rules take rows; this is the same shape without a DB."""

    def __init__(self, *, category="secret", severity="high", risk_score=70, cwe_id=None,
                 cve_ids=None, location=None, evidence=None, customer_id=CUSTOMER,
                 asset_id=ASSET):
        self.id = uuid.uuid4()
        self.category = category
        self.severity = severity
        self.risk_score = risk_score
        self.cwe_id = cwe_id
        self.cve_ids = cve_ids or []
        self.location = location or {}
        self.evidence = evidence or {}
        self.customer_id = customer_id
        self.asset_id = asset_id


def _secret(engine, redacted, **kwargs):
    return FakeFinding(
        category="secret",
        location={"engine": engine, "rule": "aws-key"},
        evidence={"detail": {"redacted": redacted}},
        **kwargs,
    )


# ── one credential, several engines ───────────────────────────────────────────────────────────────
def test_the_same_credential_from_three_engines_is_one_group():
    findings = [
        _secret("secrets", "AK********EY (len=40)"),
        _secret("sast", "AK********EY (len=40)"),
        _secret("container", "AK********EY (len=40)"),
    ]
    groups = group_same_secret(findings)
    assert len(groups) == 1
    assert groups[0].kind == "duplicate"
    assert len(groups[0].members) == 3
    assert "Rotating it once" in groups[0].description


def test_two_different_credentials_stay_apart():
    """Grouping too eagerly merges two real problems and hides the second."""
    findings = [
        _secret("secrets", "AK********EY (len=40)"),
        _secret("sast", "AK********EY (len=40)"),
        _secret("secrets", "gh********ab (len=40)"),
        _secret("container", "gh********ab (len=40)"),
    ]
    groups = group_same_secret(findings)
    assert len(groups) == 2
    assert all(len(g.members) == 2 for g in groups)


def test_one_engine_alone_is_not_a_group():
    assert group_same_secret([_secret("secrets", "AK********EY")]) == []


def test_the_same_credential_for_two_customers_is_not_one_group():
    findings = [
        _secret("secrets", "AK********EY"),
        _secret("sast", "AK********EY", customer_id=OTHER_CUSTOMER),
    ]
    assert group_same_secret(findings) == []


def test_a_fully_redacted_evidence_falls_back_to_file_and_line():
    """A secret-adjacent engine emits `<redacted>` rather than a snippet. Two findings at the same
    file and line are still the same secret."""
    findings = [
        FakeFinding(category="secret", location={"engine": "secrets", "path": "app.py", "line": 12},
                    evidence={"detail": {"redacted": "<redacted>"}}),
        FakeFinding(category="insecure-code",
                    location={"engine": "sast", "path": "app.py", "line": 12},
                    evidence={"detail": {}}),
    ]
    groups = group_same_secret(findings)
    assert len(groups) == 1


def test_a_duplicate_group_does_not_escalate():
    """Three views of one issue is still one issue. Escalating on repetition would let a noisy
    engine manufacture criticals."""
    findings = [_secret("secrets", "AK**EY"), _secret("sast", "AK**EY")]
    group = group_same_secret(findings)[0]
    assert group.severity is Severity.HIGH
    assert any("does not escalate" in line for line in group.rationale)


# ── one advisory, several engines ─────────────────────────────────────────────────────────────────
def test_the_same_cve_on_one_asset_is_grouped():
    findings = [
        FakeFinding(category="vuln-dep", cve_ids=["CVE-2021-44228"], location={"engine": "sca"}),
        FakeFinding(category="vuln-dep", cve_ids=["CVE-2021-44228"],
                    location={"engine": "container"}),
    ]
    groups = group_same_cve_on_asset(findings)
    assert len(groups) == 1
    assert "CVE-2021-44228" in groups[0].title


def test_the_same_cve_on_two_assets_is_not_grouped():
    """Two assets running the same vulnerable component are two pieces of work."""
    findings = [
        FakeFinding(category="vuln-dep", cve_ids=["CVE-2021-44228"]),
        FakeFinding(category="vuln-dep", cve_ids=["CVE-2021-44228"], asset_id=OTHER_ASSET),
    ]
    assert group_same_cve_on_asset(findings) == []


# ── shipped and running ───────────────────────────────────────────────────────────────────────────
def test_a_dependency_that_is_also_answering_on_a_port_is_escalated():
    """The dependency scan says it will be exposed on the next deploy; the service scan says it
    already is. That is what turns a patch from next sprint into today."""
    findings = [
        FakeFinding(category="vuln-dep", cve_ids=["CVE-2023-1"], severity="high", risk_score=70,
                    location={"engine": "sca"}),
        FakeFinding(category="vuln-service", cve_ids=["CVE-2023-1"], severity="high",
                    risk_score=72, location={"rule": "service-cve-CVE-2023-1"}),
    ]
    groups = group_shipped_and_running(findings)
    assert len(groups) == 1
    group = groups[0]
    assert group.kind == "chain"
    assert group.severity is Severity.CRITICAL
    assert group.risk_score == 77
    assert any("already running" in line for line in group.rationale)


def test_a_dependency_with_no_running_counterpart_is_not_escalated():
    findings = [FakeFinding(category="vuln-dep", cve_ids=["CVE-2023-1"],
                            location={"engine": "sca"})]
    assert group_shipped_and_running(findings) == []


def test_a_running_service_with_no_dependency_counterpart_is_not_escalated():
    findings = [FakeFinding(category="vuln-service", cve_ids=["CVE-2023-1"],
                            location={"rule": "service-cve-CVE-2023-1"})]
    assert group_shipped_and_running(findings) == []


def test_different_cves_do_not_chain():
    findings = [
        FakeFinding(category="vuln-dep", cve_ids=["CVE-2023-1"], location={"engine": "sca"}),
        FakeFinding(category="vuln-service", cve_ids=["CVE-2023-2"],
                    location={"rule": "service-cve-CVE-2023-2"}),
    ]
    assert group_shipped_and_running(findings) == []


# ── static and dynamic agreeing ───────────────────────────────────────────────────────────────────
def test_static_and_dynamic_agreement_is_corroboration():
    findings = [
        FakeFinding(category="injection", cwe_id="CWE-89", severity="high", risk_score=75,
                    location={"engine": "sast", "rule": "taint-sql"}),
        FakeFinding(category="injection", cwe_id="CWE-89", severity="medium", risk_score=55,
                    location={"engine": "dast"}),
    ]
    groups = group_injection_corroborated(findings)
    assert len(groups) == 1
    assert groups[0].kind == "corroboration"
    assert groups[0].severity is Severity.CRITICAL
    assert any("two independent methods" in line for line in groups[0].rationale)


def test_two_static_findings_are_not_corroboration():
    """Two runs of the same engine agreeing is not independent evidence."""
    findings = [
        FakeFinding(cwe_id="CWE-89", location={"engine": "sast"}),
        FakeFinding(cwe_id="CWE-89", location={"engine": "sast"}),
    ]
    assert group_injection_corroborated(findings) == []


def test_different_weakness_classes_do_not_corroborate():
    findings = [
        FakeFinding(cwe_id="CWE-89", location={"engine": "sast"}),
        FakeFinding(cwe_id="CWE-79", location={"engine": "dast"}),
    ]
    assert group_injection_corroborated(findings) == []


def test_a_non_injection_class_is_not_corroborated():
    """The rule is about weaknesses where a static path and a dynamic probe are independent
    evidence of one thing. A weak-hash finding is not that."""
    findings = [
        FakeFinding(cwe_id="CWE-327", location={"engine": "sast"}),
        FakeFinding(cwe_id="CWE-327", location={"engine": "dast"}),
    ]
    assert group_injection_corroborated(findings) == []


# ── the chain that changes what a customer must do ────────────────────────────────────────────────
def test_an_exposed_repository_plus_a_committed_secret_is_a_chain():
    findings = [
        FakeFinding(category="misconfig", severity="medium", risk_score=50,
                    location={"rule": "web-check-git-config-exposure"}),
        FakeFinding(category="secret", severity="high", risk_score=70,
                    location={"engine": "secrets", "rule": "aws-key"},
                    evidence={"detail": {"redacted": "AK**EY"}}),
    ]
    groups = group_exposed_repository_secret(findings)
    assert len(groups) == 1
    assert groups[0].kind == "chain"
    assert groups[0].severity is Severity.CRITICAL
    assert "rotate it" in groups[0].description


def test_an_exposed_repository_alone_is_not_a_chain():
    findings = [FakeFinding(category="misconfig",
                            location={"rule": "web-check-git-config-exposure"})]
    assert group_exposed_repository_secret(findings) == []


def test_a_secret_without_an_exposure_is_not_a_chain():
    findings = [_secret("secrets", "AK**EY")]
    assert group_exposed_repository_secret(findings) == []


def test_an_exposure_and_a_secret_for_different_customers_do_not_chain():
    findings = [
        FakeFinding(category="misconfig", location={"rule": "web-check-git-config-exposure"}),
        _secret("secrets", "AK**EY", customer_id=OTHER_CUSTOMER),
    ]
    assert group_exposed_repository_secret(findings) == []


# ── the whole pass ────────────────────────────────────────────────────────────────────────────────
def test_a_clean_finding_set_produces_no_groups():
    """Unrelated findings must not be grouped. A correlation that fires on everything says nothing."""
    findings = [
        FakeFinding(category="vuln-dep", cve_ids=["CVE-2023-1"], location={"engine": "sca"}),
        FakeFinding(category="misconfig", location={"rule": "iac-s3-public-acl"}),
        FakeFinding(category="insecure-code", cwe_id="CWE-327", location={"engine": "sast"}),
    ]
    assert correlate(findings) == []


def test_a_group_fingerprint_is_stable_across_runs():
    """A re-scan must update the group rather than create a second one."""
    findings = [_secret("secrets", "AK**EY"), _secret("sast", "AK**EY")]
    first = group_same_secret(findings)[0]
    second = group_same_secret(list(reversed(findings)))[0]
    assert first.fingerprint() == second.fingerprint()


def test_the_primary_member_is_the_one_worth_reading_first():
    findings = [
        _secret("secrets", "AK**EY", severity="medium", risk_score=40),
        _secret("sast", "AK**EY", severity="critical", risk_score=95),
    ]
    group = group_same_secret(findings)[0]
    assert group.primary == findings[1].id


@pytest.mark.parametrize("rule_output", [group_same_secret, group_same_cve_on_asset,
                                         group_shipped_and_running, group_injection_corroborated,
                                         group_exposed_repository_secret])
def test_every_rule_handles_an_empty_input(rule_output):
    assert rule_output([]) == []
