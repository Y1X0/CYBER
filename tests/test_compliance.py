"""Control coverage (WP-F4).

A compliance report is the artifact a customer hands to an auditor. There is one way it can be
wrong that matters more than all the others put together, and most of this file is about it:

**a control with no findings is only passing if something actually looked.**

If no engine capable of assessing a control ran, the honest answer is `not_assessed`. Reporting it
as `passing` manufactures an assurance nobody earned, and it is the difference between a compliance
feature and a compliance liability.
"""

from __future__ import annotations

import pytest
from guardian_core.compliance import (
    CONTROLS,
    FAILING,
    FRAMEWORKS,
    NOT_ASSESSED,
    PASSING,
    FindingRef,
    assess,
    controls_for,
    maps_to,
    summarize,
)

ALL_ENGINES = {"sast", "sca", "secrets", "dast", "api", "cspm", "k8s", "iac", "container",
               "service_cve", "nmap", "discovery"}


def _f(fid="f1", *, severity="high", cwe=None, category="", rule="", status="open", title="t"):
    return FindingRef(id=fid, severity=severity, title=title, category=category, cwe_id=cwe,
                      rule=rule, status=status)


def _status(assessment, control_id: str) -> str:
    return next(r.status for r in assessment.results if r.control.id == control_id)


# ── the property the whole module exists for ──────────────────────────────────────────────────────
def test_a_control_nobody_assessed_is_not_passing():
    """The single most consequential rule here. No engine ran, so nothing is known — and 'nothing
    is known' must never be printed as 'this control works'."""
    assessment = assess("soc2", [], engines_completed=set())
    assert all(r.status == NOT_ASSESSED for r in assessment.results)
    assert assessment.counts[PASSING] == 0


def test_a_control_becomes_passing_only_when_an_engine_that_can_assess_it_completed():
    with_cloud = assess("soc2", [], engines_completed={"cspm"})
    assert _status(with_cloud, "CC7.2") == PASSING       # cspm can assess logging
    assert _status(with_cloud, "CC6.8") == NOT_ASSESSED  # nothing that assesses software ran


def test_the_rationale_names_what_would_have_assessed_it():
    """A reader who sees `not assessed` needs to know what to run."""
    assessment = assess("soc2", [], engines_completed=set())
    logging_control = next(r for r in assessment.results if r.control.id == "CC7.2")
    assert "not assessed" in logging_control.rationale
    assert "cspm" in logging_control.rationale


def test_coverage_is_reported_alongside_the_counts():
    """A 100% pass rate over 20% coverage is the number that misleads an auditor, and it only
    misleads when the denominator is hidden."""
    partial = assess("soc2", [], engines_completed={"cspm"})
    assert 0 < partial.coverage < 100
    full = assess("soc2", [], engines_completed=ALL_ENGINES)
    assert full.coverage == 100


def test_the_summary_repeats_coverage_at_the_top_level():
    payload = summarize([assess("soc2", [], engines_completed={"cspm"})])
    assert payload["overall_coverage"] < 100
    assert "does not certify compliance" in payload["disclaimer"]


# ── mapping ───────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(("framework", "control_id", "finding"), [
    ("soc2", "CC6.2", _f(cwe="CWE-798")),
    ("soc2", "CC6.3", _f(rule="iam-admin")),
    ("soc2", "CC6.6", _f(rule="sg-admin-port-open")),
    ("soc2", "CC7.2", _f(cwe="CWE-778")),
    ("iso27001", "A.8.28", _f(cwe="CWE-89")),
    ("iso27001", "A.8.24", _f(rule="rds-unencrypted")),
    ("pci-dss", "8.3", _f(rule="iam-root-no-mfa")),
    ("pci-dss", "6.3", _f(category="vuln-dep")),
])
def test_a_finding_fails_the_control_it_is_evidence_against(framework, control_id, finding):
    assessment = assess(framework, [finding], engines_completed=ALL_ENGINES)
    assert _status(assessment, control_id) == FAILING


def test_a_failing_control_names_its_worst_finding():
    findings = [_f("a", severity="low", cwe="CWE-798", title="low one"),
                _f("b", severity="critical", cwe="CWE-798", title="the critical one")]
    assessment = assess("soc2", findings, engines_completed=ALL_ENGINES)
    result = next(r for r in assessment.results if r.control.id == "CC6.2")
    assert "critical" in result.rationale
    assert "the critical one" in result.rationale
    assert len(result.findings) == 2


def test_a_cwe_takes_precedence_over_a_category():
    """CWE is the identifier every engine sets and the one a reader can check."""
    control = next(c for c in controls_for("soc2") if c.id == "CC6.2")
    assert maps_to(control, _f(cwe="CWE-798", category="unrelated")) is True


def test_an_unrelated_finding_does_not_fail_a_control():
    assessment = assess("soc2", [_f(cwe="CWE-1004")], engines_completed=ALL_ENGINES)
    assert all(r.status != FAILING for r in assessment.results)


# ── triage decisions ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("status", ["false_positive", "resolved"])
def test_a_dismissed_or_fixed_finding_stops_failing_the_control(status):
    assessment = assess("soc2", [_f(cwe="CWE-798", status=status)],
                        engines_completed=ALL_ENGINES)
    assert _status(assessment, "CC6.2") == PASSING


def test_an_accepted_risk_still_fails_the_control():
    """Accepting a risk is a business decision about whether to fix it. It does not make the
    control work, and an auditor is asking about the control."""
    assessment = assess("soc2", [_f(cwe="CWE-798", status="accepted_risk")],
                        engines_completed=ALL_ENGINES)
    assert _status(assessment, "CC6.2") == FAILING


# ── ordering and shape ────────────────────────────────────────────────────────────────────────────
def test_failing_controls_come_first_then_unassessed_then_passing():
    findings = [_f(cwe="CWE-798")]
    assessment = assess("soc2", findings, engines_completed={"secrets", "cspm"})
    statuses = [r.status for r in assessment.results]
    assert statuses == sorted(statuses, key=lambda s: {FAILING: 0, NOT_ASSESSED: 1,
                                                       PASSING: 2}[s])


def test_the_assessment_is_deterministic():
    findings = [_f("a", cwe="CWE-798"), _f("b", rule="iam-admin")]
    first = assess("soc2", findings, engines_completed=ALL_ENGINES)
    second = assess("soc2", list(reversed(findings)), engines_completed=ALL_ENGINES)
    assert [(r.control.id, r.status) for r in first.results] == \
        [(r.control.id, r.status) for r in second.results]


@pytest.mark.parametrize("framework", FRAMEWORKS)
def test_every_framework_has_controls_and_every_control_is_actionable(framework):
    controls = controls_for(framework)
    assert controls
    for control in controls:
        assert control.title
        assert len(control.description) > 20
        # A control with no mapping and no engine can never be anything but `not_assessed`, which
        # is honest but useless — every one here must be able to say something.
        assert control.cwes or control.categories or control.rules


def test_control_ids_are_unique_within_a_framework():
    for framework in FRAMEWORKS:
        ids = [c.id for c in controls_for(framework)]
        assert len(ids) == len(set(ids))


def test_the_catalogue_covers_the_three_frameworks():
    assert {c.framework for c in CONTROLS} == set(FRAMEWORKS)
