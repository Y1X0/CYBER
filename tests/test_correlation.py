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
                 asset_id=ASSET, secret_correlation_id=None):
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
        # The keyed secret-correlation identity the engine derives from the raw value (WP-E1 fix).
        # None models a legacy/gitleaks finding that only has the lossy redaction.
        self.secret_correlation_id = secret_correlation_id


def _secret(engine, redacted, **kwargs):
    return FakeFinding(
        category="secret",
        location={"engine": engine, "rule": "aws-key"},
        evidence={"detail": {"redacted": redacted}},
        **kwargs,
    )


def _secret_id(engine, identity, redacted="AK********EY (len=40)", **kwargs):
    """A secret finding carrying the keyed correlation identity (as a real detection would)."""
    return _secret(engine, redacted, secret_correlation_id=identity, **kwargs)


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


# ── correlation confidence (WP-E1, slice 1) ─────────────────────────────────────────────────────────
# Confidence reflects how strongly the RELATIONSHIP is evidenced — NOT the members' own severity or
# finding-confidence. The FakeFinding here has no `confidence` attribute at all, which is the point:
# the rules never read it, so correlation confidence cannot be derived from it.
from guardian_core.enums import CorrelationConfidence  # noqa: E402


def _secret_at(engine, path, line, **kwargs):
    # A secret finding with NO redacted value — identity falls back to position (path:line:rule).
    return FakeFinding(
        category="secret",
        location={"engine": engine, "rule": "aws-key", "path": path, "line": line},
        evidence={},
        **kwargs,
    )


def test_same_secret_keyed_identity_is_confirmed():
    # The keyed identity is derived from the RAW secret, so a match proves the same credential.
    groups = group_same_secret([
        _secret_id("secrets", "id-aws-key-1"),
        _secret_id("sast", "id-aws-key-1"),
    ])
    assert len(groups) == 1
    assert groups[0].confidence is CorrelationConfidence.CONFIRMED


def test_same_secret_redaction_only_is_strong_evidence_not_confirmed():
    # No keyed identity — only the lossy redaction matched. A redaction can collide across two
    # different secrets, so this must be STRONG_EVIDENCE, never CONFIRMED.
    groups = group_same_secret([
        _secret("secrets", "AK********EY (len=40)"),
        _secret("sast", "AK********EY (len=40)"),
    ])
    assert len(groups) == 1
    assert groups[0].confidence is CorrelationConfidence.STRONG_EVIDENCE


def test_same_secret_position_fallback_is_only_strong_evidence():
    # No value to compare — two engines pointing at the same file:line is strong, not proof.
    groups = group_same_secret([
        _secret_at("secrets", "/app/.env", 3),
        _secret_at("sast", "/app/.env", 3),
    ])
    assert len(groups) == 1
    assert groups[0].confidence is CorrelationConfidence.STRONG_EVIDENCE


def test_same_cve_on_asset_is_strong_evidence():
    groups = group_same_cve_on_asset([
        FakeFinding(category="vuln-dep", cve_ids=["CVE-2024-1"], location={"engine": "sca"}),
        FakeFinding(category="vuln-service", cve_ids=["CVE-2024-1"],
                    location={"engine": "service_cve"}),
    ])
    assert len(groups) == 1
    assert groups[0].confidence is CorrelationConfidence.STRONG_EVIDENCE


def test_injection_corroborated_is_strong_evidence_not_confirmed():
    # Static + dynamic agree on the CWE class for one customer, but not proven the same sink.
    groups = group_injection_corroborated([
        FakeFinding(category="injection", cwe_id="CWE-89", location={"engine": "sast"}),
        FakeFinding(category="injection", cwe_id="CWE-89", location={"engine": "dast"}),
    ])
    assert len(groups) == 1
    assert groups[0].confidence is CorrelationConfidence.STRONG_EVIDENCE


def test_shipped_and_running_is_potential_because_it_keys_only_on_customer():
    # Same CVE shipped and running for one customer does NOT prove the running service IS the
    # shipped dependency (keyed on customer+CVE, not the same asset) — so it stays POTENTIAL.
    groups = group_shipped_and_running([
        FakeFinding(category="vuln-dep", cve_ids=["CVE-2024-9"], location={"engine": "sca"}),
        FakeFinding(category="vuln-service", cve_ids=["CVE-2024-9"],
                    location={"engine": "service_cve"}),
    ])
    assert len(groups) == 1
    assert groups[0].kind == "chain"
    assert groups[0].confidence is CorrelationConfidence.POTENTIAL


def test_exposed_repository_secret_is_potential():
    # Exposure + a secret for one customer does NOT prove the secret is IN the exposed repo.
    groups = group_exposed_repository_secret([
        FakeFinding(category="web-misconfig", location={"engine": "web_checks",
                                                        "rule": "web-check-git-exposed"}),
        FakeFinding(category="secret", location={"engine": "secrets", "rule": "aws-key"},
                    evidence={"detail": {"redacted": "AK****"}}),
    ])
    assert len(groups) == 1
    assert groups[0].kind == "chain"
    assert groups[0].confidence is CorrelationConfidence.POTENTIAL


def test_correlation_confidence_does_not_track_member_severity():
    # Two CRITICAL, high-value members that are only POSITION-matched must stay STRONG_EVIDENCE — the
    # relationship's evidence is what decides, not how severe the individual findings are.
    groups = group_same_secret([
        _secret_at("secrets", "/app/.env", 3, severity="critical", risk_score=99),
        _secret_at("sast", "/app/.env", 3, severity="critical", risk_score=99),
    ])
    assert groups[0].confidence is CorrelationConfidence.STRONG_EVIDENCE
    # And a keyed-identity match with LOW, low-risk members is still CONFIRMED — confidence is about
    # the link, not the members' severity.
    low = group_same_secret([
        _secret_id("secrets", "id-low", severity="low", risk_score=5),
        _secret_id("container", "id-low", severity="low", risk_score=5),
    ])
    assert low[0].confidence is CorrelationConfidence.CONFIRMED


def test_correlation_confidence_is_deterministic_and_order_independent():
    a = _secret_id("secrets", "id-x")
    b = _secret_id("sast", "id-x")
    first = group_same_secret([a, b])[0].confidence
    second = group_same_secret([b, a])[0].confidence
    assert first is second is CorrelationConfidence.CONFIRMED


# ── ordered members + per-edge evidence (WP-E1, slice 2) ────────────────────────────────────────────
# A group now carries a deterministic presentation `ordered` and a set of `edges`. An edge is a
# pairwise RELATIONSHIP between two members, anchored at the primary — it is NOT a causal/attack step
# and NOT implied by the ordinal. Every edge's rationale and confidence are owned by the rule that
# matched, derived from the evidence, never from member severity/count or Finding.confidence.

def _edge_to(group, dest):
    return next((e for e in group.edges if e.dest == dest), None)


def _others(group):
    return [m for m in group.members if m != group.primary]


def test_member_order_is_deterministic_and_input_order_independent():
    a = _secret("secrets", "AK**EY")
    b = _secret("sast", "AK**EY")
    c = _secret("container", "AK**EY")
    first = group_same_secret([a, b, c])[0].ordered
    second = group_same_secret([c, a, b])[0].ordered
    third = group_same_secret([b, c, a])[0].ordered
    assert first == second == third


def test_order_is_primary_first_then_stable_identifier():
    g = group_same_secret([_secret("secrets", "AK**EY"), _secret("sast", "AK**EY"),
                           _secret("container", "AK**EY")])[0]
    assert g.ordered[0] == g.primary
    # deterministic, from a stable identifier already available (the finding id) — not insertion
    # order and not a timestamp.
    assert g.ordered[1:] == sorted(_others(g), key=str)


def test_ordinal_is_presentation_only_not_a_causal_sequence():
    """A duplicate/corroboration group is ordered so a report can render it; the ordering must not be
    read as an attack path. The edges describe evidence, never causation."""
    g = group_same_secret([_secret("secrets", "AK**EY"), _secret("sast", "AK**EY")])[0]
    assert g.kind == "duplicate"
    prose = " ".join(e.rationale.lower() for e in g.edges)
    for causal in ("attack path", "leads to", "causes", "exploit chain", "pivot"):
        assert causal not in prose


# Edge evidence, per rule ----------------------------------------------------------------------------
def test_same_secret_identity_edge_is_confirmed():
    g = group_same_secret([_secret_id("secrets", "id-1"), _secret_id("sast", "id-1")])[0]
    edge = _edge_to(g, _others(g)[0])
    assert edge is not None
    assert edge.source == g.primary
    assert edge.confidence is CorrelationConfidence.CONFIRMED
    assert "same keyed secret identity" in edge.rationale.lower()


def test_same_secret_redaction_edge_is_strong_evidence_not_confirmed():
    g = group_same_secret([_secret("secrets", "AK**EY"), _secret("sast", "AK**EY")])[0]
    edge = _edge_to(g, _others(g)[0])
    assert edge is not None
    assert edge.confidence is CorrelationConfidence.STRONG_EVIDENCE
    assert "redacted" in edge.rationale.lower() and "not proof" in edge.rationale.lower()


def test_same_secret_position_edge_is_strong_evidence():
    g = group_same_secret([_secret_at("secrets", "/app/.env", 3),
                           _secret_at("sast", "/app/.env", 3)])[0]
    edge = _edge_to(g, _others(g)[0])
    assert edge.confidence is CorrelationConfidence.STRONG_EVIDENCE
    assert "same file location" in edge.rationale.lower()


def test_same_cve_on_asset_edge_names_cve_and_asset():
    g = group_same_cve_on_asset([
        FakeFinding(category="vuln-dep", cve_ids=["CVE-2024-1"], location={"engine": "sca"}),
        FakeFinding(category="vuln-service", cve_ids=["CVE-2024-1"],
                    location={"engine": "service_cve"}),
    ])[0]
    edge = _edge_to(g, _others(g)[0])
    assert edge.confidence is CorrelationConfidence.STRONG_EVIDENCE
    assert "same cve on the same asset" in edge.rationale.lower()


def test_injection_edge_explains_static_dynamic_corroboration_without_claiming_same_sink():
    g = group_injection_corroborated([
        FakeFinding(category="injection", cwe_id="CWE-89", location={"engine": "sast"}),
        FakeFinding(category="injection", cwe_id="CWE-89", location={"engine": "dast"}),
    ])[0]
    edge = _edge_to(g, _others(g)[0])
    assert edge.confidence is CorrelationConfidence.STRONG_EVIDENCE
    assert "static and dynamic" in edge.rationale.lower()
    assert "same sink" in edge.rationale.lower()  # explicitly disclaims proving the same sink
    assert "CWE-89" in edge.rationale


def test_shipped_and_running_edge_does_not_claim_component_identity():
    g = group_shipped_and_running([
        FakeFinding(category="vuln-dep", cve_ids=["CVE-2024-9"], location={"engine": "sca"}),
        FakeFinding(category="vuln-service", cve_ids=["CVE-2024-9"],
                    location={"engine": "service_cve"}),
    ])[0]
    edge = _edge_to(g, _others(g)[0])
    assert edge.confidence is CorrelationConfidence.POTENTIAL
    assert "not proven" in edge.rationale.lower()
    assert "same component" in edge.rationale.lower()
    assert "confirmed" not in edge.rationale.lower()


def test_exposed_repository_secret_edge_does_not_claim_secret_belongs_to_repo():
    g = group_exposed_repository_secret([
        FakeFinding(category="web-misconfig",
                    location={"engine": "web_checks", "rule": "web-check-git-exposed"}),
        FakeFinding(category="secret", location={"engine": "secrets", "rule": "aws-key"},
                    evidence={"detail": {"redacted": "AK****"}}),
    ])[0]
    edge = _edge_to(g, _others(g)[0])
    assert edge.confidence is CorrelationConfidence.POTENTIAL
    assert "not proven" in edge.rationale.lower()
    assert "inside" in edge.rationale.lower()  # not proven the credential is inside the exposure


# Negative / robustness cases ------------------------------------------------------------------------
def test_unrelated_findings_produce_no_edges():
    findings = [
        FakeFinding(category="vuln-dep", cve_ids=["CVE-2023-1"], location={"engine": "sca"}),
        FakeFinding(category="misconfig", location={"rule": "iac-s3-public-acl"}),
    ]
    assert correlate(findings) == []


def test_edge_confidence_ignores_member_severity_and_risk():
    g = group_same_secret([
        _secret_at("secrets", "/a/.env", 1, severity="critical", risk_score=99),
        _secret_at("sast", "/a/.env", 1, severity="critical", risk_score=99),
    ])[0]
    assert g.edges[0].confidence is CorrelationConfidence.STRONG_EVIDENCE


def test_edge_confidence_ignores_member_count():
    g = group_same_secret([_secret_id("secrets", "idV"), _secret_id("sast", "idV"),
                           _secret_id("container", "idV"), _secret_id("iac", "idV")])[0]
    assert len(g.edges) == 3  # star: one edge from the primary to every other member
    assert all(e.confidence is CorrelationConfidence.CONFIRMED for e in g.edges)


def test_every_member_but_the_primary_has_exactly_one_incoming_edge():
    g = group_same_secret([_secret("secrets", "V"), _secret("sast", "V"),
                           _secret("container", "V")])[0]
    dests = [e.dest for e in g.edges]
    assert sorted(dests) == sorted(_others(g))          # every non-primary is a destination once
    assert g.primary not in dests                        # the primary is the root, never a dest
    assert all(e.source == g.primary for e in g.edges)   # anchored at the primary


def test_edges_are_stable_across_repeated_runs():
    a = _secret("secrets", "AK**EY")
    b = _secret("sast", "AK**EY")
    first = group_same_secret([a, b])[0]
    second = group_same_secret([b, a])[0]

    def signature(g):
        return sorted((str(e.source), str(e.dest), e.rationale, e.confidence.value)
                      for e in g.edges)
    assert signature(first) == signature(second)


# ── same-secret redaction-collision regression (WP-E1 fix) ──────────────────────────────────────────
# The bug: the same-secret rule used the LOSSY display redaction as the secret identity, so two
# different secrets whose redactions collide were grouped and marked CONFIRMED. The fix keys the
# identity on the raw secret (Finding.secret_correlation_id). These prove the collision no longer
# produces a false relationship, that a true match still confirms, and that legacy findings are not
# upgraded.

def test_short_secret_redaction_collision_does_not_confirm():
    # abc123 and xyz789 both redact to the same all-asterisk string (len <= 8) but are different
    # secrets → different keyed identities → no same-secret group at all (certainly not CONFIRMED).
    groups = group_same_secret([
        _secret("secrets", "******", secret_correlation_id="hmac-abc123"),
        _secret("sast", "******", secret_correlation_id="hmac-xyz789"),
    ])
    assert groups == []


def test_long_secret_redaction_collision_does_not_confirm():
    # Same first-two/last-two/length redaction, different secrets → different identities → not grouped.
    groups = group_same_secret([
        _secret("secrets", "AB********YZ (len=20)", secret_correlation_id="hmac-1"),
        _secret("sast", "AB********YZ (len=20)", secret_correlation_id="hmac-2"),
    ])
    assert groups == []


def test_true_equality_confirms_via_keyed_identity():
    groups = group_same_secret([
        _secret_id("secrets", "hmac-same", redacted="ab****yz"),
        _secret_id("sast", "hmac-same", redacted="ab****yz"),
    ])
    assert len(groups) == 1
    assert groups[0].rule == "same-secret"
    assert groups[0].confidence is CorrelationConfidence.CONFIRMED


def test_legacy_redaction_only_is_strong_evidence_never_confirmed():
    # A pre-fix finding carries only the lossy redaction, no keyed identity. Two of them may still
    # group (same redaction), but the tier must be conservative — STRONG_EVIDENCE, not CONFIRMED.
    groups = group_same_secret([_secret("secrets", "AK**EY"), _secret("container", "AK**EY")])
    assert len(groups) == 1
    assert groups[0].confidence is CorrelationConfidence.STRONG_EVIDENCE


def test_legacy_redaction_and_new_identity_do_not_cross_confirm():
    # A finding that has the keyed identity and one that has only the redaction live in different
    # bases, so they never share a bucket — no cross-basis CONFIRMED.
    groups = group_same_secret([
        _secret_id("secrets", "hmac-1", redacted="AK**EY"),
        _secret("sast", "AK**EY"),
    ])
    assert groups == []


def test_keyed_identity_never_crosses_customers():
    # The same keyed identity for two different customers must NOT correlate — tenant/customer
    # isolation is unchanged; the identity is only ever compared within one customer's bucket.
    groups = group_same_secret([
        _secret_id("secrets", "hmac-shared"),
        _secret_id("sast", "hmac-shared", customer_id=OTHER_CUSTOMER),
    ])
    assert groups == []
