"""Deterministic scoring is the backbone of risk ranking — cover its rules explicitly."""

from guardian_core.enums import Severity
from guardian_core.scoring import ScoreInputs, score_severity


def test_cvss_bands_map_to_severity():
    assert score_severity(ScoreInputs(Severity.INFO, cvss_base=9.5)) == Severity.CRITICAL
    assert score_severity(ScoreInputs(Severity.INFO, cvss_base=7.5)) == Severity.HIGH
    assert score_severity(ScoreInputs(Severity.INFO, cvss_base=5.0)) == Severity.MEDIUM
    assert score_severity(ScoreInputs(Severity.INFO, cvss_base=1.0)) == Severity.LOW


def test_kev_floors_at_high_and_bumps():
    # A low base finding that is actively exploited must not stay low.
    out = score_severity(ScoreInputs(Severity.LOW, kev=True))
    assert out.rank >= Severity.HIGH.rank


def test_high_epss_bumps_one_step():
    base = score_severity(ScoreInputs(Severity.MEDIUM, epss_score=0.1))
    bumped = score_severity(ScoreInputs(Severity.MEDIUM, epss_score=0.9))
    assert bumped.rank > base.rank


def test_public_exposure_bumps_for_critical_assets():
    internal = score_severity(
        ScoreInputs(Severity.HIGH, exposure="internal", asset_criticality="critical")
    )
    public = score_severity(
        ScoreInputs(Severity.HIGH, exposure="public", asset_criticality="critical")
    )
    assert public.rank >= internal.rank
    assert public == Severity.CRITICAL


def test_base_severity_used_without_cvss():
    assert score_severity(ScoreInputs(Severity.MEDIUM)) == Severity.MEDIUM
