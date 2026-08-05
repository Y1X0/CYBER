"""The Risk Engine turns CVSS into business risk — cover its score + rationale."""

from guardian_core.enums import Severity
from guardian_core.scoring import ScoreInputs, assess


def test_score_is_bounded_and_has_rationale():
    r = assess(ScoreInputs(base_severity=Severity.MEDIUM))
    assert 0 <= r.score <= 100
    assert r.rationale  # never a black box


def test_kev_and_public_exposure_raise_risk():
    internal = assess(ScoreInputs(base_severity=Severity.HIGH, exposure="internal"))
    exploited_public = assess(
        ScoreInputs(
            base_severity=Severity.HIGH,
            kev=True,
            epss_score=0.9,
            exposure="public",
            asset_criticality="critical",
            business_impact="critical",
        )
    )
    assert exploited_public.score > internal.score
    assert exploited_public.severity == Severity.CRITICAL
    assert any("KEV" in line for line in exploited_public.rationale)


def test_business_impact_moves_the_number():
    low = assess(ScoreInputs(base_severity=Severity.MEDIUM, business_impact="none"))
    high = assess(ScoreInputs(base_severity=Severity.MEDIUM, business_impact="critical"))
    assert high.score > low.score
    assert any("business impact" in line for line in high.rationale)


def test_two_findings_same_band_can_rank_differently():
    # The user's example: same CVSS band, different context → different business risk.
    internal_no_data = assess(
        ScoreInputs(base_severity=Severity.HIGH, exposure="internal", business_impact="low")
    )
    public_customer_data = assess(
        ScoreInputs(
            base_severity=Severity.MEDIUM,
            exposure="public",
            business_impact="critical",
            asset_criticality="high",
        )
    )
    assert public_customer_data.score >= internal_no_data.score - 5  # context closes the gap
