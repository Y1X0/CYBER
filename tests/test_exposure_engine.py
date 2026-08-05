"""Exposure Engine unit tests (Phase 6) — deterministic, separate from vulnerability risk."""

from __future__ import annotations

from guardian_core.exposure import ExposureInputs, assess_exposure


def test_no_signals_is_zero():
    out = assess_exposure(ExposureInputs())
    assert out.score == 0
    assert out.rationale == []


def test_internet_facing_web_scores_and_explains():
    out = assess_exposure(ExposureInputs(
        internet_reachable=True, public_dns=True, open_ports=1, missing_tls=True
    ))
    assert out.score == 30 + 10 + 5 + 10
    assert any("public internet" in r for r in out.rationale)
    assert any("without TLS" in r for r in out.rationale)


def test_score_is_capped_at_100():
    out = assess_exposure(ExposureInputs(
        internet_reachable=True, public_dns=True, open_ports=10, sensitive_ports=True,
        missing_tls=True, cloud_public=True, dangling_dns=True, unknown_ownership=True,
    ))
    assert out.score == 100


def test_exposure_is_reproducible():
    inp = ExposureInputs(internet_reachable=True, cloud_public=True)
    assert assess_exposure(inp).score == assess_exposure(inp).score == 50


def test_open_ports_contribution_is_bounded():
    # 5 pts/port but capped at 20 — 10 ports doesn't run away.
    assert assess_exposure(ExposureInputs(open_ports=2)).score == 10
    assert assess_exposure(ExposureInputs(open_ports=99)).score == 20
