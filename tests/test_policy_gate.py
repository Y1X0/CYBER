"""The deployment gate is deterministic and blocks on real risk."""

from types import SimpleNamespace

from guardian_core.policy import DEFAULT_RULES, evaluate_gate


def _f(**kw):
    base = dict(
        id="1", title="x", severity="low", risk_score=10, epss_score=None, kev=False, status="open"
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_clean_findings_pass():
    assert evaluate_gate([_f(), _f(severity="medium")]).passed is True


def test_critical_blocks_by_default():
    r = evaluate_gate([_f(severity="critical")])
    assert r.passed is False and len(r.blocking) == 1


def test_kev_blocks_by_default():
    assert evaluate_gate([_f(severity="medium", kev=True)]).passed is False


def test_high_epss_blocks():
    assert evaluate_gate([_f(severity="high", epss_score=0.9)]).passed is False
    assert evaluate_gate([_f(severity="high", epss_score=0.1)]).passed is True  # low EPSS ok


def test_resolved_findings_never_block():
    assert evaluate_gate([_f(severity="critical", status="resolved")]).passed is True
    assert evaluate_gate([_f(severity="critical", status="false_positive")]).passed is True


def test_custom_rules():
    rules = {"fail_on": [{"risk_gte": 80}]}
    assert evaluate_gate([_f(risk_score=90)], rules).passed is False
    assert evaluate_gate([_f(risk_score=50)], rules).passed is True


def test_default_rules_shape():
    assert "fail_on" in DEFAULT_RULES
