"""The security score is deterministic and only counts open findings."""

from types import SimpleNamespace

from guardian_ai.security_score import security_score


def _f(severity, status="open"):
    return SimpleNamespace(severity=severity, status=status)


def test_no_findings_is_perfect():
    assert security_score([]) == 100


def test_criticals_hurt_most():
    assert security_score([_f("critical")]) < security_score([_f("high")])
    assert security_score([_f("high")]) < security_score([_f("medium")])


def test_resolved_findings_do_not_count():
    assert security_score([_f("critical", status="resolved")]) == 100
    assert security_score([_f("critical", status="false_positive")]) == 100
    assert security_score([_f("critical", status="accepted_risk")]) == 100


def test_score_is_bounded():
    many = [_f("critical") for _ in range(20)]
    assert security_score(many) == 0
