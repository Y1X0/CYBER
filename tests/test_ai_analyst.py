"""The AI layer explains without inventing; the stub keeps it offline + deterministic."""

from types import SimpleNamespace

from guardian_ai.analyst import executive_summary
from guardian_ai.chat import answer_question
from guardian_ai.providers.stub import StubProvider


def _finding(**kw):
    base = dict(
        id="00000000-0000-0000-0000-000000000001",
        title="Hardcoded secret: AWS Access Key ID",
        category="secret",
        description="A likely hardcoded credential was detected.",
        severity="critical",
        risk_score=100,
        risk_rationale=["Base 90 from critical severity band"],
        cwe_id="CWE-798",
        owasp_ref="A07:2021",
        cve_ids=[],
        status="open",
        evidence={"match": "AK********LE"},
        location={"path": "app.py", "line": 3},
        remediation=None,
        ai_explanation=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_stub_explanation_is_grounded():
    p = StubProvider()
    out = p.complete_json(
        system="",
        prompt="",
        schema={},
        context={
            "_kind": "finding_explanation",
            "finding": {
                "title": "X",
                "severity": "high",
                "category": "secret",
                "cwe_id": "CWE-798",
                "owasp_ref": "A07:2021",
                "cve_ids": [],
            },
            "kb": [{"body": "Rotate the secret and use a secrets manager."}],
        },
    )
    assert "high" in out["explanation"]
    assert "CWE-798" in out["references"] and "A07:2021" in out["references"]
    assert "secrets manager" in out["remediation"]
    assert out["attack_scenario"]  # present but non-actionable


def test_executive_summary_uses_deterministic_score():
    findings = [_finding(), _finding(severity="high", risk_score=72)]
    out = executive_summary(None, findings, StubProvider())
    assert out["security_score"] == 100 - 25 - 12  # critical + high penalties
    assert out["severity_counts"]["critical"] == 1
    assert "critical" in out["summary"]
    assert out["top_risks"][0]["risk_score"] == 100  # highest risk first


def test_chat_grounds_on_findings_only():
    findings = [_finding()]
    out = answer_question("what is my biggest risk?", findings, StubProvider())
    assert "CRITICAL" in out["answer"]
    assert out["cited_finding_ids"] == [findings[0].id]


def test_chat_declines_without_context():
    out = answer_question("anything?", [], StubProvider())
    assert "don't have any findings" in out["answer"]
    assert out["cited_finding_ids"] == []
