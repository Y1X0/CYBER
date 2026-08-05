"""Report renderers produce valid HTML and PDF from report + findings."""

from types import SimpleNamespace

from guardian_ai.reporting import render_html, render_pdf


def _report():
    return SimpleNamespace(
        id="11111111-1111-1111-1111-111111111111",
        title="Security Assessment — demo",
        status="approved",
        scan_id="22222222-2222-2222-2222-222222222222",
        summary={
            "security_score": 63,
            "posture": "at risk",
            "severity_counts": {"critical": 1, "high": 0, "medium": 1, "low": 0, "info": 0},
            "recommendation": "Fix the critical secret immediately.",
        },
    )


def _finding():
    return SimpleNamespace(
        title="Hardcoded secret: AWS Access Key ID",
        severity="critical",
        risk_score=100,
        cwe_id="CWE-798",
        owasp_ref="A07:2021",
        evidence={"match": "AK********LE"},
        description="A hardcoded credential was detected.",
        ai_explanation="This exposes an AWS key that could grant account access.",
        remediation={"remediation": "Rotate the key and use a secrets manager."},
    )


def test_html_contains_findings_and_score():
    out = render_html(_report(), [_finding()])
    assert "<html" in out
    assert "63/100" in out
    assert "Hardcoded secret" in out
    assert "CWE-798" in out
    # evidence stays redacted — no raw key in the report
    assert "AK********LE" in out


def test_pdf_bytes_are_valid():
    data = render_pdf(_report(), [_finding()])
    assert data.startswith(b"%PDF")
    assert len(data) > 800


def test_html_handles_no_findings():
    out = render_html(_report(), [])
    assert "No findings." in out
