"""The reference engine must find planted secrets and always redact evidence."""

from guardian_core.enums import EngineKey
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.engines.secrets_engine import SecretsEngine

SAMPLE = """
import os
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
db_password = "s3cr3t-P@ssw0rd-value-1234"
GITHUB_TOKEN = "ghp_16CharsAtLeastxxxxxxxxxxxxxxxxxxxxxxxx"
normal_var = "just a harmless string"
-----BEGIN RSA PRIVATE KEY-----
MIIEabc
-----END RSA PRIVATE KEY-----
"""


def _run(content: str):
    engine = SecretsEngine()
    ctx = ScanContext(scan_id="t", asset_kind="repo", asset_identifier="x", inline_content=content)
    return list(engine.run(ctx))


def test_detects_multiple_secret_types():
    findings = _run(SAMPLE)
    titles = " ".join(f.title for f in findings)
    assert any(f.engine == EngineKey.SECRETS for f in findings)
    assert "AWS Access Key ID" in titles
    assert "Private Key block" in titles
    assert "GitHub Token" in titles


def test_evidence_is_redacted():
    findings = _run('api_key = "AKIAIOSFODNN7EXAMPLE"')
    assert findings, "expected at least one finding"
    for f in findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in str(f.evidence)
        assert "*" in f.evidence.get("match", "")


def test_clean_code_yields_no_findings():
    assert _run("x = 1\nprint('hello world')\n") == []


def test_findings_carry_standards_mapping():
    findings = _run('password = "longenoughpassword123"')
    assert findings
    assert findings[0].cwe_id == "CWE-798"
    assert findings[0].owasp_ref == "A07:2021"


def test_fingerprint_is_stable():
    a = _run(SAMPLE)[0].fingerprint()
    b = _run(SAMPLE)[0].fingerprint()
    assert a == b and len(a) == 32
