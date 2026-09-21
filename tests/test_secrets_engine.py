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


# ── keyed secret-correlation identity (WP-E1 same-secret fix) ────────────────────────────────────────
# The engine derives a keyed, one-way identity from the RAW secret so correlation can decide "same
# credential" without the lossy display redaction. The raw is never persisted; the identity rides in
# evidence["secret_id_hmac"] until normalize relocates it into a dedicated column.
from types import SimpleNamespace  # noqa: E402

import guardian_scanner.engines.secrets_engine as _se  # noqa: E402


def _with_key(monkeypatch, key="unit-broker-seal-key"):
    monkeypatch.setattr(_se, "get_settings", lambda: SimpleNamespace(broker_seal_key=key))


def test_engine_derives_a_keyed_identity_and_never_leaks_the_raw(monkeypatch):
    _with_key(monkeypatch)
    findings = _run('aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"')
    assert findings
    f = findings[0]
    ident = f.evidence.get("secret_id_hmac")
    assert isinstance(ident, str) and len(ident) == 64
    assert "AKIAIOSFODNN7EXAMPLE" not in ident              # not the raw secret
    assert "*" in f.evidence.get("match", "")               # redaction still shown


def test_two_different_secrets_get_different_identities(monkeypatch):
    _with_key(monkeypatch)
    findings = _run(
        'a = "AKIAIOSFODNN7EXAMPLE"\nb = "ghp_16CharsAtLeastxxxxxxxxxxxxxxxxxxxxxxxx"')
    ids = [f.evidence["secret_id_hmac"] for f in findings if f.evidence.get("secret_id_hmac")]
    assert len(ids) >= 2
    assert len(set(ids)) == len(ids)                        # distinct secrets -> distinct identities


def test_no_broker_seal_key_means_no_identity(monkeypatch):
    # Conservative: with no key, no weakly-keyed identity is emitted — correlation falls back to the
    # value/position basis (STRONG_EVIDENCE at most), never CONFIRMED.
    _with_key(monkeypatch, key="")
    findings = _run('api_key = "AKIAIOSFODNN7EXAMPLE"')
    assert findings
    assert all("secret_id_hmac" not in f.evidence for f in findings)


def test_gitleaks_findings_carry_no_keyed_identity():
    # gitleaks masks the value in its OWN output (--redact), so no raw exists to key — the identity
    # is absent and correlation stays conservative for those findings.
    engine = SecretsEngine()
    item = {"RuleID": "aws-access-token", "File": "app.py", "StartLine": 3, "Secret": "REDACTED"}
    finding = engine._gitleaks_finding(item)
    assert finding is not None
    assert "secret_id_hmac" not in finding.evidence
