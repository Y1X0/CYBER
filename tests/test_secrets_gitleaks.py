"""gitleaks as an additional detection backend for SecretsEngine (Phase 1, first tool integration).

gitleaks is invoked only when the binary is present, so these tests drive it deterministically by
faking `shutil.which` and `subprocess.run` with canned gitleaks JSON — the binary itself is not
required in CI. The load-bearing property under test is redaction: a secret gitleaks reports must
never survive into a finding, whatever field it arrives in.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guardian_core.enums import EngineKey, Severity
from guardian_scanner.engines import secrets_engine as se
from guardian_scanner.engines.secrets_engine import SecretsEngine

_LEAK = {
    "Description": "AWS Access Key",
    "StartLine": 42, "EndLine": 42,
    "File": "config/prod.py",
    "Match": "aws_key = AKIAIOSFODNN7EXAMPLE",   # gitleaks' raw match — must never reach a finding
    "Secret": "REDACTED",                         # gitleaks --redact already masked this
    "Commit": "", "RuleID": "aws-access-token", "Entropy": 3.6,
}
_PEM_LEAK = {
    "Description": "Private key", "StartLine": 1, "File": "id_rsa",
    "Match": "REDACTED", "Secret": "REDACTED", "Commit": "abcdef1234567890",
    "RuleID": "private-key",
}


def _fake_gitleaks(monkeypatch, tmp_path: Path, payload: object, *, present: bool = True,
                   rc: int = 0, raises: Exception | None = None) -> None:
    monkeypatch.setattr(se.shutil, "which",
                        lambda name: "/usr/bin/gitleaks" if (present and name == "gitleaks") else None)

    def fake_run(argv, **kwargs):  # noqa: ANN001, ANN202
        if raises is not None:
            raise raises
        # gitleaks writes its JSON report to the --report-path file; mimic that.
        report_path = argv[argv.index("--report-path") + 1]
        Path(report_path).write_text(json.dumps(payload) if payload is not None else "not json")

        class _P:
            returncode = rc
            stdout = b""
            stderr = b""
        return _P()

    monkeypatch.setattr(se.subprocess, "run", fake_run)


def _findings(monkeypatch, tmp_path: Path) -> list:
    engine = SecretsEngine()
    return list(engine._run_gitleaks_if_available(tmp_path))


def test_no_op_when_gitleaks_is_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(se.shutil, "which", lambda name: None)
    assert _findings(monkeypatch, tmp_path) == []


def test_a_leak_becomes_a_redacted_finding(monkeypatch, tmp_path):
    _fake_gitleaks(monkeypatch, tmp_path, [_LEAK])
    findings = _findings(monkeypatch, tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.engine == EngineKey.SECRETS
    assert f.location["rule"] == "aws-access-token"
    assert f.location["path"] == "config/prod.py"
    assert f.location["line"] == 42
    assert f.evidence["detector"] == "gitleaks"


def test_the_raw_match_never_survives_into_a_finding(monkeypatch, tmp_path):
    # The whole point: gitleaks' Match field carries the credential in a benignly-named field.
    _fake_gitleaks(monkeypatch, tmp_path, [_LEAK])
    findings = _findings(monkeypatch, tmp_path)
    blob = json.dumps([{"title": f.title, "description": f.description,
                        "location": f.location, "evidence": f.evidence} for f in findings])
    assert "AKIAIOSFODNN7EXAMPLE" not in blob, "raw AWS key leaked into a finding"
    assert "aws_key =" not in blob, "the raw Match string leaked into a finding"


def test_a_private_key_rule_is_raised_to_critical(monkeypatch, tmp_path):
    _fake_gitleaks(monkeypatch, tmp_path, [_PEM_LEAK])
    f = _findings(monkeypatch, tmp_path)[0]
    assert f.base_severity == Severity.CRITICAL
    assert f.location["source"] == "gitleaks-history"      # it had a commit
    assert f.location["commit"] == "abcdef123456"


def test_an_empty_report_yields_nothing(monkeypatch, tmp_path):
    _fake_gitleaks(monkeypatch, tmp_path, [])
    assert _findings(monkeypatch, tmp_path) == []


def test_malformed_output_is_handled_not_crashed(monkeypatch, tmp_path):
    _fake_gitleaks(monkeypatch, tmp_path, None)   # writes non-JSON to the report
    assert _findings(monkeypatch, tmp_path) == []


def test_a_gitleaks_crash_does_not_break_the_scan(monkeypatch, tmp_path):
    _fake_gitleaks(monkeypatch, tmp_path, [_LEAK], raises=TimeoutError("gitleaks hung"))
    assert _findings(monkeypatch, tmp_path) == []


def test_findings_without_rule_or_file_are_skipped(monkeypatch, tmp_path):
    _fake_gitleaks(monkeypatch, tmp_path, [{"RuleID": "x"}, {"File": "y"}, {}])
    assert _findings(monkeypatch, tmp_path) == []


def test_duplicate_hits_collapse(monkeypatch, tmp_path):
    _fake_gitleaks(monkeypatch, tmp_path, [_LEAK, dict(_LEAK)])
    assert len(_findings(monkeypatch, tmp_path)) == 1


def test_the_built_in_engine_still_runs_without_gitleaks(monkeypatch, tmp_path):
    # Absence of gitleaks must not reduce the engine to nothing — the built-in path is complete.
    monkeypatch.setattr(se.shutil, "which", lambda name: None)
    engine = SecretsEngine()
    from guardian_scanner.engines.base import ScanContext
    ctx = ScanContext(scan_id="t", asset_kind="repo", asset_identifier="x",
                      inline_content='api_key = "AKIAIOSFODNN7EXAMPLE"')
    findings = list(engine.run(ctx))
    assert findings, "built-in detection must still work when gitleaks is absent"
    assert engine.health().ok


def test_health_reports_gitleaks_presence(monkeypatch):
    engine = SecretsEngine()
    monkeypatch.setattr(se.shutil, "which", lambda name: "/usr/bin/gitleaks")
    assert "gitleaks ruleset" in engine.health().detail
    monkeypatch.setattr(se.shutil, "which", lambda name: None)
    assert "gitleaks absent" in engine.health().detail
    assert engine.health().ok      # never degraded — built-in is complete
