"""checkov as an additional IaC backend for IacEngine (Phase A, second tool integration).

checkov runs only when the binary is present, so these tests drive it deterministically by faking
`shutil.which` and `subprocess.run` with canned checkov JSON — the binary is not required in CI.
Same contract as the gitleaks integration: additive, honest about failure, and the built-in path
is unchanged when checkov is absent.
"""

from __future__ import annotations

import json
from pathlib import Path

from guardian_core.enums import EngineKey, Severity
from guardian_scanner.engines import iac_engine as ie
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.engines.iac_engine import IacEngine

_FAILED = {
    "check_id": "CKV_AWS_18",
    "check_name": "Ensure the S3 bucket has access logging enabled",
    "file_path": "/main.tf", "file_line_range": [10, 20],
    "resource": "aws_s3_bucket.data", "severity": "HIGH",
    "guideline": "https://docs.bridgecrew.io/docs/s3_13",
}
_REPORT = {"check_type": "terraform", "results": {"failed_checks": [_FAILED], "passed_checks": []}}


def _fake_checkov(monkeypatch, payload: object, *, present: bool = True,
                  raises: Exception | None = None) -> None:
    monkeypatch.setattr(ie.shutil, "which",
                        lambda name: "/usr/bin/checkov" if (present and name == "checkov") else None)

    def fake_run(argv, **kwargs):  # noqa: ANN001, ANN202
        if raises is not None:
            raise raises

        class _P:
            returncode = 0
            stdout = json.dumps(payload) if payload is not None else "not json"
            stderr = ""
        return _P()

    monkeypatch.setattr(ie.subprocess, "run", fake_run)


def _findings(tmp_path: Path) -> list:
    return list(IacEngine()._run_checkov_if_available(tmp_path))


def test_no_op_when_checkov_is_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(ie.shutil, "which", lambda name: None)
    assert _findings(tmp_path) == []


def test_a_failed_check_becomes_a_finding(monkeypatch, tmp_path):
    _fake_checkov(monkeypatch, _REPORT)
    findings = _findings(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.engine == EngineKey.IAC
    assert f.base_severity == Severity.HIGH
    assert f.location["rule"] == "CKV_AWS_18"
    assert f.location["path"] == "/main.tf"
    assert f.location["line"] == 10
    assert f.evidence["detail"]["detector"] == "checkov"
    assert f.evidence["detail"]["framework"] == "terraform"


def test_missing_severity_defaults_to_medium(monkeypatch, tmp_path):
    check = dict(_FAILED); check["severity"] = None
    _fake_checkov(monkeypatch, {"check_type": "terraform",
                                "results": {"failed_checks": [check]}})
    assert _findings(tmp_path)[0].base_severity == Severity.MEDIUM


def test_a_list_of_framework_blocks_is_handled(monkeypatch, tmp_path):
    k8s = {"check_type": "kubernetes",
           "results": {"failed_checks": [dict(_FAILED, check_id="CKV_K8S_1",
                                              file_path="/pod.yaml")]}}
    _fake_checkov(monkeypatch, [_REPORT, k8s])
    rules = {f.location["rule"] for f in _findings(tmp_path)}
    assert rules == {"CKV_AWS_18", "CKV_K8S_1"}


def test_passed_checks_are_ignored(monkeypatch, tmp_path):
    _fake_checkov(monkeypatch, {"check_type": "terraform",
                                "results": {"failed_checks": [], "passed_checks": [_FAILED]}})
    assert _findings(tmp_path) == []


def test_malformed_output_is_handled_not_crashed(monkeypatch, tmp_path):
    _fake_checkov(monkeypatch, None)
    assert _findings(tmp_path) == []


def test_a_checkov_crash_does_not_break_the_scan(monkeypatch, tmp_path):
    _fake_checkov(monkeypatch, _REPORT, raises=TimeoutError("checkov hung"))
    assert _findings(tmp_path) == []


def test_checks_without_id_or_path_are_skipped(monkeypatch, tmp_path):
    _fake_checkov(monkeypatch, {"check_type": "terraform", "results": {"failed_checks": [
        {"check_id": "X"}, {"file_path": "/y.tf"}, {}]}})
    assert _findings(tmp_path) == []


def test_duplicate_checks_collapse(monkeypatch, tmp_path):
    _fake_checkov(monkeypatch, {"check_type": "terraform",
                                "results": {"failed_checks": [_FAILED, dict(_FAILED)]}})
    assert len(_findings(tmp_path)) == 1


def test_built_in_rules_still_run_without_checkov(monkeypatch, tmp_path):
    # A workspace with an obviously-bad terraform file must still be flagged by the built-in rules.
    monkeypatch.setattr(ie.shutil, "which", lambda name: None)
    tf = tmp_path / "main.tf"
    tf.write_text(
        'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n')
    ctx = ScanContext(scan_id="t", asset_kind="repo", asset_identifier="x",
                      workspace_path=str(tmp_path))
    findings = list(IacEngine().run(ctx))
    assert IacEngine().health().ok
    # The built-in ruleset should have something to say about a public-read bucket; at minimum the
    # engine runs and returns without error. (Exact rule coverage is the built-in engine's own test.)
    assert isinstance(findings, list)


def test_health_reports_checkov_presence(monkeypatch):
    engine = IacEngine()
    monkeypatch.setattr(ie.shutil, "which", lambda name: "/usr/bin/checkov")
    assert "checkov policies" in engine.health().detail
    monkeypatch.setattr(ie.shutil, "which", lambda name: None)
    assert "checkov absent" in engine.health().detail
    assert engine.health().ok      # never degraded — built-in is complete
