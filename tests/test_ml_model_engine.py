"""ML-model supply-chain engine — modelscan-backed detection of unsafe operators (Phase A).

This is the first engine whose tool is its ONLY detector: there is no hand-written fallback behind
modelscan the way the built-in patterns sit behind gitleaks. So the load-bearing property under test
is not just the finding mapping — it is the honesty of an *empty* result. When modelscan is absent,
the engine must report `degraded` so `verification.engine_outcome` reads its silence as
INCONCLUSIVE, never RESOLVED — a malicious model that was never scanned must never render as clean.

modelscan runs only when the binary is present, so these tests drive it deterministically by faking
`shutil.which` and `subprocess.run` with canned modelscan JSON written to the `-o` report path — the
binary is not required in CI.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from guardian_core.enums import EngineKey, Severity
from guardian_scanner.engines import ml_model_engine as me
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.engines.ml_model_engine import MlModelEngine, MlModelInputError
from guardian_scanner.verification import INCONCLUSIVE, RESOLVED, engine_outcome

_ISSUE = {
    "description": "Use of unsafe operator 'system' from module 'posix'",
    "operator": "system",
    "module": "posix",
    "source": "models/pretrained.pkl",
    "scanner": "modelscan.scanners.PickleUnsafeOpScan",
    "severity": "CRITICAL",
}
_REPORT = {
    "summary": {"total_issues": 1, "total_issues_by_severity": {"CRITICAL": 1}},
    "issues": [_ISSUE],
    "errors": [],
}


def _fake_modelscan(monkeypatch, payload: object, *, present: bool = True,
                    raises: Exception | None = None) -> None:
    monkeypatch.setattr(me.shutil, "which",
                        lambda name: "/usr/bin/modelscan" if (present and name == "modelscan")
                        else None)

    def fake_run(argv, **kwargs):  # noqa: ANN001, ANN202
        if raises is not None:
            raise raises
        out = argv[argv.index("-o") + 1]                 # modelscan writes JSON to the -o path
        Path(out).write_text(json.dumps(payload) if payload is not None else "not json")

        class _P:
            returncode = 1   # modelscan exits non-zero when issues are found — a normal outcome
            stdout = b""
            stderr = b""
        return _P()

    monkeypatch.setattr(me.subprocess, "run", fake_run)


def _findings(tmp_path: Path) -> list:
    return list(MlModelEngine()._run_modelscan_if_available(tmp_path))


def test_no_op_when_modelscan_is_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(me.shutil, "which", lambda name: None)
    assert _findings(tmp_path) == []


def test_an_unsafe_operator_becomes_a_finding(monkeypatch, tmp_path):
    _fake_modelscan(monkeypatch, _REPORT)
    findings = _findings(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.engine == EngineKey.ML_MODEL
    assert f.base_severity == Severity.CRITICAL
    assert f.location["path"] == "models/pretrained.pkl"
    assert f.location["operator"] == "system"
    assert f.location["module"] == "posix"
    assert f.evidence["detector"] == "modelscan"
    assert f.cwe_id == "CWE-502"
    assert "posix.system" in f.title


def test_missing_severity_defaults_to_high(monkeypatch, tmp_path):
    issue = dict(_ISSUE)
    del issue["severity"]
    _fake_modelscan(monkeypatch, {"issues": [issue]})
    # Loading a model is code execution regardless — an ungraded operator is HIGH, never downgraded.
    assert _findings(tmp_path)[0].base_severity == Severity.HIGH


def test_each_modelscan_grade_maps_through(monkeypatch, tmp_path):
    for grade, sev in [("CRITICAL", Severity.CRITICAL), ("HIGH", Severity.HIGH),
                       ("MEDIUM", Severity.MEDIUM), ("LOW", Severity.LOW)]:
        issue = dict(_ISSUE)
        issue["severity"] = grade
        _fake_modelscan(monkeypatch, {"issues": [issue]})
        assert _findings(tmp_path)[0].base_severity == sev, grade


def test_empty_issues_yield_nothing(monkeypatch, tmp_path):
    _fake_modelscan(monkeypatch, {"issues": [], "errors": []})
    assert _findings(tmp_path) == []


def test_malformed_output_is_handled_not_crashed(monkeypatch, tmp_path):
    _fake_modelscan(monkeypatch, None)
    assert _findings(tmp_path) == []


def test_a_modelscan_crash_does_not_break_the_scan(monkeypatch, tmp_path):
    _fake_modelscan(monkeypatch, _REPORT, raises=TimeoutError("modelscan hung"))
    assert _findings(tmp_path) == []


def test_an_issue_without_a_source_file_is_skipped(monkeypatch, tmp_path):
    payload = {"issues": [
        {"operator": "system", "module": "posix", "severity": "HIGH"},   # no source
        {"source": "", "operator": "exec", "severity": "HIGH"},          # empty source
    ]}
    _fake_modelscan(monkeypatch, payload)
    assert _findings(tmp_path) == []


def test_an_issue_without_operator_or_module_is_skipped(monkeypatch, tmp_path):
    _fake_modelscan(monkeypatch, {"issues": [{"source": "m.pkl", "severity": "HIGH"}]})
    assert _findings(tmp_path) == []


def test_duplicate_operators_in_the_same_file_collapse(monkeypatch, tmp_path):
    _fake_modelscan(monkeypatch, {"issues": [_ISSUE, dict(_ISSUE)]})
    assert len(_findings(tmp_path)) == 1


def test_the_raw_report_is_read_as_a_dict_only(monkeypatch, tmp_path):
    # A JSON array where a dict is expected (a schema drift) must not crash the scan.
    _fake_modelscan(monkeypatch, [_ISSUE])
    assert _findings(tmp_path) == []


def test_no_workspace_raises_rather_than_completing_clean(tmp_path):
    # A silent empty return would let WP-E2 resolve this engine's findings on an asset that was
    # never actually scanned. Raising turns that into a failed run → NOT_CHECKED.
    ctx = ScanContext(scan_id="t", asset_kind="repo", asset_identifier="x", workspace_path=None)
    with pytest.raises(MlModelInputError):
        list(MlModelEngine().run(ctx))


def test_inline_content_is_a_no_op(monkeypatch, tmp_path):
    # A model is a binary artifact; an inline text snippet carries no model to scan.
    ctx = ScanContext(scan_id="t", asset_kind="repo", asset_identifier="x",
                      inline_content="print('hi')")
    assert list(MlModelEngine().run(ctx)) == []


def test_health_is_degraded_without_modelscan(monkeypatch):
    engine = MlModelEngine()
    monkeypatch.setattr(me.shutil, "which", lambda name: None)
    h = engine.health()
    assert h.ok is True            # the engine still runs
    assert h.degraded is True      # but it is the ONLY detector — absent means nothing was scanned
    assert h.missing == ("modelscan",)
    assert "NOT scanned" in h.detail


def test_health_is_not_degraded_with_modelscan(monkeypatch):
    engine = MlModelEngine()
    monkeypatch.setattr(me.shutil, "which", lambda name: "/usr/bin/modelscan")
    h = engine.health()
    assert h.ok is True
    assert h.degraded is False
    assert "modelscan present" in h.detail


def test_an_absent_tool_makes_an_empty_run_inconclusive_not_resolved():
    """The whole safety property: a completed run of this engine with modelscan absent records
    `degraded`, and engine_outcome must turn that into INCONCLUSIVE — so an unscanned model can
    never resolve (clear) an existing ML-model finding, only a genuine clean scan can."""

    class _Run:
        status = "completed"
        engine = EngineKey.ML_MODEL.value
        error = None
        # What tasks.py records from a degraded MlModelEngine.health().
        tool_versions = {"ml_model": "1.0.0", "degraded": True, "missing": ["modelscan"]}

    verdict = engine_outcome(_Run())
    assert verdict.verdict == INCONCLUSIVE
    assert not verdict.is_evidence          # cannot resolve a finding
    assert verdict.verdict != RESOLVED


def test_a_clean_scan_with_modelscan_present_is_resolving_evidence():
    """The complement: when modelscan actually ran (not degraded) and reported nothing, an empty
    result IS evidence — a genuinely clean scan may resolve stale findings."""

    class _Run:
        status = "completed"
        engine = EngineKey.ML_MODEL.value
        error = None
        tool_versions = {"ml_model": "1.0.0", "degraded": False, "missing": []}

    verdict = engine_outcome(_Run())
    assert verdict.verdict == RESOLVED
    assert verdict.is_evidence
