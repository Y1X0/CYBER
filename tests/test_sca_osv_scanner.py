"""osv-scanner as an additional SCA backend for ScaEngine (Phase A, third tool integration).

osv-scanner runs only when the binary is present, so these tests drive it deterministically by
faking `shutil.which` and `subprocess.run` with canned osv-scanner JSON — the binary is not required
in CI. Same contract as the gitleaks and checkov integrations: additive (it widens lockfile coverage
to ecosystems the built-in parser skips), honest about failure, built-in path unchanged when absent.
"""

from __future__ import annotations

import json
from pathlib import Path

from guardian_core.enums import EngineKey, Severity
from guardian_scanner.engines import sca_engine as se
from guardian_scanner.engines.sca_engine import ScaEngine

_REPORT = {
    "results": [
        {
            "source": {"path": "/Cargo.lock", "type": "lockfile"},
            "packages": [
                {
                    "package": {"name": "openssl", "version": "0.10.0", "ecosystem": "crates.io"},
                    "vulnerabilities": [
                        {
                            "id": "RUSTSEC-2021-0001",
                            "summary": "Use-after-free in openssl",
                            "aliases": ["CVE-2021-1234", "GHSA-xxxx"],
                            "database_specific": {"severity": "HIGH"},
                        }
                    ],
                }
            ],
        }
    ]
}


def _fake_osv(monkeypatch, payload: object, *, present: bool = True,
              raises: Exception | None = None) -> None:
    monkeypatch.setattr(se.shutil, "which",
                        lambda name: "/usr/bin/osv-scanner" if (present and name == "osv-scanner")
                        else None)

    def fake_run(argv, **kwargs):  # noqa: ANN001, ANN202
        if raises is not None:
            raise raises

        class _P:
            returncode = 1   # osv-scanner exits 1 when vulns are found — a normal outcome
            stdout = json.dumps(payload) if payload is not None else "not json"
            stderr = ""
        return _P()

    monkeypatch.setattr(se.subprocess, "run", fake_run)


def _findings(tmp_path: Path) -> list:
    return list(ScaEngine()._run_osv_scanner_if_available(tmp_path))


def test_no_op_when_osv_scanner_is_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(se.shutil, "which", lambda name: None)
    assert _findings(tmp_path) == []


def test_a_vulnerable_dependency_becomes_a_finding(monkeypatch, tmp_path):
    _fake_osv(monkeypatch, _REPORT)
    findings = _findings(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.engine == EngineKey.SCA
    assert f.base_severity == Severity.HIGH
    assert f.location["package"] == "openssl"
    assert f.location["version"] == "0.10.0"
    assert f.location["ecosystem"] == "crates.io"
    assert "CVE-2021-1234" in f.cve_ids
    assert "GHSA-xxxx" not in f.cve_ids      # only CVE aliases are lifted into cve_ids
    assert f.references["detector"] == "osv-scanner"


def test_missing_severity_defaults_to_medium(monkeypatch, tmp_path):
    payload = json.loads(json.dumps(_REPORT))
    del payload["results"][0]["packages"][0]["vulnerabilities"][0]["database_specific"]
    _fake_osv(monkeypatch, payload)
    assert _findings(tmp_path)[0].base_severity == Severity.MEDIUM


def test_moderate_maps_to_medium(monkeypatch, tmp_path):
    payload = json.loads(json.dumps(_REPORT))
    payload["results"][0]["packages"][0]["vulnerabilities"][0]["database_specific"]["severity"] = "MODERATE"
    _fake_osv(monkeypatch, payload)
    assert _findings(tmp_path)[0].base_severity == Severity.MEDIUM


def test_empty_results_yield_nothing(monkeypatch, tmp_path):
    _fake_osv(monkeypatch, {"results": []})
    assert _findings(tmp_path) == []


def test_malformed_output_is_handled_not_crashed(monkeypatch, tmp_path):
    _fake_osv(monkeypatch, None)
    assert _findings(tmp_path) == []


def test_an_osv_crash_does_not_break_the_scan(monkeypatch, tmp_path):
    _fake_osv(monkeypatch, _REPORT, raises=TimeoutError("osv-scanner hung"))
    assert _findings(tmp_path) == []


def test_a_package_without_name_or_version_is_skipped(monkeypatch, tmp_path):
    payload = {"results": [{"source": {"path": "/x"}, "packages": [
        {"package": {"name": "", "version": "1.0"}, "vulnerabilities": [{"id": "A"}]},
        {"package": {"name": "y", "version": ""}, "vulnerabilities": [{"id": "B"}]},
    ]}]}
    _fake_osv(monkeypatch, payload)
    assert _findings(tmp_path) == []


def test_a_vuln_without_id_is_skipped(monkeypatch, tmp_path):
    payload = {"results": [{"source": {"path": "/x"}, "packages": [
        {"package": {"name": "a", "version": "1.0", "ecosystem": "npm"},
         "vulnerabilities": [{"summary": "no id"}]}]}]}
    _fake_osv(monkeypatch, payload)
    assert _findings(tmp_path) == []


def test_duplicate_vulns_collapse(monkeypatch, tmp_path):
    dup = json.loads(json.dumps(_REPORT))
    dup["results"][0]["packages"][0]["vulnerabilities"].append(
        dict(_REPORT["results"][0]["packages"][0]["vulnerabilities"][0]))
    _fake_osv(monkeypatch, dup)
    assert len(_findings(tmp_path)) == 1


def test_health_reports_osv_presence(monkeypatch):
    engine = ScaEngine()
    monkeypatch.setattr(se.shutil, "which", lambda name: "/usr/bin/osv-scanner")
    assert "osv-scanner" in engine.health().detail
    monkeypatch.setattr(se.shutil, "which", lambda name: None)
    assert "osv-scanner absent" in engine.health().detail
    assert engine.health().ok      # never degraded — built-in is complete
