"""SCA parses manifests and matches via the injected matcher (no DB needed here)."""

from guardian_core.enums import EngineKey, Severity
from guardian_scanner.engines.base import ScanContext, VulnMatch


class FakeMatcher:
    """Returns a hit only for pyyaml==5.3 (pypi)."""

    def match(self, *, name, version, ecosystem):
        if name == "pyyaml" and version == "5.3" and ecosystem == "pypi":
            return [
                VulnMatch(
                    external_id="CVE-2020-14343",
                    summary="PyYAML RCE",
                    severity=Severity.CRITICAL,
                    cvss_base=9.8,
                    epss_score=0.42,
                    cwe_ids=["CWE-502"],
                )
            ]
        return []


def _run(content: str):
    from guardian_scanner.engines.sca_engine import ScaEngine

    return list(
        ScaEngine().run(
            ScanContext(
                scan_id="t",
                asset_kind="repo",
                asset_identifier="x",
                inline_content=content,
                vuln_matcher=FakeMatcher(),
            )
        )
    )


def test_matches_vulnerable_requirement():
    findings = _run("pyyaml==5.3\nrequests==2.31.0\n")
    assert len(findings) == 1
    f = findings[0]
    assert f.engine == EngineKey.SCA
    assert "CVE-2020-14343" in f.cve_ids
    assert f.base_severity == Severity.CRITICAL
    assert f.location["package"] == "pyyaml"


def test_no_matcher_means_no_findings():
    from guardian_scanner.engines.sca_engine import ScaEngine

    ctx = ScanContext(
        scan_id="t", asset_kind="repo", asset_identifier="x", inline_content="pyyaml==5.3\n"
    )  # no matcher injected
    assert list(ScaEngine().run(ctx)) == []


def test_clean_requirements_no_findings():
    assert _run("requests==2.31.0\n") == []
