"""SCA supply-chain signals: malicious-package (MAL-) findings and typosquat indicators.

Orthogonal to the existing vuln→CVE matching (unchanged, see test_sca_engine.py). A MAL- advisory
means the package is malicious, not merely vulnerable — a CONFIRMED finding. A name that resembles a
popular package is a POTENTIAL typosquat indicator, never presented as confirmed malicious.
"""

from __future__ import annotations

from guardian_core.enums import EngineKey, Severity
from guardian_scanner.engines.base import ScanContext, VulnMatch
from guardian_scanner.engines.sca_engine import ScaEngine
from guardian_scanner.typosquat import POPULAR_LIST_VERSION, nearest_popular
from guardian_scanner.vuln_match import _is_malicious


class _MalMatcher:
    """Returns a malicious (MAL-) advisory for evil-pkg@1.0, a CVE for pyyaml@5.3 — like OSV."""

    def match(self, *, name, version, ecosystem):
        if name == "evil-pkg" and version == "1.0":
            return [VulnMatch(external_id="MAL-2024-0001", summary="Backdoored release.",
                              malicious=True)]
        if name == "pyyaml" and version == "5.3":
            return [VulnMatch(external_id="CVE-2020-14343", severity=Severity.CRITICAL,
                              cvss_base=9.8)]
        return []


def _run(content: str, matcher=None):
    return list(ScaEngine().run(ScanContext(
        scan_id="t", asset_kind="repo", asset_identifier="x",
        inline_content=content, vuln_matcher=matcher)))


# ── malicious-package (MAL-) ────────────────────────────────────────────────────────────────────
def test_a_mal_advisory_match_is_a_confirmed_malicious_finding():
    findings = _run("evil-pkg==1.0\n", _MalMatcher())
    mal = next(f for f in findings if f.category == "malicious-dep")
    assert mal.engine == EngineKey.SCA
    assert "MAL-2024-0001" in mal.title
    assert mal.confidence == "high"
    assert mal.evidence["detail"]["confidence_tier"] == "confirmed"
    assert mal.evidence["detail"]["malicious"] is True
    # No CVSS on the advisory → floored at HIGH, because a confirmed backdoor is never low.
    assert mal.base_severity == Severity.HIGH
    # It is NOT filed as an ordinary vulnerable dependency.
    assert not [f for f in findings if f.category == "vuln-dep"]


def test_a_malicious_advisory_with_a_high_cvss_keeps_it():
    class M:
        def match(self, *, name, version, ecosystem):
            return [VulnMatch(external_id="MAL-9", severity=Severity.CRITICAL, cvss_base=9.8,
                              malicious=True)]
    mal = next(f for f in _run("evil==2.0\n", M()) if f.category == "malicious-dep")
    assert mal.base_severity == Severity.CRITICAL


def test_the_mal_prefix_is_the_deterministic_signal():
    assert _is_malicious("MAL-2024-0001") is True
    assert _is_malicious("mal-2024-1") is True          # case-insensitive
    assert _is_malicious("CVE-2024-1") is False
    assert _is_malicious("GHSA-xxxx") is False
    assert _is_malicious("") is False
    assert VulnMatch(external_id="CVE-1").malicious is False   # default off


def test_an_ordinary_cve_match_is_unchanged():
    """The existing vuln→CVE path must be untouched by the malicious branch."""
    findings = _run("pyyaml==5.3\n", _MalMatcher())
    vuln = next(f for f in findings if f.category == "vuln-dep")
    assert "CVE-2020-14343" in vuln.cve_ids
    assert vuln.base_severity == Severity.CRITICAL
    assert not [f for f in findings if f.category == "malicious-dep"]


# ── typosquat indicators ────────────────────────────────────────────────────────────────────────
def test_a_near_miss_name_is_a_potential_typosquat():
    findings = _run("reqeusts==1.0\n")
    ts = next(f for f in findings if f.category == "typosquat-dep")
    assert ts.confidence == "low"
    assert ts.evidence["detail"]["confidence_tier"] == "potential"
    assert ts.evidence["detail"]["resembles"] == "requests"
    assert ts.base_severity == Severity.MEDIUM
    assert "POTENTIAL" in ts.description and "requests" in ts.title
    # Never labelled confirmed/malicious.
    assert ts.category != "malicious-dep"
    assert ts.evidence["detail"]["popular_list_version"] == POPULAR_LIST_VERSION


def test_the_real_popular_package_does_not_fire_typosquat():
    assert [f for f in _run("requests==2.31.0\n") if f.category == "typosquat-dep"] == []
    # A PyPI separator variant is the SAME package (PEP 503), not a squat.
    assert [f for f in _run("python_dateutil==2.9\n") if f.category == "typosquat-dep"] == []


def test_an_unrelated_name_does_not_fire():
    assert [f for f in _run("my-internal-service==0.1\n") if f.category == "typosquat-dep"] == []


def test_typosquat_is_deterministic_and_order_independent():
    a = _run("reqeusts==1.0\nurllib==1.0\nmy-lib==1.0\n")
    b = _run("my-lib==1.0\nurllib==1.0\nreqeusts==1.0\n")
    key = lambda fs: sorted((f.category, f.title) for f in fs)  # noqa: E731
    assert key(a) == key(b)
    assert {f.title for f in a if f.category == "typosquat-dep"}  # at least one fired


def test_nearest_popular_unit():
    assert nearest_popular("reqeusts", "pypi").popular == "requests"
    assert nearest_popular("requests", "pypi") is None          # own name is never a squat
    assert nearest_popular("lo-dash", "npm").popular == "lodash"  # npm separator IS a squat
    assert nearest_popular("python_dateutil", "pypi") is None    # PyPI separator == same package
    assert nearest_popular("totally-unrelated", "npm") is None
    assert nearest_popular("x", "pypi") is None                  # too short to judge
