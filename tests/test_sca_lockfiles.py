"""Lockfile parsing and the live vulnerability matchers.

A manifest says what was asked for; a lockfile says what was installed, including the transitive
dependencies nobody chose. Most vulnerable code arrives that way, so a scanner that reads only
`package.json` reports on a handful of packages and misses the hundreds beneath them.

The matcher tests cover the other half of the same defect: the OSV client existed, was tested, and
was wired to nothing, so dependency scanning ran against six hand-seeded advisories.
"""

from __future__ import annotations

import json

import pytest
from guardian_clients.feeds.base import NormalizedVuln
from guardian_core.cvss import base_score, severity_label
from guardian_core.enums import Severity
from guardian_scanner.engines import sca_engine as sca
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.vuln_match import CompositeVulnMatcher, OsvVulnMatcher


def _names(pairs):
    return {(n, v) for n, v, _eco, _src in pairs}


# ── npm ───────────────────────────────────────────────────────────────────────────────────────────
def test_package_lock_v3_includes_transitive_dependencies():
    text = json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/express/node_modules/cookie": {"version": "0.5.0"},
        },
    })
    found = _names(sca._parse_package_lock(text, "package-lock.json"))
    assert ("lodash", "4.17.20") in found
    assert ("cookie", "0.5.0") in found     # nested transitive
    assert ("app", "1.0.0") not in found    # the root project is not a dependency


def test_package_lock_v1_walks_nested_dependencies():
    text = json.dumps({
        "lockfileVersion": 1,
        "dependencies": {
            "lodash": {"version": "4.17.20"},
            "express": {"version": "4.18.2",
                        "dependencies": {"cookie": {"version": "0.5.0"}}},
        },
    })
    found = _names(sca._parse_package_lock(text, "package-lock.json"))
    assert {("lodash", "4.17.20"), ("express", "4.18.2"), ("cookie", "0.5.0")} <= found


def test_yarn_lock_handles_scoped_packages():
    text = '''# yarn lockfile v1
lodash@^4.17.0:
  version "4.17.20"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"

"@babel/core@^7.0.0":
  version "7.22.5"
'''
    found = _names(sca._parse_yarn_lock(text, "yarn.lock"))
    assert ("lodash", "4.17.20") in found
    assert ("@babel/core", "7.22.5") in found   # the leading @ must survive


def test_yarn_lock_multiple_specs_share_one_version():
    text = 'debug@^2.0.0, debug@^2.6.9:\n  version "2.6.9"\n'
    assert ("debug", "2.6.9") in _names(sca._parse_yarn_lock(text, "yarn.lock"))


# ── python ────────────────────────────────────────────────────────────────────────────────────────
def test_poetry_lock():
    text = '''[[package]]
name = "urllib3"
version = "1.26.5"

[[package]]
name = "requests"
version = "2.31.0"
'''
    found = _names(sca._parse_poetry_lock(text, "poetry.lock"))
    assert found == {("urllib3", "1.26.5"), ("requests", "2.31.0")}


def test_pipfile_lock_includes_dev_dependencies():
    text = json.dumps({
        "default": {"urllib3": {"version": "==1.26.5"}},
        "develop": {"pytest": {"version": "==7.4.0"}},
    })
    assert _names(sca._parse_pipfile_lock(text, "Pipfile.lock")) == {
        ("urllib3", "1.26.5"), ("pytest", "7.4.0")}


# ── other ecosystems ──────────────────────────────────────────────────────────────────────────────
def test_gemfile_lock():
    text = '''GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.4)
    rails (7.0.4)

PLATFORMS
  ruby
'''
    assert _names(sca._parse_gemfile_lock(text, "Gemfile.lock")) == {
        ("rack", "2.2.4"), ("rails", "7.0.4")}


def test_go_sum_skips_the_go_mod_hash_lines():
    text = ("github.com/pkg/errors v0.9.1 h1:abc=\n"
            "github.com/pkg/errors v0.9.1/go.mod h1:def=\n")
    assert _names(sca._parse_go_sum(text, "go.sum")) == {("github.com/pkg/errors", "0.9.1")}


def test_cargo_lock():
    text = '[[package]]\nname = "serde"\nversion = "1.0.163"\n'
    assert _names(sca._parse_cargo_lock(text, "Cargo.lock")) == {("serde", "1.0.163")}


def test_composer_lock():
    text = json.dumps({"packages": [{"name": "monolog/monolog", "version": "v2.9.1"}]})
    assert _names(sca._parse_composer_lock(text, "composer.lock")) == {
        ("monolog/monolog", "2.9.1")}


@pytest.mark.parametrize("parser", [
    sca._parse_package_lock, sca._parse_poetry_lock, sca._parse_pipfile_lock,
    sca._parse_gemfile_lock, sca._parse_go_sum, sca._parse_cargo_lock, sca._parse_composer_lock,
    sca._parse_yarn_lock,
])
def test_malformed_lockfiles_yield_nothing_rather_than_raising(parser):
    """A format that shifted between tool versions costs coverage of one file, never the scan."""
    assert list(parser("{{{ not valid at all", "f")) == []
    assert list(parser("", "f")) == []


# ── the engine end to end ─────────────────────────────────────────────────────────────────────────
class _FakeMatcher:
    def __init__(self, hits):
        self.hits = hits
        self.queried = []

    def match(self, *, name, version, ecosystem):
        self.queried.append((name, version, ecosystem))
        return self.hits.get(name, [])


def test_engine_reports_a_transitive_dependency(tmp_path):
    from guardian_scanner.engines.base import VulnMatch

    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"": {"name": "app"},
                     "node_modules/express": {"version": "4.18.2"},
                     "node_modules/express/node_modules/cookie": {"version": "0.5.0"}},
    }))
    matcher = _FakeMatcher({"cookie": [VulnMatch(external_id="CVE-2024-47764", cvss_base=7.5)]})
    ctx = ScanContext(scan_id="s", asset_kind="repo", asset_identifier="repo",
                      workspace_path=str(tmp_path), vuln_matcher=matcher)

    findings = list(sca.ScaEngine().run(ctx))
    assert len(findings) == 1
    assert "cookie@0.5.0" in findings[0].title
    assert findings[0].location["path"] == "package-lock.json"
    # The transitive package was queried, which is the behaviour the manifest-only parser lacked.
    assert ("cookie", "0.5.0", "npm") in matcher.queried


# ── CVSS ──────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("vector,expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # critical, unchanged scope
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),   # high availability impact
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),   # low: impact 1.412 + expl 0.333
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # changed scope (classic XSS)
])
def test_cvss_base_scores_match_the_specification(vector, expected):
    assert base_score(vector) == pytest.approx(expected, abs=0.05)


def test_cvss_v2_and_v4_are_not_guessed_at():
    assert base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P") is None
    assert base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N") is None


def test_incomplete_vector_returns_none_not_zero():
    """None means 'could not evaluate'; 0.0 is a real score meaning 'no impact'."""
    assert base_score("CVSS:3.1/AV:N/AC:L") is None
    assert base_score("") is None


def test_severity_labels():
    assert severity_label(9.8) == "critical"
    assert severity_label(7.5) == "high"
    assert severity_label(5.0) == "medium"
    assert severity_label(2.0) == "low"
    assert severity_label(None) is None


# ── OSV matcher ───────────────────────────────────────────────────────────────────────────────────
class _FakeOsv:
    def __init__(self, vulns=None, raises=False):
        self.vulns = vulns or []
        self.raises = raises

    def query_package(self, *, name, version, ecosystem):
        if self.raises:
            raise RuntimeError("feed down")
        return self.vulns


def test_osv_matcher_derives_severity_from_the_vector():
    osv = _FakeOsv([NormalizedVuln(
        external_id="CVE-2021-23337", source="osv", summary="lodash command injection",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cwe_ids=["CWE-78"])])
    matches = OsvVulnMatcher(client=osv).match(name="lodash", version="4.17.20", ecosystem="npm")
    assert len(matches) == 1
    assert matches[0].cvss_base == pytest.approx(9.8, abs=0.05)
    assert matches[0].severity is Severity.CRITICAL
    assert matches[0].cwe_ids == ["CWE-78"]


def test_osv_outage_degrades_to_no_matches_rather_than_failing_the_scan():
    assert OsvVulnMatcher(client=_FakeOsv(raises=True)).match(
        name="lodash", version="4.17.20", ecosystem="npm") == []


# ── composite ─────────────────────────────────────────────────────────────────────────────────────
def test_composite_merges_the_same_advisory_from_two_sources():
    from guardian_scanner.engines.base import VulnMatch

    kb = _FakeMatcher({"lodash": [VulnMatch(external_id="CVE-2021-23337", kev=True,
                                            epss_score=0.42, cvss_base=7.2)]})
    osv = _FakeMatcher({"lodash": [VulnMatch(external_id="cve-2021-23337", cvss_base=9.8,
                                             cwe_ids=["CWE-78"], summary="from osv")]})
    merged = CompositeVulnMatcher(kb, osv).match(
        name="lodash", version="4.17.20", ecosystem="npm")

    assert len(merged) == 1, "the same CVE from two sources is corroboration, not duplication"
    only = merged[0]
    assert only.kev is True                 # enrichment the KB had and OSV did not
    assert only.epss_score == 0.42
    assert only.cvss_base == 9.8            # the more severe assessment wins
    assert only.cwe_ids == ["CWE-78"]


def test_composite_survives_one_source_failing():
    from guardian_scanner.engines.base import VulnMatch

    good = _FakeMatcher({"lodash": [VulnMatch(external_id="CVE-1", cvss_base=5.0)]})
    merged = CompositeVulnMatcher(OsvVulnMatcher(client=_FakeOsv(raises=True)), good).match(
        name="lodash", version="4.17.20", ecosystem="npm")
    assert [m.external_id for m in merged] == ["CVE-1"]
