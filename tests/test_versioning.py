"""Version ordering and range evaluation, per ecosystem.

The ordering cases come from the specifications themselves (SemVer §11, PEP 440, Debian policy,
rpmvercmp), because "looks right" is not a standard and each of these ecosystems has at least one
rule that contradicts intuition.

The range cases exist because of a specific defect: matching used to be exact string membership, so
an advisory saying "fixed in 1.4.2" never matched the vulnerable 1.4.1 that a customer was actually
running. `test_the_original_defect` pins that.
"""

from __future__ import annotations

import pytest
from guardian_core.versioning import (
    Ecosystem,
    compare,
    in_event_range,
    normalize_ecosystem,
    satisfies_constraint,
    version_affected,
)


def _ordered(versions, eco):
    """Assert a list is in strictly ascending order under `eco`'s rules."""
    for lower, higher in zip(versions, versions[1:], strict=False):
        assert compare(lower, higher, eco) == -1, f"expected {lower} < {higher} under {eco}"
        assert compare(higher, lower, eco) == 1
    for v in versions:
        assert compare(v, v, eco) == 0


# ── SemVer §11 ────────────────────────────────────────────────────────────────────────────────────
def test_semver_precedence_from_the_specification():
    _ordered([
        "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
        "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
    ], Ecosystem.NPM)


def test_semver_release_outranks_any_prerelease():
    assert compare("1.0.0", "1.0.0-rc.99", Ecosystem.NPM) == 1


def test_semver_build_metadata_is_ignored():
    assert compare("1.0.0+build.1", "1.0.0+build.2", Ecosystem.NPM) == 0


def test_semver_trailing_zeros_are_insignificant():
    assert compare("1.0", "1.0.0", Ecosystem.NPM) == 0


def test_go_v_prefix_and_incompatible_suffix():
    assert compare("v1.2.3", "1.2.3", Ecosystem.GO) == 0
    assert compare("v2.0.0+incompatible", "v2.0.0", Ecosystem.GO) == 0


# ── PEP 440 ───────────────────────────────────────────────────────────────────────────────────────
def test_pep440_release_cycle_ordering():
    _ordered(["1.0.dev1", "1.0a1", "1.0b1", "1.0rc1", "1.0", "1.0.post1"], Ecosystem.PYPI)


def test_pep440_epoch_outranks_release_number():
    # An epoch exists precisely so a project can renumber downwards; 1!1.0 is newer than 2.0.
    assert compare("1!1.0", "2.0", Ecosystem.PYPI) == 1


def test_pep440_prerelease_spellings_are_equivalent():
    assert compare("1.0alpha1", "1.0a1", Ecosystem.PYPI) == 0
    assert compare("1.0beta2", "1.0b2", Ecosystem.PYPI) == 0
    assert compare("1.0c1", "1.0rc1", Ecosystem.PYPI) == 0


def test_pep440_dev_precedes_its_own_prerelease():
    assert compare("1.0.dev1", "1.0a1", Ecosystem.PYPI) == -1


# ── Debian ────────────────────────────────────────────────────────────────────────────────────────
def test_debian_tilde_sorts_before_everything():
    assert compare("1.0~rc1", "1.0", Ecosystem.DEBIAN) == -1
    assert compare("1.0~~", "1.0~", Ecosystem.DEBIAN) == -1


def test_debian_epoch_dominates():
    assert compare("1:1.0", "2.0", Ecosystem.DEBIAN) == 1


def test_debian_revision_is_compared_after_upstream():
    assert compare("1.0-1", "1.0-2", Ecosystem.DEBIAN) == -1
    assert compare("1.0-10", "1.0-9", Ecosystem.DEBIAN) == 1


def test_debian_numeric_segments_compare_numerically():
    assert compare("1.10", "1.9", Ecosystem.DEBIAN) == 1


# ── RPM ───────────────────────────────────────────────────────────────────────────────────────────
def test_rpm_tilde_is_a_prerelease_marker():
    assert compare("1.0~rc1", "1.0", Ecosystem.RPM) == -1


def test_rpm_numeric_outranks_alphabetic():
    assert compare("1.1", "1.a", Ecosystem.RPM) == 1


def test_rpm_leading_zeros_do_not_change_value():
    assert compare("1.007", "1.7", Ecosystem.RPM) == 0


def test_rpm_release_field_ordering():
    assert compare("2.0-1.el8", "2.0-2.el8", Ecosystem.RPM) == -1


# ── Maven ─────────────────────────────────────────────────────────────────────────────────────────
def test_maven_qualifier_ordering():
    _ordered(["1.0-alpha", "1.0-beta", "1.0-rc", "1.0"], Ecosystem.MAVEN)


def test_maven_service_pack_follows_release():
    assert compare("1.0-sp", "1.0", Ecosystem.MAVEN) == 1


# ── ecosystem normalization ───────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("label,expected", [
    ("PyPI", Ecosystem.PYPI), ("python", Ecosystem.PYPI),
    ("npm", Ecosystem.NPM), ("Node", Ecosystem.NPM),
    ("Ubuntu", Ecosystem.DEBIAN), ("RedHat", Ecosystem.RPM),
    ("crates.io", Ecosystem.SEMVER), ("something-new", Ecosystem.GENERIC), (None, Ecosystem.GENERIC),
])
def test_ecosystem_aliases(label, expected):
    assert normalize_ecosystem(label) is expected


def test_unparseable_versions_degrade_rather_than_raise():
    assert compare("not-a-version", "also-not", Ecosystem.PYPI) in (-1, 0, 1)
    assert compare("", "1.0", Ecosystem.NPM) in (-1, 0, 1)


# ── OSV event ranges ──────────────────────────────────────────────────────────────────────────────
_INTRODUCED_FIXED = [{"introduced": "0"}, {"fixed": "1.4.2"}]


@pytest.mark.parametrize("version,affected", [
    ("1.0.0", True), ("1.4.1", True), ("1.4.2", False), ("1.5.0", False), ("2.0.0", False),
])
def test_introduced_zero_fixed_range(version, affected):
    assert in_event_range(version, _INTRODUCED_FIXED, Ecosystem.NPM) is affected


@pytest.mark.parametrize("version,affected", [
    ("0.9.0", False), ("1.0.0", True), ("1.2.0", True), ("1.3.0", False),
])
def test_bounded_introduced_range(version, affected):
    events = [{"introduced": "1.0.0"}, {"fixed": "1.3.0"}]
    assert in_event_range(version, events, Ecosystem.NPM) is affected


def test_last_affected_is_inclusive():
    events = [{"introduced": "1.0.0"}, {"last_affected": "1.2.3"}]
    assert in_event_range("1.2.3", events, Ecosystem.NPM) is True
    assert in_event_range("1.2.4", events, Ecosystem.NPM) is False


def test_range_with_no_events_matches_nothing():
    assert in_event_range("1.0.0", [], Ecosystem.NPM) is False


# ── constraint strings ────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("version,constraint,expected", [
    ("1.4.1", "<1.4.2", True),
    ("1.4.2", "<1.4.2", False),
    ("1.5.0", ">=1.0,<2.0", True),
    ("2.0.0", ">=1.0,<2.0", False),
    ("1.0.0", "==1.0.0", True),
    ("1.0.1", "==1.0.0", False),
    ("1.0.1", "!=1.0.0", True),
    ("1.2.9", "^1.2.0", True),
    ("2.0.0", "^1.2.0", False),
])
def test_constraint_expressions(version, constraint, expected):
    assert satisfies_constraint(version, constraint, Ecosystem.NPM) is expected


def test_malformed_constraint_never_claims_a_match():
    assert satisfies_constraint("1.0.0", ">>>garbage", Ecosystem.NPM) is False


# ── entry-level evaluation, the shape the matcher consumes ────────────────────────────────────────
def test_the_original_defect():
    """A real advisory range against the version a customer is running.

    Under exact-string matching this returned False and the customer was told they were safe.
    """
    entry = {
        "ecosystem": "npm", "package": "lodash",
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
    }
    assert version_affected(entry, "4.17.20") is True
    assert version_affected(entry, "4.17.21") is False


def test_explicit_version_list_still_works():
    entry = {"ecosystem": "pypi", "versions": ["5.3", "5.3.1"]}
    assert version_affected(entry, "5.3.1") is True
    assert version_affected(entry, "5.4") is False


def test_package_level_advisory_with_no_pinning_affects_everything():
    assert version_affected({"ecosystem": "npm", "package": "left-pad"}, "1.0.0") is True


def test_ranges_that_all_evaluate_false_are_a_definite_no():
    entry = {"ecosystem": "npm",
             "ranges": [{"events": [{"introduced": "1.0.0"}, {"fixed": "1.1.0"}]}]}
    assert version_affected(entry, "2.0.0") is False


def test_empty_version_is_never_affected():
    entry = {"ecosystem": "npm", "ranges": [{"events": [{"introduced": "0"}]}]}
    assert version_affected(entry, "") is False


def test_debian_backport_ordering_in_a_range():
    """Distributions backport fixes, so the release field decides exposure."""
    entry = {"ecosystem": "debian",
             "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.0-3"}]}]}
    assert version_affected(entry, "1.0-2") is True
    assert version_affected(entry, "1.0-3") is False
