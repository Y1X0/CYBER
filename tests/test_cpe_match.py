"""Matching a running service version to the advisories that apply (WP-C3).

The version arithmetic is what this file is about. `versionEndExcluding: 9.3.2` means the advisory
covers everything below 9.3.2, and deciding whether `8.9p1` qualifies by string order puts it
*after* 9.3.2 and clears a vulnerable host. Every bound below is therefore checked against a real
comparator, not a lexical one.

The second theme is refusal. This engine's input is a guess made from a banner, so the ways it can
be wrong are the ways it must stay quiet: no product means no match, and a product with no known
release must not pull in every CVE that product ever had.
"""

from __future__ import annotations

import pytest
from guardian_scanner.cpe_match import ServiceIdentity, applies, parse_cpe, unbounded


def _row(**bounds):
    row = {"vendor": "openbsd", "product": "openssh", "version": "*"}
    row.update(bounds)
    return row


# ── CPE parsing ───────────────────────────────────────────────────────────────────────────────────
def test_a_cpe_yields_vendor_product_and_version():
    identity = parse_cpe("cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*")
    assert identity == ServiceIdentity(vendor="openbsd", product="openssh", version="8.9p1")
    assert identity.identified is True


def test_a_wildcard_version_is_no_version():
    identity = parse_cpe("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*")
    assert identity.version == ""
    assert identity.identified is True


@pytest.mark.parametrize("value", ["cpe:/a:openbsd:openssh:8.9", "not a cpe", "", "cpe:2.3:a"])
def test_a_malformed_cpe_is_refused(value):
    assert parse_cpe(value) is None


# ── version bounds ────────────────────────────────────────────────────────────────────────────────
def test_an_upper_exclusive_bound_covers_everything_below_it():
    row = _row(version_end_excluding="9.3.2")
    assert applies(row, "8.9p1") is True
    assert applies(row, "9.3.1") is True
    assert applies(row, "9.3.2") is False
    assert applies(row, "9.4") is False


def test_string_ordering_would_get_this_wrong():
    """Lexically `"10.0" < "9.0"`, so a string comparator puts every 10.x release below a 9.x
    bound — and reports a patched host as vulnerable. Double-digit majors are where this bites."""
    assert "10.0" < "9.0"                        # the wrong answer, stated plainly
    assert applies(_row(version_end_excluding="9.0"), "10.0") is False
    assert applies(_row(version_end_excluding="9.0"), "8.9") is True


def test_a_suffixed_release_is_ordered_by_its_numbers():
    """OpenSSH publishes `8.9p1`; NVD bounds it against `9.3.2`."""
    row = _row(version_start_including="5.5", version_end_excluding="9.3.2")
    assert applies(row, "8.9p1") is True
    assert applies(row, "9.4p1") is False


def test_an_upper_inclusive_bound_includes_its_endpoint():
    row = _row(version_end_including="1.24.0")
    assert applies(row, "1.24.0") is True
    assert applies(row, "1.24.1") is False


def test_a_lower_inclusive_bound_excludes_earlier_releases():
    row = _row(version_start_including="5.5", version_end_excluding="9.3.2")
    assert applies(row, "5.5") is True
    assert applies(row, "5.4") is False
    assert applies(row, "4.0") is False


def test_a_lower_exclusive_bound_excludes_its_endpoint():
    row = _row(version_start_excluding="1.0", version_end_including="2.0")
    assert applies(row, "1.0") is False
    assert applies(row, "1.0.1") is True


def test_an_exact_version_matches_only_itself():
    row = {"vendor": "v", "product": "p", "version": "2.4.52"}
    assert applies(row, "2.4.52") is True
    assert applies(row, "2.4.53") is False
    assert applies(row, "") is False


def test_an_unbounded_row_matches_nothing_by_version():
    """A product named with no constraint covers every release. Accepting it here would report
    every CVE the product ever had against a host whose version we do know."""
    row = _row()
    assert unbounded(row) is True
    assert applies(row, "1.0") is False
    assert applies(row, "") is False


def test_bounds_cannot_be_evaluated_without_a_version():
    assert applies(_row(version_end_excluding="9.3.2"), "") is False


# ── the matcher, against a real knowledge base ────────────────────────────────────────────────────
def test_an_unidentified_service_matches_nothing():
    """A port number is not a product. Matching on it attributes an advisory to whatever is
    listening, which on 8080 is anybody's guess."""
    from guardian_scanner.cpe_match import CpeVulnMatcher

    matcher = CpeVulnMatcher(session=None)
    assert matcher.match_identity(ServiceIdentity(vendor="", product="", version="1.0")) == []
    assert matcher.match_cpe("not a cpe") == []
