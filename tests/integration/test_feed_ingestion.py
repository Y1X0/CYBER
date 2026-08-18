"""Vulnerability intelligence ingestion against a real database (WP-C1).

The knowledge base was empty and nothing filled it. `sync_feeds` only enriched rows that already
existed, so it enriched nothing, reported `status=completed`, and left an operator with a green
sync over a knowledge base that had never held an advisory.

The tests that matter here are about a sync telling the truth:

* a failure is recorded as a failure and **does not advance the watermark**, so the window that
  failed is re-fetched rather than skipped forever with nothing to show the gap;
* "0 new advisories" (a healthy Tuesday) is distinguishable from "0 records seen" (an outage);
* a source that owns a field keeps it — NVD owns CVSS and CPE applicability, OSV owns package
  ranges — so the knowledge base does not depend on which feed happened to sync last.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


def _cve(suffix: str) -> str:
    return f"CVE-2099-{suffix}"


@pytest.fixture
def marker():
    return uuid.uuid4().hex[:6]


def _record(external_id, source="nvd", **kwargs):
    from guardian_clients.feeds import NormalizedVuln

    record = NormalizedVuln(external_id=external_id, source=source)
    for key, value in kwargs.items():
        setattr(record, key, value)
    return record


def _state(source):
    from guardian_db.models import FeedState
    from guardian_db.session import session_scope

    with session_scope() as db:
        return db.get(FeedState, source)


def _syncs(source):
    from guardian_db.models import FeedSync
    from guardian_db.session import session_scope

    with session_scope() as db:
        return db.query(FeedSync).filter(FeedSync.source == source).order_by(
            FeedSync.started_at
        ).all()


def _vuln(external_id):
    from guardian_db.models import Vulnerability
    from guardian_db.session import session_scope

    with session_scope() as db:
        return db.query(Vulnerability).filter(
            Vulnerability.external_id == external_id
        ).one_or_none()


# ── ingestion ─────────────────────────────────────────────────────────────────────────────────────
def test_a_sync_creates_advisories_and_advances_the_watermark(marker):
    from guardian_scanner import intel

    source = f"test-nvd-{marker}"
    result = intel.run_source(source, lambda _s, _u: [
        _record(_cve(f"{marker}01"), summary="one", cvss_base=9.8, severity="critical"),
        _record(_cve(f"{marker}02"), summary="two"),
    ])

    assert result["status"] == "completed"
    assert result["created"] == 2
    assert float(_vuln(_cve(f"{marker}01")).cvss_base) == 9.8
    assert _state(source).watermark is not None
    assert _state(source).consecutive_failures == 0


def test_a_second_sync_updates_rather_than_duplicating(marker):
    from guardian_scanner import intel

    source = f"test-nvd-{marker}"
    cve = _cve(f"{marker}10")
    intel.run_source(source, lambda _s, _u: [_record(cve, summary="first")])
    result = intel.run_source(source, lambda _s, _u: [
        _record(cve, summary="first", cvss_base=7.5, severity="high")
    ])

    assert result["created"] == 0
    assert result["updated"] == 1
    assert float(_vuln(cve).cvss_base) == 7.5


def test_no_new_advisories_is_a_success_not_an_outage(marker):
    """A quiet day and a broken feed must not look the same in the record."""
    from guardian_scanner import intel

    source = f"test-nvd-{marker}"
    result = intel.run_source(source, lambda _s, _u: [])
    assert result["status"] == "completed"
    assert result["seen"] == 0

    record = _syncs(source)[-1]
    assert record.status == "completed"
    assert record.items_ingested == 0


# ── failure semantics ─────────────────────────────────────────────────────────────────────────────
def test_a_feed_failure_is_recorded_as_a_failure(marker):
    from guardian_clients.feeds import FeedError
    from guardian_scanner import intel

    source = f"test-nvd-{marker}"

    def explode(_since, _until):
        raise FeedError("NVD request failed: 503")

    result = intel.run_source(source, explode)
    assert result["status"] == "failed"
    assert "503" in result["error"]

    record = _syncs(source)[-1]
    assert record.status == "failed"
    assert "503" in record.error


def test_a_failure_does_not_advance_the_watermark(marker):
    """Advancing on failure skips the window forever, and nothing downstream can tell it happened."""
    from guardian_clients.feeds import FeedError
    from guardian_scanner import intel

    source = f"test-nvd-{marker}"
    intel.run_source(source, lambda _s, _u: [_record(_cve(f"{marker}20"))])
    after_success = _state(source).watermark
    assert after_success is not None

    def explode(_since, _until):
        raise FeedError("down")

    intel.run_source(source, explode)
    assert _state(source).watermark == after_success
    assert _state(source).consecutive_failures == 1
    assert _state(source).last_error == "down"


def test_the_next_window_starts_where_the_last_success_ended(marker):
    from guardian_scanner import intel

    source = f"test-nvd-{marker}"
    windows: list[tuple] = []

    def capture(since, until):
        windows.append((since, until))
        return []

    first_run = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    second_run = dt.datetime(2026, 1, 2, tzinfo=dt.UTC)
    intel.run_source(source, capture, now=first_run)
    intel.run_source(source, capture, now=second_run)

    # The first run reaches back; the second starts from the first's end, minus a small overlap for
    # a feed that is eventually consistent.
    assert windows[0][1] == first_run
    assert windows[1][0] < first_run
    assert first_run - windows[1][0] <= dt.timedelta(minutes=intel.OVERLAP_MINUTES + 1)
    assert windows[1][1] == second_run


def test_repeated_failures_are_counted(marker):
    from guardian_clients.feeds import FeedError
    from guardian_scanner import intel

    source = f"test-nvd-{marker}"

    def explode(_since, _until):
        raise FeedError("down")

    for _ in range(3):
        intel.run_source(source, explode)
    assert _state(source).consecutive_failures == 3


def test_a_success_clears_the_failure_counter(marker):
    from guardian_clients.feeds import FeedError
    from guardian_scanner import intel

    source = f"test-nvd-{marker}"
    intel.run_source(source, lambda _s, _u: (_ for _ in ()).throw(FeedError("down")))
    assert _state(source).consecutive_failures == 1

    intel.run_source(source, lambda _s, _u: [])
    assert _state(source).consecutive_failures == 0
    assert _state(source).last_error is None


def test_an_unexpected_exception_is_also_a_failure(marker):
    """A feed that changed shape raises something other than FeedError. It is still an outage."""
    from guardian_scanner import intel

    source = f"test-nvd-{marker}"

    def bad_shape(_since, _until):
        raise KeyError("vulnerabilities")

    result = intel.run_source(source, bad_shape)
    assert result["status"] == "failed"
    assert "KeyError" in result["error"]
    assert _state(source).watermark is None


# ── source ownership of fields ────────────────────────────────────────────────────────────────────
def test_nvd_owns_cvss_and_cpe_applicability(marker):
    """Otherwise the knowledge base depends on which feed happened to sync last."""
    from guardian_scanner import intel

    cve = _cve(f"{marker}30")
    intel.run_source(f"osv-{marker}", lambda _s, _u: [
        _record(cve, source="osv", summary="from osv", cvss_base=5.0,
                affected=[{"ecosystem": "PyPI", "package": "x"}])
    ])
    intel.run_source(f"nvd-{marker}", lambda _s, _u: [
        _record(cve, source="nvd", cvss_base=9.8, severity="critical",
                cpe_configurations=[{"vendor": "openbsd", "product": "openssh"}])
    ])

    row = _vuln(cve)
    assert float(row.cvss_base) == 9.8                       # NVD wins
    assert row.severity == "critical"
    assert row.cpe_configurations[0]["product"] == "openssh"
    assert row.affected[0]["package"] == "x"                 # OSV's field is untouched


def test_osv_owns_package_ranges(marker):
    from guardian_scanner import intel

    cve = _cve(f"{marker}31")
    intel.run_source(f"nvd-{marker}", lambda _s, _u: [
        _record(cve, source="nvd", cvss_base=9.8,
                cpe_configurations=[{"vendor": "v", "product": "p"}])
    ])
    intel.run_source(f"osv-{marker}", lambda _s, _u: [
        _record(cve, source="osv",
                affected=[{"ecosystem": "npm", "package": "lodash",
                           "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}])
    ])

    row = _vuln(cve)
    assert row.affected[0]["package"] == "lodash"
    assert row.cpe_configurations[0]["product"] == "p"       # NVD's field is untouched
    assert float(row.cvss_base) == 9.8


# ── enrichment ────────────────────────────────────────────────────────────────────────────────────
def test_kev_marks_advisories_that_exist(marker):
    from guardian_clients.feeds import KevRecord
    from guardian_db.session import session_scope
    from guardian_scanner import intel

    cve = _cve(f"{marker}40")
    intel.run_source(f"nvd-{marker}", lambda _s, _u: [_record(cve)])

    with session_scope() as db:
        changed = intel.apply_kev(db, [KevRecord(cve_id=cve, ransomware=True)])
    assert changed == 1
    assert _vuln(cve).kev is True


def test_an_empty_kev_catalogue_is_refused_rather_than_clearing_flags():
    from guardian_clients.feeds import FeedError
    from guardian_db.session import session_scope
    from guardian_scanner import intel

    with session_scope() as db, pytest.raises(FeedError, match="empty KEV"):
        intel.apply_kev(db, [])


def test_epss_scores_are_refreshed_not_only_filled(marker):
    """A score moves daily. Keeping the first value is worse than having none, because it is
    trusted."""
    from guardian_db.session import session_scope
    from guardian_scanner import intel

    cve = _cve(f"{marker}41")
    intel.run_source(f"nvd-{marker}", lambda _s, _u: [_record(cve)])

    with session_scope() as db:
        assert intel.apply_epss(db, {cve: 0.12}) == 1
    assert float(_vuln(cve).epss_score) == pytest.approx(0.12)

    with session_scope() as db:
        assert intel.apply_epss(db, {cve: 0.94}) == 1
    assert float(_vuln(cve).epss_score) == pytest.approx(0.94)

    with session_scope() as db:
        assert intel.apply_epss(db, {cve: 0.94}) == 0      # unchanged ⇒ nothing written


def test_an_empty_score_set_is_refused():
    from guardian_clients.feeds import FeedError
    from guardian_db.session import session_scope
    from guardian_scanner import intel

    with session_scope() as db, pytest.raises(FeedError, match="empty EPSS"):
        intel.apply_epss(db, {})


# ── the ingested corpus is usable by the matcher that already exists ──────────────────────────────
def test_an_ingested_osv_advisory_is_matchable_by_version(marker):
    """The point of ingesting ranges rather than answers: the knowledge base can now answer for a
    version it was never asked about."""
    from guardian_scanner import intel
    from guardian_scanner.vuln_match import KbVulnMatcher

    cve = _cve(f"{marker}50")
    package = f"pkg-{marker}"
    intel.run_source(f"osv-{marker}", lambda _s, _u: [
        _record(cve, source="osv", summary="range advisory", cvss_base=7.5,
                affected=[{"ecosystem": "PyPI", "package": package,
                           "ranges": [{"type": "ECOSYSTEM",
                                       "events": [{"introduced": "1.0.0"}, {"fixed": "1.4.2"}]}]}])
    ])

    from guardian_db.session import session_scope

    with session_scope() as db:
        matcher = KbVulnMatcher(db)
        # Inside the fixed range.
        assert [m.external_id
                for m in matcher.match(name=package, version="1.2.0", ecosystem="PyPI")] == [cve]
        # At the fixed version, and before the introduced version: both clean.
        assert matcher.match(name=package, version="1.4.2", ecosystem="PyPI") == []
        assert matcher.match(name=package, version="0.9.0", ecosystem="PyPI") == []


def test_a_feeds_own_capitalization_does_not_hide_the_advisory(marker):
    """Feeds publish `PyPI`, `crates.io`, `Go`; a lockfile says whatever it says. The matcher's
    containment query is exact, so an un-normalized ecosystem means the advisory is ingested, sits
    in the table, and is never found by any scan."""
    from guardian_db.session import session_scope
    from guardian_scanner import intel
    from guardian_scanner.vuln_match import KbVulnMatcher

    cve = _cve(f"{marker}51")
    package = f"Requests-{marker}"
    intel.run_source(f"osv-{marker}", lambda _s, _u: [
        _record(cve, source="osv",
                affected=[{"ecosystem": "PyPI", "package": package,
                           "ranges": [{"type": "ECOSYSTEM",
                                       "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}]}])
    ])

    with session_scope() as db:
        matcher = KbVulnMatcher(db)
        for asked_package, asked_ecosystem in (
            (package, "PyPI"), (package.lower(), "pypi"), (package.upper(), "PYPI"),
        ):
            found = matcher.match(name=asked_package, version="2.0.0", ecosystem=asked_ecosystem)
            assert [m.external_id for m in found] == [cve], (asked_package, asked_ecosystem)


def test_the_original_spelling_is_kept_for_display(marker):
    from guardian_scanner import intel

    cve = _cve(f"{marker}52")
    intel.run_source(f"osv-{marker}", lambda _s, _u: [
        _record(cve, source="osv", affected=[{"ecosystem": "PyPI", "package": "Django"}])
    ])
    entry = _vuln(cve).affected[0]
    assert entry["ecosystem"] == "pypi"
    assert entry["ecosystem_display"] == "PyPI"
    assert entry["package_display"] == "Django"
