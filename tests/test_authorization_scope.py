"""The one authorization evaluator (WP-H1).

Two gates existed and they disagreed. The discovery gate matched `authorized_targets`; the scan gate
matched `asset_id` and nothing else. Each was defensible alone, and together they meant a domain a
customer had **proved they own** could clear a discovery probe and not a scan of the same host,
because WP-F1 issues its authorization scoped by target with no asset.

These tests are the rules that both gates now share.
"""

from __future__ import annotations

import datetime as dt

import pytest
from guardian_core.authorization import (
    ARTIFACT_METHODS,
    NETWORK_METHODS,
    AuthorizationView,
    decide,
    host_of,
    target_matches,
)

NOW = dt.datetime(2026, 8, 18, tzinfo=dt.UTC)


def _auth(*, method="active_recon", asset_id=None, targets=(), valid=True, revoked=False):
    return AuthorizationView(
        id="auth-1", method=method, asset_id=asset_id, customer_id="c1",
        targets=tuple(targets),
        valid_from=NOW - dt.timedelta(days=1 if valid else 30),
        valid_until=NOW + dt.timedelta(days=30) if valid else NOW - dt.timedelta(days=1),
        revoked_at=NOW - dt.timedelta(hours=1) if revoked else None,
    )


def _decide(auths, *, identifier="https://app.example.com", kind="web", asset_id="asset-1"):
    return decide(auths, asset_id=asset_id, asset_identifier=identifier, asset_kind=kind,
                  engine="dast", now=NOW)


# ── the gap this closes ───────────────────────────────────────────────────────────────────────────
def test_a_proved_domain_authorizes_scanning_that_domains_asset():
    """The defect: WP-F1 issues `authorized_targets=[{"type": "domain", …}]` with no `asset_id`, and
    the scan gate matched on `asset_id` alone — so proving you own a domain authorized nothing."""
    ownership = _auth(method="ownership_verified",
                      targets=[{"type": "domain", "value": "example.com"}])

    assert _decide([ownership]).allowed is True


def test_a_proved_domain_covers_its_subdomains():
    ownership = _auth(method="ownership_verified",
                      targets=[{"type": "domain", "value": "example.com"}])
    assert _decide([ownership], identifier="https://api.app.example.com").allowed is True


def test_a_proved_subdomain_does_not_cover_the_apex():
    """Control of one host in a zone is not control of the zone."""
    ownership = _auth(method="ownership_verified",
                      targets=[{"type": "domain", "value": "app.example.com"}])
    assert _decide([ownership], identifier="https://example.com").allowed is False


def test_an_asset_scoped_authorization_still_works():
    assert _decide([_auth(asset_id="asset-1")]).allowed is True


def test_an_authorization_for_a_different_asset_does_not():
    assert _decide([_auth(asset_id="asset-2")]).allowed is False


# ── the plane rule ────────────────────────────────────────────────────────────────────────────────
def test_consent_to_examine_an_artifact_is_not_permission_to_send_packets():
    """A customer handing over a repository has said nothing about their network."""
    consent = _auth(method="written_consent",
                    targets=[{"type": "domain", "value": "example.com"}])
    decision = _decide([consent])

    assert decision.allowed is False
    assert "artifact" in decision.reason
    assert "example.com" in decision.reason


def test_an_artifact_scan_accepts_written_consent():
    consent = _auth(method="written_consent", asset_id="asset-1")
    decision = decide([consent], asset_id="asset-1", asset_identifier="https://git/x.git",
                      asset_kind="repo", engine="secrets", now=NOW)
    assert decision.allowed is True


def test_a_network_method_also_covers_an_artifact():
    """A customer who proved they own the domain has not said less than one who sent an email."""
    ownership = _auth(method="ownership_verified", asset_id="asset-1")
    decision = decide([ownership], asset_id="asset-1", asset_identifier="repo",
                      asset_kind="repo", engine="secrets", now=NOW)
    assert decision.allowed is True


def test_the_two_method_sets_are_not_the_same():
    assert NETWORK_METHODS < ARTIFACT_METHODS
    assert "written_consent" not in NETWORK_METHODS


# ── time and revocation ───────────────────────────────────────────────────────────────────────────
def test_an_expired_authorization_authorizes_nothing():
    decision = _decide([_auth(asset_id="asset-1", valid=False)])
    assert decision.allowed is False
    assert "expired or revoked" in decision.reason


def test_a_revoked_authorization_authorizes_nothing():
    """WP-F1 revokes the authorization when the proof is withdrawn; this is what makes that
    revocation mean something."""
    assert _decide([_auth(asset_id="asset-1", revoked=True)]).allowed is False


def test_an_authorization_that_has_not_started_yet_authorizes_nothing():
    future = AuthorizationView(
        id="a", method="active_recon", asset_id="asset-1", customer_id="c1", targets=(),
        valid_from=NOW + dt.timedelta(days=1), valid_until=NOW + dt.timedelta(days=30),
    )
    assert _decide([future]).allowed is False


# ── nothing means nothing ─────────────────────────────────────────────────────────────────────────
def test_an_authorization_with_no_asset_and_no_targets_grants_nothing():
    """A record somebody half-filled in must not read as covering the estate."""
    assert _decide([_auth()]).allowed is False


def test_no_authorizations_at_all_is_refused_with_a_usable_reason():
    decision = _decide([])
    assert decision.allowed is False
    assert "app.example.com" in decision.reason
    assert "prove ownership" in decision.reason


def test_the_refusal_for_an_artifact_asks_for_the_right_thing():
    decision = decide([], asset_id="a", asset_identifier="repo.git", asset_kind="repo",
                      engine="secrets", now=NOW)
    assert "consent" in decision.reason


def test_an_allowed_decision_names_the_method_that_allowed_it():
    decision = _decide([_auth(method="ownership_verified", asset_id="asset-1")])
    assert decision.allowed is True
    assert "ownership_verified" in decision.reason
    assert decision.authorization_id == "auth-1"


# ── scope matching ────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(("identifier", "expected"), [
    ("https://app.example.com/path", "app.example.com"),
    ("http://app.example.com:8443", "app.example.com"),
    ("app.example.com", "app.example.com"),
    ("app.example.com.", "app.example.com"),
    ("[2001:db8::1]:443", "2001:db8::1"),
    ("", ""),
])
def test_the_host_is_extracted_from_any_identifier_shape(identifier, expected):
    assert host_of(identifier) == expected


def test_a_netblock_target_covers_an_address_inside_it():
    assert target_matches([{"type": "netblock", "value": "10.0.0.0/24"}], "10.0.0.5") is True
    assert target_matches([{"type": "netblock", "value": "10.0.0.0/24"}], "10.0.1.5") is False


def test_a_lookalike_domain_is_not_covered():
    targets = [{"type": "domain", "value": "example.com"}]
    assert target_matches(targets, "notexample.com") is False
    assert target_matches(targets, "example.com.attacker.net") is False


def test_a_malformed_target_entry_is_skipped_rather_than_raising():
    """A half-written authorization row must not take the gate down — it must simply not match."""
    targets = [{"type": "netblock", "value": "not-a-cidr"}, "not-a-dict", {"value": ""},
               {"type": "domain", "value": "example.com"}]
    assert target_matches(targets, "app.example.com") is True
    assert target_matches(targets, "elsewhere.net") is False


def test_the_first_matching_authorization_wins_and_the_rest_are_irrelevant():
    expired = _auth(asset_id="asset-1", valid=False)
    valid = _auth(method="ownership_verified",
                  targets=[{"type": "domain", "value": "example.com"}])
    assert _decide([expired, valid]).allowed is True
