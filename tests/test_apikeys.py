"""API key format, hashing and scopes (WP-G1).

A key is a credential that lives in a CI configuration, gets copied into a chat message when
somebody debugs a pipeline, and outlives the person who created it. So the tests here are about the
properties that make that survivable: the stored form cannot be turned back into the key, the
comparison leaks no timing, the scope set is closed, and nothing anywhere prints the secret.
"""

from __future__ import annotations

import pytest
from guardian_core import apikeys
from guardian_core.apikeys import (
    ALL_SCOPES,
    CI_SCOPES,
    PREFIX,
    READ_ONLY_SCOPES,
    InvalidKey,
    Scope,
    allows,
    digest,
    mint,
    normalize_scopes,
    parse,
    redact,
    verify,
)

PEPPER = "test-pepper-not-a-real-secret"


# ── minting ───────────────────────────────────────────────────────────────────────────────────────
def test_a_key_is_unique_and_high_entropy():
    tokens = {mint(pepper=PEPPER).token for _ in range(200)}
    assert len(tokens) == 200
    assert all(len(t) > 60 for t in tokens)


def test_a_key_announces_itself_so_a_secret_scanner_can_find_it():
    """The distinctive prefix is not decoration: it is what lets GitHub's push protection, and
    Guardian's own secrets engine, recognize one in a repository."""
    assert mint(pepper=PEPPER).token.startswith(f"{PREFIX}_")


def test_the_key_carries_its_own_id():
    """Authentication looks up one row by id and compares one digest. A scheme that has to hash the
    presented key against every key in the table gets slower with every customer."""
    issued = mint(pepper=PEPPER)
    assert parse(issued.token) == issued.key_id


def test_the_stored_form_is_not_the_key():
    issued = mint(pepper=PEPPER)
    assert issued.digest != issued.token
    assert issued.token not in issued.digest
    assert len(issued.digest) == 64


# ── verification ──────────────────────────────────────────────────────────────────────────────────
def test_the_right_key_verifies():
    issued = mint(pepper=PEPPER)
    assert verify(issued.token, issued.digest, pepper=PEPPER) is True


def test_a_different_key_does_not():
    first, second = mint(pepper=PEPPER), mint(pepper=PEPPER)
    assert verify(second.token, first.digest, pepper=PEPPER) is False


def test_the_pepper_is_what_makes_a_stolen_database_insufficient():
    """Without the application secret, an attacker holding the table cannot check a guess offline."""
    issued = mint(pepper=PEPPER)
    assert verify(issued.token, issued.digest, pepper="a-different-pepper") is False


def test_a_truncated_key_does_not_verify():
    issued = mint(pepper=PEPPER)
    assert verify(issued.token[:-4], issued.digest, pepper=PEPPER) is False


def test_verification_of_an_empty_digest_fails_rather_than_raising():
    issued = mint(pepper=PEPPER)
    assert verify(issued.token, "", pepper=PEPPER) is False


def test_the_digest_is_deterministic_for_the_same_pepper():
    issued = mint(pepper=PEPPER)
    assert digest(issued.token, pepper=PEPPER) == digest(issued.token, pepper=PEPPER)


# ── parsing ───────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("value", [
    "", "not-a-key", "gdn_", "gdn_short_x", "Bearer eyJhbGciOiJIUzI1NiJ9.x.y",
    "gdn_zzzzzzzzzzzzzzzz_abcdefghijklmnopqrstu",   # non-hex id
    "gdn_0123456789abcdef_short",                    # secret too short
])
def test_something_that_is_not_a_key_is_refused(value):
    with pytest.raises(InvalidKey):
        parse(value)


def test_a_jwt_is_not_mistaken_for_a_key():
    """Both arrive in the same Authorization header, so the two schemes must never guess."""
    with pytest.raises(InvalidKey):
        parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc")


# ── redaction ─────────────────────────────────────────────────────────────────────────────────────
def test_only_the_id_half_may_be_logged():
    issued = mint(pepper=PEPPER)
    shown = redact(issued.token)

    assert issued.key_id in shown
    # The secret half never appears anywhere — which is why this function exists rather than a
    # `token[:8]` at each call site.
    secret_half = issued.token.rsplit("_", 1)[1]
    assert secret_half not in shown


def test_redacting_a_non_key_says_so_rather_than_echoing_it():
    assert redact("hunter2-actually-a-password") == "<invalid key>"


# ── scopes ────────────────────────────────────────────────────────────────────────────────────────
def test_a_key_with_no_scopes_can_do_nothing():
    """Least privilege by default: there is no implicit 'all'."""
    assert allows((), Scope.FINDINGS_READ) is False
    assert allows(None, Scope.SCANS_WRITE) is False


def test_a_scope_grants_exactly_itself():
    """No implicit hierarchy. Two lines of scopes on a key is a small price for never having to
    reason about what a grant silently included."""
    scopes = (Scope.FINDINGS_WRITE,)
    assert allows(scopes, Scope.FINDINGS_WRITE) is True
    assert allows(scopes, Scope.FINDINGS_READ) is False
    assert allows(scopes, Scope.SCANS_WRITE) is False


def test_an_unknown_scope_is_dropped_rather_than_stored():
    assert normalize_scopes(["findings:read", "admin:*", "everything"]) == ("findings:read",)


def test_scopes_are_deduplicated_and_ordered():
    assert normalize_scopes(["scans:read", "findings:read", "scans:read"]) == (
        "findings:read", "scans:read")


def test_the_ci_preset_cannot_register_a_new_target():
    """The whole point of the preset. A leaked build key must not be able to point an active
    scanner at a host nobody authorized."""
    assert Scope.ASSETS_WRITE not in CI_SCOPES
    assert Scope.SCANS_WRITE in CI_SCOPES
    assert Scope.FINDINGS_READ in CI_SCOPES


def test_the_read_only_preset_contains_no_write_scope():
    assert all(scope.endswith(":read") for scope in READ_ONLY_SCOPES)


def test_every_scope_is_namespaced():
    for scope in ALL_SCOPES:
        assert ":" in scope
        assert scope.split(":")[1] in ("read", "write")


def test_the_module_exports_no_way_to_recover_a_key_from_its_digest():
    """There is no such function, and there must never be one."""
    assert not any(name in dir(apikeys) for name in ("decrypt", "recover", "reveal", "unhash"))
