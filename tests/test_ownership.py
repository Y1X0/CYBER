"""Domain ownership verification (WP-F1).

`Authorization.method` has always had a value `ownership_verified`, and nothing verified ownership:
a human asserted it and the platform believed them. This is the control standing between a customer
and an active scan of somebody else's domain, and it was a checkbox.

Every test here is about a way the check could be fooled, because that is the only thing that
matters about it. A verification that can be satisfied by someone who does not control the domain
is worse than no verification at all — it launders an assertion into evidence.
"""

from __future__ import annotations

import pytest
from guardian_core.ownership import (
    InvalidDomain,
    authorizes,
    dns_record_name,
    evaluate_dns,
    evaluate_http,
    http_challenge_url,
    instructions,
    new_token,
    normalize_domain,
)

TOKEN = "guardian-site-verification=abc123XYZ_token"


# ── domain normalization ──────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM", "example.com"),
        ("https://example.com/path?x=1", "example.com"),
        ("example.com.", "example.com"),
        ("example.com:8443", "example.com"),
        ("user@example.com", "example.com"),
        ("  app.example.co.uk  ", "app.example.co.uk"),
    ],
)
def test_a_domain_is_stored_in_one_canonical_form(raw, expected):
    """Two spellings of one domain would make the authorization check compare them and find them
    different — failing open or closed depending on which side is wrong."""
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "not a domain", "localhost", "..", "-bad.com", "a" * 300])
def test_a_malformed_domain_is_refused(raw):
    with pytest.raises(InvalidDomain):
        normalize_domain(raw)


# ── the token ─────────────────────────────────────────────────────────────────────────────────────
def test_tokens_are_unique_and_high_entropy():
    """A guessable or reused token could be published by one customer and claimed by another."""
    tokens = {new_token() for _ in range(200)}
    assert len(tokens) == 200
    assert all(len(t) > 40 for t in tokens)
    assert all(t.startswith("guardian-site-verification=") for t in tokens)


def test_the_challenge_locations_are_derived_from_the_domain():
    assert dns_record_name("Example.com") == "_guardian-challenge.example.com"
    assert http_challenge_url("Example.com") == (
        "https://example.com/.well-known/guardian-verification.txt"
    )


def test_instructions_tell_the_customer_exactly_what_to_publish():
    dns = instructions("example.com", "dns_txt", TOKEN)
    assert dns["record_name"] == "_guardian-challenge.example.com"
    assert dns["record_value"] == TOKEN

    http = instructions("example.com", "http_file", TOKEN)
    assert http["content"] == TOKEN
    assert "will not" in http["note"] and "redirect" in http["note"]


def test_an_unknown_method_is_refused():
    with pytest.raises(ValueError, match="unknown verification method"):
        instructions("example.com", "carrier_pigeon", TOKEN)


# ── the DNS challenge ─────────────────────────────────────────────────────────────────────────────
def test_the_expected_txt_record_verifies():
    assert evaluate_dns(TOKEN, [TOKEN]).verified is True


def test_the_token_is_found_among_other_vendors_records():
    """A real zone carries verification records from several vendors at once."""
    records = ["google-site-verification=xyz", TOKEN, "v=spf1 include:_spf.example.com ~all"]
    assert evaluate_dns(TOKEN, records).verified is True


def test_a_record_that_merely_contains_the_token_does_not_verify():
    """Otherwise anyone able to add any TXT record to a shared zone could append someone else's
    token to their own value and be credited with the domain."""
    assert evaluate_dns(TOKEN, [f"v=spf1 {TOKEN} extra"]).verified is False


def test_a_missing_record_does_not_verify():
    assert evaluate_dns(TOKEN, None).verified is False
    assert evaluate_dns(TOKEN, []).verified is False
    assert "not found" in evaluate_dns(TOKEN, None).reason


def test_another_customers_token_does_not_verify():
    assert evaluate_dns(TOKEN, ["guardian-site-verification=someone-elses"]).verified is False


def test_a_quoted_record_still_verifies():
    """Resolvers hand back TXT values with or without their quotes depending on the library."""
    assert evaluate_dns(TOKEN, [f'"{TOKEN}"']).verified is True


# ── the HTTP challenge ────────────────────────────────────────────────────────────────────────────
URL = "https://example.com/.well-known/guardian-verification.txt"


def test_the_challenge_file_verifies():
    result = evaluate_http(TOKEN, status=200, body=TOKEN, final_url=URL, expected_url=URL)
    assert result.verified is True


def test_trailing_whitespace_is_tolerated():
    result = evaluate_http(TOKEN, status=200, body=f"  {TOKEN}\n", final_url=URL, expected_url=URL)
    assert result.verified is True


def test_a_redirect_never_verifies():
    """The attack this control exists to prevent: if example.com redirects to a host the requester
    controls, following it would credit them with owning example.com."""
    result = evaluate_http(TOKEN, status=200, body=TOKEN,
                           final_url="https://attacker.example.net/token.txt", expected_url=URL)
    assert result.verified is False
    assert "redirect" in result.reason


def test_a_non_200_does_not_verify():
    for status in (301, 403, 404, 500):
        assert evaluate_http(TOKEN, status=status, body=TOKEN, final_url=URL,
                             expected_url=URL).verified is False


def test_a_page_that_merely_mentions_the_token_does_not_verify():
    """A paste site, a forum thread, or an error page echoing the URL is not a statement by the
    domain's owner."""
    body = f"<html><body>Search results for {TOKEN} — 3 matches</body></html>"
    result = evaluate_http(TOKEN, status=200, body=body, final_url=URL, expected_url=URL)
    assert result.verified is False


def test_an_empty_file_does_not_verify():
    assert evaluate_http(TOKEN, status=200, body="", final_url=URL, expected_url=URL) \
        .verified is False


def test_a_wildcard_catch_all_page_does_not_verify():
    """Many hosts serve the same page for every path. That page is not a proof."""
    body = "<!DOCTYPE html><html><head><title>Welcome</title></head><body>Hi</body></html>"
    assert evaluate_http(TOKEN, status=200, body=body, final_url=URL,
                         expected_url=URL).verified is False


# ── what a proof authorizes ───────────────────────────────────────────────────────────────────────
def test_verifying_a_domain_covers_its_subdomains():
    """Whoever controls the zone can create any name inside it."""
    assert authorizes("example.com", "example.com") is True
    assert authorizes("example.com", "app.example.com") is True
    assert authorizes("example.com", "a.b.c.example.com") is True


def test_verifying_a_subdomain_does_not_cover_the_apex():
    """Control of one host in a zone is not control of the zone. A shared-hosting customer must not
    be able to claim the apex — or, through it, every other tenant on it."""
    assert authorizes("app.example.com", "example.com") is False
    assert authorizes("app.example.com", "other.example.com") is False
    assert authorizes("app.example.com", "app.example.com") is True
    assert authorizes("app.example.com", "api.app.example.com") is True


def test_a_lookalike_suffix_is_not_covered():
    """`notexample.com` ends with `example.com` as a *string*; it is a different domain."""
    assert authorizes("example.com", "notexample.com") is False
    assert authorizes("example.com", "example.com.attacker.net") is False


def test_an_unrelated_domain_is_not_covered():
    assert authorizes("example.com", "google.com") is False


def test_a_malformed_target_is_not_covered():
    assert authorizes("example.com", "not a domain") is False
    assert authorizes("not a domain", "example.com") is False
