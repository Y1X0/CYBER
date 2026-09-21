"""The keyed secret-correlation identity (WP-E1 same-secret fix).

This is the mechanism the `same-secret` rule uses to decide "same credential" instead of the lossy
display redaction. What matters here: different secrets get different identities (the collision the
redaction caused is gone), the same secret gets the same identity (so a re-scan still correlates),
the identity is keyed (so a low-entropy secret cannot be brute-forced from it), and it is never the
raw secret.
"""

from __future__ import annotations

from guardian_core.secret_identity import secret_correlation_identity

KEY = "unit-test-server-key-not-a-real-secret"


def test_two_different_secrets_get_different_identities():
    # The exact collision the redaction produced: two different values of equal length <= 8.
    a = secret_correlation_identity("abc123", key=KEY)
    b = secret_correlation_identity("xyz789", key=KEY)
    assert a and b and a != b


def test_two_secrets_sharing_edges_and_length_still_differ():
    # first2 + last2 + length identical, different middle — collides under _redact, not here.
    a = secret_correlation_identity("ABmiddle1YZ", key=KEY)
    b = secret_correlation_identity("ABmiddle2YZ", key=KEY)
    assert a and b and a != b


def test_the_same_secret_is_stable():
    assert secret_correlation_identity("s3cr3t-value", key=KEY) == \
        secret_correlation_identity("s3cr3t-value", key=KEY)


def test_surrounding_quotes_are_ignored_like_the_redactor():
    assert secret_correlation_identity('"abc"', key=KEY) == \
        secret_correlation_identity("abc", key=KEY)


def test_it_is_keyed_so_the_key_changes_the_identity():
    assert secret_correlation_identity("value", key="key-one") != \
        secret_correlation_identity("value", key="key-two")


def test_no_key_yields_no_identity_so_the_caller_stays_conservative():
    assert secret_correlation_identity("value", key="") is None


def test_empty_value_yields_no_identity():
    assert secret_correlation_identity("", key=KEY) is None
    assert secret_correlation_identity('""', key=KEY) is None


def test_the_identity_is_not_the_raw_secret():
    raw = "AKIAIOSFODNN7EXAMPLE"
    ident = secret_correlation_identity(raw, key=KEY)
    assert ident and raw not in ident and len(ident) == 64
