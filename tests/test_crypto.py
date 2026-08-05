"""Envelope-encryption unit tests (Phase 5A) — no DB required.

Verifies the LocalKMSProvider closes the "plaintext credentials" gap: round-trips a secret, never
stores the plaintext, and fails closed on a tampered/foreign token.
"""

from __future__ import annotations

import pytest


def test_encrypt_decrypt_roundtrip():
    from guardian_common.crypto import decrypt_secret, encrypt_secret

    secret = "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    token = encrypt_secret(secret)

    assert token != secret
    assert secret not in token  # plaintext must not appear in the stored ciphertext
    assert decrypt_secret(token) == secret


def test_tampered_token_returns_none():
    from guardian_common.crypto import decrypt_secret, encrypt_secret

    token = encrypt_secret("hunter2")
    tampered = token[:-4] + ("aaaa" if not token.endswith("aaaa") else "bbbb")
    assert decrypt_secret(tampered) is None
    assert decrypt_secret("not-a-valid-token") is None


def test_json_secret_roundtrip_and_at_rest():
    from guardian_common.crypto import decrypt_json, encrypt_json

    creds = {"aws_access_key_id": "AKIA...", "aws_secret_access_key": "wJalr..."}
    token = encrypt_json(creds)

    # No credential value leaks into the stored ciphertext.
    for value in creds.values():
        assert value not in token
    assert decrypt_json(token) == creds


def test_decrypt_json_fails_closed():
    from guardian_common.crypto import decrypt_json

    assert decrypt_json(None) == {}
    assert decrypt_json("") == {}
    assert decrypt_json("garbage-token") == {}


def test_distinct_keys_do_not_cross_decrypt():
    from guardian_common.crypto import LocalKMSProvider

    a = LocalKMSProvider("key-material-one")
    b = LocalKMSProvider("key-material-two")
    ct = a.encrypt(b"secret")
    assert a.decrypt(ct) == b"secret"
    with pytest.raises(Exception):  # noqa: B017 - InvalidToken; wrong key must never decrypt
        b.decrypt(ct)
