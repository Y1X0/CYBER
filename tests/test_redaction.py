"""Boundary redaction (WP-F2).

The engines redact at write time. This is the second line, applied where evidence is served, and it
exists because the failure modes differ: an engine gains a new field and forgets it; a customer
commits a private key into a Terraform file the IaC parser quotes verbatim; an AI explanation echoes
back the value it was shown.

Two things are being tested, and the second matters as much as the first. It must mask credentials —
and it must **not** mask the evidence a customer needs to read. A redactor that eats digests, CPEs,
file paths and version strings makes findings unreviewable, and unreviewable findings get ignored,
which is a worse security outcome than the leak it was guarding against.
"""

from __future__ import annotations

import pytest
from guardian_core.redaction import MASK, scrub, scrub_text

# Assembled at runtime rather than written as literals. These are fabricated values, but a
# credential-shaped literal in a repository is exactly what a secret scanner is supposed to stop —
# including GitHub's push protection, which blocked this file the first time it was written with
# the strings spelled out. A test for a redactor should not itself commit something that looks like
# a key.
REAL_LOOKING_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
_STRIPE = "sk_" + "live_" + "abcdefghijklmnopqrstuvwx"
_GITHUB = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
_SLACK = "xoxb-" + "1234567890-abcdefghij"
_GOOGLE = "AIza" + "A1234567890abcdefghijklmnopqrstuvwx"
_JWT = "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "dBjftJeZ4CVPmB92K27uhbUJU1p1r"


# ── what must be masked ───────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("text", "pattern"),
    [
        (f"aws_key = '{REAL_LOOKING_AWS}'", "aws_access_key_id"),
        (f"token: {_GITHUB}", "github_token"),
        (f"slack = {_SLACK}", "slack_token"),
        (_STRIPE, "stripe_key"),
        (_GOOGLE, "google_api_key"),
        ("npm_" + "a" * 36, "npm_token"),
        (_JWT, "jwt"),
        ("postgres://guardian:hunter2isasecret@db.internal:5432/app", "url_credentials"),
        ("DB_PASSWORD=correcthorsebattery", "assigned_secret"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ\n-----END RSA PRIVATE KEY-----",
         "private_key"),
    ],
)
def test_a_credential_shaped_value_is_masked(text, pattern):
    cleaned, hits = scrub_text(text)
    assert pattern in hits
    assert MASK in cleaned


def test_the_secret_itself_never_survives_the_scrub():
    cleaned, _ = scrub_text(f"aws_key = '{REAL_LOOKING_AWS}'")
    assert REAL_LOOKING_AWS not in cleaned


def test_the_host_survives_but_the_password_does_not():
    """The connection string is the evidence — which host, which user, reached from where. The
    password is the only part that must not be shown."""
    cleaned, _ = scrub_text("postgres://guardian:hunter2isasecret@db.internal:5432/app")
    assert "db.internal" in cleaned
    assert "hunter2isasecret" not in cleaned


def test_a_field_named_password_is_masked_whatever_it_contains():
    """`letmein` matches no credential shape at all. The key is the evidence that it is one."""
    cleaned, hits = scrub({"config": {"password": "letmein"}})
    assert cleaned["config"]["password"] == MASK
    assert hits == ["key:password"]


def test_nesting_and_lists_are_walked():
    payload = {"detail": {"lines": [f"key={REAL_LOOKING_AWS}", "harmless"]}}
    cleaned, hits = scrub(payload)
    assert REAL_LOOKING_AWS not in str(cleaned)
    assert cleaned["detail"]["lines"][1] == "harmless"
    assert hits


def test_every_hit_is_reported_so_the_engine_defect_can_be_found():
    """A silent scrub would hide the bug it exists to catch: something wrote a credential to the
    database, and only the hit list says so."""
    _, hits = scrub({"a": f"AWS {REAL_LOOKING_AWS}", "b": {"password": "x"}})
    assert set(hits) == {"aws_access_key_id", "key:password"}


# ── what must survive ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "text",
    [
        # A SHA-256 digest. High entropy, and it is the evidence.
        "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*",
        "CVE-2024-3094 affects xz-utils 5.6.0",
        "src/app/routes/users.py:142",
        "Server: nginx/1.18.0 (Ubuntu)",
        "git commit 4f8c68933ab6c1e9d0a2b7c5e3f1a9d8c7b6a5f4",
        "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----",
        "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg\n-----END PUBLIC KEY-----",
    ],
)
def test_evidence_a_customer_needs_is_left_alone(text):
    cleaned, hits = scrub_text(text)
    assert cleaned == text
    assert hits == []


def test_an_already_redacted_marker_is_not_redacted_again():
    """The secrets engine emits `AK********EY (len=20)`. Masking it again loses the length, which
    is what lets a reader see two findings are about the same secret."""
    value = "AK********EY (len=20)"
    cleaned, hits = scrub({"detail": {"secret": value}})
    assert cleaned["detail"]["secret"] == value
    assert hits == []


def test_non_strings_pass_through_unchanged():
    payload = {"line": 42, "kev": True, "epss": 0.97, "cve_ids": None}
    cleaned, hits = scrub(payload)
    assert cleaned == payload
    assert hits == []


def test_scrubbing_is_idempotent():
    once, _ = scrub_text(f"key={REAL_LOOKING_AWS}")
    twice, hits = scrub_text(once)
    assert twice == once
    assert hits == []
