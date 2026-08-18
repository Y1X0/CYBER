"""SSO token verification (WP-G1).

Every test here signs a real token with a real key and puts it through the real verifier. The
attacks being tested for are the ones that actually break OIDC implementations in the field, and
each of them produces a token that looks entirely valid to a verifier missing one check:

* a token signed with the attacker's own key;
* a token with `alg: none`;
* an HS256 token whose "secret" is the provider's *public* key — which the attacker also has;
* a valid token from the same provider for a different application;
* a valid token from a different provider;
* an unverified email address.
"""

from __future__ import annotations

import datetime as dt

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from guardian_core.sso import (
    ASSIGNABLE_ROLES,
    Principal,
    SsoConfig,
    SsoError,
    domain_of,
    may_provision,
    role_for,
    verify_id_token,
)

ISSUER = "https://login.example.com/"
AUDIENCE = "guardian-prod"


def _keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private, public


PRIVATE, PUBLIC = _keypair()
ATTACKER_PRIVATE, _ = _keypair()

CONFIG = SsoConfig(issuer=ISSUER, audience=AUDIENCE, allowed_domains=("example.com",),
                   group_roles={"security-team": "pentester", "auditors": "reviewer",
                                "admins": "owner"})


def _token(*, key=PRIVATE, algorithm="RS256", **overrides):
    now = dt.datetime.now(dt.UTC)
    claims = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": "idp|12345",
        "iat": int(now.timestamp()), "exp": int((now + dt.timedelta(minutes=5)).timestamp()),
        "email": "alice@example.com", "email_verified": True, "name": "Alice",
        "groups": ["security-team"],
    }
    claims.update(overrides)
    for key_name in [k for k, v in overrides.items() if v is None]:
        claims.pop(key_name, None)
    return jwt.encode(claims, key, algorithm=algorithm)


# ── the happy path ────────────────────────────────────────────────────────────────────────────────
def test_a_valid_token_identifies_the_user():
    principal = verify_id_token(_token(), key=PUBLIC, config=CONFIG)

    assert principal.subject == "idp|12345"
    assert principal.email == "alice@example.com"
    assert principal.name == "Alice"
    assert principal.groups == ("security-team",)


def test_an_email_is_normalized():
    principal = verify_id_token(_token(email="Alice@Example.COM"), key=PUBLIC, config=CONFIG)
    assert principal.email == "alice@example.com"


# ── forgery ───────────────────────────────────────────────────────────────────────────────────────
def test_a_token_signed_with_another_key_is_refused():
    with pytest.raises(SsoError, match="did not verify"):
        verify_id_token(_token(key=ATTACKER_PRIVATE), key=PUBLIC, config=CONFIG)


def test_an_unsigned_token_is_refused():
    """`alg: none` is a valid JWT and an invalid credential. A verifier that reads the algorithm
    from the token accepts it."""
    unsigned = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "email": "alice@example.com",
         "email_verified": True, "iat": 0,
         "exp": int((dt.datetime.now(dt.UTC) + dt.timedelta(minutes=5)).timestamp())},
        key="", algorithm="none",
    )
    with pytest.raises(SsoError):
        verify_id_token(unsigned, key=PUBLIC, config=CONFIG)


def test_an_hmac_token_signed_with_the_public_key_is_refused():
    """The classic algorithm-confusion attack: the provider's public key is published, so if the
    verifier will accept HS256 the attacker already holds the "secret".

    Assembled by hand rather than with `jwt.encode`, which refuses to use a PEM key as an HMAC
    secret — a good guard in the signing path, and not one an attacker is bound by.
    """
    import base64
    import hashlib
    import hmac
    import json

    def b64(raw: bytes) -> bytes:
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(json.dumps({
        "iss": ISSUER, "aud": AUDIENCE, "sub": "attacker", "email": "alice@example.com",
        "email_verified": True, "iat": 0,
        "exp": int((dt.datetime.now(dt.UTC) + dt.timedelta(minutes=5)).timestamp()),
    }).encode())
    signing_input = header + b"." + payload
    signature = b64(hmac.new(PUBLIC.encode(), signing_input, hashlib.sha256).digest())
    forged = (signing_input + b"." + signature).decode()

    with pytest.raises(SsoError):
        verify_id_token(forged, key=PUBLIC, config=CONFIG)


# ── valid tokens that are not for us ──────────────────────────────────────────────────────────────
def test_a_token_for_another_application_is_refused():
    """Same provider, same signature, different audience — a perfectly valid token that is not a
    login here."""
    with pytest.raises(SsoError, match="different application"):
        verify_id_token(_token(aud="some-other-app"), key=PUBLIC, config=CONFIG)


def test_a_token_from_another_issuer_is_refused():
    with pytest.raises(SsoError, match="different issuer"):
        verify_id_token(_token(iss="https://attacker.example.net/"), key=PUBLIC, config=CONFIG)


def test_an_expired_token_is_refused():
    past = int((dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)).timestamp())
    with pytest.raises(SsoError, match="expired"):
        verify_id_token(_token(exp=past), key=PUBLIC, config=CONFIG)


@pytest.mark.parametrize("claim", ["sub", "exp", "iat"])
def test_a_token_missing_a_required_claim_is_refused(claim):
    with pytest.raises(SsoError):
        verify_id_token(_token(**{claim: None}), key=PUBLIC, config=CONFIG)


# ── claims that are not proof ─────────────────────────────────────────────────────────────────────
def test_an_unverified_email_is_refused():
    """`email` is a claim; `email_verified` is the one saying the provider checked it. Matching on
    the former lets somebody claim an account by registering the address anywhere that does not."""
    with pytest.raises(SsoError, match="did not verify this email"):
        verify_id_token(_token(email_verified=False), key=PUBLIC, config=CONFIG)


def test_a_missing_email_verified_claim_is_treated_as_unverified():
    with pytest.raises(SsoError, match="did not verify this email"):
        verify_id_token(_token(email_verified=None), key=PUBLIC, config=CONFIG)


def test_a_token_with_no_email_is_refused():
    with pytest.raises(SsoError, match="no email"):
        verify_id_token(_token(email=None), key=PUBLIC, config=CONFIG)


# ── provisioning ──────────────────────────────────────────────────────────────────────────────────
def test_a_user_is_provisioned_only_from_a_domain_the_tenant_declared():
    """Otherwise anyone whose provider will issue a token for this audience gets an account, and the
    whole access decision moves to whoever configures the IdP."""
    inside = Principal(subject="1", email="alice@example.com", email_verified=True)
    outside = Principal(subject="2", email="mallory@gmail.com", email_verified=True)

    assert may_provision(inside, CONFIG) is True
    assert may_provision(outside, CONFIG) is False


def test_no_domain_configured_means_no_automatic_provisioning():
    principal = Principal(subject="1", email="alice@example.com", email_verified=True)
    assert may_provision(principal, SsoConfig(issuer=ISSUER, audience=AUDIENCE)) is False


def test_a_lookalike_domain_does_not_provision():
    principal = Principal(subject="1", email="alice@notexample.com", email_verified=True)
    assert may_provision(principal, CONFIG) is False


def test_a_group_maps_to_a_role():
    principal = Principal(subject="1", email="a@example.com", groups=("security-team",))
    assert role_for(principal, CONFIG) == "pentester"


def test_a_group_cannot_make_somebody_an_owner():
    """The configuration maps `admins` to `owner`. Promoting somebody to owner should be an act by
    an existing owner, not a consequence of a directory group Guardian does not control."""
    principal = Principal(subject="1", email="a@example.com", groups=("admins",))
    assert role_for(principal, CONFIG) == "analyst"
    assert "owner" not in ASSIGNABLE_ROLES
    assert "admin" not in ASSIGNABLE_ROLES


def test_an_unmapped_group_gets_the_default_role():
    principal = Principal(subject="1", email="a@example.com", groups=("everyone",))
    assert role_for(principal, CONFIG) == "analyst"


def test_domain_of_handles_a_malformed_address():
    assert domain_of("not-an-email") == ""
