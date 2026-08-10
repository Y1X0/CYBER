"""Broker-seal / credential-KMS key separation (P1-A) — no DB, no network, no broker.

The DB-less execution planes (tool/recon) run untrusted external binaries. They must be secret-minimal:
they must NOT hold the JWT signing secret (a leak would forge platform tokens) and must NOT hold the
credential KMS master `GUARDIAN_ENCRYPTION_KEY` (a leak would decrypt every tenant's stored secrets).
P1-4 broker sealing therefore uses a DEDICATED `GUARDIAN_BROKER_SEAL_KEY`, distinct from that master.

This proves the six properties the hardening order requires:
  1. the tool/recon planes carry no JWT signing secret (startup refuses a real one there);
  2. holding the execution-plane secrets does not let you forge a platform JWT;
  3. broker sealing uses the dedicated seal key (not the credential master);
  4. the credential KMS uses its own separate key (the seal key cannot open credential ciphertext);
  5. startup FAILS in production if the separation is missing (unset seal key, or seal == master);
  6. P1-4 confidentiality still holds end-to-end through the separated key.
"""

from __future__ import annotations

import base64
import json

import pytest
from guardian_common.config import Settings
from pydantic import ValidationError

_STRONG = "x" * 40
_MASTER = "m" * 40           # credential KMS master (GUARDIAN_ENCRYPTION_KEY)
_SEAL = "s" * 40             # broker-seal key (GUARDIAN_BROKER_SEAL_KEY) — MUST differ from _MASTER
_PUB = base64.b64encode(b"u" * 32).decode()


def _prod(**over):
    """A valid production CONTROL-plane config; override to exercise a specific invariant."""
    base = dict(
        env="production",
        database_url="postgresql+psycopg://guardian:guardian@db:5432/guardian?sslmode=verify-full",
        app_database_url="postgresql+psycopg://guardian_app:pw@db:5432/guardian?sslmode=verify-full",
        redis_url="rediss://:rpw@redis:6379/0",
        jwt_secret=_STRONG, encryption_key=_MASTER, broker_seal_key=_SEAL,
        bootstrap_admin_password="a-strong-admin-password",  # P1-B: default is refused in prod
    )
    base.update(over)
    return Settings(**base)


def _prod_tool_plane(**over):
    """A production TOOL plane: no JWT, no KMS master — only the seal key + public signing key."""
    return _prod(tool_plane=True, jwt_secret="", encryption_key="", broker_seal_key=_SEAL,
                 job_signing_public_key=_PUB, **over)


# ── (1) execution planes carry no JWT signing secret ─────────────────────────────────────────────
def test_tool_plane_refuses_a_real_jwt_secret():
    with pytest.raises(ValidationError, match="JWT_SECRET must NOT be set on the tool/recon"):
        _prod(tool_plane=True, jwt_secret=_STRONG, encryption_key="", job_signing_public_key=_PUB)


def test_recon_plane_refuses_a_real_jwt_secret():
    with pytest.raises(ValidationError, match="JWT_SECRET must NOT be set on the tool/recon"):
        _prod(recon_plane=True, jwt_secret=_STRONG, encryption_key="", broker_seal_key="")


def test_valid_tool_plane_holds_no_jwt_secret():
    s = _prod_tool_plane()
    assert s.jwt_secret != _STRONG          # not the platform signing secret
    assert s.tool_plane is True


def test_control_plane_still_requires_a_real_jwt_secret():
    # The boundary does not weaken the token-bearing planes: a sentinel JWT is still refused there.
    with pytest.raises(ValidationError, match="JWT_SECRET must be set to a strong value"):
        _prod(jwt_secret="change-me-dev-only-do-not-use-in-production")


# ── (2) execution-plane secrets cannot forge a platform JWT ──────────────────────────────────────
def test_execution_plane_secrets_cannot_mint_a_valid_api_token():
    from guardian_common.security import create_access_token, decode_access_token

    tool = _prod_tool_plane()               # what a compromised tool plane could read from its env
    api = _prod()                           # the API that actually verifies tokens

    # The strongest key the tool plane holds is the broker-seal key. Forge a token with it…
    forged = create_access_token(subject="attacker", secret=tool.broker_seal_key,
                                 algorithm=api.jwt_algorithm)
    # …the API rejects it: the seal key is not the JWT secret.
    with pytest.raises(Exception):          # noqa: B017,PT011 - any verification failure is a pass
        decode_access_token(forged, secret=api.jwt_secret, algorithms=[api.jwt_algorithm])

    # And the tool plane cannot even reproduce the API's signing secret from what it holds.
    assert tool.broker_seal_key != api.jwt_secret
    assert tool.encryption_key != api.jwt_secret


# ── (3)+(4) broker sealing and credential KMS use SEPARATE keys ──────────────────────────────────
def test_broker_seal_uses_the_dedicated_key_not_the_credential_master(monkeypatch):
    # Under a production-shaped config with distinct keys, a broker-sealed token must NOT be openable
    # by the credential KMS, and a credential ciphertext must NOT be openable by the seal KMS.
    import guardian_common.crypto as crypto

    monkeypatch.setattr(crypto, "get_settings",
                        lambda: _prod())            # encryption_key=_MASTER, broker_seal_key=_SEAL
    crypto.get_kms.cache_clear()
    crypto.get_seal_kms.cache_clear()

    sealed = crypto.seal_secret("broker-payload")   # sealed with the broker-seal key
    credential = crypto.encrypt_secret("tenant-credential")  # encrypted with the KMS master

    assert crypto.unseal_secret(sealed) == "broker-payload"          # seal key opens seal token
    assert crypto.decrypt_secret(credential) == "tenant-credential"  # master opens credential
    # Cross-key attempts fail closed (return None) — the domains are cryptographically separate.
    assert crypto.decrypt_secret(sealed) is None       # KMS master can't open a broker token
    assert crypto.unseal_secret(credential) is None    # seal key can't open a credential
    crypto.get_kms.cache_clear()
    crypto.get_seal_kms.cache_clear()


def test_seal_kms_is_keyed_by_broker_seal_key(monkeypatch):
    # A token sealed under seal-key A must not decrypt when the seal key changes to B.
    import guardian_common.crypto as crypto

    monkeypatch.setattr(crypto, "get_settings", lambda: _prod(broker_seal_key="a" * 40))
    crypto.get_seal_kms.cache_clear()
    token = crypto.seal_secret("x")
    monkeypatch.setattr(crypto, "get_settings", lambda: _prod(broker_seal_key="b" * 40))
    crypto.get_seal_kms.cache_clear()
    assert crypto.unseal_secret(token) is None         # different seal key ⇒ cannot open
    crypto.get_seal_kms.cache_clear()


# ── (5) startup fails when the separation is missing (production) ─────────────────────────────────
def test_production_requires_broker_seal_key():
    with pytest.raises(ValidationError, match="BROKER_SEAL_KEY must be set to a strong value"):
        _prod(broker_seal_key="")


def test_production_rejects_dev_seal_sentinel():
    with pytest.raises(ValidationError, match="BROKER_SEAL_KEY must be set to a strong value"):
        _prod(broker_seal_key="dev-only-broker-seal-key-change-me")


def test_production_rejects_seal_key_equal_to_credential_master():
    with pytest.raises(ValidationError, match="must differ from GUARDIAN_ENCRYPTION_KEY"):
        _prod(broker_seal_key=_MASTER, encryption_key=_MASTER)


def test_production_tool_plane_refuses_the_credential_master():
    with pytest.raises(ValidationError, match="ENCRYPTION_KEY .*must NOT be set on the .*tool/recon"):
        _prod(tool_plane=True, jwt_secret="", encryption_key=_MASTER, job_signing_public_key=_PUB)


def test_recon_plane_needs_no_seal_key():
    # The recon plane never seals broker payloads, so it requires neither the master nor the seal key.
    s = _prod(recon_plane=True, jwt_secret="", encryption_key="", broker_seal_key="")
    assert s.recon_plane is True and s.broker_seal_key == ""


def test_valid_separated_production_config_constructs():
    s = _prod()
    assert s.broker_seal_key == _SEAL and s.encryption_key == _MASTER
    assert s.broker_seal_key != s.encryption_key


def test_local_dev_needs_no_explicit_seal_key():
    # Local/dev falls back to dev keys — no separation is enforced there.
    s = Settings(env="local", broker_seal_key="", encryption_key="")
    assert s.is_local_or_dev is True


# ── (6) P1-4 confidentiality holds end-to-end through the separated seal key ──────────────────────
def test_p1_4_sealing_roundtrips_and_hides_data_under_the_seal_key(monkeypatch):
    import guardian_common.crypto as crypto
    from guardian_scanner.tools import tasks

    monkeypatch.setattr(crypto, "get_settings", lambda: _prod())
    crypto.get_kms.cache_clear()
    crypto.get_seal_kms.cache_clear()

    secret = "SENSITIVE-ARTIFACT-BODY-xyz=="
    wire = tasks._seal_settings({"artifact_b64": secret, "media_type": "x", "allow_live": True})
    blob = json.dumps(wire)
    assert secret not in blob                                   # raw data gone from the wire
    assert "artifact_b64" not in wire and "_sealed" in wire     # moved under the sealed map
    assert tasks._unseal_settings(wire)["artifact_b64"] == secret   # roundtrips via the seal key

    # The sealed token is opaque to the credential KMS master — sealing did NOT use it.
    token = wire["_sealed"]["artifact_b64"]
    assert crypto.decrypt_secret(token) is None
    crypto.get_kms.cache_clear()
    crypto.get_seal_kms.cache_clear()
