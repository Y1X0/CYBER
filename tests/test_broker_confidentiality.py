"""Broker/result-backend confidentiality (P1-4) — no DB, no network, no broker.

Redis is broker + result backend (ADR-003); the tool plane sits on a cache-only network and holds no
DB, but a queue message still transits Redis. This proves the two halves of P1-4:

  * TLS in transit: production/staging config REFUSES a plaintext ``redis://`` broker and requires
    ``rediss://`` — local/dev is unaffected.
  * Application-layer sealing: the sensitive DATA fields of a job (the raw customer artifact, packet
    snapshots, scan XML, CT rows) and ALL returned evidence are Fernet-sealed with the existing
    ``GUARDIAN_ENCRYPTION_KEY`` before they can sit in the broker/result backend, and roundtrip back
    to plaintext only on the tool plane after signature verification. The CONTROL fields that the
    Phase-C signature must cover (execution backend, allow_live, actor/campaign/approval) stay
    plaintext inside the signed payload.
"""

from __future__ import annotations

import json

import pytest
from guardian_common.config import Settings
from guardian_scanner.tools import tasks
from pydantic import ValidationError

_STRONG = "x" * 40


def _prod(**over):
    base = dict(
        env="production",
        database_url="postgresql+psycopg://guardian:guardian@db:5432/guardian?sslmode=verify-full",
        app_database_url="postgresql+psycopg://guardian_app:pw@db:5432/guardian?sslmode=verify-full",
        redis_url="rediss://redis:6379/0",
        encryption_key=_STRONG, jwt_secret=_STRONG,
        broker_seal_key=_STRONG + "-seal",  # P1-A: set and distinct from encryption_key
        bootstrap_admin_password="a-strong-admin-password",  # P1-B: default is refused in prod
    )
    base.update(over)
    return Settings(**base)


# ── TLS in transit: plaintext broker is refused outside local/dev ────────────────────────────────
def test_production_rejects_plaintext_redis_broker():
    with pytest.raises(ValidationError, match="rediss://"):
        _prod(redis_url="redis://redis:6379/0")


def test_production_requires_rediss_scheme():
    # A non-TLS scheme of any shape is refused; only rediss:// clears the gate.
    with pytest.raises(ValidationError, match="TLS"):
        _prod(redis_url="redis://cache:6379/1")
    s = _prod(redis_url="rediss://cache:6379/1")
    assert s.redis_url.startswith("rediss://")


def test_staging_is_production_grade_for_broker_tls():
    with pytest.raises(ValidationError, match="rediss://"):
        _prod(env="staging", redis_url="redis://redis:6379/0")


@pytest.mark.parametrize("env", ["local", "dev", "development", "test", "ci"])
def test_local_and_dev_allow_plaintext_redis(env):
    # Developers run a plaintext local Redis; the TLS invariant must not fire there.
    s = Settings(env=env, redis_url="redis://localhost:6379/0")
    assert s.redis_url == "redis://localhost:6379/0"


# ── application-layer sealing: sensitive DATA never sits plaintext in the wire ────────────────────
def test_seal_settings_removes_sensitive_value_from_the_wire():
    secret = "SENSITIVE-ARTIFACT-BODY-abc123=="
    wire = tasks._seal_settings({"artifact_b64": secret, "media_type": "application/vnd.tcpdump.pcap",
                                 "_execution_backend": "inproc", "allow_live": True})
    blob = json.dumps(wire)
    assert secret not in blob                          # the raw artifact is gone from the wire
    assert "artifact_b64" not in wire                  # moved under the sealed map
    assert "_sealed" in wire and "artifact_b64" in wire["_sealed"]
    # CONTROL fields the signature must cover stay plaintext, in place.
    assert wire["_execution_backend"] == "inproc"
    assert wire["allow_live"] is True
    assert wire["media_type"] == "application/vnd.tcpdump.pcap"


def test_seal_unseal_settings_roundtrips_exactly():
    original = {"artifact_b64": "Zm9vYmFy", "snapshot": {"pkt": [1, 2, 3]}, "xml": "<x/>",
                "ct": [{"name": "a.example.com"}], "media_type": "x", "allow_live": False}
    unsealed = tasks._unseal_settings(tasks._seal_settings(original))
    assert unsealed == original                        # every sealed field decrypts back identically


def test_seal_settings_is_a_noop_without_sensitive_fields():
    # A job with only control fields carries no _sealed map (nothing to hide) and is untouched.
    plain = {"_execution_backend": "uid_nft", "allow_live": True}
    wire = tasks._seal_settings(plain)
    assert wire == plain and "_sealed" not in wire


def test_each_sealed_field_is_individually_encrypted():
    for key in tasks._SEALED_SETTING_KEYS:
        marker = f"PLAINTEXT-{key}-marker"
        wire = tasks._seal_settings({key: marker})
        assert marker not in json.dumps(wire)          # no sealed key leaks its value
        assert tasks._unseal_settings(wire)[key] == marker


# ── application-layer sealing: returned evidence never sits plaintext in the result backend ───────
def test_seal_result_hides_evidence_and_roundtrips():
    wires = [{"kind": "cleartext_http", "target": "10.0.0.9",
              "data": {"secret_flow": "GET /admin HTTP/1.1"}},
             {"kind": "artifact", "target": "cap", "data": {"sha256": "deadbeef"}}]
    sealed = tasks._seal_result(wires)
    blob = json.dumps(sealed)
    assert "secret_flow" not in blob and "cleartext_http" not in blob   # evidence body is opaque
    assert "deadbeef" not in blob
    assert list(sealed.keys()) == ["_sealed_result"]
    assert tasks._unseal_result(sealed) == wires       # dispatcher recovers it exactly


def test_unseal_result_passes_through_a_bare_list():
    # A rejection path returns a bare [] (never sealed) — the dispatcher must accept it unchanged.
    assert tasks._unseal_result([]) == []
    assert tasks._unseal_result(None) == []
    plain = [{"kind": "x", "target": "t", "data": {}}]
    assert tasks._unseal_result(plain) == plain


def test_sealed_tokens_are_not_reversible_without_the_key():
    # The sealed token is Fernet ciphertext, not an encoding — it is opaque without the KMS key.
    wire = tasks._seal_settings({"artifact_b64": "top-secret-body"})
    token = wire["_sealed"]["artifact_b64"]
    import base64
    with pytest.raises(Exception):                     # noqa: B017,PT011 - any decode of the token fails
        json.loads(base64.b64decode(token))
