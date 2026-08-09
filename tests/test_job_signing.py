"""Job signing (Phase C) — asymmetric authenticity, expiry, replay, and the private-key boundary.

No DB, no network. Proves a tampered/expired/replayed/unsigned job is rejected, that EVERY
security-relevant field is inside the signed payload, and that a plane holding only the public key
cannot mint a valid job.
"""

from __future__ import annotations

import base64
import copy
import datetime as dt

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from guardian_common import job_signing
from guardian_common.job_signing import JobVerificationError, sign_job, verify_job

_JOB = {
    "tenant_id": "11111111-1111-1111-1111-111111111111",
    "job_id": "abc123",
    "tool_key": "nmap",
    "scope": {"targets": ["10.0.0.5"], "ports": [80], "protocols": ["tcp"],
              "network_allowed": True, "read_only": True},
    "settings": {"_execution_backend": "uid_nft", "allow_live": True,
                 "actor_id": "actor-1", "campaign_id": "c-1", "approval_id": "a-1"},
}


@pytest.fixture(autouse=True)
def _fresh_nonce_cache():
    job_signing._seen_nonces.clear()
    yield
    job_signing._seen_nonces.clear()


def test_valid_signed_job_roundtrips():
    assert verify_job(sign_job(_JOB)) == _JOB


def test_unsigned_job_rejected():
    with pytest.raises(JobVerificationError):
        verify_job({"job": _JOB})                       # no signature envelope at all


@pytest.mark.parametrize("path", [
    ("tenant_id",), ("job_id",), ("tool_key",),
    ("scope", "targets"), ("scope", "ports"), ("scope", "protocols"),
    ("settings", "allow_live"), ("settings", "_execution_backend"),
    ("settings", "actor_id"), ("settings", "campaign_id"), ("settings", "approval_id"),
])
def test_any_tampered_security_field_is_rejected(path):
    signed = sign_job(_JOB)
    job = copy.deepcopy(signed["job"])
    node = job
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = "TAMPERED" if not isinstance(node[path[-1]], list) else ["TAMPERED"]
    signed["job"] = job
    with pytest.raises(JobVerificationError, match="bad signature"):
        verify_job(signed)


def test_tampered_envelope_fields_rejected():
    for field in ("issued_at", "expires_at", "nonce"):
        signed = sign_job(_JOB)
        signed[field] = (dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)).isoformat() \
            if "at" in field else "deadbeef"
        with pytest.raises(JobVerificationError):
            verify_job(signed)


def test_expired_job_rejected():
    signed = sign_job(_JOB, ttl_seconds=-1)             # already expired
    with pytest.raises(JobVerificationError, match="expired"):
        verify_job(signed)


def test_replayed_job_rejected():
    signed = sign_job(_JOB)
    assert verify_job(signed) == _JOB                   # first use ok
    with pytest.raises(JobVerificationError, match="replay"):
        verify_job(signed)                              # same nonce again


def test_public_key_only_plane_cannot_sign(monkeypatch):
    # A plane configured with ONLY the public key (and not in dev) cannot mint a job.
    pub = Ed25519PrivateKey.from_private_bytes(job_signing._DEV_SEED).public_key()
    pub_b64 = base64.b64encode(pub.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

    class _S:
        env = "production"
        is_local_or_dev = False                         # production ⇒ no dev-keypair fallback
        job_signing_private_key = ""
        job_signing_public_key = pub_b64

    monkeypatch.setattr(job_signing, "get_settings", lambda: _S())
    with pytest.raises(JobVerificationError, match="no job-signing private key"):
        sign_job(_JOB)                                  # cannot sign — no private key
    # …but it CAN still verify a job the dispatcher signed with the matching private key.
    class _D:
        env = "local"
        is_local_or_dev = True
        job_signing_private_key = ""
        job_signing_public_key = ""
    monkeypatch.setattr(job_signing, "get_settings", lambda: _D())
    signed = sign_job(_JOB)
    monkeypatch.setattr(job_signing, "get_settings", lambda: _S())
    assert verify_job(signed) == _JOB
