"""Asymmetric job signing for the execution plane (Phase C).

`run_tool` must never trust a queue message as if it came from the trusted dispatcher. The
dispatcher signs a canonical serialization of the ENTIRE job wire (every security-relevant field:
tenant, actor, scope, targets, ports, protocols, campaign/approval context, allow_live, backend, …)
plus issued_at / expires_at / a unique nonce, using an **Ed25519 private key it alone holds**. The
tool plane verifies with the **public key only** — it can never mint a valid job.

Verification is signature + expiry + replay (a bounded in-memory nonce cache; see limitations). Any
failure raises `JobVerificationError`, and the caller must refuse to execute.

Key material: base64-encoded raw 32-byte Ed25519 keys via config. If unset, a FIXED dev keypair is
derived — allowed only in local/dev, refused elsewhere. The private key must never reach the tool
plane, the queue, a job, or logs.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from guardian_common.config import get_settings

_DEFAULT_TTL_SECONDS = 300
_MAX_FUTURE_SKEW = 60

# Deterministic dev keypair seed (local/dev only) — both planes derive the same keypair in-process.
_DEV_SEED = hashlib.sha256(b"guardian-dev-job-signing-do-not-use-in-prod").digest()


class JobVerificationError(RuntimeError):
    """A job could not be authenticated (bad/absent signature, expired, replayed, malformed)."""


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _dev_allowed() -> bool:
    # Use the platform's canonical dev-env set (local/dev/development/test/ci) — the same gate every
    # other dev fallback uses. Production is never in it, so the dev keypair stays refused there.
    return get_settings().is_local_or_dev


def _private_key() -> Ed25519PrivateKey:
    raw = get_settings().job_signing_private_key
    if raw:
        return Ed25519PrivateKey.from_private_bytes(_b64d(raw))
    if _dev_allowed():
        return Ed25519PrivateKey.from_private_bytes(_DEV_SEED)
    raise JobVerificationError("no job-signing private key configured")


def _public_key() -> Ed25519PublicKey:
    raw = get_settings().job_signing_public_key
    if raw:
        return Ed25519PublicKey.from_public_bytes(_b64d(raw))
    if _dev_allowed():
        return Ed25519PrivateKey.from_private_bytes(_DEV_SEED).public_key()
    raise JobVerificationError("no job-signing public key configured")


def _canonical(job_wire: dict, issued_at: str, expires_at: str, nonce: str) -> bytes:
    """Deterministic bytes over the full job wire + envelope — any change flips the signature."""
    return json.dumps(
        {"job": job_wire, "issued_at": issued_at, "expires_at": expires_at, "nonce": nonce},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def sign_job(job_wire: dict, *, ttl_seconds: int = _DEFAULT_TTL_SECONDS) -> dict:
    """Trusted dispatcher: wrap a job wire in a signed, expiring, single-use envelope."""
    now = dt.datetime.now(dt.UTC)
    issued_at = now.isoformat()
    expires_at = (now + dt.timedelta(seconds=ttl_seconds)).isoformat()
    nonce = secrets.token_hex(16)
    signature = _private_key().sign(_canonical(job_wire, issued_at, expires_at, nonce))
    return {
        "job": job_wire, "issued_at": issued_at, "expires_at": expires_at, "nonce": nonce,
        "sig": base64.b64encode(signature).decode("ascii"),
    }


def verify_job(signed: dict) -> dict:
    """Tool plane: authenticate an envelope and return the trusted job wire, or raise."""
    if not isinstance(signed, dict):
        raise JobVerificationError("malformed envelope")
    try:
        job_wire = signed["job"]
        issued_at = str(signed["issued_at"])
        expires_at = str(signed["expires_at"])
        nonce = str(signed["nonce"])
        signature = _b64d(signed["sig"])
    except (KeyError, TypeError, ValueError, base64.binascii.Error) as exc:  # noqa: F821
        raise JobVerificationError("malformed envelope") from exc

    now = dt.datetime.now(dt.UTC)
    try:
        expires = dt.datetime.fromisoformat(expires_at)
        issued = dt.datetime.fromisoformat(issued_at)
    except ValueError as exc:
        raise JobVerificationError("bad timestamps") from exc
    if now > expires:
        raise JobVerificationError("expired job")
    if issued > now + dt.timedelta(seconds=_MAX_FUTURE_SKEW):
        raise JobVerificationError("issued in the future")

    try:
        _public_key().verify(signature, _canonical(job_wire, issued_at, expires_at, nonce))
    except InvalidSignature as exc:
        raise JobVerificationError("bad signature") from exc

    # Single-use across ALL workers/hosts (P1-1): reserve the nonce in the shared store. A replay of
    # this envelope to any other worker/process is rejected here — before the job is reconstructed.
    from guardian_common.replay import ReplayStoreUnavailable, reserve_nonce
    ttl = int(max(1, expires.timestamp() - now.timestamp()))
    try:
        fresh = reserve_nonce(nonce, ttl)
    except ReplayStoreUnavailable as exc:
        raise JobVerificationError("replay store unavailable") from exc
    if not fresh:
        raise JobVerificationError("replayed nonce")
    if not isinstance(job_wire, dict):
        raise JobVerificationError("malformed job")
    return job_wire
