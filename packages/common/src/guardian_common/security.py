"""Security primitives: password hashing (Argon2id) and JWT access tokens.

Centralized so auth logic is implemented once and reviewed once (doc 06 §5).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_ph = PasswordHasher()  # Argon2id defaults are sound for interactive auth


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:  # malformed hash → treat as non-match, never raise to caller
        return False


def needs_rehash(password_hash: str) -> bool:
    return _ph.check_needs_rehash(password_hash)


def create_access_token(
    *,
    subject: str,
    secret: str,
    algorithm: str = "HS256",
    ttl_minutes: int = 60,
    claims: dict[str, Any] | None = None,
) -> str:
    now = dt.datetime.now(dt.UTC)
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(minutes=ttl_minutes)).timestamp()),
    }
    if claims:
        payload.update(claims)
    return jwt.encode(payload, secret, algorithm=algorithm)


def decode_access_token(token: str, *, secret: str, algorithms: list[str]) -> dict[str, Any]:
    """Decode & verify a token. Raises jwt.PyJWTError on any problem."""
    return jwt.decode(token, secret, algorithms=algorithms)


# ── API keys (CI/CD) — store only a hash, never the token (doc 06 §5) ──
def generate_api_key() -> tuple[str, str]:
    """Return (plaintext_key, sha256_hash). Show plaintext once; persist only the hash."""
    raw = "sgk_" + secrets.token_urlsafe(32)
    return raw, hash_api_key(raw)


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()
