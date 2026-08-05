"""Envelope encryption for stored credential references (Phase 5A).

MVP: a `LocalKMSProvider` (AES via Fernet) keyed from `GUARDIAN_ENCRYPTION_KEY`. This closes the
"credentials stored plaintext" gap — `asset.secret_ref` holds ciphertext, decrypted only at use. A
cloud KMS / Vault provider implements the same `KMSProvider` port later (BYOK, Phase 9). No raw
secret is ever written to the DB or logs.
"""

from __future__ import annotations

import base64
import hashlib
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from guardian_common.config import get_settings

_DEV_KEY = "dev-only-encryption-key-change-me"


def _fernet_key(secret: str) -> bytes:
    # Derive a valid 32-byte urlsafe-base64 Fernet key from an arbitrary secret string.
    return base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())


class LocalKMSProvider:
    """AES-based envelope encryption using a locally-configured key (KMSProvider port)."""

    def __init__(self, key_material: str) -> None:
        self._fernet = Fernet(_fernet_key(key_material))

    def encrypt(self, plaintext: bytes, *, context: dict | None = None) -> bytes:
        return self._fernet.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes, *, context: dict | None = None) -> bytes:
        return self._fernet.decrypt(ciphertext)


@lru_cache
def get_kms() -> LocalKMSProvider:
    settings = get_settings()
    key = settings.encryption_key or _DEV_KEY
    if not settings.encryption_key and settings.is_production:
        raise ValueError("GUARDIAN_ENCRYPTION_KEY must be set outside local/dev")
    return LocalKMSProvider(key)


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret string → opaque token safe to store in the DB."""
    return get_kms().encrypt(plaintext.encode()).decode()


def decrypt_secret(token: str) -> str | None:
    """Decrypt a token produced by `encrypt_secret`. Returns None if it can't be decrypted."""
    try:
        return get_kms().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        return None


def encrypt_json(payload: dict) -> str:
    """Encrypt a JSON-serializable mapping → opaque token safe to store in the DB."""
    import json

    return encrypt_secret(json.dumps(payload, separators=(",", ":")))


def decrypt_json(token: str | None) -> dict:
    """Decrypt a token produced by `encrypt_json`. Returns {} if absent or undecryptable."""
    import json

    if not token:
        return {}
    plain = decrypt_secret(token)
    if plain is None:
        return {}
    try:
        loaded = json.loads(plain)
    except ValueError:
        return {}
    return loaded if isinstance(loaded, dict) else {}
