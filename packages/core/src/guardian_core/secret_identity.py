"""A keyed, non-reversible identity for a detected secret — for correlation only (WP-E1 fix).

The `same-secret` correlation rule needs to answer "are these two findings the *same* credential?".
It used to answer that from the display *redaction* (`AK********EY (len=40)` and friends), which is
lossy on purpose: two different secrets of equal length ≤ 8, or sharing first-two/last-two/length,
redact to the identical string. Grouping on that produced a `same-secret` group marked CONFIRMED for
two credentials that are not the same — a false relationship, and exactly the kind of over-claim the
E1 confidence model exists to prevent.

This module derives a SEPARATE identity from the *raw* secret at detection time:

    display_redaction    -> human-visible evidence (unchanged, lossy, safe to show)
    correlation identity -> HMAC-SHA256(server_key, raw)  (internal, never shown, never stored raw)

Why HMAC under a server-side key rather than a bare SHA-256 of the secret: many real secrets have
low entropy (passwords, PINs, short tokens), so a bare unkeyed digest could be brute-forced by
anyone who obtained it. Keying with a server-side secret means that even a full read of the identity
column does not let an attacker test guesses — the same rationale the platform already uses for
API-key digests (`guardian_core.apikeys.digest`, a peppered HMAC). The key stays in configuration,
never in source, findings, logs, or API responses. A per-purpose domain-separation label keeps this
HMAC distinct from any other use of the same key. The digest is one-way: it identifies "same
credential" without ever being reversible to the credential.

Determinism: the same raw secret under the same key always yields the same identity, so a re-scan
correlates the same credential; a key rotation makes new identities incomparable to old ones, which
is conservative — the worst case is a *missed* correlation, never a false one.
"""

from __future__ import annotations

import hashlib
import hmac

# Bumping the version (or the label) intentionally invalidates every previously computed identity
# — used only if the construction itself ever has to change.
_DOMAIN = b"guardian.secret-correlation-identity.v1\x00"


def secret_correlation_identity(raw_secret: str, *, key: str) -> str | None:
    """A keyed, one-way identity for a raw secret, or ``None`` when it cannot be computed safely.

    Returns ``None`` when there is no key (so the caller stays conservative and never emits a
    weakly-keyed identity) or when the value is empty after trimming surrounding quotes. The
    trimming mirrors the redactor so ``"abc"`` and ``abc`` map to one identity.

    The result is a 64-character hex HMAC-SHA256 digest. It is NOT the raw secret and NOT the
    display redaction; it must never be returned to a customer or written into human-readable text.
    """
    if not key:
        return None
    stripped = raw_secret.strip("'\"")
    if not stripped:
        return None
    return hmac.new(key.encode(), _DOMAIN + stripped.encode(), hashlib.sha256).hexdigest()


__all__ = ["secret_correlation_identity"]
