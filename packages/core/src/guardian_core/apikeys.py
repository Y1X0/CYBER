"""API key format, hashing and scopes (WP-G1).

`api_keys` has been a table since the first schema with no way to issue a key, no way to
authenticate with one, and no scope enforcement anywhere — the governance module reads
`ApiKey.scopes` for an actor id that nothing could ever produce. A CI pipeline that wants to fail a
build on a critical finding has had no way in that is not a human's password.

Three decisions shape this module.

**The key carries its own id.** `gdn_<key_id>_<secret>`: the lookup finds one row by id and then
compares one hash, instead of hashing the presented key against every key in the table. A design
that needs a table scan to authenticate is a design that gets slower the more customers you have,
and one that tempts somebody to cache the wrong thing.

**Only a peppered hash is stored.** The digest uses a server-side pepper from configuration, so a
database dump alone does not let an attacker verify guesses offline — they need the application
secret too. Comparison is constant time, because the timing of a string comparison against a stored
digest is exactly how key-prefix guessing works.

**Scopes are least privilege by default.** A key with no scope grants nothing; there is no implicit
"all". Read scopes cannot write, and the scopes that can start an active scan are separate from the
ones that read findings, because a CI key that reports build status should not be able to point the
scanner at a new target.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

PREFIX = "gdn"
KEY_ID_BYTES = 8
SECRET_BYTES = 32
# `gdn_<24 hex>_<43 url-safe chars>` — the shape a secret scanner can be taught to recognize, which
# is the point of a distinctive prefix.
KEY_RE = re.compile(rf"^{PREFIX}_([0-9a-f]{{{KEY_ID_BYTES * 2}}})_([A-Za-z0-9_-]{{20,}})$")


# ── scopes ────────────────────────────────────────────────────────────────────────────────────────
class Scope:
    """What a key may do. Deliberately coarse, deliberately explicit."""

    FINDINGS_READ = "findings:read"
    FINDINGS_WRITE = "findings:write"      # triage decisions
    SCANS_READ = "scans:read"
    SCANS_WRITE = "scans:write"            # start a scan against an existing asset
    ASSETS_READ = "assets:read"
    ASSETS_WRITE = "assets:write"          # register a new target
    REPORTS_READ = "reports:read"
    COMPLIANCE_READ = "compliance:read"
    REMEDIATION_READ = "remediation:read"
    REMEDIATION_WRITE = "remediation:write"
    GRAPH_READ = "graph:read"


ALL_SCOPES: tuple[str, ...] = tuple(
    value for name, value in vars(Scope).items()
    if not name.startswith("_") and isinstance(value, str)
)

# The scope a CI pipeline actually needs: read the findings for the scan it triggered, and start a
# scan of an asset somebody already registered and authorized. Notably absent: `assets:write`, so a
# leaked build key cannot point the scanner at a target nobody consented to.
CI_SCOPES: tuple[str, ...] = (Scope.FINDINGS_READ, Scope.SCANS_READ, Scope.SCANS_WRITE,
                              Scope.REPORTS_READ)

READ_ONLY_SCOPES: tuple[str, ...] = tuple(s for s in ALL_SCOPES if s.endswith(":read"))


class InvalidKey(ValueError):
    """The presented value is not a Guardian API key."""


@dataclass(frozen=True)
class IssuedKey:
    """A freshly minted key. The secret exists in this object and nowhere else, ever again."""

    key_id: str
    token: str
    digest: str


def normalize_scopes(scopes) -> tuple[str, ...]:  # noqa: ANN001
    """Known scopes only, deduplicated and ordered.

    An unknown scope is dropped rather than stored: a key carrying `admin:*` because somebody typed
    it would read as authoritative in an audit and grant nothing, which is the worst combination.
    """
    return tuple(sorted({s for s in (scopes or []) if s in ALL_SCOPES}))


def digest(token: str, *, pepper: str) -> str:
    """Deterministic, peppered digest of a key.

    HMAC-SHA256 rather than a password KDF on purpose: the secret is 32 bytes of CSPRNG output, so
    there is nothing to brute force and no need to make verification slow. The pepper is what stops
    a stolen database being enough — an attacker with the table still needs the application secret
    to check a guess.
    """
    return hmac.new(pepper.encode(), token.encode(), hashlib.sha256).hexdigest()


def mint(*, pepper: str) -> IssuedKey:
    """A new key. Returns the token once; only the digest is ever stored."""
    key_id = secrets.token_hex(KEY_ID_BYTES)
    secret = secrets.token_urlsafe(SECRET_BYTES)
    token = f"{PREFIX}_{key_id}_{secret}"
    return IssuedKey(key_id=key_id, token=token, digest=digest(token, pepper=pepper))


def parse(token: str) -> str:
    """The key id inside a presented token, or raise.

    Parsing before any database work means a malformed value costs one regex rather than a query,
    and — more importantly — the lookup is by id, so verification never scans the table.
    """
    match = KEY_RE.match((token or "").strip())
    if not match:
        raise InvalidKey("not a Guardian API key")
    return match.group(1)


def verify(token: str, stored_digest: str, *, pepper: str) -> bool:
    """Constant-time check of a presented token against the stored digest."""
    return hmac.compare_digest(digest(token, pepper=pepper), stored_digest or "")


def redact(token: str) -> str:
    """What may appear in a log or an audit record.

    The key id is safe and useful — it identifies which key without being one. The secret half never
    appears anywhere, which is why this function exists rather than a `token[:8]` at each call site.
    """
    try:
        return f"{PREFIX}_{parse(token)}_…"
    except InvalidKey:
        return "<invalid key>"


def allows(scopes, required: str) -> bool:  # noqa: ANN001
    """Whether a key's scopes permit an operation.

    No implicit hierarchy: holding `findings:write` does not confer `findings:read`. Two lines of
    scopes on a key is a small price for never having to reason about what a grant silently
    included.
    """
    return required in set(scopes or ())


__all__ = [
    "ALL_SCOPES",
    "CI_SCOPES",
    "KEY_RE",
    "PREFIX",
    "READ_ONLY_SCOPES",
    "InvalidKey",
    "IssuedKey",
    "Scope",
    "allows",
    "digest",
    "mint",
    "normalize_scopes",
    "parse",
    "redact",
    "verify",
]
