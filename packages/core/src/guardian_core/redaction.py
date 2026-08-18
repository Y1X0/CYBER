"""Last-line redaction for anything leaving the platform (WP-F2).

The engines redact at write time — the secrets engine has never persisted a raw credential, and the
template runner strips token-shaped runs out of every snippet. This is the second line, applied
where evidence is *served*: the findings workbench, and later reports and exports.

Two lines rather than one because the failure modes differ. An engine forgets to redact a new field;
a customer pastes a private key into a config file that the IaC parser quotes verbatim in an
`excerpt`; an AI explanation echoes back the value it was shown. Each of those is a leak through
evidence that was correct at the time it was written, and the only place that sees all of them is
the boundary.

It is deliberately **not** silent. A hit here means an engine wrote a credential into the database,
which is a defect that has to be findable: every scrub logs the finding and the pattern that fired.
Redacting quietly would hide the very bug this exists to catch.

What it does not do: entropy-guess. A high-entropy string is as likely to be a SHA-256 digest, a
fingerprint, or a base64 certificate *public* key — all of which are evidence a customer needs to
read. Only shapes that are credentials by construction are masked.
"""

from __future__ import annotations

import re
from typing import Any

MASK = "[redacted]"

# Ordered, and each one is a shape that cannot plausibly be anything but a credential.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # PEM private keys, including the OpenSSH and PKCS#8 spellings. The header alone is the tell.
    ("private_key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
        r".*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
        re.DOTALL,
    )),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    # GitHub's documented prefixes: `ghp_` personal, `gho_` OAuth, `ghu_`/`ghs_` app,
    # `ghr_` refresh.
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_key", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi_token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{16,}\b")),
    # A signed JWT: three base64url segments where the first decodes to a JSON header. Matching the
    # `eyJ` prefix is what distinguishes it from an arbitrary dotted identifier.
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    # A URL carrying inline credentials. The password is the secret; the scheme and host are the
    # evidence, so only the credential pair is masked.
    ("url_credentials", re.compile(r"(?<=://)[^\s/:@]{1,64}:[^\s/@]{1,128}(?=@)")),
    # `password = "…"` and friends. The optional prefix is what makes `DB_PASSWORD=` and
    # `db.api_key:` match: `_` and `.` are not word boundaries, so a leading `\b` would miss the
    # spelling almost every real config file uses.
    ("assigned_secret", re.compile(
        r"(?i)(?:[a-z0-9]+[_.-])*"
        r"(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token"
        r"|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*['\"]?(?P<value>[^\s'\"<>,;]{6,})",
    )),
)

# Fields whose whole value is a credential by definition, whatever it looks like.
_SENSITIVE_KEYS = frozenset({
    "password", "passwd", "pwd", "secret", "api_key", "apikey", "token", "access_token",
    "auth_token", "refresh_token", "client_secret", "private_key", "credential", "credentials",
    "authorization", "session_key", "secret_key",
})

# Already-redacted markers the engines emit. Masking them again would turn readable evidence
# ("AK********EY (len=20)") into "[redacted]" and lose the length, which is what makes two
# occurrences of the same secret recognizable as one secret.
_ALREADY_MASKED = re.compile(r"^[<\[]?redacted|\*{4,}|\bREDACTED\b")


def _mask_assigned(match: re.Match[str]) -> str:
    """Keep the key and the shape of the assignment, drop the value."""
    prefix = match.group(0)[: match.start("value") - match.start(0)]
    return prefix + MASK


def scrub_text(text: str) -> tuple[str, list[str]]:
    """Mask credential-shaped substrings; also returns which patterns fired."""
    if not text:
        return text, []
    hits: list[str] = []
    result = text
    for name, pattern in _PATTERNS:
        if not pattern.search(result):
            continue
        hits.append(name)
        result = (
            pattern.sub(_mask_assigned, result) if name == "assigned_secret"
            else pattern.sub(MASK, result)
        )
    return result, hits


def scrub(value: Any, *, _key: str | None = None) -> tuple[Any, list[str]]:
    """Recursively scrub a JSON-shaped structure.

    Returns `(scrubbed, hits)`. `hits` is never discarded by callers: a hit means a credential was
    written into the database by an engine, and that is a defect to log, not to hide.
    """
    if isinstance(value, dict):
        out: dict = {}
        hits: list[str] = []
        for key, item in value.items():
            scrubbed, found = scrub(item, _key=str(key).lower())
            out[key] = scrubbed
            hits.extend(found)
        return out, hits
    if isinstance(value, (list, tuple)):
        out_list = []
        hits = []
        for item in value:
            scrubbed, found = scrub(item, _key=_key)
            out_list.append(scrubbed)
            hits.extend(found)
        return (list(out_list), hits)
    if isinstance(value, str):
        if _key in _SENSITIVE_KEYS and value and not _ALREADY_MASKED.search(value):
            # A key named `password` holds a password regardless of what it looks like — the value
            # `letmein` matches no credential shape at all.
            return MASK, [f"key:{_key}"]
        return scrub_text(value)
    return value, []


__all__ = ["MASK", "scrub", "scrub_text"]
