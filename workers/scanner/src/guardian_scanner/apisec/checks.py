"""What proves an authorization failure (WP-D10).

A 200 is not a finding. Every rule here is about telling apart the three things a 200 can mean:

* the API returned the object, and the caller had no right to it — the finding;
* the API returned *an* object, its own empty-state page, or a login redirect with status 200 —
  which is most of what a naive BOLA scanner reports;
* the API returned an error document with a 200 status, which is common enough in the wild that
  ignoring it makes the whole check useless.

The strongest available proof is a **comparison**: what principal A gets for B's object, versus what
B gets for it. When the two responses agree, A read B's data and there is nothing left to argue
about. When only one credential exists, the bar is lower and the confidence is reported lower.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

# Error documents served with a 200. If the body says this, nothing was disclosed.
_DENIAL = re.compile(
    r"(?i)\b(?:unauthori[sz]ed|not\s+authori[sz]ed|forbidden|access\s+denied|permission\s+denied|"
    r"not\s+permitted|invalid\s+token|authentication\s+required|please\s+log\s?in|"
    r"sign\s?in\s+to\s+continue)\b"
)
# Field names no API should send to a client. Matched on the *name*; the value is never recorded.
_SENSITIVE_FIELDS = re.compile(
    r"(?i)^(?:password|passwd|password_hash|pwd|hashed_password|salt|secret|api_key|apikey|"
    r"access_token|refresh_token|private_key|ssn|social_security|tax_id|national_id|"
    r"credit_card|card_number|cvv|iban|bank_account|mfa_secret|totp_secret|session_token|"
    r"reset_token|internal_notes|password_reset_token)$"
)
MIN_BODY_BYTES = 2


@dataclass(frozen=True)
class Verdict:
    fired: bool
    indicator: str = ""
    confidence: str = "medium"
    evidence: dict | None = None


NO = Verdict(False)


def _digest(body: str) -> str:
    return hashlib.sha256((body or "").encode("utf-8", "replace")).hexdigest()[:16]


def looks_like_denial(status: int, body: str) -> bool:
    """Whether the response refused, whatever status code it used to say so."""
    if status in (401, 403, 404, 302, 303, 307, 308):
        return True
    if status >= 400:
        return True
    return bool(_DENIAL.search((body or "")[:2000]))


def substantive(body: str) -> bool:
    """Whether the response actually carries something.

    An empty body, `[]`, `{}` and `null` are what a correctly-authorized API returns when the caller
    may see nothing — and reporting those as disclosure is how a BOLA scanner becomes noise.
    """
    text = (body or "").strip()
    if len(text) <= MIN_BODY_BYTES:
        return False
    if text in ("[]", "{}", "null", '""'):
        return False
    try:
        parsed = json.loads(text)
    except ValueError:
        return True
    if parsed in ([], {}, None, ""):
        return False
    if isinstance(parsed, dict) and not any(
        v not in (None, [], {}, "") for k, v in parsed.items()
        if k not in ("status", "code", "message", "error", "detail", "errors")
    ):
        return False
    return True


# ── unauthenticated access ────────────────────────────────────────────────────────────────────────
def evaluate_unauthenticated(*, status: int, body: str, authenticated_status: int,
                             authenticated_body: str) -> Verdict:
    """The operation answered with no credential at all.

    Compared against the authenticated response rather than judged alone: an endpoint that is
    *intended* to be public answers both, and that is not a finding. What is a finding is an
    endpoint the document says requires authentication returning the same data to nobody.
    """
    if looks_like_denial(status, body) or not substantive(body):
        return NO
    if _digest(body) == _digest(authenticated_body) and 200 <= authenticated_status < 300:
        return Verdict(
            True,
            "the endpoint returned the same response with no credential as with one — the "
            "authentication requirement in the specification is not enforced",
            "high",
            {"status": status, "body_digest": _digest(body), "bytes": len(body or "")},
        )
    return Verdict(
        True,
        f"the endpoint returned HTTP {status} with a substantive body and no credential",
        "medium",
        {"status": status, "bytes": len(body or "")},
    )


# ── BOLA ──────────────────────────────────────────────────────────────────────────────────────────
def evaluate_bola(*, attacker_status: int, attacker_body: str,
                  owner_status: int | None = None, owner_body: str | None = None,
                  control_status: int | None = None, control_body: str | None = None) -> Verdict:
    """Principal A asked for principal B's object.

    `owner_*` is what B gets for the same object, when a second credential exists. That comparison
    is the conclusive one: identical bodies mean A read B's record, and no amount of arguing about
    status codes changes it.

    `control_*` is what A gets for an identifier that does not exist. Without it, an API that
    cheerfully returns a generic object for every id looks like BOLA on every endpoint.
    """
    if looks_like_denial(attacker_status, attacker_body) or not substantive(attacker_body):
        return NO

    if owner_body is not None and 200 <= (owner_status or 0) < 300:
        if _digest(attacker_body) == _digest(owner_body):
            return Verdict(
                True,
                "the response was byte-for-byte what the object's own owner receives — the "
                "credential presented has no right to it",
                "high",
                {"status": attacker_status, "body_digest": _digest(attacker_body),
                 "matched_owner": True},
            )
        return NO

    if control_body is not None and _digest(attacker_body) == _digest(control_body):
        # The same body comes back for an identifier that does not exist, so nothing was disclosed.
        return NO

    return Verdict(
        True,
        f"another principal's object identifier returned HTTP {attacker_status} with a "
        "substantive body instead of being refused",
        "medium",
        {"status": attacker_status, "bytes": len(attacker_body or "")},
    )


# ── BFLA ──────────────────────────────────────────────────────────────────────────────────────────
def evaluate_bfla(*, status: int, body: str, privileged_status: int | None = None,
                  privileged_body: str | None = None) -> Verdict:
    """A low-privilege credential invoked an operation the document marks as administrative."""
    if looks_like_denial(status, body) or not substantive(body):
        return NO
    if privileged_body is not None and _digest(body) == _digest(privileged_body):
        return Verdict(
            True,
            "an unprivileged credential received exactly what the privileged one does from an "
            "administrative operation",
            "high",
            {"status": status, "body_digest": _digest(body)},
        )
    return Verdict(
        True,
        f"an administrative operation returned HTTP {status} to an unprivileged credential",
        "medium",
        {"status": status, "bytes": len(body or "")},
    )


# ── excessive data exposure ───────────────────────────────────────────────────────────────────────
def evaluate_exposure(body: str) -> Verdict:
    """Fields in the response that no client should ever receive.

    Matched on field names, never on values: the finding is that a password hash is in the payload,
    and quoting it would put the hash in the report.
    """
    try:
        parsed = json.loads(body or "")
    except ValueError:
        return NO

    found: set[str] = set()

    def walk(node, depth: int = 0) -> None:  # noqa: ANN001
        if depth > 8:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if _SENSITIVE_FIELDS.match(str(key)) and value not in (None, "", [], {}):
                    found.add(str(key))
                walk(value, depth + 1)
        elif isinstance(node, list):
            for item in node[:50]:
                walk(item, depth + 1)

    walk(parsed)
    if not found:
        return NO
    return Verdict(
        True,
        "the response body carries " + ", ".join(f"`{name}`" for name in sorted(found)[:6])
        + " — fields a client has no use for and an attacker does",
        "high",
        # Names and count only. The values are the reason this is a finding.
        {"fields": sorted(found)[:10]},
    )


__all__ = [
    "Verdict",
    "evaluate_bfla",
    "evaluate_bola",
    "evaluate_exposure",
    "evaluate_unauthenticated",
    "looks_like_denial",
    "substantive",
]
