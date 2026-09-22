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
    # Some checks (CORS, response hygiene) grade the *same* signal into different severities; the
    # authorization checks leave this empty and the engine's fixed per-rule severity stands.
    severity: str = ""


NO = Verdict(False)

# Field names that make a response one you never want written to a shared or browser cache — secrets
# and the personal data caching rules (CWE-525) are actually about. Matched on the name only; the
# value is never read, exactly as with `_SENSITIVE_FIELDS`.
_PRIVATE_FIELDS = re.compile(
    r"(?i)^(?:password|passwd|pwd|password_hash|hashed_password|secret|api_key|apikey|access_token|"
    r"refresh_token|id_token|session_token|session|jwt|private_key|ssn|social_security|tax_id|"
    r"national_id|passport|credit_card|card_number|cvv|iban|bank_account|routing_number|"
    r"date_of_birth|dob|email|phone|phone_number|address|street|first_name|last_name|full_name|"
    r"given_name|family_name)$"
)


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


# ── CORS misconfiguration ───────────────────────────────────────────────────────────────────────
# A benign origin no server has any reason to trust. `.invalid` is reserved (RFC 2606) and can never
# resolve, so an endpoint that echoes it back in Access-Control-Allow-Origin has *reflected* an
# arbitrary origin — the confirmation. A bare `*` is never treated as reflection.
CORS_PROBE_ORIGIN = "https://guardian-apisec-cors-probe.invalid"


def evaluate_cors(headers: dict, probe_origin: str = CORS_PROBE_ORIGIN) -> Verdict:
    """CORS on an API response, graded by what is actually exploitable.

    The response was produced by a request carrying `Origin: probe_origin`, an origin the server has
    no reason to allow. Only the credentialed combinations are HIGH — they let any website read this
    endpoint's authenticated responses in a victim's session. A plain wildcard with no credentials
    is intentional often enough that it is not reported here at all: reporting it is how a CORS
    check becomes noise on every public endpoint.
    """
    lowered = {str(k).lower(): str(v).strip() for k, v in (headers or {}).items()}
    if "access-control-allow-origin" not in lowered:
        return NO
    acao = lowered["access-control-allow-origin"]
    credentials = lowered.get("access-control-allow-credentials", "").lower() == "true"
    reflected = acao.rstrip("/") == probe_origin.rstrip("/")

    if reflected and credentials:
        return Verdict(
            True,
            "the endpoint reflected an arbitrary attacker Origin and allowed credentials — any "
            "site can read this endpoint's authenticated responses in a victim's session",
            "high",
            {"allow_origin": "reflected-probe-origin", "allow_credentials": True,
             "reflection_confirmed": True},
            severity="high",
        )
    if acao == "*" and credentials:
        return Verdict(
            True,
            "`Access-Control-Allow-Origin: *` is served with `Access-Control-Allow-Credentials: "
            "true` — invalid per the CORS spec, but stacks that honour it expose authenticated "
            "responses to every origin",
            "medium",
            {"allow_origin": "*", "allow_credentials": True},
            severity="high",
        )
    if reflected:
        return Verdict(
            True,
            "the endpoint reflected an arbitrary attacker Origin (credentials were not allowed) — "
            "its responses are readable cross-origin by any site",
            "medium",
            {"allow_origin": "reflected-probe-origin", "allow_credentials": False,
             "reflection_confirmed": True},
            severity="medium",
        )
    if acao.lower() == "null":
        return Verdict(
            True,
            "the endpoint returned `Access-Control-Allow-Origin: null`, which any sandboxed, "
            "null-origin document — a `data:` URI or a sandboxed iframe — can satisfy",
            "medium",
            {"allow_origin": "null", "allow_credentials": credentials},
            severity="medium",
        )
    # A plain wildcard with no credentials, or an ACAO that did not echo our probe origin (a real
    # allowlist), is not reported: the first is usually intended, the second is correct behaviour.
    return NO


# ── response transport / header hygiene ───────────────────────────────────────────────────────────
def _carries_private_data(body: str) -> bool:
    """Whether the response body contains a field whose *name* marks it as private (CWE-525)."""
    try:
        parsed = json.loads(body or "")
    except ValueError:
        return False

    def walk(node, depth: int = 0) -> bool:  # noqa: ANN001
        if depth > 8:
            return False
        if isinstance(node, dict):
            for key, value in node.items():
                if _PRIVATE_FIELDS.match(str(key)) and value not in (None, "", [], {}):
                    return True
                if walk(value, depth + 1):
                    return True
        elif isinstance(node, list):
            for item in node[:50]:
                if walk(item, depth + 1):
                    return True
        return False

    return walk(parsed)


def evaluate_response_hygiene(headers: dict, *, is_https: bool, body: str) -> list[Verdict]:
    """Passive transport/response hygiene over a response that was *already fetched*.

    Makes no request of its own — every input here comes from a response the caller already has.
    Each check is deliberately low-FP:

      * missing HSTS on an HTTPS response (a browser may be downgraded to HTTP) — MEDIUM;
      * a response carrying recognizable private fields that is cacheable, i.e. has no
        `Cache-Control: no-store` (private data may land in shared/browser caches) — MEDIUM;
      * a missing `X-Content-Type-Options: nosniff` (the browser may MIME-sniff the body) — LOW.

    Returns one Verdict per gap; the `evidence["rule"]` names which. Order is fixed for determinism.
    """
    lowered = {str(k).lower(): str(v).strip() for k, v in (headers or {}).items()}
    out: list[Verdict] = []

    if is_https and "strict-transport-security" not in lowered:
        out.append(Verdict(
            True,
            "the HTTPS response sets no `Strict-Transport-Security` header, so a browser is not "
            "told to refuse a later plaintext request to this API",
            "high", {"rule": "hsts"}, severity="medium"))

    if substantive(body) and _carries_private_data(body):
        cache = lowered.get("cache-control", "").lower()
        if "no-store" not in cache:
            out.append(Verdict(
                True,
                "the response returns private fields without `Cache-Control: no-store`, so that "
                "data may be written to shared proxy or browser caches",
                "high",
                {"rule": "cache", "cache_control": cache or "(absent)"}, severity="medium"))

    if lowered.get("x-content-type-options", "").lower() != "nosniff":
        out.append(Verdict(
            True,
            "the response sets no `X-Content-Type-Options: nosniff`, letting a browser MIME-sniff "
            "the body away from its declared content type",
            "high", {"rule": "content-type-options"}, severity="low"))

    return out


__all__ = [
    "CORS_PROBE_ORIGIN",
    "Verdict",
    "evaluate_bfla",
    "evaluate_bola",
    "evaluate_cors",
    "evaluate_exposure",
    "evaluate_response_hygiene",
    "evaluate_unauthenticated",
    "looks_like_denial",
    "substantive",
]
