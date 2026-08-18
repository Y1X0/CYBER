"""Proving a customer owns a domain (WP-F1).

`Authorization.method` has always had a value `ownership_verified`, and nothing verified ownership —
a human asserted it and the platform believed them. This is the control standing between a customer
and an active scan of somebody else's domain, and it was a checkbox.

Two challenges, both of which only the domain's controller can satisfy:

* **DNS TXT** at `_guardian-challenge.<domain>`. Requires control of the zone.
* **HTTP file** at `https://<domain>/.well-known/guardian-verification.txt`. Requires control of
  what the domain serves.

This module is pure: it generates tokens, says where to look, and decides whether what was found
counts. The looking happens in the worker, behind the same egress discipline as every other outward
request. Keeping the decision here means the rule that "a redirect does not prove ownership" is
written once and tested without a network.

The scope rule is the part most easily got wrong. Verifying `example.com` authorizes it **and its
subdomains** — the zone's controller can create any of them. Verifying `app.example.com` authorizes
that name and *its* subdomains, and **not** `example.com`: whoever runs one host in a zone is not
necessarily its owner, and a shared-hosting customer must not be able to claim the apex.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

# A label, not a credential: it prefixes the published challenge so a customer can recognize
# which vendor a TXT record belongs to.
TOKEN_PREFIX = "guardian-site-verification"  # noqa: S105
TOKEN_BYTES = 24
DNS_LABEL = "_guardian-challenge"
HTTP_PATH = "/.well-known/guardian-verification.txt"
DEFAULT_VALIDITY_DAYS = 365
MAX_ATTEMPTS = 50

_DOMAIN_RE = re.compile(
    r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


class InvalidDomain(ValueError):
    """The value is not a domain name this system will accept."""


def normalize_domain(value: str) -> str:
    """Canonical form, or raise.

    Accepting `HTTPS://Example.COM./path` and storing it verbatim would mean the authorization
    check compares two spellings of one domain and finds them different — which fails open or
    closed depending on which side is wrong, and neither is acceptable for this control.
    """
    text = (value or "").strip().lower()
    text = re.sub(r"^[a-z]+://", "", text)
    text = text.split("/", 1)[0].split("?", 1)[0]
    text = text.split("@")[-1]
    text = text.split(":")[0]
    text = text.rstrip(".")
    if not text or len(text) > 253 or not _DOMAIN_RE.match(text):
        raise InvalidDomain(f"{value!r} is not a valid domain name")
    return text


def new_token() -> str:
    """A fresh challenge token.

    High entropy and unique per verification, so a token published for one customer's domain cannot
    be replayed to claim another's.
    """
    return f"{TOKEN_PREFIX}={secrets.token_urlsafe(TOKEN_BYTES)}"


def dns_record_name(domain: str) -> str:
    return f"{DNS_LABEL}.{normalize_domain(domain)}"


def http_challenge_url(domain: str) -> str:
    return f"https://{normalize_domain(domain)}{HTTP_PATH}"


def instructions(domain: str, method: str, token: str) -> dict:
    """What to tell the customer to publish."""
    domain = normalize_domain(domain)
    if method == "dns_txt":
        return {
            "method": "dns_txt",
            "record_type": "TXT",
            "record_name": dns_record_name(domain),
            "record_value": token,
            "note": "Publish this TXT record, then ask Guardian to check. DNS changes can take "
                    "up to an hour to become visible.",
        }
    if method == "http_file":
        return {
            "method": "http_file",
            "url": http_challenge_url(domain),
            "content": token,
            "note": "Serve this exact content at this exact URL over HTTPS. Guardian will not "
                    "follow a redirect: a redirect proves the redirect target's owner published "
                    "something, not this domain's owner.",
        }
    raise ValueError(f"unknown verification method: {method!r}")


@dataclass(frozen=True)
class CheckResult:
    verified: bool
    reason: str
    observed: tuple[str, ...] = ()


def evaluate_dns(token: str, records: list[str] | tuple[str, ...] | None) -> CheckResult:
    """Whether a TXT lookup proves ownership.

    A zone often carries several verification records from several vendors, so the token has to be
    found among them rather than being the only one — but it must be found *exactly*. Accepting a
    record that merely contains the token as a substring would let anyone who can add any TXT record
    to a shared zone append someone else's token to their own value.
    """
    if records is None:
        return CheckResult(False, "the TXT record was not found")
    values = tuple(str(r).strip().strip('"') for r in records if str(r).strip())
    if not values:
        return CheckResult(False, "the TXT record was empty")
    if token in values:
        return CheckResult(True, "the expected TXT record is published", observed=values[:10])
    return CheckResult(
        False,
        f"the expected token was not among the {len(values)} TXT record(s) published",
        observed=values[:10],
    )


def evaluate_http(token: str, *, status: int, body: str, final_url: str,
                  expected_url: str) -> CheckResult:
    """Whether an HTTP fetch proves ownership.

    Redirects are refused outright. If `example.com` redirects to a host the requester controls,
    following it would let them publish the token on their own site and be credited with owning
    `example.com` — which is the entire attack this control exists to prevent.
    """
    if final_url.rstrip("/") != expected_url.rstrip("/"):
        return CheckResult(
            False,
            "the request was redirected; a redirect proves the redirect target's owner published "
            f"something, not this domain's owner (ended at {final_url[:120]})",
        )
    if status != 200:
        return CheckResult(False, f"the challenge file returned HTTP {status}")
    content = (body or "").strip()
    if not content:
        return CheckResult(False, "the challenge file was empty")
    # The file must contain the token and nothing else of substance. A page that happens to
    # include the token — a paste site, a forum thread, an error page echoing the URL — is not a
    # statement by the domain's owner.
    if content == token:
        return CheckResult(True, "the challenge file contains exactly the expected token")
    if len(content) <= len(token) + 8 and token in content:
        return CheckResult(True, "the challenge file contains the expected token")
    return CheckResult(
        False,
        "the challenge file did not contain exactly the expected token",
        observed=(content[:120],),
    )


def authorizes(verified_domain: str, target: str) -> bool:
    """Whether a proof of `verified_domain` covers `target`.

    Downward only. Whoever controls a zone can create any name inside it, so verifying
    `example.com` covers `app.example.com`. The reverse does not hold: control of one host in a
    zone is not control of the zone, and a shared-hosting customer must not be able to claim the
    apex — or, through it, every other tenant on it.
    """
    try:
        verified = normalize_domain(verified_domain)
        candidate = normalize_domain(target)
    except InvalidDomain:
        return False
    return candidate == verified or candidate.endswith("." + verified)
