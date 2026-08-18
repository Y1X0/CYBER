"""Outbound webhooks: the envelope, the signature, and what may be sent (WP-G3).

A webhook is Guardian making an HTTP request to an address a customer typed into a form, carrying
things Guardian knows about their security posture. Both halves of that sentence are the risk.

**The address is attacker-influenced.** A URL field that accepts `http://169.254.169.254/` turns the
platform into a proxy for its own cloud metadata; one that accepts `http://10.0.0.5:6379/` turns it
into a port scanner with credentials. So the URL is validated here before anything is stored, and
pinned to a validated public address at connect time by the sender.

**The payload is the customer's security posture.** An event says which of their systems is broken
and how. It travels to an endpoint that may be a shared chat integration, so it carries identifiers
and counts — never evidence, never a credential, never the contents of a finding's excerpt.

The signature is what makes the receiver able to trust any of it: HMAC-SHA256 over `timestamp.body`,
so a replayed body with an old timestamp fails the freshness check even though the digest is
correct. Signing the body alone is the mistake that makes a webhook replayable forever.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlparse

from guardian_core.redaction import scrub

SIGNATURE_HEADER = "X-Guardian-Signature"
TIMESTAMP_HEADER = "X-Guardian-Timestamp"
EVENT_HEADER = "X-Guardian-Event"
DELIVERY_HEADER = "X-Guardian-Delivery"

# How far apart the sender's and receiver's clocks may be before a delivery is refused as a replay.
REPLAY_WINDOW_SECONDS = 300
SECRET_BYTES = 32
MAX_BODY_BYTES = 64_000

# The events a customer may subscribe to. A closed set: an endpoint that receives an event it has
# never heard of cannot decide whether to act on it.
EVENTS = (
    "scan.completed",
    "scan.failed",
    "finding.critical",
    "finding.reopened",
    "remediation.overdue",
    "ownership.verified",
    "compliance.control_failed",
)

# Retries: 1 minute, 5, 25 — bounded, and never for a 4xx. A client error will fail identically on
# every retry, and retrying it is how a misconfigured endpoint gets a denial of service from its
# own vendor.
RETRY_DELAYS_SECONDS = (60, 300, 1500)
MAX_ATTEMPTS = len(RETRY_DELAYS_SECONDS) + 1


class InvalidWebhookUrl(ValueError):
    """The URL is not one Guardian will send to."""


def validate_url(url: str) -> str:
    """Normalize a destination, or refuse it.

    Refusals here are the cheap half of SSRF defence — the sender still pins to a validated public
    address at connect time, because a hostname that resolves privately looks exactly like one that
    does not until it is resolved.
    """
    text = (url or "").strip()
    parsed = urlparse(text)
    if parsed.scheme != "https":
        # Plaintext would carry the signature and the payload across the network in the clear, and
        # the signature is only useful to a receiver who can trust it arrived unmodified.
        raise InvalidWebhookUrl("a webhook destination must be https")
    if not parsed.hostname:
        raise InvalidWebhookUrl("the destination has no host")
    if parsed.username or parsed.password:
        # Credentials in a URL end up in logs, and a `user:pass@` prefix is also the oldest trick
        # for making a host look like a different one.
        raise InvalidWebhookUrl("a webhook destination must not carry inline credentials")
    host = parsed.hostname.lower()
    # `0.0.0.0` is in the refusal list, not a bind address: a destination, not a listener.
    loopback = ("localhost", "127.0.0.1", "::1", "0.0.0.0")  # noqa: S104
    if host in loopback or host.endswith(".localhost"):
        raise InvalidWebhookUrl("a webhook destination must not be loopback")
    if len(text) > 2000:
        raise InvalidWebhookUrl("the destination is too long")
    return text


def new_secret() -> str:
    """A signing secret. Returned once; only its digest is useful to Guardian afterwards."""
    return f"whsec_{secrets.token_urlsafe(SECRET_BYTES)}"


@dataclass(frozen=True)
class Event:
    """One thing that happened, in the shape a receiver parses."""

    id: str
    type: str
    occurred_at: dt.datetime
    tenant_id: str
    customer_id: str | None = None
    data: dict = field(default_factory=dict)

    def body(self) -> str:
        payload = {
            "id": self.id,
            "type": self.type,
            "occurred_at": self.occurred_at.isoformat(),
            "tenant_id": self.tenant_id,
            "customer_id": self.customer_id,
            "data": self.data,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def sanitize(data: dict) -> tuple[dict, list[str]]:
    """What may leave in an event payload.

    Identifiers, counts, severities and titles — the things a receiver needs to decide whether to
    page somebody. Never evidence: the destination is often a shared chat channel, and a finding's
    excerpt is the one field most likely to contain the credential the finding is about.
    """
    stripped = {k: v for k, v in (data or {}).items()
                if k not in ("evidence", "excerpt", "match", "secret", "token", "raw")}
    return scrub(stripped)


def sign(body: str, *, secret: str, timestamp: int) -> str:
    """`t=<unix>,v1=<hex>` over `timestamp.body`.

    The timestamp is inside the signed material, not merely alongside it. Signing the body alone
    produces a signature that stays valid forever, so a captured delivery can be replayed at any
    time and verifies perfectly.
    """
    signed = f"{timestamp}.{body}".encode()
    digest = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


def verify(body: str, header: str, *, secret: str, now: int,
           window: int = REPLAY_WINDOW_SECONDS) -> bool:
    """The check a receiver performs. Shipped so a customer's implementation matches the sender's.

    Constant-time comparison, and the freshness check is not optional: a signature that verifies is
    only evidence the payload came from Guardian *at some point*.
    """
    parts = dict(
        piece.split("=", 1) for piece in (header or "").split(",") if "=" in piece
    )
    try:
        timestamp = int(parts.get("t", ""))
    except ValueError:
        return False
    if abs(now - timestamp) > window:
        return False
    expected = hmac.new(secret.encode(), f"{timestamp}.{body}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts.get("v1", ""))


def should_retry(status: int, *, attempt: int) -> bool:
    """Whether a failed delivery is worth trying again.

    Never a 4xx other than 408/429: a client error fails identically every time, and retrying it is
    how a customer's misconfigured endpoint receives a denial of service from its own vendor.
    """
    if attempt >= MAX_ATTEMPTS:
        return False
    if status == 0:  # connection failure — the one case where trying again is the whole point
        return True
    if 200 <= status < 300:
        return False
    if 400 <= status < 500:
        return status in (408, 429)
    return True


def retry_delay(attempt: int) -> int:
    index = min(max(attempt - 1, 0), len(RETRY_DELAYS_SECONDS) - 1)
    return RETRY_DELAYS_SECONDS[index]


def headers(event: Event, *, signature: str, delivery_id: str) -> dict:
    return {
        "content-type": "application/json",
        "user-agent": "guardian-webhooks/1",
        EVENT_HEADER: event.type,
        DELIVERY_HEADER: delivery_id,
        SIGNATURE_HEADER: signature,
        TIMESTAMP_HEADER: str(int(event.occurred_at.timestamp())),
    }


__all__ = [
    "DELIVERY_HEADER",
    "EVENTS",
    "EVENT_HEADER",
    "MAX_ATTEMPTS",
    "MAX_BODY_BYTES",
    "REPLAY_WINDOW_SECONDS",
    "RETRY_DELAYS_SECONDS",
    "SIGNATURE_HEADER",
    "TIMESTAMP_HEADER",
    "Event",
    "InvalidWebhookUrl",
    "headers",
    "new_secret",
    "retry_delay",
    "sanitize",
    "should_retry",
    "sign",
    "validate_url",
    "verify",
]
