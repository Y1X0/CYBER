"""The webhook envelope: where it may be sent, what it may carry, how it is signed (WP-G3).

Three things are load-bearing and each has failed in real products:

* **the destination.** A URL field that accepts `http://169.254.169.254/` turns the platform into a
  proxy for its own cloud metadata. The refusals below are the cheap half of that defence; the
  sender's connect-time pin is the other half and is proven over real sockets in
  `tests/integration/test_webhook_delivery.py`.
* **the payload.** An event travels to whatever a customer configured, often a shared chat channel.
  It carries identifiers and counts. A finding's excerpt — the field most likely to contain the
  credential the finding is *about* — must never leave in one.
* **the signature.** HMAC over the body alone verifies forever, so a captured delivery replays
  perfectly a year later. The timestamp has to be inside the signed material.
"""

from __future__ import annotations

import datetime as dt

import pytest
from guardian_core import webhooks as wh

SECRET = "whsec_" + "t" * 40
BODY = '{"id":"e1","type":"scan.completed"}'


# ── where Guardian will send ──────────────────────────────────────────────────────────────────────
def test_an_https_destination_is_accepted():
    assert wh.validate_url("https://hooks.example.com/guardian") == (
        "https://hooks.example.com/guardian"
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example.com/guardian",  # plaintext carries the payload in the clear
        "ftp://hooks.example.com/guardian",
        "file:///etc/passwd",
        "gopher://hooks.example.com/",
        "https://",
        "",
    ],
)
def test_a_non_https_or_hostless_destination_is_refused(url):
    with pytest.raises(wh.InvalidWebhookUrl):
        wh.validate_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost/hook",
        "https://LOCALHOST/hook",
        "https://127.0.0.1/hook",
        "https://[::1]/hook",
        "https://0.0.0.0/hook",  # noqa: S104 - a destination, not a bind address
        "https://api.localhost/hook",
    ],
)
def test_a_loopback_destination_is_refused(url):
    """Guardian's own localhost is not a customer's endpoint."""
    with pytest.raises(wh.InvalidWebhookUrl):
        wh.validate_url(url)


def test_inline_credentials_are_refused():
    """`user:pass@` lands in logs, and is also the oldest trick for making a host look like
    another one."""
    with pytest.raises(wh.InvalidWebhookUrl, match="inline credentials"):
        wh.validate_url("https://attacker.example.com:80@hooks.example.com/hook")


def test_an_absurdly_long_destination_is_refused():
    with pytest.raises(wh.InvalidWebhookUrl, match="too long"):
        wh.validate_url("https://hooks.example.com/" + "a" * 3000)


def test_the_refusal_says_which_rule_was_broken():
    """"Invalid URL" with no cause is a support ticket."""
    with pytest.raises(wh.InvalidWebhookUrl, match="https"):
        wh.validate_url("http://hooks.example.com/hook")


# ── the secret ────────────────────────────────────────────────────────────────────────────────────
def test_secrets_are_prefixed_and_unique():
    first, second = wh.new_secret(), wh.new_secret()
    assert first.startswith("whsec_")
    assert first != second
    assert len(first) > 30


# ── the signature ─────────────────────────────────────────────────────────────────────────────────
def test_a_signature_verifies_against_the_body_it_was_made_for():
    now = 1_700_000_000
    header = wh.sign(BODY, secret=SECRET, timestamp=now)

    assert header.startswith(f"t={now},v1=")
    assert wh.verify(BODY, header, secret=SECRET, now=now)


def test_a_tampered_body_does_not_verify():
    now = 1_700_000_000
    header = wh.sign(BODY, secret=SECRET, timestamp=now)

    assert not wh.verify(BODY.replace("scan.completed", "scan.failed"), header,
                         secret=SECRET, now=now)


def test_another_secret_does_not_verify():
    now = 1_700_000_000
    header = wh.sign(BODY, secret=SECRET, timestamp=now)

    assert not wh.verify(BODY, header, secret="whsec_" + "u" * 40, now=now)


def test_a_replayed_delivery_is_refused_even_though_the_digest_is_correct():
    """The point of putting the timestamp inside the signed material. A signature that verifies is
    otherwise only evidence the payload came from Guardian *at some point*."""
    signed_at = 1_700_000_000
    header = wh.sign(BODY, secret=SECRET, timestamp=signed_at)

    assert wh.verify(BODY, header, secret=SECRET, now=signed_at + 10)
    assert not wh.verify(BODY, header, secret=SECRET,
                         now=signed_at + wh.REPLAY_WINDOW_SECONDS + 1)


def test_a_future_timestamp_outside_the_window_is_refused():
    """Skew is bounded in both directions — a far-future timestamp would otherwise keep a captured
    delivery valid until it arrives."""
    signed_at = 1_700_000_000
    header = wh.sign(BODY, secret=SECRET, timestamp=signed_at)

    assert not wh.verify(BODY, header, secret=SECRET,
                         now=signed_at - wh.REPLAY_WINDOW_SECONDS - 1)


def test_moving_the_timestamp_breaks_the_signature():
    """A receiver that trusted `t=` without re-deriving the digest would accept this."""
    signed_at = 1_700_000_000
    header = wh.sign(BODY, secret=SECRET, timestamp=signed_at)
    forged = header.replace(f"t={signed_at}", f"t={signed_at + 5}")

    assert not wh.verify(BODY, forged, secret=SECRET, now=signed_at + 5)


@pytest.mark.parametrize("header", ["", "garbage", "t=,v1=abc", "t=abc,v1=abc", "v1=abc",
                                    "t=1700000000"])
def test_a_malformed_signature_header_is_refused_rather_than_raising(header):
    assert not wh.verify(BODY, header, secret=SECRET, now=1_700_000_000)


# ── what may leave ────────────────────────────────────────────────────────────────────────────────
def test_evidence_never_leaves_in_an_event():
    payload, _ = wh.sanitize({
        "finding_id": "f-1", "severity": "critical", "title": "Hardcoded credential",
        "evidence": {"excerpt": "AWS_SECRET_ACCESS_KEY=..."},
        "excerpt": "line 41: password = hunter2",
        "match": "hunter2", "raw": "…", "secret": "…", "token": "…",
    })

    assert payload["finding_id"] == "f-1"
    assert payload["severity"] == "critical"
    assert payload["title"] == "Hardcoded credential"
    for dropped in ("evidence", "excerpt", "match", "raw", "secret", "token"):
        assert dropped not in payload


def test_a_credential_that_survives_the_field_filter_is_still_masked():
    """Defence in depth: a credential in an unexpected field is a bug upstream, and this is the
    boundary — the same reasoning as the findings API in WP-F2."""
    leaked = "AKIA" + "IOSFODNN7EXAMPLE"
    payload, redacted = wh.sanitize({"summary": f"found {leaked} in config", "count": 3})

    assert leaked not in str(payload)
    assert redacted
    assert payload["count"] == 3


def test_a_clean_payload_reports_nothing_redacted():
    payload, redacted = wh.sanitize({"scan_id": "s-1", "findings": 4})
    assert redacted == []
    assert payload == {"scan_id": "s-1", "findings": 4}


def test_sanitize_tolerates_an_empty_payload():
    assert wh.sanitize({}) == ({}, [])
    assert wh.sanitize(None) == ({}, [])


# ── the envelope ──────────────────────────────────────────────────────────────────────────────────
def test_the_body_is_deterministic_so_the_signature_is_reproducible():
    """A receiver re-signs the exact bytes it received; the sender must not reorder keys between
    the signing and the send."""
    event = wh.Event(id="e1", type="scan.completed",
                     occurred_at=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
                     tenant_id="t1", data={"b": 2, "a": 1})

    assert event.body() == event.body()
    assert event.body().index('"a"') < event.body().index('"b"')
    assert " " not in event.body().replace("scan.completed", "x")


def test_the_headers_carry_the_event_type_and_delivery_id():
    event = wh.Event(id="e1", type="finding.critical",
                     occurred_at=dt.datetime(2026, 1, 1, tzinfo=dt.UTC), tenant_id="t1")
    sent = wh.headers(event, signature="t=1,v1=deadbeef", delivery_id="d-1")

    assert sent[wh.EVENT_HEADER] == "finding.critical"
    assert sent[wh.DELIVERY_HEADER] == "d-1"
    assert sent[wh.SIGNATURE_HEADER] == "t=1,v1=deadbeef"
    assert sent["content-type"] == "application/json"


def test_the_event_set_is_closed():
    """An endpoint that receives an event it has never heard of cannot decide whether to act."""
    assert "scan.completed" in wh.EVENTS
    assert "finding.critical" in wh.EVENTS
    assert len(set(wh.EVENTS)) == len(wh.EVENTS)


# ── retries ───────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (200, False), (204, False),
        (400, False), (401, False), (403, False), (404, False), (422, False),
        (408, True), (429, True),
        (500, True), (502, True), (503, True),
        (0, True),  # connection failure — the one case where trying again is the whole point
    ],
)
def test_only_failures_that_could_differ_next_time_are_retried(status, expected):
    """Retrying a 4xx is how a customer's misconfigured endpoint gets a denial of service from its
    own vendor: it will fail identically every time."""
    assert wh.should_retry(status, attempt=1) is expected


def test_retries_are_bounded():
    assert wh.should_retry(500, attempt=wh.MAX_ATTEMPTS - 1) is True
    assert wh.should_retry(500, attempt=wh.MAX_ATTEMPTS) is False
    assert wh.should_retry(0, attempt=wh.MAX_ATTEMPTS) is False


def test_the_backoff_grows_and_then_stops_growing():
    delays = [wh.retry_delay(n) for n in range(1, wh.MAX_ATTEMPTS + 2)]
    assert delays[0] < delays[1] < delays[2]
    assert delays[2] == delays[3]  # clamped, never an unbounded wait
    assert wh.retry_delay(0) == wh.RETRY_DELAYS_SECONDS[0]
