"""Sending a webhook, over real sockets, against the live database (WP-G3).

`tests/test_webhooks.py` fixes the rules on constructed strings. What this file proves is the part a
customer depends on: a delivery leaves Guardian over TCP, arrives with a signature the receiver can
verify with the secret it was given, and the bookkeeping afterwards tells the truth about what
happened.

The receiver is a local HTTP server built for the purpose. Nothing here contacts a public endpoint.

Two things about the egress pin, stated plainly rather than glossed:

* the pin refuses loopback, which is correct and is proven live in
  `test_the_transport_refuses_a_loopback_destination` below (and exhaustively in
  `tests/test_dast_ssrf.py`);
* to exercise the *rest* of the transport — the redirect refusal, the bounded body read, the error
  capture — against a real server, `loopback_allowed` substitutes the address validator for one
  that permits `127.0.0.1` and delegates everything else to the real one. The pin machinery itself
  still runs. The transport is not modified and no test asserts a weakened rule.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import contextlib
import http.server
import json
import os
import threading
import time
import uuid

import pytest
from guardian_core import webhooks as wh

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

METADATA_URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"


# ── the receiver ──────────────────────────────────────────────────────────────────────────────────
class _Receiver(http.server.BaseHTTPRequestHandler):
    """A customer's endpoint: one that works, one that is broken, one that is hostile."""

    received: list[dict] = []

    def log_message(self, *_args) -> None:  # noqa: ANN002 - silence the test server
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length).decode()
        type(self).received.append({
            "path": self.path,
            "body": body,
            "headers": {k.lower(): v for k, v in self.headers.items()},
        })

        if self.path == "/hook":
            status, headers, payload = 200, {}, "ok"
        elif self.path == "/boom":
            status, headers, payload = 500, {}, "internal error"
        elif self.path == "/nope":
            status, headers, payload = 400, {}, "I do not want this"
        elif self.path == "/redirect":
            # The reason redirects are refused rather than followed: a signed request to Guardian's
            # own metadata service, with a header the receiver could prove came from Guardian.
            status, headers, payload = 302, {"Location": METADATA_URL}, ""
        elif self.path == "/chatty":
            status, headers, payload = 200, {}, "x" * 50_000
        else:
            status, headers, payload = 404, {}, "no such hook"

        encoded = payload.encode()
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


@pytest.fixture()
def receiver():
    _Receiver.received = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture()
def loopback_allowed(monkeypatch):
    """Let the pin validate the local fixture, and nothing else.

    The pin still runs on every connect; only the address validator's verdict for `127.0.0.1` is
    substituted. Every other host goes through the real validator unchanged.
    """
    from guardian_scanner import sandbox

    real = sandbox._resolve_public_address

    def resolve(host, port):  # noqa: ANN001, ANN202
        if host == "127.0.0.1":
            return "127.0.0.1"
        return real(host, port)

    monkeypatch.setattr(sandbox, "_resolve_public_address", resolve)


# ── the estate ────────────────────────────────────────────────────────────────────────────────────
def _tenant():
    from guardian_db.models import Customer, Tenant, TenantMembership, User
    from guardian_db.session import session_scope

    slug = f"g3-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        user = User(email=f"o-{slug}@x.invalid", name="Owner", status="active")
        db.add_all([customer, user])
        db.flush()
        db.add(TenantMembership(user_id=user.id, tenant_id=tenant.id, role="owner"))
        db.flush()
        return {"tenant": tenant.id, "customer": customer.id, "user": user.id, "slug": slug}


def _endpoint(ctx, url, events=("scan.completed",), *, enabled=True, customer_scoped=False):
    """Insert an endpoint directly.

    The API refuses a loopback destination — correctly, and that refusal is tested in
    `tests/test_webhooks.py`. Testing the *sender* against a local server means putting the row in
    directly rather than weakening the rule that keeps it out.
    """
    from guardian_db.models import WebhookEndpoint
    from guardian_db.session import session_scope

    with session_scope() as db:
        row = WebhookEndpoint(
            tenant_id=ctx["tenant"],
            customer_id=ctx["customer"] if customer_scoped else None,
            url=url, description="test", events=list(events), secret=wh.new_secret(),
            enabled=enabled, created_by=ctx["user"],
        )
        db.add(row)
        db.flush()
        return {"id": row.id, "secret": row.secret}


def _enqueue(ctx, event_type="scan.completed", data=None, customer_id=None):
    from guardian_db.session import session_scope
    from guardian_scanner.webhooks import enqueue

    with session_scope() as db:
        return enqueue(db, tenant_id=ctx["tenant"], event_type=event_type,
                       data=data or {"scan_id": "s-1", "findings": 3},
                       customer_id=customer_id)


def _delivery(delivery_id):
    from guardian_db.models import WebhookDelivery
    from guardian_db.session import session_scope

    with session_scope() as db:
        row = db.get(WebhookDelivery, delivery_id)
        return {"status": row.status, "attempts": row.attempts, "error": row.error,
                "response_status": row.response_status, "payload": row.payload,
                "next_attempt_at": row.next_attempt_at, "delivered_at": row.delivered_at,
                "event_id": row.event_id}


def _endpoint_state(endpoint_id):
    from guardian_db.models import WebhookEndpoint
    from guardian_db.session import session_scope

    with session_scope() as db:
        row = db.get(WebhookEndpoint, endpoint_id)
        return {"enabled": row.enabled, "failures": row.consecutive_failures,
                "disabled_reason": row.disabled_reason, "last_success_at": row.last_success_at}


def _deliver(delivery_id):
    from guardian_scanner.webhooks import deliver_webhook

    return deliver_webhook(str(delivery_id))


# ── queueing ──────────────────────────────────────────────────────────────────────────────────────
def test_only_endpoints_that_subscribed_are_queued():
    """An endpoint subscribed to nothing receives nothing: subscribing to everything has to be an
    explicit choice, never the effect of leaving a field blank."""
    ctx = _tenant()
    wanted = _endpoint(ctx, "https://a.example.com/hook", events=("scan.completed",))
    _endpoint(ctx, "https://b.example.com/hook", events=("finding.critical",))
    _endpoint(ctx, "https://c.example.com/hook", events=())

    ids = _enqueue(ctx, "scan.completed")

    assert len(ids) == 1
    from guardian_db.models import WebhookDelivery
    from guardian_db.session import session_scope
    with session_scope() as db:
        assert db.get(WebhookDelivery, ids[0]).endpoint_id == wanted["id"]


def test_a_disabled_endpoint_is_not_queued():
    ctx = _tenant()
    _endpoint(ctx, "https://a.example.com/hook", enabled=False)
    assert _enqueue(ctx) == []


def test_another_tenants_endpoint_is_never_queued():
    ctx, other = _tenant(), _tenant()
    _endpoint(other, "https://other.example.com/hook")
    assert _enqueue(ctx) == []


def test_an_unknown_event_is_refused_rather_than_queued_unlabelled():
    ctx = _tenant()
    _endpoint(ctx, "https://a.example.com/hook")
    with pytest.raises(ValueError, match="unknown webhook event"):
        _enqueue(ctx, "scan.exploded")


def test_a_customer_scoped_endpoint_only_receives_its_own_customers_events():
    ctx = _tenant()
    _endpoint(ctx, "https://a.example.com/hook", customer_scoped=True)

    assert _enqueue(ctx, customer_id=uuid.uuid4()) == []
    assert len(_enqueue(ctx, customer_id=ctx["customer"])) == 1


def test_evidence_never_reaches_the_queued_payload():
    """The payload is stored and then sent; if evidence survived into the row it would leave."""
    ctx = _tenant()
    _endpoint(ctx, "https://a.example.com/hook")
    leaked = "AKIA" + "IOSFODNN7EXAMPLE"

    ids = _enqueue(ctx, data={"scan_id": "s-1", "evidence": {"excerpt": leaked},
                              "summary": f"key {leaked} in config"})

    payload = _delivery(ids[0])["payload"]
    assert leaked not in payload
    assert "evidence" not in payload
    assert "s-1" in payload


# ── delivery, over real sockets ───────────────────────────────────────────────────────────────────
def test_a_delivery_arrives_and_its_signature_verifies_with_the_stored_secret(
    receiver, loopback_allowed
):
    ctx = _tenant()
    endpoint = _endpoint(ctx, f"{receiver}/hook")
    (delivery_id,) = _enqueue(ctx)

    result = _deliver(delivery_id)

    assert result["status"] == "delivered"
    assert len(_Receiver.received) == 1
    request = _Receiver.received[0]
    signature = request["headers"][wh.SIGNATURE_HEADER.lower()]
    assert wh.verify(request["body"], signature, secret=endpoint["secret"],
                     now=int(time.time()))
    assert request["headers"][wh.EVENT_HEADER.lower()] == "scan.completed"
    assert request["headers"][wh.DELIVERY_HEADER.lower()] == str(delivery_id)
    assert json.loads(request["body"])["data"]["scan_id"] == "s-1"


def test_the_signature_is_over_the_exact_bytes_that_were_recorded(receiver, loopback_allowed):
    """The stored payload is what settles "the signature did not verify" — it has to be the bytes
    that were actually signed, not a re-serialization of them."""
    ctx = _tenant()
    _endpoint(ctx, f"{receiver}/hook")
    (delivery_id,) = _enqueue(ctx)
    _deliver(delivery_id)

    assert _Receiver.received[0]["body"] == _delivery(delivery_id)["payload"]


def test_another_endpoints_secret_does_not_verify_the_delivery(receiver, loopback_allowed):
    ctx = _tenant()
    _endpoint(ctx, f"{receiver}/hook")
    stranger = _endpoint(ctx, "https://b.example.com/hook", events=("finding.critical",))
    (delivery_id,) = _enqueue(ctx)
    _deliver(delivery_id)

    request = _Receiver.received[0]
    assert not wh.verify(request["body"], request["headers"][wh.SIGNATURE_HEADER.lower()],
                         secret=stranger["secret"], now=int(time.time()))


def test_a_success_records_the_delivery_and_clears_the_failure_count(receiver, loopback_allowed):
    ctx = _tenant()
    endpoint = _endpoint(ctx, f"{receiver}/hook")
    (delivery_id,) = _enqueue(ctx)
    _deliver(delivery_id)

    row = _delivery(delivery_id)
    assert row["status"] == "delivered"
    assert row["response_status"] == 200
    assert row["delivered_at"] is not None
    assert row["next_attempt_at"] is None
    assert row["error"] is None

    state = _endpoint_state(endpoint["id"])
    assert state["failures"] == 0
    assert state["last_success_at"] is not None


def test_a_delivered_delivery_is_not_sent_twice(receiver, loopback_allowed):
    ctx = _tenant()
    _endpoint(ctx, f"{receiver}/hook")
    (delivery_id,) = _enqueue(ctx)
    _deliver(delivery_id)
    _deliver(delivery_id)

    assert len(_Receiver.received) == 1


# ── failures ──────────────────────────────────────────────────────────────────────────────────────
def test_a_server_error_schedules_a_retry_and_says_what_came_back(receiver, loopback_allowed):
    ctx = _tenant()
    _endpoint(ctx, f"{receiver}/boom")
    (delivery_id,) = _enqueue(ctx)

    _deliver(delivery_id)

    row = _delivery(delivery_id)
    assert row["status"] == "pending"
    assert row["response_status"] == 500
    assert "internal error" in row["error"]
    assert row["next_attempt_at"] is not None


def test_a_client_error_is_not_retried(receiver, loopback_allowed):
    """A 400 fails identically every time; retrying it is how a misconfigured endpoint gets a denial
    of service from its own vendor."""
    ctx = _tenant()
    _endpoint(ctx, f"{receiver}/nope")
    (delivery_id,) = _enqueue(ctx)

    _deliver(delivery_id)

    row = _delivery(delivery_id)
    assert row["status"] == "failed"
    assert row["response_status"] == 400
    assert row["next_attempt_at"] is None
    assert "I do not want this" in row["error"]


def test_retries_are_bounded_and_the_failure_is_final(receiver, loopback_allowed):
    ctx = _tenant()
    _endpoint(ctx, f"{receiver}/boom")
    (delivery_id,) = _enqueue(ctx)

    for _ in range(wh.MAX_ATTEMPTS):
        _deliver(delivery_id)

    row = _delivery(delivery_id)
    assert row["attempts"] == wh.MAX_ATTEMPTS
    assert row["status"] == "failed"
    assert row["next_attempt_at"] is None


def test_an_unreachable_endpoint_records_the_real_cause(loopback_allowed):
    """A connection failure is a delivery failure with a name, not a silent zero."""
    ctx = _tenant()
    # Port 1 on loopback: nothing listens, and the pin lets 127.0.0.1 through under this fixture.
    _endpoint(ctx, "http://127.0.0.1:1/hook")
    (delivery_id,) = _enqueue(ctx)

    _deliver(delivery_id)

    row = _delivery(delivery_id)
    assert row["response_status"] == 0
    assert row["error"]
    assert row["status"] == "pending"  # worth trying again — the one case where it is


def test_repeated_failures_disable_the_endpoint_with_a_stated_reason(receiver, loopback_allowed):
    """A dead endpoint retried forever is a slow outbound flood at somebody not listening."""
    from guardian_db.models import WebhookEndpoint
    from guardian_db.session import session_scope
    from guardian_scanner.webhooks import MAX_CONSECUTIVE_FAILURES

    ctx = _tenant()
    endpoint = _endpoint(ctx, f"{receiver}/boom")
    with session_scope() as db:
        db.get(WebhookEndpoint, endpoint["id"]).consecutive_failures = (
            MAX_CONSECUTIVE_FAILURES - 1
        )

    (delivery_id,) = _enqueue(ctx)
    _deliver(delivery_id)

    state = _endpoint_state(endpoint["id"])
    assert state["enabled"] is False
    assert "consecutive failures" in state["disabled_reason"]
    assert "500" in state["disabled_reason"]


def test_a_delivery_to_a_disabled_endpoint_is_dropped_with_a_reason(receiver, loopback_allowed):
    """Not silently discarded: "we never got the alert" needs an answer."""
    from guardian_db.models import WebhookEndpoint
    from guardian_db.session import session_scope

    ctx = _tenant()
    endpoint = _endpoint(ctx, f"{receiver}/hook")
    (delivery_id,) = _enqueue(ctx)
    with session_scope() as db:
        db.get(WebhookEndpoint, endpoint["id"]).enabled = False

    _deliver(delivery_id)

    row = _delivery(delivery_id)
    assert row["status"] == "dropped"
    assert "removed or disabled" in row["error"]
    assert _Receiver.received == []


# ── egress ────────────────────────────────────────────────────────────────────────────────────────
def test_a_redirect_is_refused_rather_than_followed(receiver, loopback_allowed):
    """A customer endpoint answering `302 Location: 169.254.169.254` would otherwise have Guardian
    fetch its own cloud credentials — carrying a signature the receiver can prove came from
    Guardian."""
    ctx = _tenant()
    _endpoint(ctx, f"{receiver}/redirect")
    (delivery_id,) = _enqueue(ctx)

    _deliver(delivery_id)

    row = _delivery(delivery_id)
    assert row["response_status"] == 302
    assert "refused to follow a redirect" in row["error"]
    assert "169.254.169.254" in row["error"]
    # One request was made: the redirect target was never contacted.
    assert len(_Receiver.received) == 1


def test_the_transport_refuses_a_loopback_destination(receiver):
    """No `loopback_allowed` fixture here: this is the pin doing its actual job.

    An endpoint whose host resolves inside Guardian's own network is refused at connect time, and
    the refusal is reported rather than swallowed.
    """
    from guardian_scanner.webhooks import _transport

    status, detail = _transport()(f"{receiver}/hook", "{}", {})

    assert status == 0
    # httpx wraps the pin's PermissionError, but the reason survives into the recorded error.
    assert "denied" in detail
    assert "internal address" in detail
    assert _Receiver.received == []


def test_a_large_response_body_does_not_become_the_error_message(receiver, loopback_allowed):
    """A receiver that answers with 50KB of HTML must not put 50KB into the delivery row."""
    ctx = _tenant()
    _endpoint(ctx, f"{receiver}/chatty")
    (delivery_id,) = _enqueue(ctx)

    _deliver(delivery_id)

    assert _delivery(delivery_id)["status"] == "delivered"


# ── the retry sweep ───────────────────────────────────────────────────────────────────────────────
def test_the_sweep_dispatches_only_deliveries_whose_backoff_has_elapsed(monkeypatch):
    """The selection query is the logic under test; dispatch is stubbed so this needs no broker."""
    import datetime as dt

    from guardian_db.models import WebhookDelivery
    from guardian_db.session import session_scope
    from guardian_scanner import webhooks as sender

    ctx = _tenant()
    _endpoint(ctx, "https://a.example.com/hook")
    due, later, done = (_enqueue(ctx)[0] for _ in range(3))

    now = dt.datetime.now(dt.UTC)
    with session_scope() as db:
        # Far enough in the past to sort ahead of anything another test left behind: the sweep
        # takes the oldest overdue deliveries first, and this database is shared.
        db.get(WebhookDelivery, due).next_attempt_at = now - dt.timedelta(days=3650)
        row = db.get(WebhookDelivery, later)
        row.next_attempt_at = now + dt.timedelta(hours=1)
        finished = db.get(WebhookDelivery, done)
        finished.status = "delivered"
        finished.next_attempt_at = None

    dispatched: list[str] = []
    monkeypatch.setattr(sender.deliver_webhook, "apply_async",
                        lambda args=None, **_: dispatched.append(args[0]))

    sender.sweep_webhook_deliveries()

    assert str(due) in dispatched
    assert str(later) not in dispatched
    assert str(done) not in dispatched


# ── the management API ────────────────────────────────────────────────────────────────────────────
def _client(ctx):
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token

    settings = get_settings()
    token = create_access_token(subject=str(ctx["user"]), secret=settings.jwt_secret,
                                algorithm=settings.jwt_algorithm)
    return TestClient(app), {"Authorization": f"Bearer {token}"}


def test_the_secret_is_returned_once_and_never_again():
    ctx = _tenant()
    client, hdr = _client(ctx)

    created = client.post("/api/v1/webhook-endpoints", headers=hdr,
                          json={"url": "https://hooks.example.com/guardian",
                                "events": ["scan.completed"]})
    assert created.status_code == 201, created.text
    secret = created.json()["secret"]
    assert secret.startswith("whsec_")

    listing = client.get("/api/v1/webhook-endpoints", headers=hdr)
    assert listing.status_code == 200
    assert secret not in listing.text
    assert listing.json()[0]["url"] == "https://hooks.example.com/guardian"


def test_the_secret_never_reaches_the_audit_log():
    from guardian_db.models import AuditLog
    from guardian_db.session import session_scope

    ctx = _tenant()
    client, hdr = _client(ctx)
    secret = client.post("/api/v1/webhook-endpoints", headers=hdr,
                         json={"url": "https://hooks.example.com/guardian",
                               "events": ["scan.completed"]}).json()["secret"]

    with session_scope() as db:
        rows = db.query(AuditLog).filter(AuditLog.tenant_id == ctx["tenant"]).all()
        blob = " ".join(f"{r.action} {r.metadata_} {r.entity_id}" for r in rows)

    assert secret not in blob
    assert "webhook.created" in blob


@pytest.mark.parametrize(
    ("url", "fragment"),
    [
        ("http://hooks.example.com/guardian", "https"),
        ("https://127.0.0.1/guardian", "loopback"),
        ("https://user:pw@hooks.example.com/g", "inline credentials"),
    ],
)
def test_the_api_refuses_a_destination_guardian_will_not_send_to(url, fragment):
    ctx = _tenant()
    client, hdr = _client(ctx)

    response = client.post("/api/v1/webhook-endpoints", headers=hdr,
                           json={"url": url, "events": ["scan.completed"]})

    assert response.status_code == 422
    assert fragment in response.text


def test_an_unknown_event_is_refused_rather_than_silently_dropped():
    ctx = _tenant()
    client, hdr = _client(ctx)

    response = client.post("/api/v1/webhook-endpoints", headers=hdr,
                           json={"url": "https://hooks.example.com/g",
                                 "events": ["scan.completed", "scan.exploded"]})

    assert response.status_code == 422
    assert "scan.exploded" in response.text


def test_one_tenant_cannot_read_anothers_endpoints_or_deliveries():
    ctx, other = _tenant(), _tenant()
    theirs = _endpoint(other, "https://other.example.com/hook")
    _enqueue(other)
    mine = _endpoint(ctx, "https://mine.example.com/hook")

    client, hdr = _client(ctx)
    listing = client.get("/api/v1/webhook-endpoints", headers=hdr).json()

    assert [row["id"] for row in listing] == [str(mine["id"])]
    assert client.get(f"/api/v1/webhook-endpoints/{theirs['id']}/deliveries",
                      headers=hdr).status_code == 404
    assert client.delete(f"/api/v1/webhook-endpoints/{theirs['id']}",
                         headers=hdr).status_code == 404


def test_the_delivery_history_shows_what_was_sent(receiver, loopback_allowed):
    ctx = _tenant()
    endpoint = _endpoint(ctx, f"{receiver}/boom")
    (delivery_id,) = _enqueue(ctx)
    _deliver(delivery_id)

    client, hdr = _client(ctx)
    rows = client.get(f"/api/v1/webhook-endpoints/{endpoint['id']}/deliveries",
                      headers=hdr).json()

    assert len(rows) == 1
    assert rows[0]["status"] == "pending"
    assert rows[0]["response_status"] == 500
    assert rows[0]["error"]
    assert rows[0]["payload"] == _delivery(delivery_id)["payload"]


def test_deleting_an_endpoint_stops_delivery_to_it():
    ctx = _tenant()
    endpoint = _endpoint(ctx, "https://mine.example.com/hook")
    client, hdr = _client(ctx)

    assert client.delete(f"/api/v1/webhook-endpoints/{endpoint['id']}",
                         headers=hdr).status_code == 204
    assert _enqueue(ctx) == []


# ── the database backstop ─────────────────────────────────────────────────────────────────────────
def _app_is_rls_enforced() -> bool:
    from guardian_db.session import get_app_session
    from sqlalchemy import text

    session = get_app_session()
    try:
        _, bypass, super_ = session.execute(
            text("SELECT current_user, rolbypassrls, rolsuper "
                 "FROM pg_roles WHERE rolname = current_user")
        ).one()
        return not bypass and not super_
    finally:
        session.close()


def test_rls_keeps_webhook_rows_inside_their_tenant():
    """The application filters by tenant. This is the backstop underneath it — a signing secret is
    the last row that should be reachable on a raw query."""
    from guardian_db.session import get_app_session, reset_tenant, set_tenant
    from sqlalchemy import text

    if not _app_is_rls_enforced():
        pytest.skip("app session is not RLS-enforced (GUARDIAN_APP_DATABASE_URL is the owner)")

    ctx, other = _tenant(), _tenant()
    mine = _endpoint(ctx, "https://mine.example.com/hook")
    _endpoint(other, "https://other.example.com/hook")
    _enqueue(ctx)
    _enqueue(other)

    session = get_app_session()
    try:
        set_tenant(session, ctx["tenant"])
        endpoints = session.execute(text("SELECT id FROM webhook_endpoints")).scalars().all()
        assert endpoints == [mine["id"]]
        tenants = session.execute(
            text("SELECT DISTINCT tenant_id FROM webhook_deliveries")).scalars().all()
        assert tenants == [ctx["tenant"]]

        reset_tenant(session)  # no tenant bound -> fails closed
        assert session.execute(text("SELECT count(*) FROM webhook_endpoints")).scalar() == 0
        assert session.execute(text("SELECT count(*) FROM webhook_deliveries")).scalar() == 0
    finally:
        with contextlib.suppress(Exception):
            session.close()
