"""Ownership verification, end to end (WP-F1).

`test_ownership.py` proves the decision logic cannot be fooled. What this file proves is the part
that changes what Guardian will actually do: a verified domain creates an `Authorization`, and that
authorization is what the active-discovery gate lets through.

That link is the whole package. Before it, `Authorization.method = "ownership_verified"` was a
string somebody typed; the gate only honoured `active_recon`, so a machine-checked proof counted for
less than a checkbox. The tests below fail if any of the following stops being true:

* a failed check never grants anything — an expired, exhausted, redirected or absent proof leaves
  the customer exactly where they started;
* a granted authorization clears the verified domain **and its subdomains, and nothing else** —
  not the apex above it, not a lookalike suffix, not another tenant's domain;
* revoking the proof revokes the permission, and the gate denies from that moment.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

def _tenant():
    from guardian_db.models import Customer, Tenant, TenantMembership, User
    from guardian_db.session import session_scope

    slug = f"f1-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        user = User(email=f"{slug}@example.invalid", name="Operator")
        db.add_all([customer, user])
        db.flush()
        db.add(TenantMembership(user_id=user.id, tenant_id=tenant.id, role="admin"))
        db.flush()
        return {"tenant": tenant.id, "customer": customer.id, "user": user.id,
                "domain": f"{slug}.example.com"}


def _issue(ctx, method="dns_txt", *, validity_days=365):
    from guardian_db.session import session_scope
    from guardian_scanner.ownership import create_verification

    with session_scope() as db:
        record = create_verification(
            db, tenant_id=ctx["tenant"], customer_id=ctx["customer"],
            domain=ctx["domain"], method=method, validity_days=validity_days,
            created_by=ctx["user"],
        )
        return {"id": record.id, "token": record.token, "expires_at": record.expires_at}


def _reload(verification_id):
    from guardian_db.models import DomainVerification
    from guardian_db.session import session_scope

    with session_scope() as db:
        record = db.get(DomainVerification, verification_id)
        return {
            "status": record.status, "attempts": record.attempts,
            "last_error": record.last_error, "verified_at": record.verified_at,
            "authorization_id": record.authorization_id,
        }


def _authorizations(tenant_id):
    from guardian_db.models import Authorization
    from guardian_db.session import session_scope

    with session_scope() as db:
        return [
            {"id": a.id, "method": a.method, "targets": a.authorized_targets,
             "revoked_at": a.revoked_at, "valid_until": a.valid_until, "scope": a.scope}
            for a in db.query(Authorization).filter(Authorization.tenant_id == tenant_id).all()
        ]


def _run_check(monkeypatch, verification_id, *, txt=None, http=None):
    """Run the real task with the network replaced by a fixed answer."""
    import guardian_scanner.ownership as ownership

    if txt is not None:
        monkeypatch.setattr(ownership, "lookup_txt", lambda _name: txt)
    if http is not None:
        monkeypatch.setattr(ownership, "fetch_challenge", lambda _domain: http)
    return ownership.check_domain_verification(str(verification_id))


def _gate(ctx, candidates):
    """Ask the real active-discovery gate which of these targets it would let through."""
    from guardian_db.session import session_scope
    from guardian_scanner.discovery.authorization import authorize_targets

    with session_scope() as db:
        return authorize_targets(
            db, tenant_id=ctx["tenant"], customer_id=ctx["customer"], run_id=uuid.uuid4(),
            candidates=candidates, now=dt.datetime.now(dt.UTC),
        )


# ── issuing a challenge ───────────────────────────────────────────────────────────────────────────
def test_a_challenge_is_issued_pending_and_grants_nothing_on_its_own():
    """Asking to prove a domain is not proving it."""
    ctx = _tenant()
    issued = _issue(ctx)

    state = _reload(issued["id"])
    assert state["status"] == "pending"
    assert state["authorization_id"] is None
    assert _authorizations(ctx["tenant"]) == []

    allowed, denied = _gate(ctx, [ctx["domain"]])
    assert allowed == []
    assert denied == [ctx["domain"]]


def test_two_challenges_never_share_a_token():
    """A shared token is a token one customer could publish and another be credited for."""
    first, second = _issue(_tenant()), _issue(_tenant())
    assert first["token"] != second["token"]


# ── a proof that does not hold ────────────────────────────────────────────────────────────────────
def test_a_missing_record_leaves_the_customer_where_they_started(monkeypatch):
    ctx = _tenant()
    issued = _issue(ctx)

    result = _run_check(monkeypatch, issued["id"], txt=None)

    assert result["status"] == "pending"
    state = _reload(issued["id"])
    assert state["attempts"] == 1
    assert "not found" in state["last_error"]
    assert _authorizations(ctx["tenant"]) == []


def test_another_customers_token_does_not_grant(monkeypatch):
    ctx = _tenant()
    issued = _issue(ctx)

    _run_check(monkeypatch, issued["id"], txt=["guardian-site-verification=someone-elses"])

    assert _reload(issued["id"])["status"] == "pending"
    assert _authorizations(ctx["tenant"]) == []


def test_a_redirected_http_challenge_never_grants(monkeypatch):
    """The attack the control exists to prevent: if the domain redirects to a host the requester
    controls, following it would credit them with owning the domain."""
    ctx = _tenant()
    issued = _issue(ctx, method="http_file")

    _run_check(monkeypatch, issued["id"],
               http=(200, issued["token"], "https://attacker.example.net/token.txt"))

    state = _reload(issued["id"])
    assert state["status"] == "pending"
    assert "redirect" in state["last_error"]
    assert _authorizations(ctx["tenant"]) == []


def test_an_expired_challenge_is_refused_even_when_the_proof_is_published(monkeypatch):
    """An authorization resting on a challenge issued a year ago is one nobody re-consented to."""
    ctx = _tenant()
    issued = _issue(ctx, validity_days=-1)

    result = _run_check(monkeypatch, issued["id"], txt=[issued["token"]])

    assert result["status"] == "expired"
    assert _reload(issued["id"])["status"] == "expired"
    assert _authorizations(ctx["tenant"]) == []


def test_the_attempt_cap_stops_an_endless_poll_against_a_third_party(monkeypatch):
    """Checking is an outbound request to a customer-named domain. Unbounded retries turn the
    platform into a traffic source aimed at somebody who never consented."""
    from guardian_core.ownership import MAX_ATTEMPTS
    from guardian_db.models import DomainVerification
    from guardian_db.session import session_scope

    ctx = _tenant()
    issued = _issue(ctx)
    with session_scope() as db:
        db.get(DomainVerification, issued["id"]).attempts = MAX_ATTEMPTS

    result = _run_check(monkeypatch, issued["id"], txt=[issued["token"]])

    assert result["status"] == "failed"
    assert _reload(issued["id"])["status"] == "failed"
    assert _authorizations(ctx["tenant"]) == []


def test_a_lookup_that_raises_is_not_a_proof_and_is_not_a_silent_pass(monkeypatch):
    """Never convert an error into a result. A resolver failure is 'we do not know', not 'yes'."""
    import guardian_scanner.ownership as ownership

    ctx = _tenant()
    issued = _issue(ctx)

    def boom(_name):
        raise TimeoutError("resolver unreachable")

    monkeypatch.setattr(ownership, "lookup_txt", boom)
    result = ownership.check_domain_verification(str(issued["id"]))

    assert result["status"] == "pending"
    state = _reload(issued["id"])
    assert "TimeoutError" in state["last_error"]
    assert _authorizations(ctx["tenant"]) == []


# ── a proof that holds ────────────────────────────────────────────────────────────────────────────
def test_a_published_txt_record_grants_a_scoped_authorization(monkeypatch):
    ctx = _tenant()
    issued = _issue(ctx)

    result = _run_check(monkeypatch, issued["id"],
                        txt=["v=spf1 -all", issued["token"], "google-site-verification=x"])

    assert result["status"] == "verified"
    state = _reload(issued["id"])
    assert state["status"] == "verified"
    assert state["verified_at"] is not None
    assert state["last_error"] is None

    auths = _authorizations(ctx["tenant"])
    assert len(auths) == 1
    assert auths[0]["method"] == "ownership_verified"
    assert auths[0]["targets"] == [{"type": "domain", "value": ctx["domain"]}]
    assert auths[0]["id"] == state["authorization_id"]
    # The authorization must not outlive the proof it rests on.
    assert auths[0]["valid_until"] == issued["expires_at"]
    assert ctx["domain"] in auths[0]["scope"]


def test_a_published_challenge_file_grants(monkeypatch):
    from guardian_core.ownership import http_challenge_url

    ctx = _tenant()
    issued = _issue(ctx, method="http_file")
    url = http_challenge_url(ctx["domain"])

    result = _run_check(monkeypatch, issued["id"], http=(200, f"{issued['token']}\n", url))

    assert result["status"] == "verified"
    assert len(_authorizations(ctx["tenant"])) == 1


def test_checking_again_after_success_does_not_grant_a_second_authorization(monkeypatch):
    """A customer polling the check button must not accumulate permissions."""
    ctx = _tenant()
    issued = _issue(ctx)

    _run_check(monkeypatch, issued["id"], txt=[issued["token"]])
    _run_check(monkeypatch, issued["id"], txt=[issued["token"]])

    assert len(_authorizations(ctx["tenant"])) == 1


# ── what the proof actually buys: the gate ────────────────────────────────────────────────────────
def test_the_gate_lets_the_verified_domain_and_its_subdomains_through(monkeypatch):
    """The point of the package. Before this, the gate honoured only `active_recon`, so a proof
    Guardian went and read with its own eyes cleared nothing."""
    ctx = _tenant()
    issued = _issue(ctx)
    _run_check(monkeypatch, issued["id"], txt=[issued["token"]])

    allowed, denied = _gate(ctx, [ctx["domain"], f"app.{ctx['domain']}", f"{ctx['domain']}:443"])

    assert denied == []
    assert len(allowed) == 3


def test_the_gate_still_denies_everything_the_proof_did_not_cover(monkeypatch):
    """Verifying `x.example.com` proves control of one host, not of the zone above it — and a
    lookalike suffix is a different domain owned by somebody else."""
    ctx = _tenant()
    issued = _issue(ctx)
    _run_check(monkeypatch, issued["id"], txt=[issued["token"]])

    apex = ctx["domain"].split(".", 1)[1]
    others = [apex, f"not{ctx['domain']}", f"{ctx['domain']}.attacker.example.net", "google.com"]
    allowed, denied = _gate(ctx, others)

    assert allowed == []
    assert denied == others


def test_revoking_the_proof_revokes_the_permission(monkeypatch):
    """Leaving an authorization standing after its evidence is withdrawn is how a scan keeps
    running against a domain the customer no longer claims."""
    from guardian_db.models import Authorization, DomainVerification
    from guardian_db.session import session_scope

    ctx = _tenant()
    issued = _issue(ctx)
    _run_check(monkeypatch, issued["id"], txt=[issued["token"]])
    assert _gate(ctx, [ctx["domain"]])[0] == [ctx["domain"]]

    with session_scope() as db:
        record = db.get(DomainVerification, issued["id"])
        record.status = "revoked"
        db.get(Authorization, record.authorization_id).revoked_at = dt.datetime.now(dt.UTC)

    allowed, denied = _gate(ctx, [ctx["domain"]])
    assert allowed == []
    assert denied == [ctx["domain"]]


def test_one_tenants_proof_never_clears_anothers_target(monkeypatch):
    mine, theirs = _tenant(), _tenant()
    issued = _issue(mine)
    _run_check(monkeypatch, issued["id"], txt=[issued["token"]])

    allowed, denied = _gate(theirs, [mine["domain"]])
    assert allowed == []
    assert denied == [mine["domain"]]
    assert _authorizations(theirs["tenant"]) == []


def test_an_artifact_consent_does_not_become_a_licence_to_probe():
    """`written_consent` covers an artifact a customer handed over. It is not permission to send
    packets at a host, and the gate must not confuse the two."""
    from guardian_db.models import Authorization
    from guardian_db.session import session_scope

    ctx = _tenant()
    now = dt.datetime.now(dt.UTC)
    with session_scope() as db:
        db.add(Authorization(
            tenant_id=ctx["tenant"], customer_id=ctx["customer"], scope="artifact",
            authorized_targets=[{"type": "domain", "value": ctx["domain"]}],
            method="written_consent", authorized_by=ctx["user"],
            valid_from=now - dt.timedelta(days=1),
            valid_until=now + dt.timedelta(days=1),
        ))

    allowed, denied = _gate(ctx, [ctx["domain"]])
    assert allowed == []
    assert denied == [ctx["domain"]]


# ── the customer-facing API ───────────────────────────────────────────────────────────────────────
def _client_and_headers(ctx):
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token

    settings = get_settings()
    token = create_access_token(subject=str(ctx["user"]), secret=settings.jwt_secret,
                                algorithm=settings.jwt_algorithm)
    return TestClient(app), {"Authorization": f"Bearer {token}"}


def test_the_api_issues_a_challenge_and_says_what_to_publish(monkeypatch):
    ctx = _tenant()
    client, hdr = _client_and_headers(ctx)

    created = client.post("/api/v1/verifications", headers=hdr, json={
        "customer_id": str(ctx["customer"]), "domain": f"HTTPS://{ctx['domain'].upper()}/x",
        "method": "dns_txt",
    })
    assert created.status_code == 201, created.text
    body = created.json()
    # Normalized on the way in, so the authorization check never compares two spellings of one
    # domain and finds them different.
    assert body["domain"] == ctx["domain"]
    assert body["status"] == "pending"
    assert body["instructions"]["record_name"] == f"_guardian-challenge.{ctx['domain']}"
    token = body["instructions"]["record_value"]

    # Re-readable: a challenge nobody can look up again is one they have to start over.
    fetched = client.get(f"/api/v1/verifications/{body['id']}", headers=hdr).json()
    assert fetched["instructions"]["record_value"] == token

    # And it grants nothing until the proof is actually read.
    assert _authorizations(ctx["tenant"]) == []
    del monkeypatch


def test_the_api_refuses_a_malformed_domain():
    ctx = _tenant()
    client, hdr = _client_and_headers(ctx)
    response = client.post("/api/v1/verifications", headers=hdr, json={
        "customer_id": str(ctx["customer"]), "domain": "not a domain", "method": "dns_txt",
    })
    assert response.status_code == 422


def test_the_api_will_not_issue_a_challenge_for_another_tenants_customer():
    mine, theirs = _tenant(), _tenant()
    client, hdr = _client_and_headers(mine)
    response = client.post("/api/v1/verifications", headers=hdr, json={
        "customer_id": str(theirs["customer"]), "domain": theirs["domain"], "method": "dns_txt",
    })
    assert response.status_code == 404


def test_the_api_queues_the_check_rather_than_performing_it(monkeypatch):
    """The API holds every tenant's session. Reaching a customer-named domain over DNS and HTTPS is
    outbound work with an SSRF surface, and it belongs in the worker's egress guard."""
    from guardian_scanner.celery_app import celery_app

    ctx = _tenant()
    client, hdr = _client_and_headers(ctx)
    created = client.post("/api/v1/verifications", headers=hdr, json={
        "customer_id": str(ctx["customer"]), "domain": ctx["domain"], "method": "dns_txt",
    }).json()

    sent: list[tuple] = []
    monkeypatch.setattr(celery_app, "send_task",
                        lambda name, args=None, **kw: sent.append((name, args)))

    response = client.post(f"/api/v1/verifications/{created['id']}/check", headers=hdr)
    assert response.status_code == 200
    assert sent == [("guardian.check_domain_verification", [created["id"]])]


def test_revoking_through_the_api_withdraws_the_authorization(monkeypatch):
    ctx = _tenant()
    client, hdr = _client_and_headers(ctx)
    created = client.post("/api/v1/verifications", headers=hdr, json={
        "customer_id": str(ctx["customer"]), "domain": ctx["domain"], "method": "dns_txt",
    }).json()
    token = created["instructions"]["record_value"]
    _run_check(monkeypatch, uuid.UUID(created["id"]), txt=[token])
    assert _gate(ctx, [ctx["domain"]])[0] == [ctx["domain"]]

    assert client.delete(f"/api/v1/verifications/{created['id']}", headers=hdr).status_code == 204

    assert _reload(uuid.UUID(created["id"]))["status"] == "revoked"
    assert _authorizations(ctx["tenant"])[0]["revoked_at"] is not None
    assert _gate(ctx, [ctx["domain"]]) == ([], [ctx["domain"]])


def test_one_tenant_cannot_read_or_revoke_anothers_verification(monkeypatch):
    mine, theirs = _tenant(), _tenant()
    issued = _issue(mine)
    _run_check(monkeypatch, issued["id"], txt=[issued["token"]])

    client, hdr = _client_and_headers(theirs)
    assert client.get(f"/api/v1/verifications/{issued['id']}", headers=hdr).status_code == 404
    assert client.delete(f"/api/v1/verifications/{issued['id']}", headers=hdr).status_code == 404
    assert client.get("/api/v1/verifications", headers=hdr).json() == []
    # The proof — and the permission it bought — are untouched.
    assert _reload(issued["id"])["status"] == "verified"
    assert _authorizations(mine["tenant"])[0]["revoked_at"] is None


# ── row-level security ────────────────────────────────────────────────────────────────────────────
def test_the_verification_table_enforces_row_level_security():
    """A verification names a customer's domains and carries the token that grants scanning."""
    from guardian_db.session import session_scope

    with session_scope() as db:
        enabled = db.execute(
            text("SELECT rowsecurity FROM pg_tables WHERE tablename = 'domain_verifications'")
        ).scalar_one()
        policies = db.execute(
            text("SELECT polname FROM pg_policy "
                 "WHERE polrelid = to_regclass('domain_verifications')")
        ).scalars().all()
    assert enabled is True
    assert "tenant_isolation" in policies
