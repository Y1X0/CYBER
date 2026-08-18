"""The API seams the product UI depends on (WP-P0).

The console is the product for a paying customer, and every screen it renders is only as honest as
the route behind it. These tests hold the four seams added for it to the promises the UI makes:

* **`POST /auth/signup`** is the front door. It must create an organization and grant it *nothing* —
  no authorization, no verified domain, no ability to scan. A signup that quietly authorized the
  new tenant to scan what it named would be the worst defect this platform could ship.
* **`POST /authorizations`** records consent. Consent is adequate for an artifact the customer hands
  over and is *not* adequate for sending packets at a host, so `active_recon` is refused unless the
  domain has already been verified. This is the one endpoint where a wrong answer means scanning
  somebody else's systems.
* **`GET /scans/{id}/engines`** is what stops "completed, 0 findings" from reading as "you are
  clean" when three engines failed. Each engine's own outcome, and what it means, per run.
* **`GET /scans/queue-health`** answers "why is my scan still waiting?" — the question a customer
  asks when there is no worker, which is exactly the state this deployment is in.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


# ── helpers ───────────────────────────────────────────────────────────────────────────────────────
def _client():
    from fastapi.testclient import TestClient
    from guardian_api.main import app

    return TestClient(app)


def _signup(client, **overrides) -> tuple[dict, dict]:
    """Sign a new organization up. Returns (body, auth header).

    The window is cleared first. Sign-up shares the login limiter and every test here comes from the
    same client address, so without this the suite rate-limits itself — the limit is doing its job
    and `test_sign_up_is_rate_limited` below is what proves it still applies.
    """
    from guardian_api.ratelimit import login_limiter

    login_limiter().reset()
    slug = uuid.uuid4().hex[:10]
    payload = {
        "organization": f"Org {slug}",
        "company": "Production estate",
        "name": "Owner",
        "email": f"owner-{slug}@example.com",
        "password": "a-long-enough-password",
    }
    payload.update(overrides)
    response = client.post("/api/v1/auth/signup", json=payload)
    assert response.status_code == 201, response.text
    body = response.json()
    return body, {"Authorization": f"Bearer {body['access_token']}"}


# ── the front door ────────────────────────────────────────────────────────────────────────────────
class TestSignup:
    def test_creates_an_organization_that_can_immediately_authenticate(self):
        client = _client()
        body, hdr = _signup(client)

        assert body["tenant_id"] and body["customer_id"]
        me = client.get("/api/v1/auth/me", headers=hdr)
        assert me.status_code == 200, me.text
        assert me.json()["tenant_id"] == body["tenant_id"]

    def test_the_new_organization_is_authorized_to_scan_nothing(self):
        """The security property of the whole endpoint.

        Creating an account is not consent, and it is certainly not proof of control. A new tenant
        must own zero authorizations and zero verified domains, so the scan gate refuses everything
        until the customer does the work.
        """
        from guardian_db.models import Authorization, DomainVerification
        from guardian_db.session import session_scope

        client = _client()
        body, hdr = _signup(client)
        tenant = uuid.UUID(body["tenant_id"])

        with session_scope() as db:
            assert db.query(Authorization).filter(
                Authorization.tenant_id == tenant).count() == 0
            assert db.query(DomainVerification).filter(
                DomainVerification.tenant_id == tenant).count() == 0

        assert client.get("/api/v1/authorizations", headers=hdr).json() == []

    def test_it_works_under_the_rls_enforced_role(self):
        """The defect this test exists for.

        `get_db` hands out an RLS-enforced session, and the policies on `tenants`,
        `tenant_memberships` and `customers` check each row against `app.current_tenant`. Sign-up is
        the one request where the row being written *is* the tenant, so with nothing bound
        PostgreSQL refused the insert and the whole front door returned a 500 — invisible on a
        developer database where the app role is the owner and RLS is inert.
        """
        from guardian_db.session import get_app_session
        from sqlalchemy import text

        session = get_app_session()
        try:
            _, bypass, superuser = session.execute(text(
                "SELECT current_user, rolbypassrls, rolsuper FROM pg_roles "
                "WHERE rolname = current_user")).one()
        finally:
            session.close()
        if bypass or superuser:
            pytest.skip("app session is not RLS-enforced (GUARDIAN_APP_DATABASE_URL is the owner)")

        client = _client()
        body, hdr = _signup(client)
        assert client.get("/api/v1/auth/me", headers=hdr).status_code == 200
        assert client.get("/api/v1/customers", headers=hdr).json()[0]["id"] == body["customer_id"]

    def test_it_sees_only_its_own_estate(self):
        """Two organizations sign up through the same door and share nothing."""
        client = _client()
        first, first_hdr = _signup(client)
        second, second_hdr = _signup(client)

        assert first["tenant_id"] != second["tenant_id"]
        mine = client.get("/api/v1/customers", headers=first_hdr).json()
        theirs = client.get("/api/v1/customers", headers=second_hdr).json()
        assert {c["id"] for c in mine}.isdisjoint({c["id"] for c in theirs})
        assert first["customer_id"] in {c["id"] for c in mine}
        assert first["customer_id"] not in {c["id"] for c in theirs}

    def test_a_taken_address_is_refused_without_confirming_it_is_taken(self):
        """Sign-up is unauthenticated, so a distinct answer here is an account-enumeration oracle."""
        client = _client()
        email = f"dup-{uuid.uuid4().hex[:10]}@example.com"
        _signup(client, email=email)

        again = client.post("/api/v1/auth/signup", json={
            "organization": "Another Org", "email": email,
            "password": "a-long-enough-password",
        })
        assert again.status_code == 409, again.text
        detail = again.json()["detail"].lower()
        assert "cannot be used" in detail
        assert "already" not in detail and "exists" not in detail and "registered" not in detail

    def test_a_short_password_is_refused(self):
        client = _client()
        response = client.post("/api/v1/auth/signup", json={
            "organization": "Org", "email": f"short-{uuid.uuid4().hex[:8]}@example.com",
            "password": "short",
        })
        assert response.status_code == 422, response.text

    def test_sign_up_is_rate_limited(self):
        """An unbounded tenant-creation endpoint fills a database from one laptop."""
        from guardian_api.ratelimit import login_limiter
        from guardian_common.config import get_settings

        login_limiter().reset()
        client = _client()
        ceiling = get_settings().auth_rate_limit_per_minute
        codes = [
            client.post("/api/v1/auth/signup", json={
                "organization": f"Flood {i}",
                "email": f"flood-{uuid.uuid4().hex[:10]}@example.com",
                "password": "a-long-enough-password",
            }).status_code
            for i in range(ceiling + 2)
        ]
        assert 429 in codes, f"{ceiling + 2} sign-ups from one address were all accepted: {codes}"
        login_limiter().reset()

    def test_a_deployment_can_turn_self_service_off(self):
        """Managed deployments provision tenants by hand; the door has to be closable."""
        from guardian_common.config import get_settings

        settings = get_settings()
        original = settings.self_serve_signup
        settings.self_serve_signup = False
        try:
            response = _client().post("/api/v1/auth/signup", json={
                "organization": "Org", "email": f"off-{uuid.uuid4().hex[:8]}@example.com",
                "password": "a-long-enough-password",
            })
            assert response.status_code == 403, response.text
            assert "operator" in response.json()["detail"]
        finally:
            settings.self_serve_signup = original


# ── recording consent, and refusing to accept it as proof ─────────────────────────────────────────
class TestAuthorizations:
    def test_the_methods_explain_themselves_from_the_gate_s_own_constants(self):
        """The explanation the UI shows must not be able to drift away from the behaviour."""
        from guardian_core import authorization as authz

        client = _client()
        _, hdr = _signup(client)

        body = client.get("/api/v1/authorizations/methods", headers=hdr).json()
        by_method = {m["method"]: m for m in body["methods"]}
        for method, spec in by_method.items():
            assert spec["permits_network"] == (method in authz.NETWORK_METHODS)
            assert spec["permits_artifact"] == (method in authz.ARTIFACT_METHODS)
        assert by_method["written_consent"]["permits_network"] is False
        assert "does not by itself authorize" in body["note"]

    def test_written_consent_is_recorded_and_permits_only_the_artifact_plane(self):
        client = _client()
        body, hdr = _signup(client)

        response = client.post("/api/v1/authorizations", headers=hdr, json={
            "customer_id": body["customer_id"], "method": "written_consent",
            "scope": "Repository review", "domains": ["example.com"],
            "reference": "Signed engagement letter",
        })
        assert response.status_code == 201, response.text
        row = response.json()
        assert row["permits_artifact"] is True
        assert row["permits_network"] is False
        assert row["state"] == "active"
        assert row["authorized_by"].endswith("@example.com")

    def test_active_testing_is_refused_for_a_domain_nobody_proved_they_own(self):
        """The whole point. Recorded consent is a claim; packets need proof."""
        client = _client()
        body, hdr = _signup(client)

        response = client.post("/api/v1/authorizations", headers=hdr, json={
            "customer_id": body["customer_id"], "method": "active_recon",
            "scope": "External test", "domains": ["not-mine.example.com"],
        })
        assert response.status_code == 409, response.text
        detail = response.json()["detail"]
        # The refusal names the domain, so the customer knows what to go and verify.
        assert "not-mine.example.com" in detail
        assert "verified" in detail

    def test_active_testing_is_accepted_once_the_domain_is_verified(self):
        from guardian_db.models import DomainVerification
        from guardian_db.session import session_scope

        client = _client()
        body, hdr = _signup(client)
        domain = f"owned-{uuid.uuid4().hex[:8]}.example.com"

        now = dt.datetime.now(dt.UTC)
        with session_scope() as db:
            db.add(DomainVerification(
                tenant_id=uuid.UUID(body["tenant_id"]),
                customer_id=uuid.UUID(body["customer_id"]),
                domain=domain, method="dns_txt", token=uuid.uuid4().hex,
                status="verified", verified_at=now, expires_at=now + dt.timedelta(days=90)))

        response = client.post("/api/v1/authorizations", headers=hdr, json={
            "customer_id": body["customer_id"], "method": "active_recon",
            "scope": "External test", "domains": [domain],
        })
        assert response.status_code == 201, response.text
        assert response.json()["permits_network"] is True

    def test_a_verified_apex_covers_a_subdomain_and_not_a_neighbour(self):
        from guardian_db.models import DomainVerification
        from guardian_db.session import session_scope

        client = _client()
        body, hdr = _signup(client)
        apex = f"apex-{uuid.uuid4().hex[:8]}.example.com"

        now = dt.datetime.now(dt.UTC)
        with session_scope() as db:
            db.add(DomainVerification(
                tenant_id=uuid.UUID(body["tenant_id"]),
                customer_id=uuid.UUID(body["customer_id"]),
                domain=apex, method="dns_txt", token=uuid.uuid4().hex,
                status="verified", verified_at=now, expires_at=now + dt.timedelta(days=90)))

        inside = client.post("/api/v1/authorizations", headers=hdr, json={
            "customer_id": body["customer_id"], "method": "active_recon",
            "scope": "Subdomain", "domains": [f"api.{apex}"]})
        assert inside.status_code == 201, inside.text

        outside = client.post("/api/v1/authorizations", headers=hdr, json={
            "customer_id": body["customer_id"], "method": "active_recon",
            "scope": "Neighbour", "domains": [f"x{apex}"]})
        assert outside.status_code == 409, outside.text

    def test_an_authorization_naming_neither_asset_nor_domain_is_refused(self):
        """The gate reads it as granting nothing; refusing now beats a silently skipped engine."""
        client = _client()
        body, hdr = _signup(client)

        response = client.post("/api/v1/authorizations", headers=hdr, json={
            "customer_id": body["customer_id"], "method": "written_consent",
            "scope": "Everything", "domains": []})
        assert response.status_code == 422, response.text
        assert "authorizes nothing" in response.json()["detail"]

    def test_another_tenant_s_customer_cannot_be_authorized(self):
        client = _client()
        mine, my_hdr = _signup(client)
        theirs, _ = _signup(client)

        response = client.post("/api/v1/authorizations", headers=my_hdr, json={
            "customer_id": theirs["customer_id"], "method": "written_consent",
            "scope": "Not mine", "domains": ["example.com"]})
        assert response.status_code == 404, response.text
        del mine

    def test_revoking_marks_it_revoked_and_the_gate_stops_honouring_it(self):
        from guardian_core import authorization as authz
        from guardian_db.models import Authorization
        from guardian_db.session import session_scope

        client = _client()
        body, hdr = _signup(client)
        created = client.post("/api/v1/authorizations", headers=hdr, json={
            "customer_id": body["customer_id"], "method": "written_consent",
            "scope": "Repository review", "domains": ["example.com"]}).json()

        assert client.delete(f"/api/v1/authorizations/{created['id']}",
                             headers=hdr).status_code == 204

        listed = client.get("/api/v1/authorizations", headers=hdr).json()
        assert [row["state"] for row in listed] == ["revoked"]

        with session_scope() as db:
            row = db.get(Authorization, uuid.UUID(created["id"]))
            view = authz.AuthorizationView(
                id=str(row.id), method=row.method, asset_id=None,
                customer_id=str(row.customer_id), targets=tuple(row.authorized_targets or []),
                valid_from=row.valid_from, valid_until=row.valid_until,
                revoked_at=row.revoked_at)
        decision = authz.decide([view], asset_id=None, asset_identifier="app.example.com",
                                asset_kind="repo", engine="secrets")
        assert not decision.allowed
        assert "expired or revoked" in decision.reason


# ── what the scan screen needs in order not to lie ────────────────────────────────────────────────
def _scan_with_engine_runs(runs: list[dict]) -> tuple[str, dict]:
    """A tenant with one scan whose engine runs are exactly `runs`. Returns (scan id, auth header)."""
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token
    from guardian_db.models import (
        Asset,
        Customer,
        Scan,
        ScanEngineRun,
        Tenant,
        TenantMembership,
        User,
    )
    from guardian_db.session import session_scope

    slug = f"ps-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        user = User(email=f"{slug}@example.com", name="Owner", status="active")
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        db.add_all([user, customer])
        db.flush()
        db.add(TenantMembership(user_id=user.id, tenant_id=tenant.id, role="owner"))
        asset = Asset(tenant_id=tenant.id, customer_id=customer.id, name="app", kind="repo",
                      identifier=f"inline-{slug}", exposure="public", config={})
        db.add(asset)
        db.flush()
        scan = Scan(tenant_id=tenant.id, customer_id=customer.id, asset_id=asset.id,
                    trigger="manual", status="completed",
                    requested_engines=[r["engine"] for r in runs], stats={"total": 0})
        db.add(scan)
        db.flush()
        for run in runs:
            db.add(ScanEngineRun(
                scan_id=scan.id, engine=run["engine"], status=run["status"],
                tool_versions=run.get("tool_versions", {}), error=run.get("error")))
        scan_id, user_id = str(scan.id), user.id

    settings = get_settings()
    token = create_access_token(subject=str(user_id), secret=settings.jwt_secret,
                                algorithm=settings.jwt_algorithm)
    return scan_id, {"Authorization": f"Bearer {token}"}


class TestScanEngineOutcomes:
    def test_every_engine_reports_its_own_outcome(self):
        scan_id, hdr = _scan_with_engine_runs([
            {"engine": "secrets", "status": "completed"},
            {"engine": "sast", "status": "failed", "error": "semgrep exited 137"},
            {"engine": "sca", "status": "skipped"},
        ])

        response = _client().get(f"/api/v1/scans/{scan_id}/engines", headers=hdr)
        assert response.status_code == 200, response.text
        by_engine = {row["engine"]: row for row in response.json()}

        assert by_engine["secrets"]["customer_state"] == "checked"
        # The two that did not answer are never described as having found nothing.
        assert by_engine["sast"]["customer_state"] == "not_checked"
        assert "unknown, not absent" in by_engine["sast"]["meaning"]
        assert by_engine["sast"]["error"] == "semgrep exited 137"
        assert by_engine["sca"]["customer_state"] == "not_checked"

    def test_an_engine_that_ran_without_its_tools_is_inconclusive_not_checked_off(self):
        """A completed run with degraded tooling looked with one eye. That is not a clean result."""
        scan_id, hdr = _scan_with_engine_runs([
            {"engine": "sast", "status": "completed",
             "tool_versions": {"degraded": True, "missing": ["semgrep"]}},
        ])

        row = _client().get(f"/api/v1/scans/{scan_id}/engines", headers=hdr).json()[0]
        assert row["status"] == "completed"
        assert row["customer_state"] == "inconclusive"
        assert row["degraded"] is True
        assert row["missing"] == ["semgrep"]
        assert "unknown, not clean" in row["meaning"]

    def test_an_unknown_engine_status_is_never_read_as_checked(self):
        """Fail closed on a state this route has not been taught."""
        scan_id, hdr = _scan_with_engine_runs([{"engine": "dast", "status": "wedged"}])

        row = _client().get(f"/api/v1/scans/{scan_id}/engines", headers=hdr).json()[0]
        assert row["customer_state"] == "not_checked"

    def test_another_tenant_cannot_read_the_engine_outcomes(self):
        scan_id, _ = _scan_with_engine_runs([{"engine": "secrets", "status": "completed"}])
        _, other_hdr = _scan_with_engine_runs([{"engine": "secrets", "status": "completed"}])

        response = _client().get(f"/api/v1/scans/{scan_id}/engines", headers=other_hdr)
        assert response.status_code == 404


class TestQueueHealth:
    def test_the_route_is_reachable_and_not_swallowed_by_the_scan_id_route(self):
        """`/scans/queue-health` must not be parsed as `/scans/{scan_id}` — it was, and 422'd."""
        client = _client()
        _, hdr = _signup(client)

        response = client.get("/api/v1/scans/queue-health", headers=hdr)
        assert response.status_code == 200, response.text

    def test_a_tenant_with_nothing_in_flight_is_told_so_plainly(self):
        client = _client()
        _, hdr = _signup(client)

        body = client.get("/api/v1/scans/queue-health", headers=hdr).json()
        assert body["queued"] == 0 and body["running"] == 0
        assert body["state"] in ("idle", "stalled")
        assert body["detail"]
        assert body["scanner"]["status"] in ("healthy", "degraded", "unknown")

    def test_a_waiting_scan_is_reported_as_waiting_and_never_as_a_result(self):
        """The state this deployment is actually in: queued work and no worker to execute it."""
        from guardian_common.config import get_settings
        from guardian_common.security import create_access_token
        from guardian_db.models import Asset, Customer, Scan, Tenant, TenantMembership, User
        from guardian_db.session import session_scope

        slug = f"qh-{uuid.uuid4().hex[:10]}"
        with session_scope() as db:
            tenant = Tenant(name=slug, slug=slug, mode="hybrid")
            db.add(tenant)
            db.flush()
            user = User(email=f"{slug}@example.com", name="Owner", status="active")
            customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
            db.add_all([user, customer])
            db.flush()
            db.add(TenantMembership(user_id=user.id, tenant_id=tenant.id, role="owner"))
            asset = Asset(tenant_id=tenant.id, customer_id=customer.id, name="app", kind="repo",
                          identifier=f"inline-{slug}", exposure="public", config={})
            db.add(asset)
            db.flush()
            db.add(Scan(tenant_id=tenant.id, customer_id=customer.id, asset_id=asset.id,
                        trigger="manual", status="queued", requested_engines=["secrets"],
                        stats={}))
            user_id = user.id

        settings = get_settings()
        token = create_access_token(subject=str(user_id), secret=settings.jwt_secret,
                                    algorithm=settings.jwt_algorithm)
        body = _client().get("/api/v1/scans/queue-health",
                             headers={"Authorization": f"Bearer {token}"}).json()

        assert body["queued"] == 1
        assert body["state"] in ("working", "stalled")
        if body["state"] == "stalled":
            # The wording the customer reads when there is no worker. It must not imply a result.
            assert "no result has been produced" in body["detail"].lower()
        assert body["oldest_waiting_seconds"] >= 0


# ── the dashboard's numbers ───────────────────────────────────────────────────────────────────────
class TestDashboard:
    def test_a_brand_new_organization_gets_real_zeroes_not_a_reassuring_score(self):
        client = _client()
        _, hdr = _signup(client)

        body = client.get("/api/v1/dashboard", headers=hdr).json()
        assert body["assets_total"] == 0
        assert body["open_findings"] == 0
        assert body["scans_completed"] == 0
        assert body["last_successful_scan_at"] is None
        assert body["risk_trend"] == [] and body["exposure_trend"] == []

    def test_the_counts_come_from_rows_that_exist(self):
        client = _client()
        body, hdr = _signup(client)

        for name in ("one", "two"):
            created = client.post("/api/v1/assets", headers=hdr, json={
                "customer_id": body["customer_id"], "name": name, "kind": "repo",
                "identifier": f"inline-{uuid.uuid4().hex[:8]}", "exposure": "public"})
            assert created.status_code == 201, created.text

        dash = client.get("/api/v1/dashboard", headers=hdr).json()
        assert dash["assets_total"] == 2
        assert dash["assets_by_exposure"].get("public") == 2
        # Every asset was added today, so the surface trend has to account for both of them.
        assert sum(row["count"] for row in dash["exposure_trend"]) == 2

    def test_engine_runs_that_did_not_resolve_are_surfaced_for_the_dashboard_warning(self):
        """The dashboard's one non-negotiable notice: engines that did not answer are not clean."""
        scan_id, hdr = _scan_with_engine_runs([
            {"engine": "secrets", "status": "completed"},
            {"engine": "sast", "status": "failed", "error": "boom"},
            {"engine": "sca", "status": "skipped"},
        ])
        del scan_id

        body = _client().get("/api/v1/dashboard", headers=hdr).json()
        assert body["engine_runs_unresolved"].get("failed") == 1
        assert body["engine_runs_unresolved"].get("skipped") == 1
        assert "completed" not in body["engine_runs_unresolved"]
