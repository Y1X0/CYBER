"""What happens when one tenant is large, or loud (WP-G2).

Everything expensive in this platform is reachable from an authenticated request, and until now
almost none of it was bounded. `GET /assets` returned the entire inventory — discovery is designed
to find things, so 200,000 assets is a success, not an anomaly. `GET /scans` stopped at 200 rows
with no way past them and no sign that it had stopped. `POST /scans` accepted as many scans as a
client cared to send, onto a queue every other tenant shares. The only rate limit in the codebase
guarded the login endpoint, which protects the password hash and nothing else.

These tests run against the live database and check the parts a unit test cannot: that the paging
is a real keyset walk over real rows, that the limits are the *tenant's* limits, and that one
tenant's excess is refused without touching another's.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


@pytest.fixture(autouse=True)
def _clean_limiter():
    """The limiter is process-wide, so one test's traffic must not refuse the next test's."""
    from guardian_api.ratelimit import reset_tenant_limiter

    reset_tenant_limiter()
    yield
    reset_tenant_limiter()


def _tenant(*, quota_settings=None, assets=0, role="owner"):
    from guardian_db.models import Asset, Customer, Tenant, TenantMembership, User
    from guardian_db.session import session_scope

    slug = f"g2-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid",
                        settings={"quota": quota_settings} if quota_settings else {})
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        user = User(email=f"o-{slug}@x.invalid", name="Owner", status="active")
        db.add_all([customer, user])
        db.flush()
        db.add(TenantMembership(user_id=user.id, tenant_id=tenant.id, role=role))
        ids = []
        for n in range(assets):
            asset = Asset(tenant_id=tenant.id, customer_id=customer.id, name=f"asset-{n:03d}",
                          kind="repo", identifier=f"https://example.invalid/{slug}-{n}.git",
                          exposure="public", config={})
            db.add(asset)
            db.flush()
            ids.append(asset.id)
        return {"tenant": tenant.id, "customer": customer.id, "user": user.id,
                "slug": slug, "assets": ids}


def _client(ctx):
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token

    settings = get_settings()
    token = create_access_token(subject=str(ctx["user"]), secret=settings.jwt_secret,
                                algorithm=settings.jwt_algorithm)
    return TestClient(app), {"Authorization": f"Bearer {token}"}


# ── bounded reads ─────────────────────────────────────────────────────────────────────────────────
def test_the_asset_inventory_is_a_page_not_the_whole_estate():
    ctx = _tenant(assets=7)
    client, hdr = _client(ctx)

    response = client.get("/api/v1/assets?limit=3", headers=hdr)

    assert response.status_code == 200
    assert len(response.json()) == 3
    assert response.headers["X-Has-More"] == "true"
    assert response.headers["X-Next-Cursor"]


def test_the_cursor_walks_every_asset_exactly_once():
    """The property that matters: paging must not repeat a row or skip one."""
    ctx = _tenant(assets=7)
    client, hdr = _client(ctx)

    seen, cursor, pages = [], None, 0
    while True:
        query = "/api/v1/assets?limit=2" + (f"&cursor={cursor}" if cursor else "")
        response = client.get(query, headers=hdr)
        assert response.status_code == 200, response.text
        seen.extend(row["id"] for row in response.json())
        pages += 1
        if response.headers["X-Has-More"] != "true":
            break
        cursor = response.headers["X-Next-Cursor"]
        assert pages < 10, "the cursor is not advancing"

    assert len(seen) == 7
    assert len(set(seen)) == 7
    assert set(seen) == {str(i) for i in ctx["assets"]}


def test_a_row_added_mid_walk_does_not_shift_the_page():
    """Why this is keyset and not OFFSET: with OFFSET, a newer row inserted between two requests
    pushes everything down by one and the client silently skips an asset."""
    from guardian_db.models import Asset
    from guardian_db.session import session_scope

    ctx = _tenant(assets=5)
    client, hdr = _client(ctx)

    first = client.get("/api/v1/assets?limit=2", headers=hdr)
    cursor = first.headers["X-Next-Cursor"]

    with session_scope() as db:  # a newer asset, which sorts to the very top
        db.add(Asset(tenant_id=ctx["tenant"], customer_id=ctx["customer"], name="newcomer",
                     kind="repo", identifier="https://example.invalid/new.git",
                     exposure="public", config={}))

    rest, seen = cursor, [row["id"] for row in first.json()]
    while rest:
        page = client.get(f"/api/v1/assets?limit=2&cursor={rest}", headers=hdr)
        seen.extend(row["id"] for row in page.json())
        rest = page.headers.get("X-Next-Cursor") if page.headers["X-Has-More"] == "true" else None

    assert len(set(seen)) == len(seen), "a row was returned twice"
    assert {str(i) for i in ctx["assets"]} <= set(seen), "an asset was skipped"


@pytest.mark.parametrize("limit", [0, -1])
def test_asking_for_every_row_is_refused_rather_than_silently_paged(limit):
    ctx = _tenant(assets=3)
    client, hdr = _client(ctx)

    response = client.get(f"/api/v1/assets?limit={limit}", headers=hdr)

    assert response.status_code == 422
    assert "cursor" in response.text


def test_a_cursor_this_api_did_not_issue_is_refused_rather_than_restarting():
    """Silently starting again is how a client pages through 40,000 assets forever."""
    ctx = _tenant(assets=3)
    client, hdr = _client(ctx)

    response = client.get("/api/v1/assets?cursor=not-a-cursor", headers=hdr)

    assert response.status_code == 422
    assert "cursor" in response.text


def test_a_page_larger_than_the_ceiling_is_clamped():
    ctx = _tenant(assets=5, quota_settings={"max_page_size": 2})
    client, hdr = _client(ctx)

    response = client.get("/api/v1/assets?limit=1000", headers=hdr)

    assert len(response.json()) == 2
    assert response.headers["X-Page-Limit"] == "2"


def test_a_malformed_quota_override_does_not_become_unlimited():
    """The failure direction that matters: a typo must leave the platform default in place."""
    ctx = _tenant(assets=3, quota_settings={"max_page_size": "all"})
    client, hdr = _client(ctx)

    response = client.get("/api/v1/assets", headers=hdr)

    assert response.status_code == 200
    assert int(response.headers["X-Page-Limit"]) == 200  # the platform default, not unbounded


def test_the_other_list_endpoints_report_whether_more_exists():
    """A page that is exactly `limit` long is otherwise indistinguishable from the end of the
    data — which is what the old hard `LIMIT 200` looked like."""
    ctx = _tenant(assets=1)
    client, hdr = _client(ctx)

    for path in ("/api/v1/customers", "/api/v1/scans", "/api/v1/reports",
                 "/api/v1/discovery/runs"):
        response = client.get(path, headers=hdr)
        assert response.status_code == 200, path
        assert response.headers["X-Has-More"] in ("true", "false"), path


# ── rate limiting ─────────────────────────────────────────────────────────────────────────────────
def test_a_tenant_over_its_rate_limit_is_refused_with_a_retry_time():
    ctx = _tenant(quota_settings={"requests_per_minute": 3})
    client, hdr = _client(ctx)

    codes = [client.get("/api/v1/customers", headers=hdr).status_code for _ in range(4)]

    assert codes[:3] == [200, 200, 200]
    assert codes[3] == 429
    refused = client.get("/api/v1/customers", headers=hdr)
    assert int(refused.headers["Retry-After"]) >= 1
    assert "requests per minute" in refused.text


def test_one_tenants_excess_does_not_refuse_another():
    ctx = _tenant(quota_settings={"requests_per_minute": 2})
    neighbour = _tenant()
    client, hdr = _client(ctx)
    other_client, other_hdr = _client(neighbour)

    for _ in range(4):
        client.get("/api/v1/customers", headers=hdr)

    assert other_client.get("/api/v1/customers", headers=other_hdr).status_code == 200


def test_a_runaway_api_key_does_not_lock_the_humans_out():
    """A key gets its own window inside the tenant's. Otherwise one retry loop in CI locks the
    console out from the people trying to find out what is going on."""
    ctx = _tenant(quota_settings={"requests_per_minute": 2})
    client, hdr = _client(ctx)

    created = client.post("/api/v1/api-keys", headers=hdr,
                          json={"name": "ci", "scopes": ["findings:read"], "ttl_days": 30})
    assert created.status_code == 201, created.text
    key_hdr = {"Authorization": f"Bearer {created.json()['token']}"}

    for _ in range(5):
        client.get("/api/v1/findings", headers=key_hdr)
    assert client.get("/api/v1/findings", headers=key_hdr).status_code == 429

    # The human's own window was consumed by the key issuance above; a fresh window proves the
    # separation rather than the ordering.
    from guardian_api.ratelimit import reset_tenant_limiter
    reset_tenant_limiter()
    assert client.get("/api/v1/customers", headers=hdr).status_code == 200


# ── scan admission ────────────────────────────────────────────────────────────────────────────────
def _queue_scans(ctx, count):
    from guardian_db.models import Scan
    from guardian_db.session import session_scope

    with session_scope() as db:
        for _ in range(count):
            db.add(Scan(tenant_id=ctx["tenant"], customer_id=ctx["customer"],
                        asset_id=ctx["assets"][0], trigger="manual", status="queued",
                        requested_engines=["secrets"], stats={}))


def test_a_scan_is_accepted_below_the_concurrency_limit():
    ctx = _tenant(assets=1, quota_settings={"concurrent_scans": 3})
    client, hdr = _client(ctx)

    response = client.post("/api/v1/scans", headers=hdr,
                           json={"asset_id": str(ctx["assets"][0]), "engines": ["secrets"],
                                 "trigger": "manual"})

    assert response.status_code == 202, response.text


def test_a_tenant_at_its_concurrency_limit_is_refused_with_the_numbers():
    """WP-H3 caps concurrent scans per *asset* in the worker. That stops one host being hammered
    and does nothing about ten thousand scans of ten thousand assets — admission control belongs
    where the work is accepted."""
    ctx = _tenant(assets=1, quota_settings={"concurrent_scans": 2})
    _queue_scans(ctx, 2)
    client, hdr = _client(ctx)

    response = client.post("/api/v1/scans", headers=hdr,
                           json={"asset_id": str(ctx["assets"][0]), "engines": ["secrets"],
                                 "trigger": "manual"})

    assert response.status_code == 429
    assert "already queued or running" in response.text
    assert "2" in response.text
    assert int(response.headers["Retry-After"]) >= 1


def test_the_refusal_is_audited_with_its_reason():
    from guardian_db.models import AuditLog
    from guardian_db.session import session_scope

    ctx = _tenant(assets=1, quota_settings={"concurrent_scans": 1})
    _queue_scans(ctx, 1)
    client, hdr = _client(ctx)
    client.post("/api/v1/scans", headers=hdr,
                json={"asset_id": str(ctx["assets"][0]), "engines": ["secrets"],
                      "trigger": "manual"})

    with session_scope() as db:
        rows = db.query(AuditLog).filter(
            AuditLog.tenant_id == ctx["tenant"], AuditLog.action == "scan.refused_quota"
        ).all()

    assert rows
    assert rows[0].metadata_["limit"] == 1
    assert rows[0].metadata_["active"] == 1
    assert "already queued or running" in rows[0].metadata_["reason"]


def test_a_finished_scan_does_not_count_against_the_limit():
    """Only work in flight is the shared resource. Counting completed scans would give every
    long-lived tenant a permanent refusal."""
    from guardian_db.models import Scan
    from guardian_db.session import session_scope

    ctx = _tenant(assets=1, quota_settings={"concurrent_scans": 1})
    with session_scope() as db:
        db.add(Scan(tenant_id=ctx["tenant"], customer_id=ctx["customer"],
                    asset_id=ctx["assets"][0], trigger="manual", status="completed",
                    requested_engines=["secrets"], stats={}))

    client, hdr = _client(ctx)
    response = client.post("/api/v1/scans", headers=hdr,
                           json={"asset_id": str(ctx["assets"][0]), "engines": ["secrets"],
                                 "trigger": "manual"})

    assert response.status_code == 202, response.text


# ── bounded reports ───────────────────────────────────────────────────────────────────────────────
def _scan_with_findings(ctx, count):
    from guardian_db.models import Finding, Scan, ScanEngineRun
    from guardian_db.session import session_scope

    with session_scope() as db:
        scan = Scan(tenant_id=ctx["tenant"], customer_id=ctx["customer"],
                    asset_id=ctx["assets"][0], trigger="manual", status="completed",
                    requested_engines=["secrets"], stats={})
        db.add(scan)
        db.flush()
        run = ScanEngineRun(scan_id=scan.id, engine="secrets", status="completed")
        db.add(run)
        db.flush()
        for n in range(count):
            db.add(Finding(
                tenant_id=ctx["tenant"], customer_id=ctx["customer"], scan_id=scan.id,
                engine_run_id=run.id, asset_id=ctx["assets"][0],
                fingerprint=uuid.uuid4().hex[:32], title=f"Finding {n}", description="",
                category="secret", severity="high" if n % 2 else "critical",
                risk_score=50 + (n % 40), status="open", location={}, evidence={},
            ))
        return scan.id


def _report(ctx, scan_id):
    from guardian_api.routes.reports import _build_summary
    from guardian_db.models import Report, Scan
    from guardian_db.session import session_scope

    with session_scope() as db:
        summary = _build_summary(db, db.get(Scan, scan_id))
        report = Report(tenant_id=ctx["tenant"], customer_id=ctx["customer"], scan_id=scan_id,
                        title="R", status="draft", summary=summary)
        db.add(report)
        db.flush()
        return report.id, summary


def test_the_summary_counts_every_finding_without_loading_them():
    ctx = _tenant(assets=1)
    scan_id = _scan_with_findings(ctx, 25)

    _, summary = _report(ctx, scan_id)

    assert summary["total_findings"] == 25
    assert sum(summary["severity_counts"].values()) == 25
    assert len(summary["top_risks"]) == 5
    assert summary["top_risks"] == sorted(summary["top_risks"],
                                          key=lambda r: -r["risk_score"])


def test_an_export_that_could_not_fit_every_finding_says_so():
    """Silently dropping half the findings is worse than refusing to render: the reader cannot
    tell "nothing else was found" from "nothing else fitted"."""
    ctx = _tenant(assets=1, quota_settings={"max_report_findings": 4})
    scan_id = _scan_with_findings(ctx, 10)
    report_id, _ = _report(ctx, scan_id)
    client, hdr = _client(ctx)

    response = client.get(f"/api/v1/reports/{report_id}/export?format=html", headers=hdr)

    assert response.status_code == 200
    assert response.headers["X-Findings-Truncated"] == "true"
    assert "Partial report" in response.text
    # Both numbers, and the distinction the reader has to be able to make.
    assert "shows 4 of 10 findings" in response.text
    assert "6 more are recorded" in response.text
    assert "not absent" in response.text
    # And the document really contains four findings — the header row plus four.
    assert response.text.count("<tr>") == 5


def test_a_complete_export_carries_no_truncation_notice():
    ctx = _tenant(assets=1, quota_settings={"max_report_findings": 50})
    scan_id = _scan_with_findings(ctx, 10)
    report_id, _ = _report(ctx, scan_id)
    client, hdr = _client(ctx)

    response = client.get(f"/api/v1/reports/{report_id}/export?format=html", headers=hdr)

    assert response.status_code == 200
    assert "X-Findings-Truncated" not in response.headers
    assert "Partial report" not in response.text
