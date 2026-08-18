"""The findings workbench, end to end (WP-F2).

What is being proved here is not that the endpoints return 200. It is that an analyst working a
large backlog is shown the truth:

* the worst findings are on the first page even when there are more findings than fit on it — the
  previous implementation took an arbitrary 1000 rows and sorted *those*, so on a big customer the
  criticals were simply not in the result;
* paging is stable while a scan writes rows underneath the scroll, and never skips or repeats;
* a decision taken on fifty findings at once is recorded fifty times, with fifty events, and every
  finding it could not apply to is **named** rather than silently dropped;
* a credential that reached the database is masked before it reaches the response;
* every one of these is tenant-scoped, and a portal contact sees only their own customer.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

# Assembled rather than spelled out: a credential-shaped literal in a repository is what a secret
# scanner exists to stop, and GitHub's push protection rejects one even in a redactor's test.
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def _tenant(*, engine="secrets"):
    from guardian_db.models import (
        Asset,
        Customer,
        CustomerContact,
        Scan,
        ScanEngineRun,
        Tenant,
        TenantMembership,
        User,
    )
    from guardian_db.session import session_scope

    slug = f"f2-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        other = Customer(tenant_id=tenant.id, name="Other", criticality="low")
        staff = User(email=f"s-{slug}@x.invalid", name="Analyst", status="active")
        contact_user = User(email=f"p-{slug}@x.invalid", name="Portal", status="active")
        db.add_all([customer, other, staff, contact_user])
        db.flush()
        db.add(TenantMembership(user_id=staff.id, tenant_id=tenant.id, role="pentester"))
        db.add(CustomerContact(customer_id=customer.id, user_id=contact_user.id,
                               role="customer_viewer"))
        asset = Asset(tenant_id=tenant.id, customer_id=customer.id, name="app", kind="repo",
                      identifier=f"https://example.invalid/{slug}.git", config={})
        db.add(asset)
        db.flush()
        scan = Scan(tenant_id=tenant.id, customer_id=customer.id, asset_id=asset.id,
                    trigger="manual", status="completed", requested_engines=[engine], stats={})
        db.add(scan)
        db.flush()
        run = ScanEngineRun(scan_id=scan.id, engine=engine, status="completed")
        db.add(run)
        db.flush()
        return {"tenant": tenant.id, "customer": customer.id, "other_customer": other.id,
                "asset": asset.id, "scan": scan.id, "run": run.id,
                "staff": staff.id, "contact": contact_user.id, "slug": slug}


def _finding(ctx, *, severity="high", risk=70, title="Hardcoded credential", status="open",
             evidence=None, customer=None, cve=None, kev=False, maturity=None, category="secret",
             correlation_id=None, verified=None, description="", location=None):
    from guardian_db.models import Finding
    from guardian_db.session import session_scope

    with session_scope() as db:
        finding = Finding(
            tenant_id=ctx["tenant"], customer_id=customer or ctx["customer"], scan_id=ctx["scan"],
            engine_run_id=ctx["run"], asset_id=ctx["asset"], fingerprint=uuid.uuid4().hex[:32],
            title=title, description=description, category=category, severity=severity,
            risk_score=risk, status=status, cve_ids=[cve] if cve else [], kev=kev,
            exploit_maturity=maturity, correlation_id=correlation_id,
            verification_verdict=verified,
            location=location or {"path": "app/config.py", "line": 12},
            evidence=evidence or {"detail": {"excerpt": "redacted"}},
        )
        db.add(finding)
        db.flush()
        return finding.id


def _client(ctx, *, portal=False):
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token

    settings = get_settings()
    subject = str(ctx["contact"] if portal else ctx["staff"])
    token = create_access_token(subject=subject, secret=settings.jwt_secret,
                                algorithm=settings.jwt_algorithm)
    return TestClient(app), {"Authorization": f"Bearer {token}"}


def _ids(response) -> list[str]:
    return [row["id"] for row in response.json()]


# ── ordering and paging ───────────────────────────────────────────────────────────────────────────
def test_the_worst_findings_are_on_the_first_page_however_many_there_are():
    """The defect this replaces: the old endpoint took 1000 rows in whatever order the database
    returned them and sorted that page in Python. The criticals were not in the page to sort."""
    ctx = _tenant()
    for _ in range(30):
        _finding(ctx, severity="low", risk=20)
    worst = _finding(ctx, severity="critical", risk=95, title="RCE")
    second = _finding(ctx, severity="high", risk=88)

    client, hdr = _client(ctx)
    page = client.get(f"/api/v1/findings?scan_id={ctx['scan']}&limit=5", headers=hdr)

    assert page.status_code == 200
    assert _ids(page)[:2] == [str(worst), str(second)]
    assert page.headers["X-Has-More"] == "true"


def test_paging_walks_every_finding_exactly_once():
    ctx = _tenant()
    created = {str(_finding(ctx, severity="medium", risk=50 + (i % 7))) for i in range(23)}

    client, hdr = _client(ctx)
    seen: list[str] = []
    cursor = None
    for _ in range(20):  # bounded so a paging bug fails rather than hangs
        url = f"/api/v1/findings?scan_id={ctx['scan']}&limit=5"
        if cursor:
            url += f"&cursor={cursor}"
        response = client.get(url, headers=hdr)
        seen.extend(_ids(response))
        cursor = response.headers.get("X-Next-Cursor")
        if not cursor:
            break

    assert len(seen) == len(set(seen)) == len(created)
    assert set(seen) == created


def test_a_row_written_mid_scroll_does_not_shift_the_page_underneath():
    """Keyset paging exists for this: with OFFSET, a finding inserted above the current position
    pushes one row across the boundary and it is never shown."""
    ctx = _tenant()
    for i in range(10):
        _finding(ctx, severity="medium", risk=40 + i)

    client, hdr = _client(ctx)
    first = client.get(f"/api/v1/findings?scan_id={ctx['scan']}&limit=4", headers=hdr)
    cursor = first.headers["X-Next-Cursor"]

    # A scan lands a new critical while the analyst is on page 1.
    _finding(ctx, severity="critical", risk=99, title="landed mid-scroll")

    rest = client.get(
        f"/api/v1/findings?scan_id={ctx['scan']}&limit=20&cursor={cursor}", headers=hdr
    )
    assert set(_ids(first)).isdisjoint(_ids(rest))
    assert len(set(_ids(first)) | set(_ids(rest))) == 10


def test_a_forged_cursor_is_refused():
    ctx = _tenant()
    client, hdr = _client(ctx)
    response = client.get("/api/v1/findings?cursor=not-a-real-cursor", headers=hdr)
    assert response.status_code == 422
    assert "cursor" in response.text


# ── filters ───────────────────────────────────────────────────────────────────────────────────────
def test_the_filters_narrow_to_what_was_asked_for():
    ctx = _tenant()
    critical = _finding(ctx, severity="critical", risk=95, title="RCE in parser",
                        cve="CVE-2024-3094", kev=True, maturity="functional")
    _finding(ctx, severity="low", risk=10, title="Verbose header", category="misconfig")
    triaged = _finding(ctx, severity="high", risk=70, status="triaged")

    client, hdr = _client(ctx)
    base = f"/api/v1/findings?scan_id={ctx['scan']}"

    assert _ids(client.get(f"{base}&severity=critical", headers=hdr)) == [str(critical)]
    assert _ids(client.get(f"{base}&status=triaged", headers=hdr)) == [str(triaged)]
    assert _ids(client.get(f"{base}&cve=CVE-2024-3094", headers=hdr)) == [str(critical)]
    assert _ids(client.get(f"{base}&exploited=true", headers=hdr)) == [str(critical)]
    assert _ids(client.get(f"{base}&min_risk=90", headers=hdr)) == [str(critical)]
    assert _ids(client.get(f"{base}&category=misconfig", headers=hdr)) != [str(critical)]
    assert _ids(client.get(f"{base}&q=parser", headers=hdr)) == [str(critical)]
    assert _ids(client.get(f"{base}&engine=secrets", headers=hdr))
    assert _ids(client.get(f"{base}&engine=iac", headers=hdr)) == []


def test_a_search_term_is_matched_literally_not_as_a_pattern():
    """`%` in a search box must find findings containing a percent sign, not every finding."""
    ctx = _tenant()
    match = _finding(ctx, title="CPU at 100% under load")
    _finding(ctx, title="unrelated")

    client, hdr = _client(ctx)
    assert _ids(client.get(f"/api/v1/findings?scan_id={ctx['scan']}&q=100%25", headers=hdr)) == [
        str(match)
    ]


def test_severity_filters_combine_as_an_or_within_the_field():
    ctx = _tenant()
    critical = _finding(ctx, severity="critical", risk=95)
    high = _finding(ctx, severity="high", risk=80)
    _finding(ctx, severity="low", risk=10)

    client, hdr = _client(ctx)
    got = _ids(client.get(
        f"/api/v1/findings?scan_id={ctx['scan']}&severity=critical&severity=high", headers=hdr
    ))
    assert got == [str(critical), str(high)]


def test_an_unrecognized_filter_value_is_refused_rather_than_dropped():
    """Dropping it widens the query the caller asked to narrow: `?severity=criticl` would return
    everything, and read as 'there are no criticals' only after the analyst had scrolled past
    three hundred lows."""
    ctx = _tenant()
    _finding(ctx, severity="low", risk=10)
    client, hdr = _client(ctx)

    response = client.get("/api/v1/findings?severity=criticl", headers=hdr)
    assert response.status_code == 422
    assert "criticl" in response.text
    assert client.get("/api/v1/findings?status=wontfix", headers=hdr).status_code == 422


# ── the summary ───────────────────────────────────────────────────────────────────────────────────
def test_the_summary_counts_what_the_caller_can_see():
    ctx = _tenant()
    _finding(ctx, severity="critical", risk=95, kev=True)
    _finding(ctx, severity="high", risk=70, status="triaged")
    _finding(ctx, severity="high", risk=60)

    client, hdr = _client(ctx)
    body = client.get(f"/api/v1/findings/summary?scan_id={ctx['scan']}", headers=hdr).json()

    assert body["total"] == 3
    assert body["by_severity"] == {"critical": 1, "high": 2}
    assert body["by_status"] == {"open": 2, "triaged": 1}
    assert body["by_engine"] == {"secrets": 3}
    assert body["exploitable"] == 1
    assert body["unverified"] == 3


# ── the dossier ───────────────────────────────────────────────────────────────────────────────────
def test_the_dossier_carries_the_whole_chain():
    """Correlation, verification history and triage timeline in one place — the evidence a customer
    would use to check the claim, not a headline."""
    from guardian_db.models import FindingVerification
    from guardian_db.session import session_scope

    ctx = _tenant()
    finding_id = _finding(ctx, severity="critical", risk=95, title="RCE", cve="CVE-2024-3094",
                          kev=True, maturity="functional")
    with session_scope() as db:
        db.add(FindingVerification(
            tenant_id=ctx["tenant"], finding_id=finding_id, scan_id=ctx["scan"],
            verdict="still_present", method="rescan", engine="secrets",
            rationale="the engine reported it again", evidence={},
            checked_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        ))

    client, hdr = _client(ctx)
    client.patch(f"/api/v1/findings/{finding_id}", headers=hdr,
                 json={"status": "confirmed", "note": "reproduced by hand"})

    body = client.get(f"/api/v1/findings/{finding_id}", headers=hdr).json()

    assert body["finding"]["title"] == "RCE"
    assert body["engine"] == "secrets"
    assert body["asset"]["kind"] == "repo"
    assert body["scan"]["status"] == "completed"
    assert body["exploit"] == {"kev": True, "maturity": "functional", "ransomware": False,
                               "epss": None, "cvss_base": None}
    assert body["verifications"][0]["verdict"] == "still_present"
    assert body["timeline"][-1]["to_status"] == "confirmed"
    assert body["timeline"][-1]["note"] == "reproduced by hand"


def test_the_dossier_shows_the_correlation_group_and_its_other_members():
    from guardian_scanner.correlation import correlate_tenant

    ctx = _tenant()
    first = _finding(ctx, evidence={"detail": {"redacted": "AK********EY"}},
                     location={"engine": "secrets", "path": "app/config.py"})
    second = _finding(ctx, category="insecure-code",
                      evidence={"detail": {"redacted": "AK********EY"}},
                      location={"engine": "sast", "path": "app/config.py"})
    correlate_tenant(str(ctx["tenant"]))

    client, hdr = _client(ctx)
    body = client.get(f"/api/v1/findings/{first}", headers=hdr).json()

    assert body["correlation"]["rule"] == "same-secret"
    assert body["correlation"]["member_count"] == 2
    assert [row["id"] for row in body["related"]] == [str(second)]


def test_a_finding_in_another_tenant_is_not_found():
    mine, theirs = _tenant(), _tenant()
    hidden = _finding(theirs)

    client, hdr = _client(mine)
    assert client.get(f"/api/v1/findings/{hidden}", headers=hdr).status_code == 404


# ── redaction at the boundary ─────────────────────────────────────────────────────────────────────
def test_a_credential_that_reached_the_database_never_reaches_the_response():
    """The engines redact at write time. This is the second line, and it is what stands between a
    parser that quoted a config file verbatim and a customer's credential in an HTTP response."""
    ctx = _tenant()
    finding_id = _finding(ctx, evidence={"detail": {"excerpt": f"aws_key = '{AWS_KEY}'"}})

    client, hdr = _client(ctx)
    listed = client.get(f"/api/v1/findings?scan_id={ctx['scan']}", headers=hdr)
    dossier = client.get(f"/api/v1/findings/{finding_id}", headers=hdr)

    assert AWS_KEY not in listed.text
    assert AWS_KEY not in dossier.text
    assert "[redacted]" in dossier.text


def test_a_triage_note_quoting_the_secret_is_scrubbed_too():
    """Free text written by a human is the one field no engine ever redacts."""
    ctx = _tenant()
    finding_id = _finding(ctx)

    client, hdr = _client(ctx)
    client.patch(f"/api/v1/findings/{finding_id}", headers=hdr,
                 json={"status": "false_positive", "note": f"this is the test key {AWS_KEY}"})

    body = client.get(f"/api/v1/findings/{finding_id}", headers=hdr)
    assert AWS_KEY not in body.text


# ── triage ────────────────────────────────────────────────────────────────────────────────────────
def test_silencing_a_finding_without_a_reason_is_refused():
    ctx = _tenant()
    finding_id = _finding(ctx)
    client, hdr = _client(ctx)

    for target in ("false_positive", "accepted_risk", "resolved"):
        response = client.patch(f"/api/v1/findings/{finding_id}", headers=hdr,
                                json={"status": target})
        assert response.status_code == 422, target


def test_a_status_outside_the_vocabulary_is_refused():
    ctx = _tenant()
    finding_id = _finding(ctx)
    client, hdr = _client(ctx)
    response = client.patch(f"/api/v1/findings/{finding_id}", headers=hdr,
                            json={"status": "wontfix", "note": "n/a"})
    assert response.status_code == 422


def test_bulk_triage_records_a_decision_per_finding():
    """Fifty findings closed in one click still means fifty decisions, each individually
    reconstructable afterwards."""
    from guardian_db.models import FindingEvent
    from guardian_db.session import session_scope

    ctx = _tenant()
    ids = [str(_finding(ctx)) for _ in range(5)]
    client, hdr = _client(ctx)

    response = client.post("/api/v1/findings/bulk-triage", headers=hdr, json={
        "finding_ids": ids, "status": "false_positive", "note": "same test fixture in all five",
    })

    assert response.status_code == 200
    assert set(response.json()["updated"]) == set(ids)
    assert response.json()["refused"] == []
    with session_scope() as db:
        events = db.query(FindingEvent).filter(
            FindingEvent.finding_id.in_([uuid.UUID(i) for i in ids])
        ).all()
    assert len(events) == 5
    assert {e.to_status for e in events} == {"false_positive"}
    assert all(e.actor_id == ctx["staff"] for e in events)


def test_bulk_triage_without_a_reason_is_refused_for_all_of_them():
    ctx = _tenant()
    ids = [str(_finding(ctx)) for _ in range(3)]
    client, hdr = _client(ctx)

    response = client.post("/api/v1/findings/bulk-triage", headers=hdr, json={
        "finding_ids": ids, "status": "accepted_risk",
    })
    assert response.status_code == 422

    listed = client.get(f"/api/v1/findings?scan_id={ctx['scan']}", headers=hdr).json()
    assert {row["status"] for row in listed} == {"open"}


def test_bulk_triage_names_what_it_could_not_apply():
    """An analyst who selects fifty findings and is told 'done' while twelve were skipped believes
    decisions were recorded that were not."""
    mine, theirs = _tenant(), _tenant()
    ok = str(_finding(mine))
    foreign = str(_finding(theirs))
    missing = str(uuid.uuid4())

    client, hdr = _client(mine)
    body = client.post("/api/v1/findings/bulk-triage", headers=hdr, json={
        "finding_ids": [ok, foreign, missing], "status": "confirmed", "note": "reviewed",
    }).json()

    assert body["updated"] == [ok]
    assert {row["id"] for row in body["refused"]} == {foreign, missing}
    assert all("not found in this tenant" in row["reason"] for row in body["refused"])


def test_bulk_triage_never_touches_another_tenants_finding():
    from guardian_db.models import Finding
    from guardian_db.session import session_scope

    mine, theirs = _tenant(), _tenant()
    foreign = _finding(theirs)

    client, hdr = _client(mine)
    client.post("/api/v1/findings/bulk-triage", headers=hdr, json={
        "finding_ids": [str(foreign)], "status": "false_positive", "note": "not mine",
    })

    with session_scope() as db:
        assert db.get(Finding, foreign).status == "open"


# ── portal visibility ─────────────────────────────────────────────────────────────────────────────
def test_a_portal_contact_sees_only_their_own_customer():
    ctx = _tenant()
    mine = _finding(ctx)
    theirs = _finding(ctx, customer=ctx["other_customer"])

    client, hdr = _client(ctx, portal=True)
    listed = _ids(client.get("/api/v1/findings", headers=hdr))

    assert str(mine) in listed
    assert str(theirs) not in listed
    assert client.get(f"/api/v1/findings/{theirs}", headers=hdr).status_code == 404


def test_a_portal_contacts_summary_counts_only_their_own_customer():
    """A count of rows the caller cannot read still discloses that they exist."""
    ctx = _tenant()
    _finding(ctx, severity="critical", risk=95)
    _finding(ctx, severity="critical", risk=95, customer=ctx["other_customer"])

    client, hdr = _client(ctx, portal=True)
    body = client.get("/api/v1/findings/summary", headers=hdr).json()
    assert body["total"] == 1


def test_a_portal_contact_cannot_triage():
    ctx = _tenant()
    finding_id = _finding(ctx)
    client, hdr = _client(ctx, portal=True)

    assert client.patch(f"/api/v1/findings/{finding_id}", headers=hdr,
                        json={"status": "confirmed"}).status_code in (401, 403)
    assert client.post("/api/v1/findings/bulk-triage", headers=hdr, json={
        "finding_ids": [str(finding_id)], "status": "confirmed",
    }).status_code in (401, 403)
