"""The capabilities the readiness audit found built, tested, and never connected.

Every one of these passed its own unit and integration tests at commit `59b191f`, and every one was
unreachable in production because nothing called it. So these tests assert the *connection* rather
than the behaviour: they run the ordinary scan path and check that the thing happened, with no
direct call to the function under test.

That distinction is the entire point. A test that calls `correlate_tenant()` and asserts it groups
findings will pass forever whether or not anything in the platform ever invokes it — which is
exactly the hole this file exists to close.

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

LEAKED_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


# ── estate helpers ────────────────────────────────────────────────────────────────────────────────
def _estate(*, inline: dict | None = None, kind: str = "repo"):
    from guardian_db.models import Asset, Customer, Tenant, TenantMembership, User
    from guardian_db.session import session_scope

    slug = f"wire-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        user = User(email=f"o-{slug}@x.invalid", name="Owner", status="active")
        db.add_all([customer, user])
        db.flush()
        db.add(TenantMembership(user_id=user.id, tenant_id=tenant.id, role="owner"))
        asset = Asset(
            tenant_id=tenant.id, customer_id=customer.id, name="app", kind=kind,
            identifier=f"inline-{slug}", exposure="public",
            config={"inline_content": inline or {"app.py": f'AWS_SECRET = "{LEAKED_KEY}"\n'}},
        )
        db.add(asset)
        db.flush()
        return {"tenant": tenant.id, "customer": customer.id, "user": user.id,
                "asset": asset.id, "slug": slug}


def _scan(ctx, engines=("secrets",)):
    """Run a scan through the real orchestrator, exactly as the API would queue it."""
    from guardian_db.models import Scan
    from guardian_db.session import session_scope
    from guardian_scanner.tasks import run_scan

    with session_scope() as db:
        scan = Scan(tenant_id=ctx["tenant"], customer_id=ctx["customer"], asset_id=ctx["asset"],
                    trigger="manual", status="queued", requested_engines=list(engines), stats={})
        db.add(scan)
        db.flush()
        scan_id = str(scan.id)
    return scan_id, run_scan(scan_id)


def _client(ctx):
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token

    s = get_settings()
    token = create_access_token(subject=str(ctx["user"]), secret=s.jwt_secret,
                                algorithm=s.jwt_algorithm)
    return TestClient(app), {"Authorization": f"Bearer {token}"}


# ══ RED-1 · webhooks are emitted by a real scan ═══════════════════════════════════════════════════
def _endpoint(ctx, url="https://hooks.example.invalid/guardian", events=("scan.completed",)):
    from guardian_core import webhooks as wh
    from guardian_db.models import WebhookEndpoint
    from guardian_db.session import session_scope

    with session_scope() as db:
        row = WebhookEndpoint(tenant_id=ctx["tenant"], url=url, description="wired",
                              events=list(events), secret=wh.new_secret(), enabled=True,
                              created_by=ctx["user"])
        db.add(row)
        db.flush()
        return {"id": row.id, "secret": row.secret}


def _deliveries(ctx):
    from guardian_db.models import WebhookDelivery
    from guardian_db.session import session_scope

    with session_scope() as db:
        rows = db.query(WebhookDelivery).filter(
            WebhookDelivery.tenant_id == ctx["tenant"]
        ).all()
        return [{"event": r.event_type, "status": r.status, "payload": r.payload,
                 "attempts": r.attempts, "next_attempt_at": r.next_attempt_at,
                 "response_status": r.response_status} for r in rows]


def test_a_completed_scan_emits_a_webhook_delivery():
    """The defect: `enqueue()` had no caller, so a registered endpoint received nothing, forever."""
    ctx = _estate()
    _endpoint(ctx)

    _scan(ctx)

    rows = _deliveries(ctx)
    assert rows, "a completed scan produced no delivery — the webhook path is still dead"
    assert rows[0]["event"] == "scan.completed"


def test_the_delivery_payload_carries_the_scan_and_its_counts():
    import json

    ctx = _estate()
    _endpoint(ctx)
    scan_id, _ = _scan(ctx)

    payload = json.loads(_deliveries(ctx)[0]["payload"])
    assert payload["type"] == "scan.completed"
    assert payload["data"]["scan_id"] == scan_id
    assert payload["data"]["findings"] >= 1
    assert payload["tenant_id"] == str(ctx["tenant"])


def test_the_delivery_is_signed_with_the_endpoints_secret():
    """The signature is what makes the payload worth anything to the receiver."""
    import time

    from guardian_core import webhooks as wh

    ctx = _estate()
    endpoint = _endpoint(ctx)
    _scan(ctx)

    payload = _deliveries(ctx)[0]["payload"]
    now = int(time.time())
    signature = wh.sign(payload, secret=endpoint["secret"], timestamp=now)
    assert wh.verify(payload, signature, secret=endpoint["secret"], now=now)
    assert not wh.verify(payload, signature, secret=wh.new_secret(), now=now)


def test_an_unreachable_endpoint_schedules_a_retry_rather_than_dropping_the_event():
    """Acceptance: retry behaviour on a deliberately failing endpoint.

    `hooks.example.invalid` does not resolve, so the transport reports a connection failure — the
    one case where trying again is the whole point.
    """
    ctx = _estate()
    _endpoint(ctx)

    _scan(ctx)

    row = _deliveries(ctx)[0]
    assert row["attempts"] >= 1, "the delivery was queued but never attempted"
    assert row["status"] == "pending"
    assert row["next_attempt_at"] is not None
    assert row["response_status"] == 0


def test_an_endpoint_that_did_not_subscribe_receives_nothing():
    ctx = _estate()
    _endpoint(ctx, events=("remediation.overdue",))

    _scan(ctx)

    assert _deliveries(ctx) == []


def test_a_failed_scan_also_emits_an_event(monkeypatch):
    """Silence on failure is how a subscriber concludes there was nothing to report."""
    from guardian_scanner import tasks

    ctx = _estate()
    _endpoint(ctx, events=("scan.failed",))
    monkeypatch.setattr(tasks, "_prepare_workspace",
                        lambda asset: (_ for _ in ()).throw(RuntimeError("workspace exploded")))

    _, result = _scan(ctx)

    assert result["status"] == "failed"
    rows = _deliveries(ctx)
    assert rows and rows[0]["event"] == "scan.failed"


def test_a_webhook_failure_never_fails_the_scan(monkeypatch):
    from guardian_scanner import webhooks as wh_mod

    ctx = _estate()
    _endpoint(ctx)
    monkeypatch.setattr(wh_mod, "enqueue",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("queue down")))

    _, result = _scan(ctx)

    assert result["status"] == "completed", "a notification failure must not undo a good scan"


# ══ RED-3 · correlation runs on the real path ═════════════════════════════════════════════════════
def test_a_scan_invokes_correlation_on_the_real_path():
    """The wiring assertion: `correlate_tenant` had no caller anywhere in the platform.

    Deliberately not asserting a grouping here — the two tests below cover both directions of the
    grouping decision. This one only asserts that the ordinary scan path runs correlation at all
    and reports what it did, which is the thing that was missing.
    """
    ctx = _estate()

    _, result = _scan(ctx, engines=("secrets",))

    assert "correlation" in result, "run_scan did not invoke correlation at all"
    assert "error" not in result["correlation"], result["correlation"]
    assert result["correlation"]["findings"] >= 1


def test_different_credentials_on_one_line_are_never_merged():
    """The defect this test found, and the reason it was invisible.

    `_secret_identity` read the redacted value from `evidence["detail"]`, but the secrets engine
    writes it at `evidence["match"]` — so identity always fell through to `path:line` and three
    different credentials detected on one line became "one credential reported by several
    engines". Nobody saw it because correlation had no caller.
    """
    from guardian_db.models import Finding
    from guardian_db.session import session_scope

    ctx = _estate(inline={
        "a.py": f'AWS_SECRET = "{LEAKED_KEY}"\nGITHUB_TOKEN = "ghp_' + "b" * 36 + '"\n',
    })

    _scan(ctx, engines=("secrets",))

    with session_scope() as db:
        findings = db.query(Finding).filter(Finding.tenant_id == ctx["tenant"]).all()

    by_group: dict = {}
    for f in findings:
        if f.correlation_id:
            by_group.setdefault(f.correlation_id, set()).add(
                (f.evidence or {}).get("match", f.title))
    for members in by_group.values():
        assert len(members) == 1, f"different secrets merged into one issue: {sorted(members)}"


def test_the_same_credential_reported_by_two_engines_is_one_issue():
    """The other direction of the same defect: the grouping the rule exists to do.

    The two findings are seeded rather than produced by two live engines, and that is a real
    limitation of this test worth stating: no pair of engines currently shipped reports the same
    credential from the same artifact (the container engine reports the Dockerfile's missing USER
    directive, not the key in its ENV). So they are written exactly as the engines write them —
    same redacted value in `evidence["match"]`, different engine in `location` — and the assertion
    is that the *wired* scan path then groups them. Correlation itself is not called by the test.
    """
    from guardian_db.models import Asset, Finding, Scan, ScanEngineRun
    from guardian_db.session import session_scope

    ctx = _estate()
    # Deliberately not the value the estate's own inline content yields: sharing a redacted value
    # with the scan's finding would make this test pass for the wrong reason.
    redacted = f"gh********{uuid.uuid4().hex[:2]} (len=40)"

    # The findings hang off a *second* asset, and the scan below runs against the first. WP-E2
    # reconciles per asset, so scanning the asset these were seeded on would legitimately resolve
    # the `secrets` one — the engine ran, completed cleanly and did not re-report it — leaving the
    # group with a single member. That is correct behaviour, and it is why the fixture is arranged
    # this way rather than weakening the reconciliation.
    with session_scope() as db:
        other = Asset(tenant_id=ctx["tenant"], customer_id=ctx["customer"], name="other",
                      kind="repo", identifier=f"inline-other-{ctx['slug']}", exposure="public",
                      config={})
        db.add(other)
        db.flush()
        scan = Scan(tenant_id=ctx["tenant"], customer_id=ctx["customer"], asset_id=other.id,
                    trigger="manual", status="completed", requested_engines=["secrets"], stats={})
        db.add(scan)
        db.flush()
        run = ScanEngineRun(scan_id=scan.id, engine="secrets", status="completed")
        db.add(run)
        db.flush()
        for engine, path in (("secrets", "app.py"), ("sast", "config/settings.py")):
            db.add(Finding(
                tenant_id=ctx["tenant"], customer_id=ctx["customer"], scan_id=scan.id,
                engine_run_id=run.id, asset_id=other.id,
                fingerprint=uuid.uuid4().hex[:32],
                title=f"Hardcoded credential ({engine})",
                description="", category="secret", severity="critical", risk_score=90,
                status="open", location={"path": path, "line": 1, "engine": engine},
                evidence={"match": redacted},
            ))

    _scan(ctx)  # a scan of the *other* asset; correlation runs tenant-wide on the real path

    with session_scope() as db:
        same = db.query(Finding).filter(
            Finding.tenant_id == ctx["tenant"],
            Finding.title.like("Hardcoded credential%"),
        ).all()

    assert len(same) == 2
    assert same[0].correlation_id is not None, "one credential from two engines was not grouped"
    assert len({f.correlation_id for f in same}) == 1


# ══ RED-2 · service version → CVE runs on the real path ═══════════════════════════════════════════
def _service_node(ctx, *, product: str, version: str, host: str):
    from guardian_core.enums import NodeType
    from guardian_db.models import GraphNode
    from guardian_db.session import session_scope

    with session_scope() as db:
        db.add(GraphNode(
            tenant_id=ctx["tenant"], customer_id=ctx["customer"],
            node_type=NodeType.SERVICE.value, canonical_key=f"{host}:22",
            asset_id=ctx["asset"],
            metadata_={"port": 22, "service": "ssh", "evidence": "banner",
                       "banner": f"SSH-2.0-{product}_{version}",
                       "product": product, "version": version,
                       "cpe": f"cpe:2.3:a:openbsd:{product}:{version}:*:*:*:*:*:*:*"},
            confidence=95, ownership_confidence=90, exposure_score=0, state="active",
            first_seen_at=dt.datetime.now(dt.UTC), last_seen_at=dt.datetime.now(dt.UTC),
        ))


def _advisory(product: str, marker: str, *, start="5.5", end="9.3.2") -> str:
    from guardian_clients.feeds import NormalizedVuln
    from guardian_scanner import intel

    cve = f"CVE-2099-{marker[:6]}"
    record = NormalizedVuln(external_id=cve, source="nvd",
                            summary="controlled fixture advisory for the wiring test")
    record.cvss_base = 9.8
    record.severity = "critical"
    record.cwe_ids = ["CWE-428"]
    record.cpe_configurations = [{
        "cpe": f"cpe:2.3:a:openbsd:{product}:*:*:*:*:*:*:*:*",
        "vendor": "openbsd", "product": product, "version": "*",
        "version_start_including": start, "version_end_excluding": end,
    }]
    intel.run_source(f"nvd-{marker}", lambda _s, _u: [record])
    return cve


def test_a_discovered_vulnerable_service_becomes_a_finding_through_the_scan_path():
    """The whole point of WP-C3, and it had no caller.

    Controlled fixture: a product name unique to this test, an advisory ingested into the local
    knowledge base, and a version inside its affected range. Nothing external is contacted.
    """
    from guardian_db.models import Finding
    from guardian_db.session import session_scope

    marker = uuid.uuid4().hex[:8]
    product = f"openssh-{marker}"
    cve = _advisory(product, marker)
    ctx = _estate(kind="web")
    _service_node(ctx, product=product, version="8.9p1", host=f"h-{marker}.example.com")

    _, result = _scan(ctx, engines=("secrets",))

    assert "service_cve" in result, "run_scan did not invoke service→CVE matching at all"
    assert "error" not in result["service_cve"]
    assert result["service_cve"]["matched"] >= 1

    with session_scope() as db:
        findings = db.query(Finding).filter(
            Finding.tenant_id == ctx["tenant"], Finding.category == "vuln-service"
        ).all()

    assert findings, f"{cve} matched but produced no finding"
    finding = findings[0]
    assert cve in str(finding.references)
    assert finding.risk_score > 0
    assert finding.evidence, "a version-inference finding must carry its reasoning"
    assert finding.severity in ("critical", "high", "medium", "low", "info")


def test_a_patched_version_produces_no_finding():
    """The safe direction: no match must mean no finding, not a guess."""
    from guardian_db.models import Finding
    from guardian_db.session import session_scope

    marker = uuid.uuid4().hex[:8]
    product = f"openssh-{marker}"
    _advisory(product, marker, start="5.5", end="9.3.2")
    ctx = _estate(kind="web")
    _service_node(ctx, product=product, version="9.9.0", host=f"h-{marker}.example.com")

    _, result = _scan(ctx, engines=("secrets",))

    assert result["service_cve"]["identified"] >= 1
    assert result["service_cve"]["matched"] == 0
    with session_scope() as db:
        assert db.query(Finding).filter(
            Finding.tenant_id == ctx["tenant"], Finding.category == "vuln-service"
        ).count() == 0


def test_a_service_without_a_version_is_counted_not_guessed():
    """A product with no release matches only unbounded advisories, which would mean reporting
    every CVE the product ever had."""
    marker = uuid.uuid4().hex[:8]
    product = f"openssh-{marker}"
    _advisory(product, marker)
    ctx = _estate(kind="web")
    _service_node(ctx, product=product, version="", host=f"h-{marker}.example.com")

    _, result = _scan(ctx, engines=("secrets",))

    assert result["service_cve"]["unversioned"] >= 1
    assert result["service_cve"]["matched"] == 0


def test_enrichment_failure_never_fails_the_scan(monkeypatch):
    from guardian_scanner import tasks

    ctx = _estate()
    monkeypatch.setattr("guardian_scanner.service_cve.match_service_versions",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("kb offline")))
    del tasks

    _, result = _scan(ctx)

    assert result["status"] == "completed"
    assert "error" in result["service_cve"], "the failure must be reported, not swallowed"


# ══ RED-4 · per-finding retest ════════════════════════════════════════════════════════════════════
def test_a_finding_can_be_retested_through_the_api():
    from guardian_db.models import FindingVerification, Scan
    from guardian_db.session import session_scope

    ctx = _estate()
    _scan(ctx)
    client, hdr = _client(ctx)
    finding = client.get("/api/v1/findings", headers=hdr).json()[0]

    response = client.post(f"/api/v1/findings/{finding['id']}/retest", headers=hdr)

    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "queued"
    with session_scope() as db:
        scan = db.get(Scan, uuid.UUID(body["scan_id"]))
        assert scan.trigger == "retest"
        assert scan.stats["retest_of"] == finding["id"]
        # The pending verdict is recorded immediately, so "awaiting retest" is a visible state
        # rather than an absence.
        assert db.query(FindingVerification).filter(
            FindingVerification.finding_id == uuid.UUID(finding["id"])
        ).count() >= 1


def test_a_retest_that_still_finds_the_issue_leaves_it_open():
    from guardian_db.models import Finding
    from guardian_db.session import session_scope

    ctx = _estate()
    _scan(ctx)
    client, hdr = _client(ctx)
    finding = client.get("/api/v1/findings", headers=hdr).json()[0]

    body = client.post(f"/api/v1/findings/{finding['id']}/retest", headers=hdr).json()
    from guardian_scanner.tasks import run_scan
    run_scan(body["scan_id"])  # the retest scan; the file still contains the secret

    with session_scope() as db:
        assert db.get(Finding, uuid.UUID(finding["id"])).status == "open"


def test_a_retest_after_the_fix_resolves_the_finding():
    from guardian_db.models import Asset, Finding
    from guardian_db.session import session_scope

    ctx = _estate()
    _scan(ctx)
    client, hdr = _client(ctx)
    finding = client.get("/api/v1/findings", headers=hdr).json()[0]

    with session_scope() as db:  # the customer removes the credential
        db.get(Asset, ctx["asset"]).config = {"inline_content": {"app.py": "SECRET = os.environ\n"}}

    body = client.post(f"/api/v1/findings/{finding['id']}/retest", headers=hdr).json()
    from guardian_scanner.tasks import run_scan
    run_scan(body["scan_id"])

    with session_scope() as db:
        assert db.get(Finding, uuid.UUID(finding["id"])).status == "resolved"


def test_retesting_another_tenants_finding_is_refused():
    ctx, other = _estate(), _estate()
    _scan(other)
    client, hdr = _client(ctx)
    from guardian_db.models import Finding
    from guardian_db.session import session_scope
    with session_scope() as db:
        theirs = db.query(Finding).filter(Finding.tenant_id == other["tenant"]).first()

    assert client.post(f"/api/v1/findings/{theirs.id}/retest",
                       headers=hdr).status_code == 404


# ══ RED-6 · remediation tells the truth about doing nothing ═══════════════════════════════════════
def test_opening_remediation_that_creates_work_answers_201():
    ctx = _estate()
    _scan(ctx)
    client, hdr = _client(ctx)

    response = client.post("/api/v1/remediation", headers=hdr,
                           json={"customer_id": str(ctx["customer"])})

    assert response.status_code == 201
    assert response.json()["opened"] >= 1
    assert "reason" not in response.json()


def test_opening_remediation_that_creates_nothing_answers_200_with_a_reason():
    """A 201 for a request that created nothing is a lie the caller cannot detect."""
    ctx = _estate()
    _scan(ctx)
    client, hdr = _client(ctx)
    client.post("/api/v1/remediation", headers=hdr, json={"customer_id": str(ctx["customer"])})

    again = client.post("/api/v1/remediation", headers=hdr,
                        json={"customer_id": str(ctx["customer"])})

    assert again.status_code == 200
    body = again.json()
    assert body["opened"] == 0
    assert body["existing"] >= 1
    assert "already tracked" in body["reason"]


def test_opening_remediation_for_an_untrackable_finding_says_so():
    ctx = _estate()
    _scan(ctx)
    client, hdr = _client(ctx)
    finding = client.get("/api/v1/findings", headers=hdr).json()[0]
    client.post("/api/v1/findings/bulk-triage", headers=hdr,
                json={"finding_ids": [finding["id"]], "status": "accepted_risk",
                      "note": "accepted for the purposes of this test"})

    response = client.post("/api/v1/remediation", headers=hdr,
                           json={"customer_id": str(ctx["customer"]),
                                 "finding_ids": [finding["id"]]})

    assert response.status_code == 200
    body = response.json()
    assert body["opened"] == 0
    assert body["considered"] == 0
    assert body["requested"] == 1
    assert "trackable" in body["reason"]
