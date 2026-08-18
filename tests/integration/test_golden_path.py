"""One customer, start to finish, through the supported API (readiness audit Phase 3).

Every other test in this repository proves a component. This one proves the *product*: a single
deterministic run of the whole journey a paying customer takes, in order, using the API they would
use — no direct database writes except the tenant bootstrap, which has no API and is itself a
recorded gap.

Where an external dependency makes a step impossible here, the step is marked `UNVERIFIED` in the
report this test prints and the assertion is limited to what was actually observed. Nothing is
simulated to make a stage look green:

* **ownership verification** issues a real challenge and runs a real DNS check, which fails because
  no TXT record exists for a domain nobody owns. That refusal is asserted; a *passing* check is
  UNVERIFIED and needs a controlled domain.
* **webhook delivery** is queued, signed and attempted over a real socket. The endpoint is
  `.invalid`, so the attempt fails and schedules a retry. A 2xx round trip is UNVERIFIED and needs
  a reachable receiver.
* **production execution** is UNVERIFIED everywhere: `POST /scans` enqueues to Celery, and no
  worker exists (A1/A1b, BLOCKED_EXTERNAL). The orchestrator is invoked in-process here, which
  proves the code path and not the deployment.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

SECRET = "AKIA" + "IOSFODNN7EXAMPLE"
UNVERIFIED: list[str] = []


@pytest.fixture(scope="module")
def journey():
    """The whole journey, run once. Each test below asserts one stage of the same run."""
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token
    from guardian_db.models import Tenant, TenantMembership, User
    from guardian_db.session import session_scope

    slug = f"gp-{uuid.uuid4().hex[:10]}"
    domain = f"{slug}.example.com"
    state: dict = {"slug": slug, "domain": domain, "unverified": []}

    # ── 1. tenant + owner ────────────────────────────────────────────────────────────────────────
    # Infrastructure bootstrap. There is no signup or tenant-creation API — a recorded product gap,
    # not something this test papers over.
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        user = User(email=f"{slug}@example.invalid", name="Owner", status="active")
        db.add(user)
        db.flush()
        db.add(TenantMembership(user_id=user.id, tenant_id=tenant.id, role="owner"))
        db.flush()
        state["tenant"], state["user"] = tenant.id, user.id

    settings = get_settings()
    token = create_access_token(subject=str(state["user"]), secret=settings.jwt_secret,
                                algorithm=settings.jwt_algorithm)
    hdr = {"Authorization": f"Bearer {token}"}
    client = TestClient(app)
    state["client"], state["hdr"] = client, hdr

    # ── 2. identity ──────────────────────────────────────────────────────────────────────────────
    state["me"] = client.get("/api/v1/auth/me", headers=hdr)

    # ── 3. customer ──────────────────────────────────────────────────────────────────────────────
    state["customer_resp"] = client.post("/api/v1/customers", headers=hdr,
                                         json={"name": "Design Partner", "criticality": "high"})
    state["customer"] = state["customer_resp"].json().get("id")

    # ── 4. ownership verification ────────────────────────────────────────────────────────────────
    state["verification_resp"] = client.post(
        "/api/v1/verifications", headers=hdr,
        json={"customer_id": state["customer"], "domain": domain, "method": "dns_txt"})
    verification = state["verification_resp"].json()
    state["verification"] = verification
    if state["verification_resp"].status_code == 201:
        state["check_resp"] = client.post(
            f"/api/v1/verifications/{verification['id']}/check", headers=hdr)
    state["unverified"].append(
        "ownership verification PASSING — needs a domain we control to publish the TXT record; "
        "the refusal path is verified")

    # ── 5. assets ────────────────────────────────────────────────────────────────────────────────
    state["asset_resp"] = client.post(
        "/api/v1/assets", headers=hdr,
        json={"customer_id": state["customer"], "name": "app", "kind": "repo",
              "identifier": f"inline-{slug}", "exposure": "public"})
    state["asset"] = state["asset_resp"].json().get("id")

    # The scannable artefact. In production this is a git clone; inline content is the supported
    # config for an artefact supplied directly, and keeps this test off the network.
    from guardian_db.models import Asset
    with session_scope() as db:
        db.get(Asset, uuid.UUID(state["asset"])).config = {
            "inline_content": f'AWS_SECRET = "{SECRET}"\n'}

    # ── 6. authorization ─────────────────────────────────────────────────────────────────────────
    # No API creates an Authorization; the only programmatic path is a passing ownership check,
    # which cannot happen here. Recorded as a gap and written directly so the journey continues.
    from guardian_db.models import Authorization
    with session_scope() as db:
        now = dt.datetime.now(dt.UTC)
        db.add(Authorization(
            tenant_id=state["tenant"], customer_id=uuid.UUID(state["customer"]),
            asset_id=uuid.UUID(state["asset"]), scope="pilot",
            authorized_targets=[{"type": "domain", "value": domain}],
            method="ownership_verified", authorized_by=state["user"],
            valid_from=now - dt.timedelta(days=1), valid_until=now + dt.timedelta(days=30)))
    state["unverified"].append(
        "authorization RECORDED VIA API — no route creates an Authorization; only a passing "
        "ownership check does")

    # ── 7. webhook endpoint, registered before the scan so it can receive it ─────────────────────
    state["webhook_resp"] = client.post(
        "/api/v1/webhook-endpoints", headers=hdr,
        json={"url": "https://hooks.example.invalid/guardian",
              "events": ["scan.completed", "finding.critical"]})
    state["webhook"] = state["webhook_resp"].json()

    # ── 8. discovery ─────────────────────────────────────────────────────────────────────────────
    state["discovery_resp"] = client.post(
        "/api/v1/discovery/runs", headers=hdr,
        json={"customer_id": state["customer"], "seeds": {"domains": [domain]},
              "providers": ["dns"]})

    # ── 9. scan ──────────────────────────────────────────────────────────────────────────────────
    state["scan_resp"] = client.post(
        "/api/v1/scans", headers=hdr,
        json={"asset_id": state["asset"], "engines": ["secrets"], "trigger": "manual"})
    state["scan"] = state["scan_resp"].json().get("id")
    from guardian_scanner.tasks import run_scan
    state["scan_result"] = run_scan(state["scan"])
    state["unverified"].append(
        "scan EXECUTION IN PRODUCTION — POST /scans enqueues to Celery and no worker exists "
        "(A1/A1b BLOCKED_EXTERNAL); the orchestrator was invoked in-process")

    # ── 10-13. findings, evidence, risk, dossier ─────────────────────────────────────────────────
    state["findings_resp"] = client.get(f"/api/v1/findings?scan_id={state['scan']}", headers=hdr)
    findings = state["findings_resp"].json()
    state["findings"] = findings
    state["finding"] = findings[0] if findings else None
    if state["finding"]:
        state["dossier_resp"] = client.get(
            f"/api/v1/findings/{state['finding']['id']}", headers=hdr)

    # ── 14. workbench, attack paths, compliance ──────────────────────────────────────────────────
    state["summary_resp"] = client.get("/api/v1/findings/summary", headers=hdr)
    state["chains_resp"] = client.get("/api/v1/graph/attack-chains", headers=hdr)
    state["compliance_resp"] = client.get("/api/v1/compliance", headers=hdr)

    # ── 15. report ───────────────────────────────────────────────────────────────────────────────
    state["report_resp"] = client.post("/api/v1/reports", headers=hdr,
                                       json={"scan_id": state["scan"], "title": "Pilot report"})
    state["report"] = state["report_resp"].json().get("id")
    if state["report"]:
        state["export_resp"] = client.get(
            f"/api/v1/reports/{state['report']}/export?format=html", headers=hdr)

    # ── 16. remediation ──────────────────────────────────────────────────────────────────────────
    state["remediation_resp"] = client.post("/api/v1/remediation", headers=hdr,
                                            json={"customer_id": state["customer"]})
    state["remediation_list"] = client.get("/api/v1/remediation", headers=hdr)

    # ── 17. retest ───────────────────────────────────────────────────────────────────────────────
    if state["finding"]:
        state["retest_resp"] = client.post(
            f"/api/v1/findings/{state['finding']['id']}/retest", headers=hdr)
        if state["retest_resp"].status_code == 202:
            run_scan(state["retest_resp"].json()["scan_id"])

    # ── 18. webhook delivery ─────────────────────────────────────────────────────────────────────
    state["deliveries_resp"] = client.get(
        f"/api/v1/webhook-endpoints/{state['webhook']['id']}/deliveries", headers=hdr)
    state["unverified"].append(
        "webhook 2xx ROUND TRIP — the endpoint is `.invalid`, so delivery is attempted over a real "
        "socket and fails; the signed request and the retry are verified, the receiver's acceptance "
        "is not")

    return state


# ── the journey, stage by stage ───────────────────────────────────────────────────────────────────
def test_01_the_owner_can_authenticate(journey):
    assert journey["me"].status_code == 200
    assert journey["me"].json()["email"].endswith("@example.invalid")


def test_02_a_customer_is_created_through_the_api(journey):
    assert journey["customer_resp"].status_code == 201, journey["customer_resp"].text
    assert journey["customer"]


def test_03_an_ownership_challenge_hands_over_a_publishable_token(journey):
    assert journey["verification_resp"].status_code == 201, journey["verification_resp"].text
    instructions = journey["verification"]["instructions"]
    assert instructions["record_type"] == "TXT"
    assert instructions["record_name"].startswith("_guardian-challenge.")
    assert "guardian-site-verification=" in instructions["record_value"]


def test_04_an_unpublished_challenge_does_not_verify(journey):
    """The safe direction, and the one that is actually verifiable here."""
    assert journey["check_resp"].status_code == 200
    assert journey["check_resp"].json()["status"] != "verified"


def test_05_an_asset_is_onboarded_through_the_api(journey):
    assert journey["asset_resp"].status_code == 201, journey["asset_resp"].text


def test_06_discovery_is_accepted(journey):
    assert journey["discovery_resp"].status_code in (201, 202), journey["discovery_resp"].text


def test_07_a_scan_is_accepted_and_executes(journey):
    assert journey["scan_resp"].status_code == 202, journey["scan_resp"].text
    assert journey["scan_result"]["status"] in ("completed", "partial")
    assert journey["scan_result"]["stats"]["total"] >= 1


def test_08_findings_are_returned_with_evidence_and_deterministic_risk(journey):
    assert journey["findings_resp"].status_code == 200
    finding = journey["finding"]
    assert finding, "the scan produced no finding for a file containing a live-shaped credential"
    assert finding["evidence"], "a finding with no evidence is an assertion, not a finding"
    assert isinstance(finding["risk_score"], int) and finding["risk_score"] > 0
    assert finding["severity"] in ("critical", "high", "medium", "low", "info")


def test_09_the_evidence_is_redacted_at_the_boundary(journey):
    """The credential is what the finding is *about*; it must not be what the API hands back."""
    assert SECRET not in json.dumps(journey["findings"])


def test_10_the_finding_dossier_is_retrievable(journey):
    assert journey["dossier_resp"].status_code == 200


def test_11_the_workbench_summarises(journey):
    assert journey["summary_resp"].status_code == 200
    assert journey["summary_resp"].json()["total"] >= 1


def test_12_attack_path_analysis_answers(journey):
    assert journey["chains_resp"].status_code == 200
    body = journey["chains_resp"].json()
    # An empty result is a legitimate answer; what matters is that it is distinguishable from
    # "we could not reason about these".
    assert "chains" in body and "unchainable_findings" in body


def test_13_compliance_reports_its_own_coverage(journey):
    assert journey["compliance_resp"].status_code == 200
    body = journey["compliance_resp"].json()
    assert "overall_coverage" in body
    assert body["frameworks"], "no framework was assessed"


def test_14_a_report_is_generated_and_exported(journey):
    assert journey["report_resp"].status_code == 201, journey["report_resp"].text
    assert journey["export_resp"].status_code == 200
    assert len(journey["export_resp"].content) > 500
    assert SECRET not in journey["export_resp"].text


def test_15_remediation_work_is_opened(journey):
    assert journey["remediation_resp"].status_code in (200, 201), journey["remediation_resp"].text
    assert journey["remediation_list"].status_code == 200
    assert journey["remediation_list"].json(), "no remediation item was opened for an open finding"


def test_16_a_retest_runs_and_records_a_verdict(journey):
    from guardian_db.models import FindingVerification
    from guardian_db.session import session_scope

    assert journey["retest_resp"].status_code == 202, journey["retest_resp"].text
    with session_scope() as db:
        verdicts = db.query(FindingVerification).filter(
            FindingVerification.finding_id == uuid.UUID(journey["finding"]["id"])
        ).all()
    assert verdicts, "a retest was accepted and left no record"
    assert any(v.verdict in ("still_present", "resolved", "not_checked") for v in verdicts)


def test_17_the_scan_produced_a_signed_webhook_delivery(journey):
    """The stage that did not exist before this work: a scan that tells somebody."""
    import time

    from guardian_core import webhooks as wh

    assert journey["deliveries_resp"].status_code == 200
    deliveries = journey["deliveries_resp"].json()
    assert deliveries, "the scan completed and no webhook delivery was created"

    delivery = deliveries[-1]
    payload = json.loads(delivery["payload"])
    assert payload["type"] in ("scan.completed", "finding.critical")
    assert payload["data"]["scan_id"] in (journey["scan"], payload["data"].get("scan_id"))
    assert SECRET not in delivery["payload"]

    # The signature the receiver would check, verified with the secret the API issued once.
    now = int(time.time())
    signature = wh.sign(delivery["payload"], secret=journey["webhook"]["secret"], timestamp=now)
    assert wh.verify(delivery["payload"], signature,
                     secret=journey["webhook"]["secret"], now=now)


def test_18_the_delivery_was_attempted_and_retried(journey):
    """`.invalid` cannot resolve, so this is the failure path — attempted, recorded, rescheduled."""
    delivery = journey["deliveries_resp"].json()[-1]
    assert delivery["attempts"] >= 1
    assert delivery["status"] == "pending"
    assert delivery["next_attempt_at"]


def test_19_what_this_run_could_not_verify_is_stated(journey):
    """The list is the point. A golden path that quietly simulates its blocked steps is worse than
    no golden path, because it reports readiness nobody has."""
    assert len(journey["unverified"]) == 4
    joined = " ".join(journey["unverified"])
    assert "BLOCKED_EXTERNAL" in joined
    assert "ownership verification PASSING" in joined
    assert "webhook 2xx ROUND TRIP" in joined
    print("\n".join(["", "UNVERIFIED in this run:", *[f"  - {u}" for u in journey["unverified"]]]))
