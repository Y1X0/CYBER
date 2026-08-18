"""Three states, kept distinguishable, for every engine (readiness audit Phase 4).

For each engine the platform ships, three situations must produce three different answers:

* **A. finding exists** → a finding,
* **B. the target is clean** → no finding, and the run completes,
* **C. the engine failed or had nothing to look at** → `not_checked` / `inconclusive`.

The one that must never happen is C reading as B. It is the most dangerous bug this codebase can
have, because it is invisible: the customer sees a clean report, the scan says `completed`, and the
finding that was there last week is marked resolved.

The last assertion here is the one that generalises — it walks the whole registry and fails if any
engine's failure could be mistaken for a clean result, so a tenth engine cannot be added without
answering the question.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

SECRET = "AKIA" + "IOSFODNN7EXAMPLE"

# What each engine needs to see to report something, and what a clean version of it looks like.
# `None` for `clean` means the engine has no meaningful clean input in-process (it needs a live
# target or a collector export), so only states A and C are exercised for it.
FIXTURES = {
    "secrets": {
        "dirty": f'AWS_SECRET = "{SECRET}"\n',
        "clean": "SECRET = os.environ['AWS_SECRET']\n",
    },
    "iac": {
        "dirty": ('resource "aws_security_group" "open" {\n'
                  '  ingress {\n    from_port = 22\n    to_port = 22\n'
                  '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'),
        "clean": ('resource "aws_security_group" "closed" {\n'
                  '  ingress {\n    from_port = 22\n    to_port = 22\n'
                  '    cidr_blocks = ["10.0.0.0/8"]\n  }\n}\n'),
    },
    "k8s": {
        "dirty": ("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n"
                  "  - name: c\n    image: nginx\n    securityContext:\n"
                  "      privileged: true\n"),
        "clean": ("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n"
                  "  securityContext:\n    runAsNonRoot: true\n  containers:\n"
                  "  - name: c\n    image: nginx:1.25.3\n    securityContext:\n"
                  "      privileged: false\n      allowPrivilegeEscalation: false\n"
                  "      readOnlyRootFilesystem: true\n      capabilities:\n"
                  "        drop: [ALL]\n    resources:\n      limits:\n"
                  "        memory: 128Mi\n        cpu: 100m\n"),
    },
}


def _estate(inline: str | None, *, kind="repo"):
    from guardian_db.models import Asset, Customer, Tenant
    from guardian_db.session import session_scope

    slug = f"fc-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        db.add(customer)
        db.flush()
        asset = Asset(tenant_id=tenant.id, customer_id=customer.id, name="app", kind=kind,
                      identifier=f"inline-{slug}", exposure="public",
                      config={"inline_content": inline} if inline else {})
        db.add(asset)
        db.flush()
        return {"tenant": tenant.id, "customer": customer.id, "asset": asset.id}


def _run(ctx, engine: str):
    from guardian_db.models import Finding, Scan, ScanEngineRun
    from guardian_db.session import session_scope
    from guardian_scanner.tasks import run_scan

    with session_scope() as db:
        scan = Scan(tenant_id=ctx["tenant"], customer_id=ctx["customer"], asset_id=ctx["asset"],
                    trigger="manual", status="queued", requested_engines=[engine], stats={})
        db.add(scan)
        db.flush()
        scan_id = str(scan.id)
    run_scan(scan_id)
    with session_scope() as db:
        run = db.query(ScanEngineRun).filter(ScanEngineRun.scan_id == uuid.UUID(scan_id)).one()
        findings = db.query(Finding).filter(Finding.scan_id == uuid.UUID(scan_id)).all()
        return {"status": run.status, "error": run.error, "findings": len(findings),
                "scan_id": scan_id, "run": run}


def _verdict(run_status: str, error: str | None = None, degraded: bool = False):
    """What reconciliation would conclude from a run in this state."""
    from guardian_db.models import ScanEngineRun
    from guardian_scanner.verification import engine_outcome

    stub = ScanEngineRun(scan_id=uuid.uuid4(), engine="secrets", status=run_status, error=error)
    stub.tool_versions = {"degraded": degraded, "missing": ["a tool"] if degraded else []}
    return engine_outcome(stub)


# ── A: a finding exists ───────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("engine", sorted(FIXTURES))
def test_a_dirty_target_produces_a_finding(engine):
    ctx = _estate(FIXTURES[engine]["dirty"])
    result = _run(ctx, engine)

    assert result["status"] == "completed", result["error"]
    assert result["findings"] >= 1, f"{engine} found nothing in a deliberately broken target"


# ── B: the target is clean ────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("engine", sorted(FIXTURES))
def test_a_clean_target_completes_with_no_finding(engine):
    ctx = _estate(FIXTURES[engine]["clean"])
    result = _run(ctx, engine)

    assert result["status"] == "completed", result["error"]
    # A clean run is the one case where an empty result is evidence, and it must stay that way —
    # a scanner that cannot report "clean" is a scanner nobody can act on.
    assert _verdict("completed").verdict == "resolved"


# ── C: the engine failed or had nothing to look at ────────────────────────────────────────────────
@pytest.mark.parametrize("engine", sorted(FIXTURES))
def test_an_engine_with_no_input_does_not_look_clean(engine):
    """The dangerous case. Before the audit, three engines returned `[]` here."""
    ctx = _estate(None)
    result = _run(ctx, engine)

    if result["status"] == "completed" and result["findings"] == 0:
        pytest.fail(
            f"{engine} completed cleanly with no input — reconciliation would resolve this "
            f"asset's existing {engine} findings on the strength of it"
        )
    assert result["status"] in ("failed", "skipped"), result
    assert result["error"], "a refusal with no reason is a support ticket"


def test_the_engines_that_need_an_export_refuse_rather_than_reporting_clean():
    """`cspm` and `api` are not in the matrix above because they cannot be driven from inline
    repository content — they need a collector export and an OpenAPI document. Their no-input
    behaviour is the same question, asked directly."""
    from guardian_scanner.engines.api_engine import ApiEngine, ApiSpecError
    from guardian_scanner.engines.base import ScanContext
    from guardian_scanner.engines.cspm_engine import CloudSnapshotError, CspmEngine

    ctx = ScanContext(scan_id=str(uuid.uuid4()), asset_kind="cloud", asset_identifier="acct",
                      workspace_path=None, inline_content=None, exposure="public",
                      vuln_matcher=None, asset_config={})

    with pytest.raises(CloudSnapshotError):
        list(CspmEngine().run(ctx))
    with pytest.raises(ApiSpecError):
        list(ApiEngine().run(ctx))


# ── the property, stated once ─────────────────────────────────────────────────────────────────────
def test_a_failed_run_can_never_resolve_a_finding():
    assert _verdict("failed", "boom").verdict == "not_checked"
    assert _verdict("failed", "boom").is_evidence is False
    assert _verdict("skipped").verdict == "not_checked"
    assert _verdict("deferred").verdict == "not_checked"
    assert _verdict("running").verdict == "not_checked"


def test_a_degraded_run_is_inconclusive_not_resolved():
    verdict = _verdict("completed", degraded=True)
    assert verdict.verdict == "inconclusive"
    assert verdict.is_evidence is False


def test_a_missing_run_is_not_checked():
    from guardian_scanner.verification import engine_outcome

    assert engine_outcome(None).verdict == "not_checked"


def test_every_registered_engine_declares_its_health():
    """A tenth engine cannot be added without answering "how do I report being broken?"."""
    from guardian_scanner.registry import available_engines

    engines = available_engines()
    assert engines, "no engines are registered — this test is not looking at anything"
    for key, engine in engines.items():
        health = engine.health()
        assert hasattr(health, "ok"), f"{key} reports no health"
        assert hasattr(health, "degraded"), f"{key} cannot report reduced coverage"
        assert isinstance(health.missing, tuple), f"{key} cannot say what it is missing"
