"""Tool execution pipeline (Framework Phase 1) — Control Plane governs, execution plane is dumb.

Two tasks, two planes (generalizing 6C.4):

  * `dispatch_tool_job` — TRUSTED Control Plane (default queue, DB). Loads authorizations,
    derives the EffectiveScope (never wider than the authorization), runs the deterministic policy
    gate (+ human-approval boundary), audits the decision, dispatches the job, and persists the
    returned evidence as a hash chain. It is the ONLY place authorization/scope/policy is decided.
  * `run_tool` — EXECUTION plane (tools queue, NO DB/KMS/RLS). Runs the provider in the mandatory
    sandbox with egress bound to the scope, and RETURNS RawEvidence. It knows nothing about tenants,
    findings, assets, or the database — so a compromise inside a tool finds no crown jewels.

No tool ships in Phase 1; this is the governed rail. Human approval is required for active/network
destructive tools before a job is dispatched.
"""

from __future__ import annotations

import datetime as dt
import uuid

from guardian_common.config import get_settings
from guardian_common.logging import get_logger
from guardian_core.tool import (
    ToolJob,
    derive_effective_scope,
    evaluate_tool_policy,
    evidence_from_wire,
    evidence_to_wire,
    job_from_wire,
    job_to_wire,
)
from guardian_db.audit import record_audit
from guardian_db.models import Authorization, Customer, Scan, ScanEngineRun
from guardian_db.session import session_scope
from sqlalchemy import select

from guardian_scanner.celery_app import celery_app

log = get_logger("guardian.tools")


def _enforce_tool_plane(*, expect_tool: bool) -> None:
    """Pin a task to its plane; a misroute fails loudly. Skipped under eager (tests)."""
    if celery_app.conf.task_always_eager:
        return
    if get_settings().tool_plane != expect_tool:
        role = "run_tool (tools plane)" if expect_tool else "dispatch_tool_job (Control Plane)"
        raise RuntimeError(f"{role} was routed to the wrong plane")


@celery_app.task(name="guardian.run_tool")
def run_tool(job_wire: dict) -> list[dict]:
    """EXECUTION PLANE (no DB): run the provider in the sandbox, return RawEvidence."""
    _enforce_tool_plane(expect_tool=True)
    from guardian_scanner.tools import registry
    from guardian_scanner.tools.execution import execute_tool

    job: ToolJob = job_from_wire(job_wire)
    provider = registry.tool_for(job.tool_key)
    if provider is None:
        return []
    evidence = execute_tool(provider, job)
    return [evidence_to_wire(e) for e in evidence]


def _authorized_target_values(session, tenant_id: uuid.UUID, now: dt.datetime) -> list[str]:
    """The target VALUES a valid, non-revoked authorization already cleared for this tenant."""
    rows = session.execute(
        select(Authorization).where(
            Authorization.tenant_id == tenant_id,
            Authorization.revoked_at.is_(None),
            Authorization.valid_from <= now, Authorization.valid_until >= now,
        )
    ).scalars()
    values: set[str] = set()
    for a in rows:
        for t in a.authorized_targets or []:
            if t.get("value"):
                values.add(str(t["value"]))
    return sorted(values)


@celery_app.task(name="guardian.dispatch_tool_job", bind=True)
def dispatch_tool_job(  # noqa: ANN001, PLR0913
    self, tenant_id: str, tool_key: str, requested_targets: list[str],
    human_approved: bool = False, settings: dict | None = None, policy: dict | None = None,
) -> dict:
    """TRUSTED Control Plane: authorize → scope → policy → dispatch → persist evidence chain."""
    _enforce_tool_plane(expect_tool=False)
    from guardian_scanner.tools import registry
    from guardian_scanner.tools.evidence import persist_evidence_chain

    caps = registry.capabilities_for(tool_key)
    if caps is None:
        return {"status": "unknown_tool", "tool": tool_key}

    tid = uuid.UUID(tenant_id)
    now = dt.datetime.now(dt.UTC)

    # Control Plane derives scope (never wider than authorization) and runs the deterministic gate.
    with session_scope() as session:
        authorized = _authorized_target_values(session, tid, now)
        scope = derive_effective_scope(requested_targets or [], authorized, caps, policy)
        decision = evaluate_tool_policy(caps, scope, human_approved=human_approved)
        record_audit(
            session, action="tool.job.decision", tenant_id=tid, entity_type="tool_job",
            entity_id=tool_key,
            metadata={"allowed": decision.allowed,
                      "requires_approval": decision.requires_human_approval,
                      "reasons": list(decision.reasons), "targets": list(scope.targets)},
        )
        if not decision.allowed:
            return {"status": "denied", "tool": tool_key, "reasons": list(decision.reasons),
                    "requires_human_approval": decision.requires_human_approval}

    job = ToolJob(tenant_id=tenant_id, job_id=uuid.uuid4().hex, tool_key=tool_key,
                  scope=scope, settings=settings or {})

    # Execution plane (no DB) → RawEvidence via result-return.
    wire = run_tool.apply_async(args=[job_to_wire(job)], queue="tools").get(
        timeout=300, disable_sync_subtasks=False
    )
    evidences = [evidence_from_wire(w) for w in wire or []]

    # Evidence-first: persist the hash chain (primary truth), THEN derive findings only where the
    # evidence binds to exactly one asset. Evidence-only when there is no asset or more than one.
    with session_scope() as session:
        ids = persist_evidence_chain(session, tenant_id=tid, evidences=evidences)
        bound = _bind_and_derive_findings(session, tid, tool_key, evidences)

    # Auto-enrich the graph per bound customer (trusted plane, 6E) — evidence → finding → graph.
    from guardian_scanner.discovery.tasks import enrich_graph
    for cid in sorted({c for c, _ in bound}):
        enrich_graph.apply_async(args=[str(tid), cid])

    findings = sum(n for _, n in bound)
    log.info("tool_job_done", tool=tool_key, evidence=len(ids),
             assets_bound=len(bound), findings=findings)
    return {"status": "completed", "tool": tool_key, "job_id": job.job_id,
            "evidence": len(ids), "assets_bound": len(bound), "findings": findings,
            "requires_human_approval": decision.requires_human_approval}


def _bind_and_derive_findings(session, tenant_id, tool_key, evidences):  # noqa: ANN001, ANN202
    """Evidence-first finding derivation. Returns [(customer_id, findings_count)] for bound assets.

    Groups evidence by host; for a host that binds to EXACTLY one web/api asset, reuses
    Scan/ScanEngineRun(engine=tool_key) + the provider's deterministic normalize → to_finding. A
    host with zero or 2+ matching assets stays Evidence-only (no Scan, no Finding).
    """
    from guardian_scanner.normalize import to_finding
    from guardian_scanner.tools import registry
    from guardian_scanner.tools.binding import resolve_asset

    provider = registry.tool_for(tool_key)
    if provider is None:
        return []

    by_host: dict[str, list] = {}
    for e in evidences:
        by_host.setdefault(e.target, []).append(e)

    bound: list[tuple[str, int]] = []
    for host, host_evidence in sorted(by_host.items()):
        asset = resolve_asset(session, tenant_id=tenant_id, host=host)
        if asset is None:
            continue  # Evidence-only: no asset or ambiguous — never a guessed binding
        customer = session.get(Customer, asset.customer_id)
        criticality = customer.criticality if customer is not None else "medium"

        scan = Scan(tenant_id=tenant_id, customer_id=asset.customer_id, asset_id=asset.id,
                    trigger="tool", status="completed", requested_engines=[tool_key])
        session.add(scan)
        session.flush()
        run = ScanEngineRun(scan_id=scan.id, engine=tool_key[:30], status="completed",
                            tool_versions={tool_key: provider.version})
        session.add(run)
        session.flush()

        count = 0
        for e in host_evidence:
            raw = provider.normalize(e)
            if raw is None:
                continue
            session.add(to_finding(
                raw, tenant_id=tenant_id, customer_id=asset.customer_id, scan_id=scan.id,
                engine_run_id=run.id, asset_id=asset.id, exposure=asset.exposure,
                asset_criticality=criticality, business_impact=criticality,
            ))
            count += 1
        bound.append((str(asset.customer_id), count))
    return bound
