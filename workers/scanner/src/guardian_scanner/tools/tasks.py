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

import base64
import datetime as dt
import json
import uuid
from dataclasses import replace

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
from guardian_db.models import Asset, Authorization, Customer, Scan, ScanEngineRun, ToolCatalog
from guardian_db.session import session_scope
from sqlalchemy import select

from guardian_scanner.celery_app import celery_app
from guardian_scanner.tools.governance import evaluate_governance

log = get_logger("guardian.tools")

# Inline artifact transport cap (Provider #2). A raw artifact above this is rejected fail-closed,
# BEFORE any execution — the artifact travels inline in the ToolJob (no object storage, no table).
_ARTIFACT_MAX_BYTES = 2 * 1024 * 1024

# Per-tool finding binders. Strict tools create a Scan/Finding ONLY when a finding is derived
# (ADR-0019); web_tls keeps its eager default binder (reconciliation deferred). Populated below.
_BINDERS: dict = {}

# Default execution backend per tool when the catalog does not override it. External binaries get
# the kernel-isolating uid+nft backend; everything else stays in-process. Admins can override via
# tool_catalog.metadata["execution_backend"].
_DEFAULT_BACKENDS = {"nmap": "uid_nft"}

# Broker confidentiality (P1-4): sensitive DATA fields that must NEVER sit plaintext in the
# broker/result backend. They are Fernet-encrypted (reusing GUARDIAN_ENCRYPTION_KEY, already on
# every plane) before the job is signed, and decrypted on the tool plane after verification. The
# CONTROL fields (_execution_backend, allow_live, actor_id, campaign/approval) stay plaintext inside
# the signed payload — the Phase-C property that no security field lives outside the signature.
_SEALED_SETTING_KEYS = ("artifact_b64", "snapshot", "xml", "ct")


def _seal(value) -> str:  # noqa: ANN001
    from guardian_common.crypto import encrypt_secret
    return encrypt_secret(json.dumps(value, separators=(",", ":")))


def _unseal(token: str):  # noqa: ANN201
    from guardian_common.crypto import decrypt_secret
    raw = decrypt_secret(token)
    if raw is None:
        raise ValueError("sealed payload could not be decrypted")
    return json.loads(raw)


def _seal_settings(settings: dict) -> dict:
    """Move each sensitive DATA field into an encrypted `_sealed` map — nothing sensitive stays
    plaintext in the wire that transits the broker."""
    out = dict(settings)
    sealed = {k: _seal(out.pop(k)) for k in _SEALED_SETTING_KEYS if k in out}
    if sealed:
        out["_sealed"] = sealed
    return out


def _unseal_settings(settings: dict) -> dict:
    """Tool plane: decrypt sealed DATA fields back to plaintext for the provider (after verify)."""
    out = dict(settings)
    sealed = out.pop("_sealed", None)
    if isinstance(sealed, dict):
        for k, token in sealed.items():
            out[k] = _unseal(token)
    return out


def _seal_result(wires: list[dict]) -> dict:
    """Tool plane: encrypt returned evidence so it never sits plaintext in the result backend."""
    return {"_sealed_result": _seal(wires)}


def _unseal_result(result) -> list[dict]:  # noqa: ANN001
    """Dispatcher: decrypt evidence from the result backend. A bare list (empty/reject) passes."""
    if isinstance(result, dict) and "_sealed_result" in result:
        return _unseal(result["_sealed_result"])
    return list(result or [])


def _execution_backend_for(session, tool_key):  # noqa: ANN001, ANN202
    """The isolation backend for a tool: catalog metadata override, else the code default."""
    cat = session.get(ToolCatalog, tool_key)
    if cat is not None and (cat.metadata_ or {}).get("execution_backend"):
        return cat.metadata_["execution_backend"]
    return _DEFAULT_BACKENDS.get(tool_key, "inproc")


def _enforce_tool_plane(*, expect_tool: bool) -> None:
    """Pin a task to its plane; a misroute fails loudly. Skipped under eager (tests)."""
    if celery_app.conf.task_always_eager:
        return
    if get_settings().tool_plane != expect_tool:
        role = "run_tool (tools plane)" if expect_tool else "dispatch_tool_job (Control Plane)"
        raise RuntimeError(f"{role} was routed to the wrong plane")


@celery_app.task(name="guardian.run_tool")
def run_tool(signed: dict) -> list[dict]:
    """EXECUTION PLANE (no DB): AUTHENTICATE the job, THEN run the provider. Return RawEvidence.

    A queue message is untrusted. The signed envelope is verified (signature + expiry + replay) with
    the tool plane's PUBLIC key BEFORE anything is reconstructed, a backend is chosen, nft rules are
    built, or a provider runs. A forged/tampered/expired/replayed job is refused here.
    """
    _enforce_tool_plane(expect_tool=True)
    from guardian_common.job_signing import JobVerificationError, verify_job

    from guardian_scanner.tools import registry
    from guardian_scanner.tools.execution import execute_tool

    try:
        job_wire = verify_job(signed)      # untrusted → authenticated, before ANY execution work
    except JobVerificationError as exc:
        log.warning("run_tool_rejected", reason=str(exc))
        return []

    job: ToolJob = job_from_wire(job_wire)
    job = replace(job, settings=_unseal_settings(job.settings))  # decrypt sealed DATA after verify
    provider = registry.tool_for(job.tool_key)
    if provider is None:
        return []
    evidence = execute_tool(provider, job)
    # Seal evidence so it never sits plaintext in the Redis result backend (P1-4).
    return _seal_result([evidence_to_wire(e) for e in evidence])


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
    self, tenant_id: str, tool_key: str, requested_targets: list[str], actor_id: str | None = None,
    human_approved: bool = False, settings: dict | None = None, policy: dict | None = None,
    campaign_id: str | None = None, approval_id: str | None = None,
) -> dict:
    """TRUSTED Control Plane: identity → authorize → scope → policy → dispatch → persist."""
    _enforce_tool_plane(expect_tool=False)
    from guardian_scanner.tools import registry
    from guardian_scanner.tools.evidence import persist_evidence_chain

    caps = registry.capabilities_for(tool_key)
    if caps is None:
        return {"status": "unknown_tool", "tool": tool_key}

    tid = uuid.UUID(tenant_id)
    now = dt.datetime.now(dt.UTC)

    # Control Plane: WHO may run this? (governance) then WHAT may it touch? (authz/scope).
    with session_scope() as session:
        gov = evaluate_governance(
            session, tenant_id=tid, actor_id=actor_id, caps=caps, tool_key=tool_key,
            campaign_id=campaign_id, approval_id=approval_id)
        record_audit(
            session, action="tool.capability.decision", tenant_id=tid, actor_id=gov.actor_uuid,
            entity_type="tool_job", entity_id=tool_key,
            metadata={"allowed": gov.allowed, "principal": gov.principal_kind,
                      "level": gov.required_level, "reasons": list(gov.reasons),
                      "campaign_id": campaign_id},
        )
        if not gov.allowed:
            return {"status": "forbidden", "tool": tool_key, "principal": gov.principal_kind,
                    "level": gov.required_level, "reasons": list(gov.reasons)}

        authorized = _authorized_target_values(session, tid, now)
        scope = derive_effective_scope(requested_targets or [], authorized, caps, policy)
        backend_name = _execution_backend_for(session, tool_key)
        decision = evaluate_tool_policy(caps, scope, human_approved=human_approved)
        record_audit(
            session, action="tool.job.decision", tenant_id=tid, actor_id=gov.actor_uuid,
            entity_type="tool_job", entity_id=tool_key,
            metadata={"allowed": decision.allowed,
                      "requires_approval": decision.requires_human_approval,
                      "reasons": list(decision.reasons), "targets": list(scope.targets)},
        )
        if not decision.allowed:
            return {"status": "denied", "tool": tool_key, "reasons": list(decision.reasons),
                    "requires_human_approval": decision.requires_human_approval}

        # L3+ only: consume the single-use approval now that the whole gate has passed.
        if gov.approval_id is not None:
            from guardian_db.models import Approval
            from sqlalchemy import update
            consumed = session.execute(
                update(Approval).where(Approval.id == gov.approval_id,
                                       Approval.consumed_at.is_(None)).values(consumed_at=now)
            )
            if consumed.rowcount == 0:
                return {"status": "forbidden", "tool": tool_key, "level": gov.required_level,
                        "reasons": ["approval already consumed"]}

    job_settings = _seal_settings({**(settings or {}), "_execution_backend": backend_name})
    job = ToolJob(tenant_id=tenant_id, job_id=uuid.uuid4().hex, tool_key=tool_key,
                  scope=scope, settings=job_settings)

    # Execution plane (no DB) → RawEvidence via result-return. The job is signed so the tool plane
    # can authenticate it (a forged run_tool message is refused there); sensitive DATA is sealed.
    from guardian_common.job_signing import sign_job
    wire = run_tool.apply_async(args=[sign_job(job_to_wire(job))], queue="tools").get(
        timeout=300, disable_sync_subtasks=False
    )
    evidences = [evidence_from_wire(w) for w in _unseal_result(wire)]

    # Evidence-first: persist the hash chain (primary truth), THEN derive findings only where the
    # evidence binds to exactly one asset. Evidence-only when there is no asset or more than one.
    # The semantic contract (ADR-0019) — a Scan/Finding is created ONLY when a finding is derived —
    # is honored by the strict binders; web_tls keeps its existing binder (reconciliation deferred).
    binder = _BINDERS.get(tool_key, _bind_and_derive_findings)
    with session_scope() as session:
        ids = persist_evidence_chain(session, tenant_id=tid, evidences=evidences)
        bound = binder(session, tid, tool_key, evidences)

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


def _bind_and_derive_findings_strict(session, tenant_id, tool_key, evidences):  # noqa: ANN001, ANN202
    """Host-binding that honors the ADR-0019 contract: a Scan is created ONLY when a finding exists.

    Evidence is persisted independently (the source of truth); a host that binds but yields no
    weakness produces evidence and NO Scan/Finding (evidence-only). Returns [(customer_id, count)].
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
        raws = [r for r in (provider.normalize(e) for e in host_evidence) if r is not None]
        if not raws:
            continue  # Evidence persisted; nothing derived — no empty Scan (ADR-0019 contract)

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
        for raw in raws:
            session.add(to_finding(
                raw, tenant_id=tenant_id, customer_id=asset.customer_id, scan_id=scan.id,
                engine_run_id=run.id, asset_id=asset.id, exposure=asset.exposure,
                asset_criticality=criticality, business_impact=criticality,
            ))
        bound.append((str(asset.customer_id), len(raws)))
    return bound


def _asset_for_target_ip(session, tenant_id, ip, now):  # noqa: ANN001, ANN202
    """The asset named by a valid, asset-bound authorization that cleared this IP target, or None.

    nmap findings attach to an EXISTING asset (via Authorization.asset_id) only — the provider never
    creates IP/Service nodes. A scope-based (asset_id-less) authorization ⇒ Evidence-only.
    """
    rows = session.execute(
        select(Authorization).where(
            Authorization.tenant_id == tenant_id, Authorization.revoked_at.is_(None),
            Authorization.asset_id.isnot(None),
            Authorization.valid_from <= now, Authorization.valid_until >= now)
    ).scalars()
    for a in rows:
        for t in a.authorized_targets or []:
            if str(t.get("value")) == str(ip):
                return session.get(Asset, a.asset_id)
    return None


def _bind_nmap_findings(session, tenant_id, tool_key, evidences):  # noqa: ANN001, ANN202
    """Bind nmap findings to the asset named by each target IP's authorization (ADR-0019 strict)."""
    from guardian_scanner.normalize import to_finding
    from guardian_scanner.tools import registry

    provider = registry.tool_for(tool_key)
    if provider is None:
        return []
    now = dt.datetime.now(dt.UTC)
    by_ip: dict[str, list] = {}
    for e in evidences:
        if e.kind == "nmap_service":
            by_ip.setdefault(e.target, []).append(e)

    bound: list[tuple[str, int]] = []
    for ip, ip_evidence in sorted(by_ip.items()):
        asset = _asset_for_target_ip(session, tenant_id, ip, now)
        if asset is None:
            continue  # Evidence-only: no asset-bound authorization for this IP
        raws = [r for r in (provider.normalize(e) for e in ip_evidence) if r is not None]
        if not raws:
            continue
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
        for raw in raws:
            session.add(to_finding(
                raw, tenant_id=tenant_id, customer_id=asset.customer_id, scan_id=scan.id,
                engine_run_id=run.id, asset_id=asset.id, exposure=asset.exposure,
                asset_criticality=criticality, business_impact=criticality))
        bound.append((str(asset.customer_id), len(raws)))
    return bound


def _ct_upsert(ingestor, cache, node_type, key):  # noqa: ANN001, ANN202
    """Upsert a CT-sourced graph node once per identity; cache and return its UUID."""
    from guardian_core.discovery import DiscoveredAsset
    from guardian_core.enums import DiscoverySource

    ck = (node_type.value, key)
    if ck not in cache:
        cache[ck] = ingestor.upsert_node(DiscoveredAsset(
            node_type=node_type, canonical_key=key, source=DiscoverySource.CT_LOG,
            confidence=95, ownership_confidence=90, attributes={"public_dns": True},
        ))
    return cache[ck]


def _bind_ct_surface_assets(session, tenant_id, tool_key, evidences):  # noqa: ANN001, ANN202
    """Promote CT `discovered_asset` evidence into the World Model (ADR-0026 Option 2).

    The trusted Control Plane opens a real `DiscoveryRun(trigger="tool")` and ingests each
    discovered subdomain through the SAME `DbGraphIngestor` the discovery plane uses — one
    provenance model, a real `discovery_run_id` (never NULL), reusing the existing
    ownership/dedup/lifecycle. It creates NO Scan/Finding (an asset is inventory, not a
    vulnerability). Ownership/customer is scoped by the parent domain's managed asset when one
    exists (else a tenant-scoped, customer-less run, like scope-based discovery). The provider
    boundary, Evidence chain, and graph schema are untouched.
    """
    from guardian_core.enums import EdgeRelation, NodeType
    from guardian_db.models import DiscoveryRun

    from guardian_scanner.discovery.ingestor import DbGraphIngestor
    from guardian_scanner.tools.binding import resolve_asset

    by_domain: dict[str, list] = {}
    for e in evidences:
        if e.kind == "discovered_asset":
            by_domain.setdefault(str((e.data or {}).get("parent_domain") or ""), []).append(e)

    now = dt.datetime.now(dt.UTC)
    bound: list[tuple[str, int]] = []
    for domain, items in sorted(by_domain.items()):
        if not domain:
            continue
        parent_asset = resolve_asset(session, tenant_id=tenant_id, host=domain)
        customer_id = parent_asset.customer_id if parent_asset is not None else None

        run = DiscoveryRun(tenant_id=tenant_id, customer_id=customer_id, trigger="tool",
                           status="running", seeds={"domains": [domain], "source": tool_key},
                           started_at=now)
        session.add(run)
        session.flush()  # a real run id — nodes/edges are stamped with it, never NULL

        ingestor = DbGraphIngestor(session, tenant_id=tenant_id, run_id=run.id)
        cache: dict[tuple[str, str], uuid.UUID] = {}
        dom_id = _ct_upsert(ingestor, cache, NodeType.DOMAIN, domain)
        for e in items:
            host = e.target
            if host == domain:
                continue  # the apex is the DOMAIN node itself, not a subdomain
            sub_id = _ct_upsert(ingestor, cache, NodeType.SUBDOMAIN, host)
            ingestor.link(src_id=sub_id, relation=EdgeRelation.SUBDOMAIN_OF.value, dst_id=dom_id,
                          src_type=NodeType.SUBDOMAIN.value, dst_type=NodeType.DOMAIN.value,
                          source="ct_log", confidence=95)

        run.status = "completed"
        run.finished_at = dt.datetime.now(dt.UTC)
        run.stats = dict(ingestor.stats)
        if customer_id is not None:
            bound.append((str(customer_id), 0))  # no findings; drives owner graph enrichment
    return bound


_BINDERS.update({"dns_posture": _bind_and_derive_findings_strict, "nmap": _bind_nmap_findings,
                 "ct_surface": _bind_ct_surface_assets})


# ── Provider #2: artifact analysis (asset-anchored, non-network). Reuses the same rail. ──
def _authorized_asset(session, tenant_id, asset_id, now):  # noqa: ANN001, ANN202
    """The asset IFF it exists, is owned by this tenant, and carries a valid authorization.

    The asset is the authorization ANCHOR — it is never treated as a network target, and the
    execution plane it feeds holds no DB/KMS/network. Returns None (⇒ denied) on any miss.
    """
    asset = session.get(Asset, asset_id)
    if asset is None or asset.tenant_id != tenant_id:
        return None
    authz = session.execute(
        select(Authorization).where(
            Authorization.tenant_id == tenant_id,
            Authorization.asset_id == asset_id,
            Authorization.revoked_at.is_(None),
            Authorization.valid_from <= now, Authorization.valid_until >= now,
        ).limit(1)
    ).scalar_one_or_none()
    return asset if authz is not None else None


def _derive_artifact_findings(session, tenant_id, tool_key, asset_id, evidences):  # noqa: ANN001, ANN202
    """Evidence-first: derive findings bound to the ANCHORED asset only. No findings ⇒ no Scan.

    Reuses Scan/ScanEngineRun(engine=tool_key) + normalize → to_finding. Evidence is already
    persisted independently, so a benign artifact yields evidence with zero findings.
    """
    from guardian_scanner.normalize import to_finding
    from guardian_scanner.tools import registry

    provider = registry.tool_for(tool_key)
    asset = session.get(Asset, asset_id)
    if provider is None or asset is None:
        return 0
    raws = [r for r in (provider.normalize(e) for e in evidences) if r is not None]
    if not raws:
        return 0  # Evidence persisted; nothing to derive — no empty Scan (Evidence-first)

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
    for raw in raws:
        session.add(to_finding(
            raw, tenant_id=tenant_id, customer_id=asset.customer_id, scan_id=scan.id,
            engine_run_id=run.id, asset_id=asset.id, exposure=asset.exposure,
            asset_criticality=criticality, business_impact=criticality,
        ))
    return len(raws)


@celery_app.task(name="guardian.dispatch_artifact_job", bind=True)
def dispatch_artifact_job(  # noqa: ANN001, PLR0911, PLR0913
    self, tenant_id: str, tool_key: str, asset_id: str, artifact_b64: str,
    actor_id: str | None = None,
    media_type: str | None = None, settings: dict | None = None, policy: dict | None = None,
) -> dict:
    """TRUSTED Control Plane for artifact analysis (Provider #2).

    Identity/capability governance → asset-anchored authorization → artifact-analysis scope → policy
    → DB-less sandboxed parse (no network) → Evidence-first persist (artifact sha256 is the chain
    root) → findings bound to the anchored asset → 6E graph. The artifact travels inline (≤2 MB); an
    oversized or undecodable blob is rejected fail-closed BEFORE anything runs.
    """
    _enforce_tool_plane(expect_tool=False)
    from guardian_scanner.tools import registry
    from guardian_scanner.tools.evidence import persist_evidence_chain

    caps = registry.capabilities_for(tool_key)
    if caps is None:
        return {"status": "unknown_tool", "tool": tool_key}

    tid = uuid.UUID(tenant_id)

    # Capability governance FIRST: who is asking, and may they run this capability level here?
    with session_scope() as session:
        gov = evaluate_governance(session, tenant_id=tid, actor_id=actor_id, caps=caps,
                                  tool_key=tool_key)
        record_audit(
            session, action="tool.capability.decision", tenant_id=tid, actor_id=gov.actor_uuid,
            entity_type="tool_job", entity_id=tool_key,
            metadata={"allowed": gov.allowed, "principal": gov.principal_kind,
                      "level": gov.required_level, "reasons": list(gov.reasons)},
        )
        if not gov.allowed:
            return {"status": "forbidden", "tool": tool_key, "principal": gov.principal_kind,
                    "level": gov.required_level, "reasons": list(gov.reasons)}

    # Fail-closed transport bound, before any execution: reject an undecodable/empty/oversized blob.
    try:
        raw_len = len(base64.b64decode(artifact_b64 or "", validate=True))
    except (ValueError, TypeError):
        return {"status": "rejected", "tool": tool_key, "reason": "invalid_encoding"}
    if raw_len == 0:
        return {"status": "rejected", "tool": tool_key, "reason": "empty_artifact"}
    if raw_len > _ARTIFACT_MAX_BYTES:
        return {"status": "rejected", "tool": tool_key,
                "reason": "artifact_exceeds_2mb", "size": raw_len}

    aid = uuid.UUID(asset_id)
    now = dt.datetime.now(dt.UTC)

    # Asset-anchored gate: the asset is the anchor placed into scope (never a network target).
    with session_scope() as session:
        asset = _authorized_asset(session, tid, aid, now)
        anchored = [str(asset.id)] if asset is not None else []
        scope = derive_effective_scope(anchored, anchored, caps, policy)
        decision = evaluate_tool_policy(caps, scope, human_approved=False)
        record_audit(
            session, action="tool.artifact.decision", tenant_id=tid, actor_id=gov.actor_uuid,
            entity_type="tool_job", entity_id=tool_key,
            metadata={"allowed": decision.allowed and asset is not None, "asset_id": asset_id,
                      "reasons": list(decision.reasons), "authorized_asset": asset is not None},
        )
        if asset is None or not decision.allowed:
            reasons = list(decision.reasons) or ["asset not found, not owned, or not authorized"]
            return {"status": "denied", "tool": tool_key, "reasons": reasons}
        customer_id = str(asset.customer_id)

    job_settings = _seal_settings(
        {**(settings or {}), "artifact_b64": artifact_b64, "media_type": media_type})
    job = ToolJob(tenant_id=tenant_id, job_id=uuid.uuid4().hex, tool_key=tool_key,
                  scope=scope, settings=job_settings)

    # Execution plane (no DB, no network) → RawEvidence via result-return. Signed for authenticity;
    # the raw customer artifact is Fernet-sealed so it never sits plaintext in the broker.
    from guardian_common.job_signing import sign_job
    wire = run_tool.apply_async(args=[sign_job(job_to_wire(job))], queue="tools").get(
        timeout=300, disable_sync_subtasks=False
    )
    evidences = [evidence_from_wire(w) for w in _unseal_result(wire)]

    # Evidence-first: persist the hash chain (artifact sha256 is its root), THEN derive findings.
    with session_scope() as session:
        ids = persist_evidence_chain(session, tenant_id=tid, evidences=evidences)
        n_findings = _derive_artifact_findings(session, tid, tool_key, aid, evidences)

    if n_findings:  # graph integration only when a finding was actually derived (6E)
        from guardian_scanner.discovery.tasks import enrich_graph
        enrich_graph.apply_async(args=[str(tid), customer_id])

    log.info("artifact_job_done", tool=tool_key, evidence=len(ids), findings=n_findings)
    return {"status": "completed", "tool": tool_key, "job_id": job.job_id,
            "evidence": len(ids), "asset_id": asset_id, "findings": n_findings}
