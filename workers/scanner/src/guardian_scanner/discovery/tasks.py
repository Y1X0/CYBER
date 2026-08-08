"""Discovery orchestration (Phase 6B; result-return split in 6C.4).

Two tasks across two planes so the plane that touches untrusted network holds no DB credentials:

  * `run_discovery` — the TRUSTED orchestrator (default queue, DB). Loads the run, runs the
    authorization gate (DB) and audits denials, dispatches collection to the recon plane, then
    persists the returned evidence via the ingestor. It opens NO DB session while probes run.
  * `recon_collect` — the RECON plane (recon queue, NO DB). Receives already-authorized targets,
    runs providers/probes inside the sandbox + egress allowlist, and RETURNS structured evidence.
    It never touches the database.

The graph/node/edge/event semantics are unchanged: the same providers run in the same order and the
same ingestor writes the same rows — only *where* the work runs (and what it can reach) changed.
"""

from __future__ import annotations

import datetime as dt
import uuid

from guardian_common.config import get_settings
from guardian_common.logging import get_logger
from guardian_core.discovery import DiscoveryContext, asset_from_wire, asset_to_wire
from guardian_core.enums import NodeType
from guardian_db.models import DiscoveryRun, DiscoveryScope, GraphNode
from guardian_db.session import session_scope
from sqlalchemy import select

from guardian_scanner import egress
from guardian_scanner.celery_app import celery_app
from guardian_scanner.discovery.authorization import authorize_targets
from guardian_scanner.discovery.ingestor import DbGraphIngestor, mark_stale_edges
from guardian_scanner.discovery.normalizer import edge_target, normalize
from guardian_scanner.discovery.registry import available_providers

log = get_logger("guardian.discovery")

_DEFAULT_PASSIVE = ["dns", "ct"]
_RECON_TIMEOUT = 900  # seconds the orchestrator will wait for the recon plane's evidence
_MAX_ASN_IPS = 10_000  # bound the IP set handed to the passive ASN/RIR provider (6F-b)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _egress_hosts(allowed_targets: list[str]) -> frozenset[str]:
    """Hosts a run's probes may reach — derived only from gate-cleared targets, with ports stripped.

    This is what the runtime egress allowlist is bound to, so the socket layer permits exactly the
    hosts the authorization gate cleared and nothing else.
    """
    return frozenset(t.split(":")[0] for t in allowed_targets if t)


def _enforce_plane(*, expect_recon: bool) -> None:
    """Pin a task to its execution plane (6C.4); a misroute fails loudly instead of leaking.

    Skipped under Celery's eager mode, where both tasks necessarily share one process (tests) — the
    pinning is a deployment property enforced by the worker's `GUARDIAN_RECON_PLANE` + its network.
    """
    if celery_app.conf.task_always_eager:
        return
    if get_settings().recon_plane != expect_recon:
        role = "recon_collect (recon plane, no DB)" if expect_recon else "run_discovery (DB plane)"
        raise RuntimeError(
            f"{role} was routed to the wrong execution plane "
            f"(GUARDIAN_RECON_PLANE={get_settings().recon_plane})"
        )


@celery_app.task(name="guardian.enrich_graph")
def enrich_graph(tenant_id: str, customer_id: str | None = None) -> dict:
    """Project assets + findings into the graph (Phase 6E). Trusted plane, DB-only, idempotent.

    Runs after a scan completes; creates/refreshes asset+finding nodes and exposes/serves edges. No
    network, no recon, no AI — a re-run updates in place (dedupe on identity).
    """
    _enforce_plane(expect_recon=False)
    from guardian_scanner.discovery.enricher import GraphEnricher

    with session_scope() as session:
        enricher = GraphEnricher(
            session, tenant_id=uuid.UUID(tenant_id),
            customer_id=uuid.UUID(customer_id) if customer_id else None,
        )
        stats = enricher.enrich()
        log.info("graph_enriched", tenant_id=tenant_id, **stats)
        return {"tenant_id": tenant_id, "status": "completed", "stats": stats}


@celery_app.task(name="guardian.recon_collect")
def recon_collect(payload: dict) -> list[dict]:
    """RECON PLANE (no DB): run providers/probes over already-authorized targets, return evidence.

    `payload` carries everything collection needs (no DB handles): tenant/run/customer ids, the
    enabled providers, seeds, the gate-cleared `authorized_targets`, and offline settings. Active
    providers run under the egress allowlist bound to exactly those targets.
    """
    _enforce_plane(expect_recon=True)

    tenant_id = payload["tenant_id"]
    run_id = payload["run_id"]
    customer_id = payload.get("customer_id")
    enabled = payload.get("providers") or _DEFAULT_PASSIVE
    seeds = payload.get("seeds") or {}
    settings = payload.get("settings") or {}
    allowed = list(payload.get("authorized_targets") or [])

    providers = available_providers()
    evidence: list[dict] = []

    passive_ctx = DiscoveryContext(
        tenant_id=tenant_id, run_id=run_id, seeds=seeds,
        customer_id=customer_id, authorized=False, settings=settings,
    )

    for key in enabled:
        provider = providers.get(key)
        if provider is None:
            continue
        if provider.requires_authorization:
            if not allowed:
                continue  # nothing cleared → active provider does not run (no network)
            active_ctx = DiscoveryContext(
                tenant_id=tenant_id, run_id=run_id, seeds=seeds, customer_id=customer_id,
                authorized=True, authorized_targets=allowed, settings=settings,
            )
            # Second defense layer (6C.3): egress allowlist bound to the gate-cleared hosts.
            with egress.allowlist(_egress_hosts(allowed)):
                for raw in provider.collect(active_ctx):
                    evidence.append(asset_to_wire(raw))
        else:
            for raw in provider.collect(passive_ctx):
                evidence.append(asset_to_wire(raw))

    log.info("recon_collect_done", run_id=run_id, evidence=len(evidence))
    return evidence


@celery_app.task(name="guardian.run_discovery", bind=True)
def run_discovery(self, run_id: str) -> dict:  # noqa: ANN001
    """TRUSTED ORCHESTRATOR (DB): authorize (DB) → collect on the recon plane → persist (DB)."""
    _enforce_plane(expect_recon=False)

    # ── Phase 1 (DB): load, authorize + audit denials, build the recon payload ──
    with session_scope() as session:
        run: DiscoveryRun | None = session.get(DiscoveryRun, uuid.UUID(run_id))
        if run is None:
            return {"run_id": run_id, "status": "not_found"}

        run.status = "running"
        run.started_at = _now()
        session.flush()

        raw_seeds = dict(run.seeds or {})
        settings = raw_seeds.pop("settings", {})  # offline snapshots live under this key
        scope = session.get(DiscoveryScope, run.scope_id) if run.scope_id else None
        enabled = list(scope.providers if scope and scope.providers else _DEFAULT_PASSIVE)
        providers = available_providers()

        allowed: list[str] = []
        if any(providers.get(k) and providers[k].requires_authorization for k in enabled):
            # Authorize every candidate target FIRST, in the trusted plane, before any network.
            # Only DB-stored, tenant-owned, valid authorizations grant a target; denials are audited
            # here and never leave this plane — the recon plane only ever sees cleared targets.
            candidates = list(raw_seeds.get("active_targets", []))
            allowed, denied = authorize_targets(
                session, tenant_id=run.tenant_id, customer_id=run.customer_id,
                run_id=run.id, candidates=candidates, now=_now(),
            )
            if denied:
                log.info("discovery_targets_blocked", count=len(denied), run_id=run_id)

        if "asn" in enabled:
            # The passive ASN/RIR provider (6F-b) maps DISCOVERED IPs to netblocks. Supply the
            # from existing ip_address nodes (never raw user seeds); dedup + bound + deterministic.
            ip_keys = session.execute(
                select(GraphNode.canonical_key).where(
                    GraphNode.tenant_id == run.tenant_id,
                    GraphNode.node_type == NodeType.IP_ADDRESS.value,
                )
            ).scalars().all()
            raw_seeds = {**raw_seeds,
                         "ips": sorted(set(ip_keys))[:_MAX_ASN_IPS]}

        payload = {
            "tenant_id": str(run.tenant_id), "run_id": str(run.id),
            "customer_id": str(run.customer_id) if run.customer_id else None,
            "providers": enabled, "seeds": raw_seeds,
            "authorized_targets": allowed, "settings": settings,
        }
        tenant_uuid, run_uuid, scope_id = run.tenant_id, run.id, run.scope_id
    # session closed — NO DB session is open while the recon plane runs probes.

    # ── Phase 2 (RECON plane, no DB): collect evidence via result-return ──
    wire = recon_collect.apply_async(args=[payload], queue="recon").get(
        timeout=_RECON_TIMEOUT, disable_sync_subtasks=False
    )

    # ── Phase 3 (DB): persist the returned evidence, exactly as before ──
    with session_scope() as session:
        run = session.get(DiscoveryRun, run_uuid)
        ingestor = DbGraphIngestor(session, tenant_id=tenant_uuid, run_id=run_uuid)
        node_cache: dict[tuple[str, str], uuid.UUID] = {}

        def _resolve(asset) -> uuid.UUID:  # noqa: ANN001 - upsert once per identity, cache the uuid
            k = (asset.node_type.value, asset.canonical_key)
            if k not in node_cache:
                node_cache[k] = ingestor.upsert_node(asset)
            return node_cache[k]

        def _ingest(raw) -> None:  # noqa: ANN001 - normalize -> resolve -> link one discovered asset
            asset = normalize(raw)
            src_uuid = _resolve(asset)
            for edge in asset.edges:
                dst = normalize(edge_target(edge, asset.source))
                dst_uuid = _resolve(dst)
                ingestor.link(
                    src_id=src_uuid, relation=edge.relation.value, dst_id=dst_uuid,
                    src_type=asset.node_type.value, dst_type=edge.dst_type.value,
                    source=asset.source.value, confidence=edge.confidence,
                )

        for d in wire or []:
            _ingest(asset_from_wire(d))

        stale = mark_stale_edges(session, tenant_id=tenant_uuid, run_id=run_uuid)
        ingestor.stats["edges_marked_stale"] = stale

        # 6F-a: enrich the graph with netblocks the operator explicitly authorized, linking each to
        # the ip_address nodes it contains (CIDR containment). Trusted plane, no network; idempotent
        # and convergent with the passive ASN/RIR provider (same canonical netblock identity).
        from guardian_scanner.discovery.netblock import NetblockEnricher

        run_customer = run.customer_id if run is not None else None
        nb_stats = NetblockEnricher(
            session, tenant_id=tenant_uuid, customer_id=run_customer
        ).enrich()
        ingestor.stats.update(nb_stats)

        if run is not None:
            run.stats = ingestor.stats
            run.status = "completed"
            run.finished_at = _now()
        scope = session.get(DiscoveryScope, scope_id) if scope_id else None
        if scope is not None:
            scope.last_run_at = _now()

        log.info("discovery_completed", run_id=run_id, **ingestor.stats)
        return {"run_id": run_id, "status": "completed", "stats": ingestor.stats}
