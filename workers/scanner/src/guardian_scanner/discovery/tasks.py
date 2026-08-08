"""Discovery orchestration task (Phase 6B).

Runs the fixed pipeline for one `DiscoveryRun`:

    provider.collect()  ->  normalize  ->  upsert node (identity resolve + dedup)
                        ->  upsert edge targets + link  ->  mark stale  ->  stats

Passive providers only in 6B. Active providers (requires_authorization=True) are skipped unless the
run is authorized — the gate is wired now so 6C only has to flip authorization on, not re-plumb.
"""

from __future__ import annotations

import datetime as dt
import uuid

from guardian_common.logging import get_logger
from guardian_db.models import DiscoveryRun, DiscoveryScope
from guardian_db.session import session_scope

from guardian_scanner.celery_app import celery_app
from guardian_scanner.discovery.authorization import authorize_targets
from guardian_scanner.discovery.ingestor import DbGraphIngestor, mark_stale_edges
from guardian_scanner.discovery.normalizer import edge_target, normalize
from guardian_scanner.discovery.registry import available_providers

log = get_logger("guardian.discovery")

_DEFAULT_PASSIVE = ["dns", "ct"]


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


@celery_app.task(name="guardian.run_discovery", bind=True)
def run_discovery(self, run_id: str) -> dict:  # noqa: ANN001
    """Execute a discovery run: fan out enabled providers, normalize, and ingest the graph."""
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
        enabled = (scope.providers if scope and scope.providers else _DEFAULT_PASSIVE)

        from guardian_core.discovery import DiscoveryContext

        ctx = DiscoveryContext(
            tenant_id=str(run.tenant_id), run_id=str(run.id), seeds=raw_seeds,
            customer_id=str(run.customer_id) if run.customer_id else None,
            authorized=False, settings=settings,
        )

        ingestor = DbGraphIngestor(session, tenant_id=run.tenant_id, run_id=run.id)
        node_cache: dict[tuple[str, str], uuid.UUID] = {}
        providers = available_providers()

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

        for key in enabled:
            provider = providers.get(key)
            if provider is None:
                continue

            if provider.requires_authorization:
                # Active provider: authorize every candidate target FIRST, before any network.
                # Only DB-stored, tenant-owned, valid authorizations grant a target; denials are
                # audited and the target never reaches the provider (no socket is opened).
                candidates = list(raw_seeds.get("active_targets", []))
                allowed, denied = authorize_targets(
                    session, tenant_id=run.tenant_id, customer_id=run.customer_id,
                    run_id=run.id, candidates=candidates, now=_now(),
                )
                if denied:
                    log.info("discovery_targets_blocked", provider=key, count=len(denied),
                             run_id=run_id)
                if not allowed:
                    continue
                active_ctx = DiscoveryContext(
                    tenant_id=str(run.tenant_id), run_id=str(run.id), seeds=raw_seeds,
                    customer_id=str(run.customer_id) if run.customer_id else None,
                    authorized=True, authorized_targets=allowed, settings=settings,
                )
                for raw in provider.collect(active_ctx):
                    _ingest(raw)
            else:
                for raw in provider.collect(ctx):  # passive: no gate
                    _ingest(raw)

        stale = mark_stale_edges(session, tenant_id=run.tenant_id, run_id=run.id)
        ingestor.stats["edges_marked_stale"] = stale

        run.stats = ingestor.stats
        run.status = "completed"
        run.finished_at = _now()
        if scope is not None:
            scope.last_run_at = run.finished_at

        log.info("discovery_completed", run_id=run_id, **ingestor.stats)
        return {"run_id": run_id, "status": "completed", "stats": ingestor.stats}
