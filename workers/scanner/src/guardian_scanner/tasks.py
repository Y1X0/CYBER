"""The scan task: trigger → run engines (sandboxed intent) → normalize → persist → audit.

Idempotent per (scan_id, engine) via the unique constraint on scan_engine_runs. A single engine
failure degrades the scan to `partial` rather than failing the whole run (doc 01 §4).
"""

from __future__ import annotations

import datetime as dt
import shutil
import subprocess  # noqa: S404 - used with a fixed argv, no shell
import tempfile
import uuid

from guardian_common.config import get_settings
from guardian_common.crypto import decrypt_json
from guardian_common.logging import get_logger
from guardian_core.enums import ACTIVE_ENGINES, EngineKey, ScanStatus
from guardian_db.audit import record_audit
from guardian_db.models import (
    Asset,
    Authorization,
    Customer,
    Finding,
    Scan,
    ScanEngineRun,
    UsageRecord,
)
from guardian_db.session import session_scope

from guardian_scanner import sandbox
from guardian_scanner.celery_app import celery_app
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.normalize import severity_counts, to_finding
from guardian_scanner.registry import get_engine
from guardian_scanner.vuln_match import KbVulnMatcher

log = get_logger("guardian.scanner")

_CLONE_TIMEOUT = 120


def _run_engine(engine, ctx: ScanContext) -> list:  # noqa: ANN001 - engine is a ScanEngine
    """Execute an engine, optionally inside the worker sandbox (5A hard gate).

    When `sandbox_engines` is on, untrusted-input engines run in a resource-limited, egress-
    restricted child process. SCA is exempt: it matches against the local KB over a DB handle that
    isn't fork-safe, and its input (trusted, local advisory data) is low-risk — it stays in-process.
    """
    settings = get_settings()
    if (
        settings.sandbox_engines
        and sandbox.supported()
        and engine.key != EngineKey.SCA
    ):
        return sandbox.run_in_sandbox(lambda: list(engine.run(ctx)), sandbox.policy_for(engine.key))
    return list(engine.run(ctx))


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _prepare_workspace(asset: Asset) -> tuple[str | None, str | None, str | None]:
    """Return (workspace_path, inline_content, tempdir_to_cleanup).

    Priority: explicit inline content (tests/demo) → local path → shallow git clone.
    Cloning is best-effort and network-restricted at the infra layer (sandbox egress allowlist).
    """
    cfg = asset.config or {}
    if cfg.get("inline_content"):
        return None, str(cfg["inline_content"]), None
    if cfg.get("local_path"):
        return str(cfg["local_path"]), None, None
    if asset.kind == "repo" and asset.identifier.startswith(("http://", "https://", "git@")):
        tmp = tempfile.mkdtemp(prefix="guardian_ws_")
        try:
            subprocess.run(  # noqa: S603,S607 - fixed argv, no shell, timeout-bounded
                ["git", "clone", "--depth", "1", asset.identifier, tmp],  # noqa: S607
                check=True,
                capture_output=True,
                timeout=_CLONE_TIMEOUT,
            )
            return tmp, None, tmp
        except (subprocess.SubprocessError, OSError) as exc:
            shutil.rmtree(tmp, ignore_errors=True)
            raise RuntimeError(f"workspace preparation failed: {exc}") from exc
    return None, None, None


def _authorized(session, asset: Asset) -> bool:
    now = _now()
    q = (
        session.query(Authorization)
        .filter(Authorization.asset_id == asset.id)
        .filter(Authorization.revoked_at.is_(None))
        .filter(Authorization.valid_from <= now)
        .filter(Authorization.valid_until >= now)
    )
    return session.query(q.exists()).scalar()


@celery_app.task(name="guardian.run_scan", bind=True)
def run_scan(self, scan_id: str) -> dict:  # noqa: ANN001
    """Execute all requested engines for a scan."""
    with session_scope() as session:
        scan: Scan | None = session.get(Scan, uuid.UUID(scan_id))
        if scan is None:
            return {"scan_id": scan_id, "status": "not_found"}
        asset: Asset | None = session.get(Asset, scan.asset_id)
        customer: Customer | None = session.get(Customer, scan.customer_id)
        if asset is None or customer is None:
            scan.status = ScanStatus.FAILED.value
            scan.error = "asset or customer missing"
            return {"scan_id": scan_id, "status": "failed"}

        scan.status = ScanStatus.RUNNING.value
        scan.started_at = _now()
        session.flush()

        workspace, inline, cleanup = None, None, None
        all_findings: list[Finding] = []
        engine_statuses: list[str] = []

        try:
            for engine_key in scan.requested_engines or [EngineKey.SECRETS.value]:
                run = ScanEngineRun(scan_id=scan.id, engine=engine_key, status="running")
                session.add(run)
                session.flush()

                engine = get_engine(engine_key)
                if engine is None:
                    run.status = "skipped"
                    run.error = "engine not registered"
                    engine_statuses.append("skipped")
                    continue

                # Safe-scanning gate: active engines need a valid authorization (doc 06 §4).
                # Use the engine's own key (already an EngineKey) — never coerce the raw request
                # string, which would raise on an unknown/third-party key and fail the whole scan.
                needs_auth = engine.requires_authorization or engine.key in ACTIVE_ENGINES
                if needs_auth and not _authorized(session, asset):
                    run.status = "skipped"
                    run.error = "no valid authorization for active scan"
                    engine_statuses.append("skipped")
                    record_audit(
                        session,
                        action="scan.engine.blocked_unauthorized",
                        tenant_id=scan.tenant_id,
                        customer_id=scan.customer_id,
                        entity_type="scan_engine_run",
                        entity_id=str(run.id),
                        metadata={"engine": engine_key},
                    )
                    continue

                if not engine.supports(asset.kind):
                    run.status = "skipped"
                    run.error = f"engine does not support asset kind '{asset.kind}'"
                    engine_statuses.append("skipped")
                    continue

                if workspace is None and inline is None:
                    workspace, inline, cleanup = _prepare_workspace(asset)

                ctx = ScanContext(
                    scan_id=str(scan.id),
                    asset_kind=asset.kind,
                    asset_identifier=asset.identifier,
                    workspace_path=workspace,
                    inline_content=inline,
                    exposure=asset.exposure,
                    vuln_matcher=KbVulnMatcher(session),  # SCA matches against the local KB
                    asset_config=asset.config or {},  # offline snapshots for active engines
                    # Least privilege: decrypt credentials only for engines that declare they need
                    # them (cloud/DAST/API) — a SAST/secrets engine never receives cloud keys.
                    secret_config=(
                        decrypt_json(asset.secret_ref)
                        if getattr(engine, "wants_secrets", False) else {}
                    ),
                )
                # Business impact defaults to the customer's criticality (overridable per asset).
                business_impact = (asset.config or {}).get("business_impact", customer.criticality)
                try:
                    raws = _run_engine(engine, ctx)
                    run.tool_versions = {engine.key.value: engine.version}
                    for raw in raws:
                        finding = to_finding(
                            raw,
                            tenant_id=scan.tenant_id,
                            customer_id=scan.customer_id,
                            scan_id=scan.id,
                            engine_run_id=run.id,
                            asset_id=asset.id,
                            exposure=asset.exposure,
                            asset_criticality=customer.criticality,
                            business_impact=business_impact,
                        )
                        session.add(finding)
                        all_findings.append(finding)
                    run.status = "completed"
                    engine_statuses.append("completed")
                except Exception as exc:  # noqa: BLE001 - isolate per-engine failure
                    run.status = "failed"
                    run.error = str(exc)[:2000]
                    engine_statuses.append("failed")
                    log.error("engine_failed", engine=engine_key, scan_id=scan_id, error=str(exc))
        finally:
            if cleanup:
                shutil.rmtree(cleanup, ignore_errors=True)

        session.flush()
        scan.stats = severity_counts(all_findings)
        scan.finished_at = _now()
        if engine_statuses and all(s == "failed" for s in engine_statuses):
            scan.status = ScanStatus.FAILED.value
        elif any(s in {"failed", "skipped"} for s in engine_statuses):
            scan.status = ScanStatus.PARTIAL.value
        else:
            scan.status = ScanStatus.COMPLETED.value

        session.add(
            UsageRecord(
                tenant_id=scan.tenant_id,
                customer_id=scan.customer_id,
                metric="scan_run",
                quantity=1,
                meta={"engines": scan.requested_engines},
            )
        )
        record_audit(
            session,
            action="scan.completed",
            tenant_id=scan.tenant_id,
            customer_id=scan.customer_id,
            actor_id=scan.created_by,
            entity_type="scan",
            entity_id=str(scan.id),
            metadata={"status": scan.status, "stats": scan.stats},
        )
        result = {"scan_id": scan_id, "status": scan.status, "stats": scan.stats}
        _tenant, _customer, _status = str(scan.tenant_id), str(scan.customer_id), scan.status

    # After the scan commits, project its findings into the attack graph (Phase 6E) on the trusted
    # plane. Fire-and-forget + idempotent; never blocks the scan and never runs on the recon worker.
    if _status in (ScanStatus.COMPLETED.value, ScanStatus.PARTIAL.value):
        from guardian_scanner.discovery.tasks import enrich_graph

        enrich_graph.apply_async(args=[_tenant, _customer])
    return result
