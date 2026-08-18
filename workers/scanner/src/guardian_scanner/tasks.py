"""The scan task: trigger → run engines (sandboxed intent) → normalize → persist → audit.

Idempotent per (scan_id, engine) via the unique constraint on scan_engine_runs. A single engine
failure degrades the scan to `partial` rather than failing the whole run (doc 01 §4).
"""

from __future__ import annotations

import datetime as dt
import os
import shutil
import subprocess  # noqa: S404 - used with a fixed argv, no shell
import tempfile
import uuid
from urllib.parse import urlsplit

from guardian_common.config import get_settings
from guardian_common.crypto import decrypt_json
from guardian_common.logging import get_logger
from guardian_core import authorization as authz
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
# Commits walked when cloning a repository for scanning. Secrets live in history far more
# often than in the working tree, so the default fetches it; 0 means full history via a
# blobless clone. Bounded so a pathological repository degrades instead of hanging.
_DEFAULT_HISTORY_DEPTH = 1000


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


def _clone_host(url: str) -> str | None:
    """Extract the host from a clone URL — http(s)://host/… or the scp-like git@host:path."""
    if url.startswith(("http://", "https://")):
        return urlsplit(url).hostname
    if url.startswith("git@"):
        return url[4:].split(":", 1)[0] or None
    return None


def _clone_port(url: str) -> int:
    if url.startswith("https://"):
        return 443
    if url.startswith("git@"):
        return 22
    return 80


def _git_env(home: str) -> dict[str, str]:
    """Minimal, secret-free environment for `git clone` (P1-Ⓐ). An ALLOWLIST: no GUARDIAN_* secret
    (KMS master, JWT, broker-seal key, DB/Redis URLs) is inherited by the git child; the host git
    config/.netrc are isolated (HOME → the throwaway workspace, system config ignored); and no
    interactive/credential prompt can block or leak host credentials."""
    return {
        "PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
        "HOME": home,                       # isolate from host ~/.gitconfig / ~/.netrc
        "GIT_CONFIG_NOSYSTEM": "1",         # ignore /etc/gitconfig
        "GIT_TERMINAL_PROMPT": "0",         # never prompt for / block on credentials
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }


def _prepare_workspace(asset: Asset) -> tuple[str | None, str | None, str | None]:
    """Return (workspace_path, inline_content, tempdir_to_cleanup).

    Priority: explicit inline content (tests/demo) → local path → shallow git clone. The clone
    target is tenant-controlled, so before cloning we resolve its host and REFUSE any private/
    loopback/link-local/metadata (incl. IPv4-mapped-IPv6) address (P1-Ⓐ SSRF guard, reusing the
    repo's `sandbox._resolve_public_address`), run git with redirects disabled (so a redirect can't
    bounce to an internal host) and with a scrubbed, secret-free environment.
    """
    cfg = asset.config or {}
    if cfg.get("inline_content"):
        return None, str(cfg["inline_content"]), None
    if cfg.get("local_path"):
        return str(cfg["local_path"]), None, None
    if asset.kind == "repo" and asset.identifier.startswith(("http://", "https://", "git@")):
        host = _clone_host(asset.identifier)
        if not host:
            raise RuntimeError("workspace preparation failed: unparseable clone host")
        try:
            sandbox._resolve_public_address(host, _clone_port(asset.identifier))  # reject internal
        except PermissionError as exc:
            raise RuntimeError(f"workspace preparation refused: {exc}") from exc
        tmp = tempfile.mkdtemp(prefix="guardian_ws_")
        # Depth is the difference between scanning a snapshot and scanning a repository. A secret
        # committed and later deleted is invisible at depth 1 while remaining readable by anyone
        # who can clone, so history is fetched by default and bounded rather than skipped.
        # `--filter=blob:none` keeps the commit graph cheap: blobs arrive only when a scan reads
        # them, so a deep history costs walk time instead of a full-content download.
        depth = int(cfg.get("history_depth", _DEFAULT_HISTORY_DEPTH))
        depth_args = ["--filter=blob:none"] if depth <= 0 else ["--depth", str(min(depth, 5000))]
        try:
            subprocess.run(  # noqa: S603 - fixed argv, no shell, timeout-bounded, scrubbed env
                ["git", "-c", "http.followRedirects=false", "-c", "credential.helper=",  # noqa: S607
                 "clone", *depth_args, asset.identifier, tmp],
                check=True,
                capture_output=True,
                timeout=_CLONE_TIMEOUT,
                env=_git_env(tmp),
            )
            return tmp, None, tmp
        except (subprocess.SubprocessError, OSError) as exc:
            shutil.rmtree(tmp, ignore_errors=True)
            raise RuntimeError(f"workspace preparation failed: {exc}") from exc
    return None, None, None


def _authorized(session, asset: Asset, *, engine_key: str) -> authz.Decision:
    """The safe-scanning gate, delegated to the one evaluator both gates share (WP-H1).

    This used to match on `asset_id` alone, which meant a domain the customer had *proved they own*
    could not authorize scanning it: WP-F1 issues an authorization scoped by `authorized_targets`
    with no asset, so the gate looked straight past it and skipped every active engine.
    """
    now = _now()
    rows = session.query(Authorization).filter(
        Authorization.tenant_id == asset.tenant_id,
        Authorization.customer_id == asset.customer_id,
    ).limit(200).all()
    views = [
        authz.AuthorizationView(
            id=str(row.id), method=row.method, asset_id=str(row.asset_id) if row.asset_id else None,
            customer_id=str(row.customer_id), targets=tuple(row.authorized_targets or ()),
            valid_from=row.valid_from, valid_until=row.valid_until, revoked_at=row.revoked_at,
        )
        for row in rows
    ]
    return authz.decide(
        views, asset_id=str(asset.id), asset_identifier=asset.identifier or "",
        asset_kind=asset.kind, engine=engine_key, now=now,
    )


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
                decision = (_authorized(session, asset, engine_key=engine_key)
                            if needs_auth else None)
                if decision is not None and not decision.allowed:
                    run.status = "skipped"
                    # The reason, not just the refusal: "blocked" with no cause is a support ticket.
                    run.error = decision.reason
                    engine_statuses.append("skipped")
                    record_audit(
                        session,
                        action="scan.engine.blocked_unauthorized",
                        tenant_id=scan.tenant_id,
                        customer_id=scan.customer_id,
                        entity_type="scan_engine_run",
                        entity_id=str(run.id),
                        metadata={"engine": engine_key, "reason": decision.reason},
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
                    # Record the engine's own health alongside its version. WP-E2 reads this to
                    # decide whether an empty result is evidence: an engine that completed without
                    # its tool saw less, and calling that "resolved" would close real findings.
                    health = engine.health()
                    run.tool_versions = {
                        engine.key.value: engine.version,
                        "degraded": bool(getattr(health, "degraded", False)),
                        "missing": list(getattr(health, "missing", ())),
                    }
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
        except Exception as exc:  # noqa: BLE001 - a failure OUTSIDE the per-engine guard (workspace
            # preparation, engine lookup, ScanContext build …) must still put the scan in a terminal
            # FAILED state with the error recorded. Otherwise the exception escapes session_scope,
            # which rolls back the RUNNING write and strands the scan at `queued` forever with no
            # error. Mirror the asset/customer-missing guard above: set a terminal status + audit,
            # then return rather than re-raise.
            scan.status = ScanStatus.FAILED.value
            scan.error = str(exc)[:2000]
            scan.finished_at = _now()
            log.error("scan_failed", scan_id=scan_id, error=str(exc))
            record_audit(
                session,
                action="scan.failed",
                tenant_id=scan.tenant_id,
                customer_id=scan.customer_id,
                actor_id=scan.created_by,
                entity_type="scan",
                entity_id=str(scan.id),
                metadata={"status": scan.status, "error": scan.error},
            )
            return {"scan_id": scan_id, "status": scan.status}
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

        # Compare this scan against what was already open on the asset (WP-E2). Findings it did not
        # report are resolved only where the engine that would have found them completed cleanly —
        # the reconciliation itself enforces that, which is why it is called rather than inlined.
        from guardian_scanner.verification import reconcile_scan

        try:
            result["verification"] = reconcile_scan(scan_id)
        except Exception as exc:  # noqa: BLE001 - a reconciliation failure must not fail the scan
            log.error("reconcile_failed", scan_id=scan_id, error=str(exc)[:300])
            result["verification"] = {"error": f"{type(exc).__name__}: {exc}"[:200]}

        # Close the remediation items this scan proved fixed, and reopen what came back (WP-F5).
        # Runs after reconciliation because it reads the verification records — a fix is verified by
        # the engine that found the issue running again and not reporting it, never by a person
        # marking it done.
        from guardian_scanner.remediation import verify_after_scan

        try:
            with session_scope() as session:
                result["remediation"] = verify_after_scan(
                    session, scan_id=uuid.UUID(str(scan_id))
                )
        except Exception as exc:  # noqa: BLE001 - must not fail a completed scan
            log.error("remediation_verify_failed", scan_id=scan_id, error=str(exc)[:300])
            result["remediation"] = {"error": f"{type(exc).__name__}: {exc}"[:200]}
    return result
