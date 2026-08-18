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
from guardian_core import safescan
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
from sqlalchemy import select, update

from guardian_scanner import sandbox
from guardian_scanner.celery_app import celery_app
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.normalize import merge_sighting, severity_counts, to_finding
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


def _safe_scan_verdict(session, scan: Scan, asset: Asset, customer: Customer) -> safescan.Verdict:
    """The safe-scanning gate (WP-H3): may an active engine run *now*, and how hard.

    Authorization answers whether we may scan this at all. This answers whether now is a time the
    customer agreed to, whether something is already scanning the same host, and whether anybody
    has hit the stop button.
    """
    settings = get_settings()
    try:
        policy = safescan.parse_policy(customer.settings or {})
    except safescan.SafeScanRefusal as exc:
        # A malformed window is not "no window" — it is a window the customer meant to have.
        return safescan.Verdict(False, str(exc), action="refuse")

    concurrent = session.query(Scan).filter(
        Scan.asset_id == asset.id,
        Scan.id != scan.id,
        Scan.status.in_((ScanStatus.RUNNING.value, ScanStatus.QUEUED.value)),
    ).count()
    return safescan.check(
        policy,
        now=_now(),
        active_scans_on_asset=concurrent,
        platform_paused=bool(getattr(settings, "active_scanning_paused", False)),
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

        # Claim the scan, atomically. `queued → running` is a conditional UPDATE that exactly one
        # caller can win, so a message delivered twice — a broker redelivery, or a recovery sweep
        # racing a message that turned up after all — runs the scan once and returns. Without this
        # the second run would reach `ScanEngineRun` and collide on `uq_engine_run_scan_engine`,
        # turning a duplicate delivery into a failed scan.
        claimed = session.execute(
            update(Scan)
            .where(Scan.id == scan.id, Scan.status == ScanStatus.QUEUED.value)
            .values(status=ScanStatus.RUNNING.value, started_at=_now())
        ).rowcount
        if not claimed:
            session.expire(scan)
            log.info("scan_already_claimed", scan_id=scan_id, status=scan.status)
            return {"scan_id": scan_id, "status": scan.status, "claimed": False}
        session.expire(scan)
        session.flush()

        workspace, inline, cleanup = None, None, None
        engine_statuses: list[str] = []
        # Every issue already known for this asset, by fingerprint. A scan re-observing one folds
        # into it rather than filing a duplicate, so the row count tracks distinct issues and a
        # finding keeps its history across rescans.
        known: dict[str, Finding] = {
            row.fingerprint: row for row in session.execute(
                select(Finding).where(
                    Finding.tenant_id == scan.tenant_id,
                    Finding.asset_id == asset.id,
                )
            ).scalars()
        }
        # What *this* scan saw, deduplicated — two engines reporting one issue is one sighting.
        observed: dict[str, Finding] = {}

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
                if needs_auth:
                    safe = _safe_scan_verdict(session, scan, asset, customer)
                    if not safe.allowed:
                        # Deferred, not silently skipped: a skipped engine reads as a clean one.
                        run.status = "deferred" if safe.action == "defer" else "skipped"
                        run.error = safe.reason
                        engine_statuses.append("skipped")
                        record_audit(
                            session,
                            action="scan.engine.deferred_safe_scanning",
                            tenant_id=scan.tenant_id,
                            customer_id=scan.customer_id,
                            entity_type="scan_engine_run",
                            entity_id=str(run.id),
                            metadata={"engine": engine_key, "reason": safe.reason,
                                      "action": safe.action,
                                      "retry_after": (safe.retry_after.isoformat()
                                                      if safe.retry_after else None)},
                        )
                        continue
                    # The customer's intensity profile caps what the active engines may spend.
                    # Named for the engines that read them (WP-D2/B2), so a customer dialling the
                    # profile down actually slows the scanner rather than only the paperwork.
                    scan_settings = {
                        "dast_max_requests": safe.limits["max_requests"],
                        "dast_rate": safe.limits["rate_per_second"],
                        "api_max_requests": safe.limits["max_requests"],
                        "api_rate": safe.limits["rate_per_second"],
                        "scan_profile": safe.reason,
                    }
                else:
                    scan_settings = {}

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
                    settings=scan_settings,  # the customer's intensity profile (WP-H3)
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
                        # One row per issue, not one per sighting. Without this a rescan filed a
                        # duplicate of everything it saw and the customer's open count climbed while
                        # nothing got worse — and a returning issue arrived as a new finding with no
                        # history, which is the case `verification._apply` was written to prevent.
                        prior = known.get(finding.fingerprint)
                        if prior is None:
                            session.add(finding)
                            known[finding.fingerprint] = finding
                            observed[finding.fingerprint] = finding
                        else:
                            observed[finding.fingerprint] = merge_sighting(
                                prior, finding, scan_id=scan.id, engine_run_id=run.id)
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
            failure = {"scan_id": scan_id, "status": scan.status}
            # A failed scan is exactly the event an integration needs; silence on failure is how a
            # subscriber concludes there was nothing to report. Enqueued on its own session, so it
            # neither joins nor blocks the transaction recording the failure.
            _emit_scan_event(scan_id, str(scan.tenant_id),
                             str(scan.customer_id) if scan.customer_id else None,
                             scan.status, failure)
            return failure
        finally:
            if cleanup:
                shutil.rmtree(cleanup, ignore_errors=True)

        session.flush()
        scan.stats = severity_counts(list(observed.values()))
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

        # Join what this scan found to what the other engines already know (WP-E1). Runs after
        # reconciliation so a finding this scan resolved is no longer a candidate for a group, and
        # before the remediation opener below, because "one item per underlying issue" is a promise
        # that depends on the group existing first.
        from guardian_scanner.correlation import correlate_tenant

        try:
            result["correlation"] = correlate_tenant(_tenant, _customer)
        except Exception as exc:  # noqa: BLE001 - correlation is enrichment, not the scan
            log.error("correlation_failed", scan_id=scan_id, error=str(exc)[:300])
            result["correlation"] = {"error": f"{type(exc).__name__}: {exc}"[:200]}

        # Turn what the graph now knows about running services into vulnerability findings (WP-C3).
        # This is the only path by which a host with no repository gets one: B2/B3 collect the
        # product and version, C1 supplies the CPE applicability, and nothing else joins them.
        # After `enrich_graph`, so it sees the services this scan just projected.
        from guardian_scanner.service_cve import match_service_versions

        try:
            result["service_cve"] = match_service_versions(_tenant, _customer)
        except Exception as exc:  # noqa: BLE001 - matching is enrichment, not the scan
            log.error("service_cve_failed", scan_id=scan_id, error=str(exc)[:300])
            result["service_cve"] = {"error": f"{type(exc).__name__}: {exc}"[:200]}

    # Tell whoever asked to be told (WP-G3). Emitted for every terminal state, including failure:
    # a scan that died is exactly the event an integration needs, and silence on failure is how a
    # webhook consumer concludes there was nothing to report.
    _emit_scan_event(scan_id, _tenant, _customer, _status, result)
    return result


def _emit_scan_event(scan_id: str, tenant_id: str, customer_id: str | None,
                     status: str, result: dict) -> None:
    """Guarded wrapper. See `_emit_scan_event_inner` for what it does and why."""
    try:
        _emit_scan_event_inner(scan_id, tenant_id, customer_id, status, result)
    except Exception as exc:  # noqa: BLE001 - a notification defect must never fail a scan
        # This guard exists because the first version of it did exactly that: a bad keyword in a
        # log line raised *after* the deliveries were queued and took a completed scan down with
        # it. The blast radius of the notification path stops here.
        log.error("webhook_emit_failed", scan_id=scan_id,
                  error=f"{type(exc).__name__}: {exc}"[:300])


def _emit_scan_event_inner(scan_id: str, tenant_id: str, customer_id: str | None,
                           status: str, result: dict) -> None:
    """Queue the outbound webhooks for a finished scan, and dispatch them.

    Failures here are logged and dropped rather than raised: the scan is already committed and its
    findings are already durable, so failing the task would re-run a completed scan to retry a
    notification. The deliveries themselves are persisted rows with their own retry policy, so a
    delivery that cannot be sent now is not lost — only an enqueue that raises is, and that is what
    the log line records.
    """
    from guardian_scanner.webhooks import deliver_webhook, enqueue

    terminal = {
        ScanStatus.COMPLETED.value: "scan.completed",
        ScanStatus.PARTIAL.value: "scan.completed",
        ScanStatus.FAILED.value: "scan.failed",
    }
    event_type = terminal.get(status)
    if event_type is None:
        return

    stats = result.get("stats") or {}
    data = {
        "scan_id": scan_id,
        "status": status,
        "findings": int(stats.get("total", 0) or 0),
        "severity_counts": {k: v for k, v in stats.items() if k != "total"},
    }
    delivery_ids: list[str] = []
    try:
        with session_scope() as session:
            ids = enqueue(session, tenant_id=uuid.UUID(tenant_id), event_type=event_type,
                          data=data, customer_id=uuid.UUID(customer_id) if customer_id else None)
            delivery_ids = [str(i) for i in ids]

            # A critical finding is its own event: a subscriber who only wants to be woken for
            # those should not have to parse every scan.completed to discover one.
            if int(stats.get("critical", 0) or 0) > 0:
                critical = enqueue(
                    session, tenant_id=uuid.UUID(tenant_id), event_type="finding.critical",
                    data={"scan_id": scan_id, "critical": int(stats.get("critical", 0))},
                    customer_id=uuid.UUID(customer_id) if customer_id else None,
                )
                delivery_ids.extend(str(i) for i in critical)
    except Exception as exc:  # noqa: BLE001 - the scan is committed; a notification must not undo it
        log.error("webhook_enqueue_failed", scan_id=scan_id, error=str(exc)[:300])
        return

    for delivery_id in delivery_ids:
        try:
            deliver_webhook.apply_async(args=[delivery_id])
        except Exception as exc:  # noqa: BLE001 - the row is durable; the sweep retries it
            log.error("webhook_dispatch_failed", delivery=delivery_id, error=str(exc)[:200])
    if delivery_ids:
        log.info("webhooks_queued", scan_id=scan_id, event_type=event_type,
                 count=len(delivery_ids))
