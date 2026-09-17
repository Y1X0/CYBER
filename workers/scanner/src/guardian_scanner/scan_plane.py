"""The scan execution plane (ISSUE-3): run untrusted engine code off the control plane.

`guardian.run_scan` is the control-plane orchestrator: it holds the KMS master (to decrypt tenant
credentials) and the JWT secret, claims the scan, authorizes, persists findings, and encrypts
proofs. The one part of a scan that parses attacker-controlled bytes — an engine's ``run()`` and
``collect_inventory()`` — is dispatched here, onto the ``scan`` queue, whose worker holds NEITHER
the KMS master NOR the JWT secret (config refuses to start a ``scan_plane`` that carries either).

Boundary contract:

* The control plane decrypts tenant credentials (master key) and hands this plane only the per-job
  data an engine needs, SEALED with the broker-seal key (``seal_engine_job``). This plane unseals
  it with the same broker-seal key — it can decrypt this one job, never the credential store.
* This plane runs the engine inside the fork sandbox (which additionally scrubs ``GUARDIAN_*`` from
  the child env), then seals the raw findings + health + SBOM inventory back.
* Only JSON crosses the boundary (``RawFinding.to_dict`` / ``EngineHealth`` / inventory tuples),
  never pickle: the scan plane is the lower-trust side, and a pickle travelling back to the control
  plane would let a compromised engine execute code where the KMS master lives. The pickle the
  sandbox uses internally (child → parent) stays WITHIN this plane, same trust domain.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from guardian_common.config import get_settings
from guardian_common.crypto import seal_secret, unseal_secret
from guardian_common.logging import get_logger
from guardian_core.enums import EngineKey
from guardian_core.findings import RawFinding

from guardian_scanner import sandbox
from guardian_scanner.celery_app import celery_app
from guardian_scanner.engines.base import EngineHealth, ScanContext
from guardian_scanner.registry import get_engine

log = get_logger("guardian.scan_plane")

# The ScanContext fields an engine needs. `vuln_matcher` is deliberately excluded — it is a
# DB-bound object, is not serialisable, and is used only by SCA, which never offloads.
_CTX_FIELDS = (
    "scan_id", "asset_kind", "asset_identifier", "workspace_path", "artifact_path",
    "inline_content", "exposure", "settings", "asset_config", "secret_config",
)

SCAN_QUEUE = "scan"


@dataclass
class EngineOutcome:
    """What one engine produced: findings, its own health, and any SBOM inventory it enumerated.

    The uniform return of both the in-process path and the offloaded scan-plane path, so
    ``run_scan`` consumes them the same way regardless of where the engine actually ran.
    """

    raws: list[RawFinding]
    health: EngineHealth
    inventory: list[tuple[str, str, str, str]]


def seal_engine_job(engine_key: str, ctx: ScanContext) -> str:
    """Seal one engine job for the scan plane. The payload includes the decrypted `secret_config`
    (for wants-secrets engines) — sealed with the broker key, never the master — so the scan plane
    can use per-job credentials without ever holding the key that decrypts the credential store."""
    payload = {"engine_key": engine_key, "ctx": {f: getattr(ctx, f) for f in _CTX_FIELDS}}
    return seal_secret(json.dumps(payload, separators=(",", ":")))


def _collect_inventory(engine, ctx: ScanContext) -> list[tuple[str, str, str, str]]:  # noqa: ANN001
    """An engine's SBOM component inventory, or [] — never raises. Runs where the engine runs, so on
    the offloaded path it executes on the scan plane (it re-parses untrusted bytes), never here."""
    collect = getattr(engine, "collect_inventory", None)
    if not callable(collect):
        return []
    try:
        return [tuple(row) for row in (collect(ctx) or [])]
    except Exception as exc:  # noqa: BLE001 - SBOM capture must never fail the scan
        log.warning("inventory_collect_failed", error=f"{type(exc).__name__}: {exc}"[:200])
        return []


def _run_engine_sandboxed(engine, ctx: ScanContext) -> dict:  # noqa: ANN001
    """Run the engine (and its inventory pass) inside the fork sandbox when supported.

    Returns a plain dict {raws, health, inventory}; the sandbox pickles it back from the child to
    this same (scan-plane) process — that pickle never leaves this trust domain.
    """
    settings = get_settings()

    def _work() -> dict:
        raws = list(engine.run(ctx))
        health = engine.health()
        inventory = _collect_inventory(engine, ctx)
        return {"raws": raws, "health": health, "inventory": inventory}

    if settings.sandbox_engines and sandbox.supported() and engine.key != EngineKey.SCA:
        return sandbox.run_in_sandbox(_work, sandbox.policy_for(engine.key))
    return _work()


@celery_app.task(name="guardian.execute_engine")
def execute_engine(sealed_job: str) -> str:
    """Scan-plane entry point: unseal a job, run the engine, seal the result. Holds no master key.

    Runs on the `scan` queue. `run_scan` on the control plane calls this via `run_engine_offloaded`
    and blocks on the sealed result.
    """
    raw = unseal_secret(sealed_job)
    if raw is None:
        raise ValueError("scan-plane job could not be unsealed (wrong broker-seal key?)")
    job = json.loads(raw)
    engine_key = job["engine_key"]
    ctx = ScanContext(vuln_matcher=None, **job["ctx"])

    engine = get_engine(engine_key)
    if engine is None:
        raise ValueError(f"scan-plane received an unknown engine key: {engine_key!r}")

    result = _run_engine_sandboxed(engine, ctx)
    health: EngineHealth = result["health"]
    bundle = {
        "raws": [r.to_dict() for r in result["raws"]],
        "health": {
            "ok": bool(getattr(health, "ok", True)),
            "detail": str(getattr(health, "detail", "")),
            "degraded": bool(getattr(health, "degraded", False)),
            "missing": list(getattr(health, "missing", ()) or ()),
        },
        "inventory": [list(row) for row in result["inventory"]],
    }
    return seal_secret(json.dumps(bundle, separators=(",", ":")))


def run_engine_offloaded(engine_key: str, ctx: ScanContext) -> EngineOutcome:
    """Control-plane side: dispatch one engine to the scan plane and wait for its sealed result.

    Seals the job (creds included, broker-key only), sends it to the `scan` queue, blocks up to
    `scan_offload_timeout_seconds`, unseals the reply, and rebuilds it from JSON. Raising on
    timeout/failure is intended: `run_scan` catches per-engine failures and degrades that one
    engine, never the whole scan.
    """
    settings = get_settings()
    sealed_in = seal_engine_job(engine_key, ctx)
    async_result = celery_app.send_task(
        "guardian.execute_engine", args=[sealed_in], queue=SCAN_QUEUE
    )
    # disable_sync_subtasks=False: this .get() is a deliberate synchronous wait from the
    # orchestrator on a task that runs on a DIFFERENT worker (the scan plane), so Celery's
    # "never call get() within a task" guard would otherwise refuse it. The wait cannot deadlock
    # because run_scan (default queue) and execute_engine (scan queue) are separate workers.
    sealed_out = async_result.get(
        timeout=settings.scan_offload_timeout_seconds, disable_sync_subtasks=False
    )
    raw = unseal_secret(sealed_out)
    if raw is None:
        raise ValueError("scan-plane result could not be unsealed (wrong broker-seal key?)")
    bundle = json.loads(raw)
    return EngineOutcome(
        raws=[RawFinding.from_dict(d) for d in bundle.get("raws", [])],
        health=EngineHealth(**{
            "ok": bool(bundle.get("health", {}).get("ok", True)),
            "detail": str(bundle.get("health", {}).get("detail", "")),
            "degraded": bool(bundle.get("health", {}).get("degraded", False)),
            "missing": tuple(bundle.get("health", {}).get("missing", ()) or ()),
        }),
        inventory=[tuple(row) for row in bundle.get("inventory", [])],
    )
