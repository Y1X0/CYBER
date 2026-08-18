"""Liveness, readiness, metrics, and the security SLOs (WP-G4)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.responses import PlainTextResponse
from guardian_common.config import get_settings
from guardian_common.metrics import REGISTRY
from sqlalchemy import text
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, get_current_identity, get_db
from guardian_api.observability import collect_execution_metrics, evaluate_slos, overall

router = APIRouter()


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "guardian-api"}


@router.get("/health/ready")
def ready(db: Session = Depends(get_db)) -> dict:
    db.execute(text("SELECT 1"))
    return {"status": "ready", "database": "ok"}


def _operator(x_metrics_token: str | None = Header(default=None),
              identity: Identity | None = None) -> None:
    """Metrics are operator-only.

    Not because a request count is a secret, but because route labels enumerate the API surface and
    the SLO detail strings describe how the platform is failing — which is a useful thing for an
    attacker to read. A scrape token is accepted so Prometheus does not need a human's session.
    """
    settings = get_settings()
    expected = getattr(settings, "metrics_token", "") or ""
    if expected and x_metrics_token and x_metrics_token == expected:
        return
    del identity
    raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                        "metrics require the scrape token or an authenticated operator")


@router.get("/metrics", response_class=PlainTextResponse)
def metrics(x_metrics_token: str | None = Header(default=None),
            db: Session = Depends(get_db)) -> str:
    """Prometheus text exposition.

    Scan-execution telemetry is read from the database on the way out (RED-5). The worker is a
    different process, so anything it counted in memory would never reach this endpoint — and a
    metric that is structurally always zero is worse than an absent one, because it reads as "no
    engines have failed" rather than "nobody is looking".

    A database failure here is surfaced, not swallowed: serving HTTP 200 with stale numbers is how
    a monitoring system reports health it did not measure.
    """
    _operator(x_metrics_token)
    try:
        collect_execution_metrics(db)
    except Exception as exc:  # noqa: BLE001 - reported, never rendered as healthy silence
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"scan-execution metrics could not be read from the database: "
            f"{type(exc).__name__}: {exc}",
        ) from exc
    return REGISTRY.render()


@router.get("/health/slo")
def slo(
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> dict:
    """Whether the security function is working, not just whether the process is up.

    Authenticated because the detail strings say precisely how the platform is failing.
    """
    del identity
    results = evaluate_slos(db)
    return {
        "status": overall(results),
        "slos": [item.as_dict() for item in results],
        # Spelled out because it is the whole point: an SLO nobody could evaluate is a question
        # nobody answered, and it must not read as a pass.
        "note": ("`unknown` means there was no data to judge from — it is not `healthy`, and the "
                 "overall status never collapses one into the other."),
    }
