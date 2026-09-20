"""Best-effort, on-demand provisioning of the external GitHub Actions scan plane.

When engine execution is offloaded to the GitHub scan plane (``external_scan_plane``) and a GitHub
dispatch token is configured, ``ensure_scan_plane_running`` triggers the guardian-scan-plane
workflow so an operator only has to start a scan in the console — the runner spins up on demand.

WHAT THIS IS NOT. It never starts a scan. A human already created the scan in the console and it
passed the ownership gate (or the owner-direct affirmation); this only provisions the *worker* that
runs an already-queued, already-authorized engine job. So it does not reintroduce the "a schedule
must never begin active testing" risk the workflows guard against — the trigger here is one human-
initiated scan needing a consumer, not a cron probing hosts on its own.

BOUNDARY. The dispatch token is a control-plane secret: run_scan runs on guardian-api's control
worker, which already holds the JWT and KMS master. The DB-less scan plane never receives this token
(it runs on a GitHub runner that only holds the broker URL + seal key).

FAIL-SAFE. Every network error is logged and swallowed. If the token is missing, wrong, or GitHub is
unreachable, the scan simply waits for a manually-started window as before — the auto-dispatch only
ever removes a manual step, it can never fail a scan.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from guardian_common.config import get_settings
from guardian_common.logging import get_logger

log = get_logger("guardian.scan_plane_dispatch")

_API = "https://api.github.com"
_TIMEOUT = 5  # seconds; this is best-effort and must never hold up a scan for long


def _request(method: str, url: str, token: str, payload: dict | None = None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)  # noqa: S310 - fixed https api.github.com
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    return urllib.request.urlopen(req, timeout=_TIMEOUT)  # noqa: S310 - fixed https api.github.com


def _a_run_is_active(repo: str, workflow: str, token: str) -> bool:
    """True if a scan-plane run is already queued or in progress — a consumer is (about to be) up,
    so we must not pile on a second run and burn Actions minutes."""
    for status in ("in_progress", "queued"):
        url = f"{_API}/repos/{repo}/actions/workflows/{workflow}/runs?status={status}&per_page=1"
        with _request("GET", url, token) as resp:
            if json.loads(resp.read()).get("total_count", 0) > 0:
                return True
    return False


def ensure_scan_plane_running() -> None:
    """Provision the external scan plane if it isn't already running.

    No-op unless the external scan plane is configured AND a dispatch token is set. Best-effort: any
    failure is logged and swallowed so a dispatch problem never fails the scan.
    """
    s = get_settings()
    if not (s.external_scan_plane and s.github_dispatch_token):
        return
    repo, workflow, token = s.github_repo, s.scan_plane_workflow_file, s.github_dispatch_token
    try:
        if _a_run_is_active(repo, workflow, token):
            log.info("scan_plane_already_running")
            return
        with _request(
            "POST",
            f"{_API}/repos/{repo}/actions/workflows/{workflow}/dispatches",
            token,
            {"ref": s.scan_plane_workflow_ref,
             "inputs": {"minutes": str(s.scan_plane_window_minutes)}},
        ):
            pass
        log.info("scan_plane_dispatched", workflow=workflow, ref=s.scan_plane_workflow_ref)
    except urllib.error.HTTPError as exc:  # noqa: BLE001 - handled: best-effort
        log.warning("scan_plane_dispatch_failed", status=exc.code)
    except Exception as exc:  # noqa: BLE001 - best-effort; a dispatch problem must never fail a scan
        log.warning("scan_plane_dispatch_error", error=f"{type(exc).__name__}: {exc}"[:160])
