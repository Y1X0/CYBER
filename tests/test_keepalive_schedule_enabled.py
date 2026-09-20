"""The keep-alive cron is ENABLED so the free-tier control plane never sleeps.

Render's free plan stops the instance after ~15 minutes of no traffic; a slept instance makes the
console show a stale "QUEUED" for a scan that has actually finished. A 10-minute /health ping keeps
it warm. This asserts the schedule is active (and no faster than hourly is needed here), that manual
dispatch is still available, and — the load-bearing safety property — that the keep-alive only ever
pings /health and can never start a scan.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_KEEPALIVE = (_ROOT / ".github/workflows/guardian-keepalive.yml").read_text()


def _active_cron_lines() -> list[str]:
    return [ln.strip() for ln in _KEEPALIVE.splitlines()
            if "cron:" in ln and not ln.lstrip().startswith("#")]


def test_an_active_cron_schedule_is_present():
    crons = _active_cron_lines()
    assert crons, "the keep-alive must have an active cron schedule so the instance stays warm"


def test_the_cron_runs_at_least_every_fifteen_minutes():
    # Must fire inside Render's 15-minute free-tier idle window, or the instance sleeps between pings.
    crons = _active_cron_lines()
    minute_field = crons[0].split('"')[1].split()[0]  # e.g. "*/10" from `- cron: "*/10 * * * *"`
    m = re.fullmatch(r"\*/(\d+)", minute_field)
    assert m, f"expected a */N minute cron, got {minute_field!r}"
    assert int(m.group(1)) <= 15, "the ping interval must be <= 15 minutes to beat the idle window"


def test_manual_dispatch_is_kept():
    # A manual warm-up must remain available even with the schedule on.
    assert "workflow_dispatch:" in _KEEPALIVE


def _executable_yaml() -> str:
    # The comments deliberately discuss the burst/scan-plane workflows to explain why a *scheduled*
    # keep-alive is safe when a scheduled scanner is not. Behaviour lives in the non-comment lines,
    # so the safety check inspects those alone — full-line and trailing comments are stripped.
    out = []
    for line in _KEEPALIVE.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        out.append(line.split(" #", 1)[0])
    return "\n".join(out).lower()


def test_keepalive_only_pings_health_and_never_starts_a_scan():
    # The one safety property that lets a *scheduled* workflow exist at all: it may only GET /health.
    body = _executable_yaml()
    assert "/health" in body
    for forbidden in ("workflows/", "/dispatches", "run_scan", "scan-plane", "burst"):
        assert forbidden not in body, (
            f"keep-alive must not act on {forbidden!r} — it may only ping /health")
