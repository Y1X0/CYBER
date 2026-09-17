"""The keep-alive cron is disabled; the workflow runs on workflow_dispatch only (Item 5, OPS).

The 10-minute schedule was removed as part of the deployment cutover. This asserts no ACTIVE cron
schedule remains (any cron line is commented out) while manual dispatch is still available.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_KEEPALIVE = (_ROOT / ".github/workflows/guardian-keepalive.yml").read_text()


def test_manual_dispatch_is_kept():
    assert "workflow_dispatch:" in _KEEPALIVE


def test_no_active_cron_schedule():
    for line in _KEEPALIVE.splitlines():
        if "cron:" in line:
            assert line.lstrip().startswith("#"), f"an active cron schedule remains: {line!r}"


def test_no_active_schedule_key():
    active = [ln for ln in _KEEPALIVE.splitlines()
              if ln.strip() == "schedule:" and not ln.lstrip().startswith("#")]
    assert active == [], "the `schedule:` trigger must be commented out / removed"


def test_cutover_plan_is_documented():
    doc = _ROOT / "docs/deployment/11-branch-cutover.md"
    assert doc.exists(), "the branch-cutover plan must be documented"
    text = doc.read_text()
    assert "main" in text and "render.yaml" in text
