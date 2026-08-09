"""ct_surface → World Model binder wiring (no DB). Proves the binder is registered for the tool and
that it short-circuits (touching no session) when there is nothing to promote."""

from __future__ import annotations

from guardian_core.tool import RawEvidence
from guardian_scanner.tools.tasks import _BINDERS, _bind_ct_surface_assets


def test_ct_surface_binder_is_registered():
    # The seam: dispatch_tool_job routes ct_surface evidence to the World-Model binder, not the
    # default finding binder (which would drop discovered assets).
    assert _BINDERS.get("ct_surface") is _bind_ct_surface_assets


def test_binder_no_discovered_assets_touches_no_session():
    # No discovered_asset evidence ⇒ returns [] before opening a DiscoveryRun or touching the DB.
    other = RawEvidence(tool="ct_surface", execution_id="j", target="x", kind="other", data={})
    assert _bind_ct_surface_assets(None, None, "ct_surface", []) == []
    assert _bind_ct_surface_assets(None, None, "ct_surface", [other]) == []
