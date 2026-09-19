"""render.yaml stays valid against Render's Blueprint schema, and the control plane keeps its keys.

Not a full schema check (Render's own validator is the authority), but two guards that already bit
us: an unknown TOP-LEVEL key fails the whole sync (a stray `services_note:` once did — "field
services_note not found in type file.Spec"), and guardian-api must remain the trusted control plane
that holds the JWT secret and KMS master.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[1]


def _blueprint() -> dict:
    return yaml.safe_load((_ROOT / "render.yaml").read_text()) or {}


def _services() -> dict:
    return {s["name"]: s for s in _blueprint().get("services", [])}


def test_render_blueprint_has_only_valid_top_level_keys():
    # Render's blueprint decoder is strict: an unknown top-level key fails the whole sync. file.Spec
    # accepts only this fixed set — guard it so a note or typo can never break a sync again.
    allowed = {"services", "databases", "envVarGroups", "previews", "version"}
    extra = set(_blueprint()) - allowed
    assert not extra, f"render.yaml has top-level keys Render's schema rejects: {sorted(extra)}"


def test_guardian_api_holds_the_master_keys_and_is_the_control_plane():
    env = {e["key"]: e for e in _services()["guardian-api"].get("envVars", [])}
    assert env["GUARDIAN_JWT_SECRET"].get("generateValue") is True
    assert env["GUARDIAN_ENCRYPTION_KEY"].get("generateValue") is True
    assert "GUARDIAN_SCAN_PLANE" not in env, "guardian-api is the control plane, not a scan plane"
