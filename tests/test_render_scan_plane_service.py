"""The `guardian-scan` Render service keeps the scan-plane secret boundary — declared, not assumed.

The capacity split moves untrusted engine execution to its own free service so a heavy DAST scan
cannot OOM-kill the API. That service is only safe if its DECLARED environment matches the boundary
config.py enforces at boot: DB-less, no JWT secret, no KMS master, and the broker + seal key SHARED
with guardian-api (or every offloaded job fails to unseal). config.py refuses a mis-set scan_plane at
runtime; this test refuses a mis-set render.yaml at review time, before it ever deploys.
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
    # Render's blueprint decoder is strict: an unknown top-level key fails the whole sync (a stray
    # `services_note:` once did exactly that — "field services_note not found in type file.Spec").
    # file.Spec accepts only this fixed set; guard it so a note or typo can never break a sync again.
    allowed = {"services", "databases", "envVarGroups", "previews", "version"}
    extra = set(_blueprint()) - allowed
    assert not extra, f"render.yaml has top-level keys Render's schema rejects: {sorted(extra)}"


def _env(svc: dict) -> dict:
    return {e["key"]: e for e in svc.get("envVars", [])}


def test_guardian_scan_service_exists_and_runs_the_scan_plane_start_script():
    svc = _services().get("guardian-scan")
    assert svc is not None, "render.yaml must declare the isolated guardian-scan service"
    assert svc["type"] == "web", "free tier bills background workers, so the scan plane is a web service"
    assert svc["plan"] == "free"
    assert "start-scan-plane.sh" in svc["startCommand"]
    # A web service must bind a port; the health responder is that port.
    assert svc.get("healthCheckPath") == "/health"


def test_guardian_scan_is_marked_the_scan_plane_and_sandboxed():
    env = _env(_services()["guardian-scan"])
    assert env["GUARDIAN_SCAN_PLANE"]["value"] == "true"
    assert env["GUARDIAN_SANDBOX_ENGINES"]["value"] == "true"


def test_guardian_scan_carries_no_master_keys():
    # The boundary, as declared config. Neither the JWT secret nor the credential KMS master may be
    # set on the scan plane — config.py refuses to boot one that carries either, and they must not be
    # in the blueprint's env at all (not even as generateValue/sync:false).
    env = _env(_services()["guardian-scan"])
    assert "GUARDIAN_JWT_SECRET" not in env, "the scan plane must NOT carry the JWT secret"
    assert "GUARDIAN_ENCRYPTION_KEY" not in env, "the scan plane must NOT carry the KMS master"


def test_guardian_scan_is_db_less():
    # Set EMPTY, not unset: the settings default is a non-empty localhost DSN that fails the prod TLS
    # check. Empty string keeps the plane DB-less past that validator.
    env = _env(_services()["guardian-scan"])
    for key in ("GUARDIAN_DATABASE_URL", "GUARDIAN_APP_DATABASE_URL"):
        assert key in env, f"{key} must be declared (empty), not omitted"
        assert env[key].get("value") == "", f"{key} must be empty on the DB-less scan plane"


def test_guardian_scan_shares_the_broker_and_seal_key_with_guardian_api():
    # The control plane seals each engine job with the broker-seal key; the scan plane unseals with the
    # SAME key. Pull both the broker URL and the seal key from guardian-api via fromService so they
    # agree by construction — a freshly generated seal key here would fail every unseal.
    env = _env(_services()["guardian-scan"])
    for key in ("GUARDIAN_REDIS_URL", "GUARDIAN_BROKER_SEAL_KEY"):
        ref = env[key].get("fromService")
        assert ref, f"{key} must be shared from guardian-api via fromService"
        assert ref["name"] == "guardian-api" and ref["envVarKey"] == key


def test_guardian_api_still_holds_the_master_keys_and_is_not_a_scan_plane():
    # The other side of the boundary: guardian-api remains the trusted control plane — it holds the
    # JWT secret and KMS master and is never marked a scan plane.
    env = _env(_services()["guardian-api"])
    assert env["GUARDIAN_JWT_SECRET"].get("generateValue") is True
    assert env["GUARDIAN_ENCRYPTION_KEY"].get("generateValue") is True
    assert "GUARDIAN_SCAN_PLANE" not in env, "guardian-api is the control plane, not a scan plane"
