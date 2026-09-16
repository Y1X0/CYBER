"""Scan-artifact upload, authorization, lifecycle, and worker resolution — end to end (AUD-P1-7/P1-6).

What is proved against a real database + RLS:
  * a .apk/.ipa uploads only to an asset of the matching kind, and only within the caller's tenant;
  * another tenant cannot upload to, list, or delete an asset's artifacts by changing the id (RLS);
  * a scan of a mobile/iOS asset is refused until its artifact is attached, and accepted after;
  * the worker resolves the artifact by opaque id scoped to (tenant, asset) and runs the engine on a
    server-owned temp file, cleaning it up — never trusting a config path (AUD-P1-6).

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import io
import os
import uuid
import zipfile

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


# ── fixtures: bytes ─────────────────────────────────────────────────────────────────────────────
def _apk_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml",
                    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                    'package="com.x"><application android:debuggable="true"/></manifest>')
        zf.writestr("classes.dex", b"dexcontent")
    return buf.getvalue()


def _ipa_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("Payload/App.app/Info.plist",
                    b"<plist><dict><key>CFBundleIdentifier</key><string>com.x</string>"
                    b"</dict></plist>")
    return buf.getvalue()


def _tenant(kind: str = "mobile_app"):
    from guardian_db.models import Asset, Customer, Tenant, TenantMembership, User
    from guardian_db.session import session_scope

    slug = f"art-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        staff = User(email=f"s-{slug}@x.invalid", name="Analyst", status="active")
        db.add_all([customer, staff])
        db.flush()
        db.add(TenantMembership(user_id=staff.id, tenant_id=tenant.id, role="pentester"))
        asset = Asset(tenant_id=tenant.id, customer_id=customer.id, name="app", kind=kind,
                      identifier="com.x", config={})
        db.add(asset)
        db.flush()
        return {"tenant": tenant.id, "customer": customer.id, "staff": staff.id,
                "asset": asset.id, "slug": slug}


def _client(ctx):
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token

    settings = get_settings()
    token = create_access_token(subject=str(ctx["staff"]), secret=settings.jwt_secret,
                                algorithm=settings.jwt_algorithm)
    return TestClient(app), {"Authorization": f"Bearer {token}"}


def _upload(client, hdr, asset_id, name, data):
    return client.post(f"/api/v1/assets/{asset_id}/artifact",
                       files={"file": (name, data, "application/octet-stream")}, headers=hdr)


# ── upload happy path + type honesty ─────────────────────────────────────────────────────────────
def test_valid_apk_uploads_and_attaches_to_the_asset():
    ctx = _tenant("mobile_app")
    client, hdr = _client(ctx)
    r = _upload(client, hdr, ctx["asset"], "app.apk", _apk_bytes())
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["kind"] == "apk" and body["size_bytes"] > 0 and len(body["sha256"]) == 64
    # The asset now points at the artifact, so a scan will resolve it.
    from guardian_db.models import Asset
    from guardian_db.session import session_scope
    with session_scope() as db:
        asset = db.get(Asset, ctx["asset"])
        assert asset.config.get("artifact_id") == body["id"]


def test_valid_ipa_uploads_to_an_ios_asset():
    ctx = _tenant("ios_app")
    client, hdr = _client(ctx)
    r = _upload(client, hdr, ctx["asset"], "app.ipa", _ipa_bytes())
    assert r.status_code == 201, r.text
    assert r.json()["kind"] == "ipa"


def test_wrong_type_is_refused():
    ctx = _tenant("mobile_app")  # android asset…
    client, hdr = _client(ctx)
    r = _upload(client, hdr, ctx["asset"], "app.apk", _ipa_bytes())  # …but ipa bytes
    assert r.status_code == 415
    assert "Android" in r.json()["detail"]


def test_a_corrupt_archive_is_refused():
    ctx = _tenant("mobile_app")
    client, hdr = _client(ctx)
    r = _upload(client, hdr, ctx["asset"], "app.apk", b"PK\x03\x04 not really a zip body")
    assert r.status_code == 415


def test_upload_to_a_non_artifact_asset_is_refused():
    ctx = _tenant("repo")
    client, hdr = _client(ctx)
    r = _upload(client, hdr, ctx["asset"], "app.apk", _apk_bytes())
    assert r.status_code == 400


def test_oversized_upload_is_refused(monkeypatch):
    from guardian_common.config import get_settings
    monkeypatch.setattr(get_settings(), "artifact_max_bytes", 128)
    ctx = _tenant("mobile_app")
    client, hdr = _client(ctx)
    r = _upload(client, hdr, ctx["asset"], "app.apk", _apk_bytes())  # apk is > 128 bytes
    assert r.status_code == 413


# ── tenant isolation ─────────────────────────────────────────────────────────────────────────────
def test_another_tenant_cannot_upload_to_your_asset():
    owner = _tenant("mobile_app")
    intruder = _tenant("mobile_app")
    client, hdr = _client(intruder)  # intruder's token, owner's asset
    r = _upload(client, hdr, owner["asset"], "app.apk", _apk_bytes())
    assert r.status_code == 404


def test_another_tenant_cannot_list_or_delete_your_artifacts():
    owner = _tenant("mobile_app")
    oclient, ohdr = _client(owner)
    up = _upload(oclient, ohdr, owner["asset"], "app.apk", _apk_bytes()).json()

    intruder = _tenant("mobile_app")
    iclient, ihdr = _client(intruder)
    assert iclient.get(f"/api/v1/assets/{owner['asset']}/artifacts",
                       headers=ihdr).status_code == 404
    assert iclient.delete(f"/api/v1/assets/{owner['asset']}/artifacts/{up['id']}",
                          headers=ihdr).status_code == 404
    # …and the artifact is still there for its owner.
    assert len(oclient.get(f"/api/v1/assets/{owner['asset']}/artifacts",
                           headers=ohdr).json()) == 1


def test_list_and_delete_clears_the_asset_pointer():
    ctx = _tenant("mobile_app")
    client, hdr = _client(ctx)
    up = _upload(client, hdr, ctx["asset"], "app.apk", _apk_bytes()).json()
    listed = client.get(f"/api/v1/assets/{ctx['asset']}/artifacts", headers=hdr).json()
    assert [a["id"] for a in listed] == [up["id"]]

    d = client.delete(f"/api/v1/assets/{ctx['asset']}/artifacts/{up['id']}", headers=hdr)
    assert d.status_code == 204
    from guardian_db.models import Asset
    from guardian_db.session import session_scope
    with session_scope() as db:
        assert "artifact_id" not in (db.get(Asset, ctx["asset"]).config or {})


# ── scan lifecycle gate ──────────────────────────────────────────────────────────────────────────
def test_scan_is_refused_without_the_artifact_then_allowed_after_upload():
    ctx = _tenant("mobile_app")
    client, hdr = _client(ctx)
    body = {"asset_id": str(ctx["asset"]), "engines": ["mobile"], "trigger": "manual"}
    before = client.post("/api/v1/scans", json=body, headers=hdr)
    assert before.status_code == 422 and "upload" in before.json()["detail"].lower()

    _upload(client, hdr, ctx["asset"], "app.apk", _apk_bytes())
    after = client.post("/api/v1/scans", json=body, headers=hdr)
    assert after.status_code == 202


# ── worker resolution is (tenant, asset)-scoped and cleans up ────────────────────────────────────
def test_worker_resolves_only_within_tenant_and_asset():
    from guardian_db.artifact_store import create_artifact
    from guardian_db.models import Asset
    from guardian_db.session import session_scope
    from guardian_scanner.tasks import _materialize_artifact

    ctx = _tenant("mobile_app")
    with session_scope() as db:
        rec = create_artifact(db, tenant_id=ctx["tenant"], customer_id=ctx["customer"],
                              asset_id=ctx["asset"], kind="apk", filename="app.apk",
                              content_type="", content=_apk_bytes(), created_by=ctx["staff"])
        db.commit()
        art_id = rec.id
        asset = db.get(Asset, ctx["asset"])
        asset.config = {"artifact_id": str(art_id)}
        db.commit()

    with session_scope() as db:
        asset = db.get(Asset, ctx["asset"])
        path, cleanup = _materialize_artifact(db, asset)
        assert path is not None and os.path.isfile(path)
        assert open(path, "rb").read()[:2] == b"PK"
        import shutil
        shutil.rmtree(cleanup, ignore_errors=True)

    # A different tenant's asset pointing at the same artifact id resolves to nothing.
    other = _tenant("mobile_app")
    with session_scope() as db:
        asset = db.get(Asset, other["asset"])
        asset.config = {"artifact_id": str(art_id)}  # smuggled id from another tenant
        db.commit()
    with session_scope() as db:
        asset = db.get(Asset, other["asset"])
        path, cleanup = _materialize_artifact(db, asset)
        assert path is None and cleanup is None


def test_full_scan_reads_the_uploaded_apk_and_cleans_up():
    from guardian_core.enums import ScanStatus
    from guardian_db.models import Finding, Scan
    from guardian_db.session import session_scope
    from guardian_scanner.tasks import run_scan

    ctx = _tenant("mobile_app")
    client, hdr = _client(ctx)
    _upload(client, hdr, ctx["asset"], "app.apk", _apk_bytes())
    with session_scope() as db:
        scan = Scan(tenant_id=ctx["tenant"], customer_id=ctx["customer"], asset_id=ctx["asset"],
                    trigger="manual", status=ScanStatus.QUEUED.value, requested_engines=["mobile"],
                    stats={})
        db.add(scan)
        db.flush()
        scan_id = scan.id
        db.commit()

    run_scan(str(scan_id))

    import glob
    with session_scope() as db:
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        # The debuggable manifest yields at least one finding — the engine read the uploaded apk.
        assert any("debuggable" in f.title.lower() for f in findings)
    # No materialized artifact temp dir left behind.
    assert glob.glob("/tmp/guardian_artifact_*") == []
