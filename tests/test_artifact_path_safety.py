"""The artifact-path boundary that closes AUD-P1-6 (arbitrary worker file read).

Engines must read an artifact ONLY from a server-owned location — the worker-materialized
`ScanContext.artifact_path` — never from a path smuggled through the asset's tenant-controlled config
(`apk_path` / `ipa_path` / `local_path` / `image_archive`). These tests construct a context the way a
hostile config would and prove the engine ignores it, and prove the server-owned path IS honoured.
"""

from __future__ import annotations

import io
import zipfile

from guardian_scanner.engines.base import ScanContext
from guardian_scanner.engines.container_engine import ContainerEngine
from guardian_scanner.engines.ios_engine import IosEngine, IosInputError
from guardian_scanner.engines.mobile_engine import MobileEngine, MobileInputError


def _apk(tmp_path):
    p = tmp_path / "real.apk"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "AndroidManifest.xml",
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            'package="com.x"><application android:debuggable="true"/></manifest>')
    p.write_bytes(buf.getvalue())
    return p


def _ipa(tmp_path):
    p = tmp_path / "real.ipa"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("Payload/App.app/Info.plist",
                    b"<plist><dict><key>CFBundleIdentifier</key><string>com.x</string></dict></plist>")
    p.write_bytes(buf.getvalue())
    return p


# ── a tenant-controlled config path is NEVER opened (AUD-P1-6) ───────────────────────────────────
def test_mobile_ignores_apk_path_in_config(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("PRETEND /etc/passwd CONTENTS")
    # Old behaviour would have opened cfg['apk_path']; now the engine has no server-owned artifact,
    # so it refuses with a clear error rather than reading the named file.
    ctx = ScanContext(scan_id="t", asset_kind="mobile_app", asset_identifier="x",
                      asset_config={"apk_path": str(secret), "local_path": str(secret),
                                    "artifact_path": str(secret)})
    try:
        list(MobileEngine().run(ctx))
        raise AssertionError("expected MobileInputError — the config path must not be read")
    except MobileInputError as exc:
        assert "upload" in str(exc).lower()


def test_ios_ignores_ipa_path_in_config(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("PRETEND SECRET")
    ctx = ScanContext(scan_id="t", asset_kind="ios_app", asset_identifier="x",
                      asset_config={"ipa_path": str(secret), "local_path": str(secret)})
    try:
        list(IosEngine().run(ctx))
        raise AssertionError("expected IosInputError — the config path must not be read")
    except IosInputError as exc:
        assert "upload" in str(exc).lower()


def test_container_ignores_image_archive_in_config(tmp_path):
    secret = tmp_path / "secret.tar"
    secret.write_bytes(b"not really a tar")
    ctx = ScanContext(scan_id="t", asset_kind="container_image", asset_identifier="x",
                      asset_config={"image_archive": str(secret)})
    # No artifact_path, no workspace → nothing is scanned; crucially the config path is not opened.
    findings = list(ContainerEngine().run(ctx))
    assert findings == []


# ── the server-owned artifact_path IS honoured ───────────────────────────────────────────────────
def test_mobile_reads_server_owned_artifact_path(tmp_path):
    apk = _apk(tmp_path)
    ctx = ScanContext(scan_id="t", asset_kind="mobile_app", asset_identifier="x",
                      artifact_path=str(apk))
    findings = list(MobileEngine().run(ctx))
    assert any("debuggable" in f.title.lower() for f in findings)


def test_ios_reads_server_owned_artifact_path(tmp_path):
    ipa = _ipa(tmp_path)
    ctx = ScanContext(scan_id="t", asset_kind="ios_app", asset_identifier="x",
                      artifact_path=str(ipa))
    # Runs without raising and reads the bundle from the server-owned path.
    list(IosEngine().run(ctx))
