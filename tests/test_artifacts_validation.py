"""Artifact validation — the static, DB-free rules that gate every upload (AUD-P1-7).

These prove the upload boundary is honest and safe *before* any bytes are stored: an artifact is only
accepted when its content really is the archive the asset needs, and the uploader's filename can never
carry a path out of a controlled directory. No filesystem, no database — pure functions on bytes.
"""

from __future__ import annotations

import io
import zipfile

import pytest
from guardian_core.artifacts import (
    ArtifactValidationError,
    artifact_kind_for_asset,
    asset_requires_artifact,
    detect_artifact_kind,
    sanitize_filename,
    validate_artifact,
)


def _zip(names: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in names.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _apk_bytes() -> bytes:
    return _zip({"AndroidManifest.xml": b"<manifest package='com.x'/>",
                 "classes.dex": b"dex\n035\x00"})


def _ipa_bytes() -> bytes:
    return _zip({"Payload/App.app/Info.plist": b"<plist><dict></dict></plist>",
                 "Payload/App.app/App": b"\xca\xfe\xba\xbe"})


# ── kind detection is by structure, not extension ───────────────────────────────────────────────
def test_detects_apk_by_manifest():
    assert detect_artifact_kind(_apk_bytes()) == "apk"


def test_detects_ipa_by_payload():
    assert detect_artifact_kind(_ipa_bytes()) == "ipa"


def test_a_plain_zip_that_is_neither_is_rejected():
    assert detect_artifact_kind(_zip({"readme.txt": b"hi"})) is None


def test_a_renamed_non_archive_is_not_an_artifact():
    assert detect_artifact_kind(b"%PDF-1.4 not a zip at all") is None


def test_an_archive_that_is_both_is_ambiguous_and_refused():
    both = _zip({"AndroidManifest.xml": b"<manifest/>",
                 "Payload/App.app/Info.plist": b"<plist/>"})
    assert detect_artifact_kind(both) is None


# ── validate_artifact enforces the expected kind ────────────────────────────────────────────────
def test_validate_accepts_matching_kind():
    validate_artifact("apk", _apk_bytes())  # does not raise
    validate_artifact("ipa", _ipa_bytes())


def test_validate_rejects_wrong_kind_with_safe_message():
    with pytest.raises(ArtifactValidationError) as e:
        validate_artifact("apk", _ipa_bytes())
    # Customer-safe: names the kinds, leaks no path/tenant/stack.
    assert "Android" in str(e.value) and "iOS" in str(e.value)


def test_validate_rejects_empty():
    with pytest.raises(ArtifactValidationError):
        validate_artifact("apk", b"")


def test_validate_rejects_non_archive():
    with pytest.raises(ArtifactValidationError):
        validate_artifact("ipa", b"definitely not a zip")


def test_validate_rejects_unknown_expected_kind():
    with pytest.raises(ArtifactValidationError):
        validate_artifact("exe", _apk_bytes())


# ── filename sanitization is traversal-proof (display-only, but defence in depth) ────────────────
@pytest.mark.parametrize("hostile,expected_basename", [
    ("../../etc/passwd", "passwd"),
    ("..\\..\\windows\\system32\\cmd.exe", "cmd.exe"),
    ("/abs/path/app.apk", "app.apk"),
    ("normal name (1).apk", "normal name (1).apk"),
])
def test_sanitize_strips_directories(hostile, expected_basename):
    assert sanitize_filename(hostile) == expected_basename


def test_sanitize_removes_control_and_odd_chars():
    out = sanitize_filename("a\n\t\x00b;rm -rf.apk")
    assert "/" not in out and "\n" not in out and "\x00" not in out
    assert out.endswith(".apk")


def test_sanitize_caps_length():
    assert len(sanitize_filename("x" * 5000 + ".apk")) <= 255


def test_sanitize_empty_defaults():
    assert sanitize_filename("") == "artifact"
    assert sanitize_filename(None) == "artifact"
    assert sanitize_filename("...") == "artifact"


# ── asset-kind mapping ──────────────────────────────────────────────────────────────────────────
def test_only_mobile_and_ios_require_an_artifact():
    assert asset_requires_artifact("mobile_app")
    assert asset_requires_artifact("ios_app")
    for kind in ("repo", "web", "api", "cloud_account", "container_image", "network_host"):
        assert not asset_requires_artifact(kind)


def test_artifact_kind_for_asset():
    assert artifact_kind_for_asset("mobile_app") == "apk"
    assert artifact_kind_for_asset("ios_app") == "ipa"
    assert artifact_kind_for_asset("repo") is None
