"""Decompression-bomb safety for the zip-based artifact engines (AUD-P1-5).

The mobile/iOS engines used `zipfile.read(name)[:budget]`, which fully inflates a member into memory
before slicing — a small `.apk`/`.ipa` with a high DEFLATE ratio could balloon to gigabytes first.
These tests prove the replacement reads are *bounded*: a member that inflates far past the budget is
never materialized past it, and members that must be parsed whole are refused when implausibly large.
"""

from __future__ import annotations

import io
import zipfile

import pytest
from guardian_scanner.mobile.safezip import (
    ArchiveMemberTooLarge,
    read_bounded,
    read_whole_capped,
)


def _zip_with(name: str, data: bytes) -> zipfile.ZipFile:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(name, data)
    buf.seek(0)
    return zipfile.ZipFile(buf)


def test_read_bounded_truncates_a_large_member():
    # 8 MB of highly compressible zeros — a stand-in for a bomb member. read_bounded must return at
    # most the limit, never the whole inflated member.
    big = b"\x00" * (8 * 1024 * 1024)
    zf = _zip_with("classes.dex", big)
    out = read_bounded(zf, "classes.dex", 4096)
    assert len(out) == 4096


def test_read_bounded_returns_whole_small_member():
    zf = _zip_with("a", b"hello")
    assert read_bounded(zf, "a", 1024) == b"hello"


def test_read_whole_capped_accepts_small_member():
    zf = _zip_with("Info.plist", b"<plist/>")
    assert read_whole_capped(zf, "Info.plist", cap=1024) == b"<plist/>"


def test_read_whole_capped_rejects_oversized_member():
    zf = _zip_with("Info.plist", b"\x00" * (2 * 1024 * 1024))
    with pytest.raises(ArchiveMemberTooLarge):
        read_whole_capped(zf, "Info.plist", cap=1024)


def test_a_zip_bomb_apk_does_not_exhaust_memory_and_still_scans():
    # A valid-looking APK whose classes.dex inflates to 60 MB from a tiny compressed blob. The engine
    # must complete (manifest posture findings) with its content read bounded — not inflate 60 MB.
    from guardian_scanner.engines.base import ScanContext
    from guardian_scanner.engines.mobile_engine import MobileEngine

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "AndroidManifest.xml",
            b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            b'package="com.x"><application android:debuggable="true"/></manifest>')
        zf.writestr("classes.dex", b"\x00" * (60 * 1024 * 1024))
    apk = io.BytesIO(buf.getvalue())

    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".apk") as fh:
        fh.write(apk.getvalue())
        fh.flush()
        ctx = ScanContext(scan_id="t", asset_kind="mobile_app", asset_identifier="x",
                          artifact_path=fh.name)
        findings = list(MobileEngine().run(ctx))
    # It produced findings from the manifest and did not raise/hang on the bomb member.
    assert any(f.category.startswith("mobile") for f in findings)
