"""Mobile app static analysis (Android APK) — Phase 1.

Two layers are tested: the binary-AXML decoder (round-tripped through a tiny in-test encoder, so the
production decoder is exercised on real binary bytes), and the engine's finding logic (driven with
plaintext-XML manifests wrapped in a real zip, which the engine also accepts). Findings must flow
through the canonical RawFinding pipeline, and secret detection must reuse the platform's patterns.
"""

from __future__ import annotations

import struct
import zipfile

import pytest
from guardian_core.enums import EngineKey, Severity
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.engines.mobile_engine import MobileEngine, MobileInputError
from guardian_scanner.mobile.axml import parse_axml

# ── AXML decoder round-trip ─────────────────────────────────────────────────────────────────────


def _encode_axml(tag: str, attrs: dict[str, object]) -> bytes:
    """Minimal AXML encoder for one element (UTF-8 pool; string + bool attrs). Matches the decoder."""
    strings = [tag, *attrs.keys()]
    svals = {}
    for v in attrs.values():
        if isinstance(v, str):
            svals[v] = None
    pool_strings = strings + list(svals.keys())
    idx = {s: i for i, s in enumerate(pool_strings)}

    # string data (UTF-8: nchars, nbytes, bytes, NUL)
    data = b""
    offsets = []
    for s in pool_strings:
        offsets.append(len(data))
        b = s.encode("utf-8")
        data += bytes([len(s) & 0x7F, len(b) & 0x7F]) + b + b"\x00"
    while len(data) % 4:
        data += b"\x00"
    header = 28
    strings_start = header + 4 * len(pool_strings)
    pool_size = strings_start + len(data)
    pool = struct.pack("<HHIIIIII", 0x0001, 28, pool_size, len(pool_strings), 0,
                       0x100, strings_start, 0)
    pool += b"".join(struct.pack("<I", o) for o in offsets) + data

    # start element
    attr_bytes = b""
    for k, v in attrs.items():
        if isinstance(v, bool):
            dtype, dval, rawv = 0x12, (1 if v else 0), 0xFFFFFFFF
        else:
            dtype, dval, rawv = 0x03, idx[v], idx[v]
        attr_bytes += struct.pack("<IIIHBBI", 0xFFFFFFFF, idx[k], rawv, 8, 0, dtype, dval)
    start_size = 16 + 20 + len(attr_bytes)
    start = struct.pack("<HHIIIIIHHHHHH", 0x0102, 16, start_size, 1, 0xFFFFFFFF,
                        0xFFFFFFFF, idx[tag], 20, 20, len(attrs), 0, 0, 0) + attr_bytes
    end = struct.pack("<HHIIIII", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, idx[tag])

    body = pool + start + end
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def test_axml_decoder_round_trips_string_and_bool_attrs():
    raw = _encode_axml("manifest", {"package": "com.example.app", "debuggable": True})
    root = parse_axml(raw)
    el = root.children[0]
    assert el.tag == "manifest"
    assert el.attrs["package"] == "com.example.app"
    assert el.attrs["debuggable"] is True


def test_the_engine_reads_a_real_binary_axml_manifest(tmp_path):
    raw = _encode_axml("manifest", {"package": "com.bin.app"})
    apk = tmp_path / "b.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", raw)          # binary AXML, not text
        z.writestr("classes.dex", b"dex\n")
    # No crash decoding binary AXML; a manifest with a package parses (no findings required here).
    ctx = ScanContext(scan_id="t", asset_kind="mobile_app", asset_identifier="x",
                      workspace_path=str(tmp_path))
    assert isinstance(list(MobileEngine().run(ctx)), list)


# ── engine finding logic (plaintext manifest in a real zip) ─────────────────────────────────────

_NS = 'xmlns:android="http://schemas.android.com/apk/res/android"'
_BAD_MANIFEST = f"""<manifest {_NS} package="com.example.app">
  <uses-sdk android:minSdkVersion="19" android:targetSdkVersion="22"/>
  <uses-permission android:name="android.permission.READ_SMS"/>
  <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
  <application android:debuggable="true" android:allowBackup="true"
               android:usesCleartextTraffic="true">
    <activity android:name=".Main" android:exported="true"><intent-filter/></activity>
    <provider android:name=".Prov" android:exported="true"/>
  </application>
</manifest>"""

_GOOD_MANIFEST = f"""<manifest {_NS} package="com.secure.app">
  <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34"/>
  <application android:debuggable="false" android:allowBackup="false"
               android:usesCleartextTraffic="false" android:networkSecurityConfig="@xml/nsc">
    <activity android:name=".Main" android:exported="false"/>
    <provider android:name=".Prov" android:exported="false"/>
  </application>
</manifest>"""


def _apk(tmp_path, manifest: str, extra: dict | None = None):
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", (extra or {}).get("classes.dex", b"dexcontent"))
        for name, blob in (extra or {}).items():
            if name != "classes.dex":
                z.writestr(name, blob)
    return tmp_path


def _run(tmp_path, manifest: str, extra: dict | None = None):
    ctx = ScanContext(scan_id="t", asset_kind="mobile_app", asset_identifier="x",
                      workspace_path=str(_apk(tmp_path, manifest, extra)))
    return list(MobileEngine().run(ctx))


def _cats(findings):
    return {f.title.split(":")[0].strip() for f in findings}


def test_a_hardened_app_is_clean(tmp_path):
    findings = _run(tmp_path, _GOOD_MANIFEST)
    assert findings == [], f"a hardened app should be clean, got {[f.title for f in findings]}"


def test_debuggable_build_is_flagged_high(tmp_path):
    f = next(x for x in _run(tmp_path, _BAD_MANIFEST) if "Debuggable" in x.title)
    assert f.engine == EngineKey.MOBILE
    assert f.base_severity == Severity.HIGH
    assert f.cwe_id == "CWE-489"


def test_backup_allowed_is_flagged(tmp_path):
    f = next(x for x in _run(tmp_path, _BAD_MANIFEST) if "backup" in x.title.lower())
    assert f.base_severity == Severity.MEDIUM
    assert f.cwe_id == "CWE-530"


def test_cleartext_traffic_is_flagged_high(tmp_path):
    f = next(x for x in _run(tmp_path, _BAD_MANIFEST) if "Cleartext" in x.title)
    assert f.base_severity == Severity.HIGH
    assert f.cwe_id == "CWE-319"


def test_exported_provider_without_permission_is_high(tmp_path):
    f = next(x for x in _run(tmp_path, _BAD_MANIFEST) if "content provider" in x.title)
    assert f.base_severity == Severity.HIGH
    assert f.cwe_id == "CWE-926"


def test_exported_activity_without_permission_is_flagged(tmp_path):
    f = next(x for x in _run(tmp_path, _BAD_MANIFEST)
             if "Exported activity" in x.title)
    assert f.base_severity == Severity.MEDIUM


def test_high_risk_and_dangerous_permissions_are_reported(tmp_path):
    findings = _run(tmp_path, _BAD_MANIFEST)
    assert any("High-risk permissions" in f.title for f in findings)
    assert any("Dangerous permissions" in f.title for f in findings)


def test_default_cleartext_on_low_target_sdk(tmp_path):
    manifest = f"""<manifest {_NS} package="com.d">
      <uses-sdk android:targetSdkVersion="22"/>
      <application android:name=".A"/></manifest>"""
    f = next(x for x in _run(tmp_path, manifest) if "default" in x.title.lower())
    assert f.base_severity == Severity.MEDIUM


def test_a_hardcoded_secret_in_the_apk_is_found_and_redacted(tmp_path):
    key = "AKIA" + "I" * 16
    findings = _run(tmp_path, _GOOD_MANIFEST,
                    {"classes.dex": f'apiKey = "{key}"'.encode()})
    secret = next(f for f in findings if f.category == "secret")
    assert secret.cwe_id == "CWE-798"
    blob = f"{secret.title} {secret.description} {secret.evidence}"
    assert key not in blob, "a raw secret leaked from an APK into a finding"


def test_a_webview_bridge_indicator_is_detected(tmp_path):
    findings = _run(tmp_path, _GOOD_MANIFEST,
                    {"classes.dex": b"...addJavascriptInterface...Landroid/webkit/WebView;"})
    assert any(f.category == "webview-jsbridge" for f in findings)


def test_a_cleartext_http_url_in_resources_is_flagged(tmp_path):
    findings = _run(tmp_path, _GOOD_MANIFEST,
                    {"assets/config.json": b'{"api":"http://api.evil.example/v1"}'})
    assert any(f.category == "mobile-network" and "http://api.evil.example" in str(f.evidence)
               for f in findings)


def test_no_apk_raises_rather_than_completing_clean(tmp_path):
    ctx = ScanContext(scan_id="t", asset_kind="mobile_app", asset_identifier="x",
                      workspace_path=str(tmp_path))   # empty dir, no apk
    with pytest.raises(MobileInputError):
        list(MobileEngine().run(ctx))


def test_a_non_apk_file_is_rejected(tmp_path):
    (tmp_path / "app.apk").write_bytes(b"not a zip")
    ctx = ScanContext(scan_id="t", asset_kind="mobile_app", asset_identifier="x",
                      workspace_path=str(tmp_path))
    with pytest.raises(MobileInputError):
        list(MobileEngine().run(ctx))


def test_supports_and_health():
    e = MobileEngine()
    assert e.supports("mobile_app") is True
    assert e.supports("repo") is False
    assert e.health().ok is True
    assert e.health().degraded is False
