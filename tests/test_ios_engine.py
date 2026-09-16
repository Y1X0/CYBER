"""iOS .ipa static analysis engine — completes the Mobile scanner alongside Android.

No device and no macOS: an .ipa is a zip and Info.plist is a (binary or XML) plist that stdlib
`plistlib` reads, so the whole engine is testable from a synthetic .ipa built in the test. The
load-bearing properties: ATS weakening and a development-signed (get-task-allow) build are caught,
URL schemes / privacy usage are inventoried, hardcoded secrets reuse the platform's patterns AND
redaction (a raw key never survives), a FairPlay-encrypted binary is reported honestly rather than
as "no secrets", and a clean release build produces no false high/medium findings.
"""

from __future__ import annotations

import plistlib
import struct
import zipfile

import pytest
from guardian_core.enums import EngineKey, Severity
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.engines.ios_engine import IosEngine, IosInputError

# Assembled so a real AWS-key literal is not committed (push protection rejects one even in a test).
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def _mobileprovision(entitlements: dict) -> bytes:
    """A provisioning profile is a CMS blob with the entitlements plist embedded in the clear."""
    inner = plistlib.dumps({"Entitlements": entitlements}, fmt=plistlib.FMT_XML)
    return b"\x30\x82CMSHEADER" + inner + b"CMSTRAILER"


def _encrypted_macho() -> bytes:
    """A minimal 64-bit Mach-O carrying LC_ENCRYPTION_INFO_64 with cryptid=1 (FairPlay)."""
    hdr = struct.pack("<I", 0xFEEDFACF)              # magic (on disk, little-endian)
    hdr += struct.pack("<iiIIII", 0x0100000C, 0, 2, 1, 24, 0)  # cpu, sub, filetype, ncmds, size, flags
    hdr += struct.pack("<I", 0)                       # reserved (64-bit header)
    lc = struct.pack("<IIIII", 0x2C, 24, 0, 0, 1) + struct.pack("<I", 0)  # cmd,size,off,sz,cryptid,pad
    return hdr + lc


def _ipa(tmp_path, info: dict, *, entitlements=None, exe=b"App binary strings", app="App"):
    path = tmp_path / "app.ipa"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"Payload/{app}.app/Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
        z.writestr(f"Payload/{app}.app/{info.get('CFBundleExecutable', 'App')}", exe)
        if entitlements is not None:
            z.writestr(f"Payload/{app}.app/embedded.mobileprovision",
                       _mobileprovision(entitlements))
    return str(path)


def _run(tmp_path, info, **kw):
    ipa = _ipa(tmp_path, info, **kw)
    ctx = ScanContext(scan_id="t", asset_kind="ios_app", asset_identifier="x",
                      artifact_path=ipa)
    return list(IosEngine().run(ctx))


def _base_info(**over):
    info = {"CFBundleIdentifier": "com.acme.app", "CFBundleExecutable": "App",
            "MinimumOSVersion": "13.0"}
    info.update(over)
    return info


# ── App Transport Security ──────────────────────────────────────────────────────────────────────
def test_ats_disabled_globally_is_high(tmp_path):
    f = next(x for x in _run(tmp_path, _base_info(
        NSAppTransportSecurity={"NSAllowsArbitraryLoads": True})) if "disabled globally" in x.title)
    assert f.base_severity == Severity.HIGH
    assert f.cwe_id == "CWE-319"
    assert f.engine == EngineKey.IOS


def test_per_domain_insecure_http_and_weak_tls(tmp_path):
    findings = _run(tmp_path, _base_info(NSAppTransportSecurity={"NSExceptionDomains": {
        "api.acme.com": {"NSExceptionAllowsInsecureHTTPLoads": True,
                         "NSExceptionMinimumTLSVersion": "TLSv1.0"}}}))
    assert any("insecure-HTTP exception" in x.title for x in findings)
    tls = next(x for x in findings if "weak TLS" in x.title)
    assert tls.base_severity == Severity.MEDIUM and tls.cwe_id == "CWE-326"


# ── entitlements ────────────────────────────────────────────────────────────────────────────────
def test_get_task_allow_is_high_debuggable(tmp_path):
    f = next(x for x in _run(tmp_path, _base_info(), entitlements={"get-task-allow": True})
             if "get-task-allow" in x.title)
    assert f.base_severity == Severity.HIGH
    assert f.cwe_id == "CWE-489"


def test_wildcard_app_id_and_dev_aps(tmp_path):
    findings = _run(tmp_path, _base_info(), entitlements={
        "application-identifier": "ABCDE12345.*", "aps-environment": "development"})
    assert any("Wildcard application identifier" in x.title for x in findings)
    assert any("Development push" in x.title for x in findings)


# ── Info.plist surface ──────────────────────────────────────────────────────────────────────────
def test_url_schemes_are_inventoried(tmp_path):
    f = next(x for x in _run(tmp_path, _base_info(
        CFBundleURLTypes=[{"CFBundleURLSchemes": ["acme", "fb123"]}])) if "URL scheme" in x.title)
    assert f.base_severity == Severity.LOW and f.cwe_id == "CWE-939"


def test_file_sharing_enabled_is_medium(tmp_path):
    assert any(x.base_severity == Severity.MEDIUM and "file sharing" in x.title
               for x in _run(tmp_path, _base_info(UIFileSharingEnabled=True)))


def test_privacy_usage_is_inventoried(tmp_path):
    f = next(x for x in _run(tmp_path, _base_info(
        NSCameraUsageDescription="cam", NSContactsUsageDescription="c")) if "Sensitive data" in
        x.title)
    assert f.base_severity == Severity.LOW


# ── binary content ──────────────────────────────────────────────────────────────────────────────
def test_hardcoded_secret_is_detected_and_redacted(tmp_path):
    findings = _run(tmp_path, _base_info(), exe=f"config {AWS_KEY} end".encode())
    f = next(x for x in findings if x.category == "secret")
    assert f.base_severity == Severity.HIGH and f.cwe_id == "CWE-798"
    blob = f"{f.title} {f.description} {f.evidence}"
    assert AWS_KEY not in blob, "a raw secret survived redaction"


def test_deprecated_and_weak_crypto_indicators(tmp_path):
    findings = _run(tmp_path, _base_info(), exe=b"uses UIWebView and CC_MD5 here")
    cats = {x.category for x in findings}
    assert "ios-webview-deprecated" in cats
    assert "ios-weak-crypto" in cats


def test_encrypted_binary_is_reported_honestly(tmp_path):
    f = next(x for x in _run(tmp_path, _base_info(), exe=_encrypted_macho())
             if "encrypted" in x.title.lower())
    assert f.base_severity == Severity.INFO


# ── clean build + negatives ─────────────────────────────────────────────────────────────────────
def test_a_clean_release_build_has_no_high_or_medium_findings(tmp_path):
    findings = _run(tmp_path, _base_info(
        NSAppTransportSecurity={"NSAllowsArbitraryLoads": False}),
        entitlements={"get-task-allow": False, "application-identifier": "ABCDE12345.com.acme.app",
                      "aps-environment": "production"}, exe=b"clean https://api.acme.com only")
    assert [x for x in findings if x.base_severity in (Severity.HIGH, Severity.MEDIUM)] == []


def test_a_non_ipa_file_is_refused(tmp_path):
    bad = tmp_path / "x.ipa"
    bad.write_bytes(b"not a zip")
    ctx = ScanContext(scan_id="t", asset_kind="ios_app", asset_identifier="x",
                      artifact_path=str(bad))
    with pytest.raises(IosInputError):
        list(IosEngine().run(ctx))


def test_a_zip_without_a_bundle_is_refused(tmp_path):
    path = tmp_path / "x.ipa"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("random.txt", "nothing here")
    ctx = ScanContext(scan_id="t", asset_kind="ios_app", asset_identifier="x",
                      artifact_path=str(path))
    with pytest.raises(IosInputError):
        list(IosEngine().run(ctx))


def test_missing_input_raises(tmp_path):
    ctx = ScanContext(scan_id="t", asset_kind="ios_app", asset_identifier="x")
    with pytest.raises(IosInputError):
        list(IosEngine().run(ctx))


def test_supports_and_health():
    e = IosEngine()
    assert e.supports("ios_app") is True
    assert e.supports("mobile_app") is False   # the Android engine owns that kind
    assert e.health().ok is True


def test_collect_inventory_lists_frameworks_and_dylibs(tmp_path):
    path = tmp_path / "app.ipa"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("Payload/App.app/Info.plist", plistlib.dumps({"CFBundleExecutable": "App"}))
        z.writestr("Payload/App.app/App", b"x")
        z.writestr("Payload/App.app/Frameworks/Alamofire.framework/Info.plist",
                   plistlib.dumps({"CFBundleShortVersionString": "5.6.1"}))
        z.writestr("Payload/App.app/Frameworks/Alamofire.framework/Alamofire", b"x")
        z.writestr("Payload/App.app/Frameworks/libswiftCore.dylib", b"x")
    ctx = ScanContext(scan_id="t", asset_kind="ios_app", asset_identifier="x",
                      artifact_path=str(path))
    inv = {n: (v, e) for (n, v, e, _s) in IosEngine().collect_inventory(ctx)}
    assert inv["Alamofire"] == ("5.6.1", "ios-framework")     # framework version from its Info.plist
    assert inv["libswiftCore.dylib"] == ("", "ios-framework")  # a loose dylib, version-less


def test_xml_plist_is_also_parsed(tmp_path):
    # Not every Info.plist is binary; plistlib reads XML too. Build one explicitly.
    path = tmp_path / "app.ipa"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("Payload/App.app/Info.plist", plistlib.dumps(
            _base_info(NSAppTransportSecurity={"NSAllowsArbitraryLoads": True}),
            fmt=plistlib.FMT_XML))
        z.writestr("Payload/App.app/App", b"x")
    ctx = ScanContext(scan_id="t", asset_kind="ios_app", asset_identifier="x",
                      artifact_path=str(path))
    assert any("disabled globally" in x.title for x in IosEngine().run(ctx))
