"""iOS app static analysis engine — .ipa (completes the Mobile scanner alongside Android).

An `.ipa` is a zip whose `Payload/<App>.app/` holds `Info.plist` (binary or XML plist), the Mach-O
executable, `embedded.mobileprovision` (entitlements), and frameworks. This engine reads it
**statically** — no device, no macOS/Xcode, no execution — and reports the posture a reviewer would
check by hand: App Transport Security weakened, a development-signed (debuggable) build, custom URL
schemes and file sharing as attack surface, sensitive privacy usage, and hardcoded secrets / weak
-crypto indicators in the binary. Findings flow through the normal pipeline (RawFinding → risk →
evidence → AI analyst → report); secret detection reuses the platform's existing patterns and
redaction rather than adding a second secrets engine — exactly as the Android engine does.

Static only, by deployment reality: dynamic iOS analysis needs a device/jailbroken host the cloud
does not have, and App-Store binaries are FairPlay-encrypted (their strings unreadable) — both
documented (docs/MOBILE_SCANNER.md), not faked. The engine says so in a finding when it sees an
encrypted binary, rather than silently reporting "no secrets".
"""

from __future__ import annotations

import re
import zipfile
from collections.abc import Iterable
from pathlib import Path

from guardian_common.logging import get_logger
from guardian_core.enums import EngineKey, Severity
from guardian_core.findings import RawFinding

from guardian_scanner.engines.base import EngineHealth, ScanContext
from guardian_scanner.engines.secrets_engine import _PATTERNS as _SECRET_PATTERNS
from guardian_scanner.engines.secrets_engine import _redact
from guardian_scanner.mobile.ipa import IpaBundle, IpaError, read_bundle

log = get_logger("guardian.engine.ios")

_MAX_SCAN_BYTES = 40_000_000
_MAX_FINDINGS = 2_000
_STRING_RE = re.compile(rb"[\x20-\x7e]{6,}")
_HTTP_URL_RE = re.compile(r"http://(?!localhost|127\.0\.0\.1|10\.|192\.168\.)[a-zA-Z0-9.\-]+")

# Privacy-sensitive Info.plist usage keys — the iOS parallel to Android's dangerous permissions.
# Presence is inventory for review, not a vulnerability on its own.
_PRIVACY_KEYS = {
    "NSCameraUsageDescription": "camera",
    "NSMicrophoneUsageDescription": "microphone",
    "NSLocationAlwaysUsageDescription": "location (always)",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "location (always)",
    "NSLocationWhenInUseUsageDescription": "location",
    "NSContactsUsageDescription": "contacts",
    "NSPhotoLibraryUsageDescription": "photo library",
    "NSPhotoLibraryAddUsageDescription": "photo library (add)",
    "NSFaceIDUsageDescription": "Face ID",
    "NSHealthShareUsageDescription": "health",
    "NSHealthUpdateUsageDescription": "health (update)",
    "NSBluetoothAlwaysUsageDescription": "bluetooth",
    "NSCalendarsUsageDescription": "calendars",
    "NSRemindersUsageDescription": "reminders",
    "NSMotionUsageDescription": "motion",
    "NSSpeechRecognitionUsageDescription": "speech recognition",
    "NSAppleMusicUsageDescription": "media library",
}

# High-signal Mach-O string indicators — deprecated/insecure APIs. Presence in the binary is a
# reliable indicator (Objective-C selectors and C symbols are stored as strings), framed as such.
_CODE_INDICATORS: tuple[tuple[str, str, Severity, str, str], ...] = (
    ("UIWebView", "ios-webview-deprecated", Severity.MEDIUM, "CWE-477",
     "The app links the deprecated UIWebView, which cannot be updated for modern web security and "
     "is rejected by App Review. Migrate to WKWebView."),
    ("allowsAnyHTTPSCertificate", "ios-tls-trust-all", Severity.HIGH, "CWE-295",
     "allowsAnyHTTPSCertificate disables TLS certificate validation — a man-in-the-middle risk."),
    ("continueWithoutCredentialForAuthenticationChallenge", "ios-tls-trust-all", Severity.HIGH,
     "CWE-295",
     "The app appears to accept any server trust in an auth challenge, disabling TLS validation."),
    ("kCCAlgorithmDES", "ios-weak-crypto", Severity.MEDIUM, "CWE-327",
     "The DES algorithm is present; DES is cryptographically broken. Use AES."),
    ("kCCAlgorithm3DES", "ios-weak-crypto", Severity.MEDIUM, "CWE-327",
     "Triple-DES is present; it is deprecated and weak. Use AES."),
    ("CC_MD5", "ios-weak-crypto", Severity.LOW, "CWE-328",
     "MD5 is present; it is broken for security use. Use SHA-256 or better."),
    ("CC_SHA1", "ios-weak-crypto", Severity.LOW, "CWE-328",
     "SHA-1 is present; it is weak for security use. Prefer SHA-256."),
    ("SecKeychainAddGenericPassword", "ios-keychain", Severity.LOW, "CWE-522",
     "Keychain usage is present; confirm items use an appropriate accessibility class "
     "(e.g. WhenUnlockedThisDeviceOnly) rather than an always-accessible one."),
)

_ATS = "NSAppTransportSecurity"


class IosInputError(RuntimeError):
    """No readable .ipa was provided (readiness audit)."""


class IosEngine:
    key = EngineKey.IOS
    name = "Guardian iOS Static Analysis (.ipa)"
    version = "1.0.0"
    requires_authorization = False  # passive, offline: reads an uploaded artifact

    def supports(self, asset_kind: str) -> bool:
        return asset_kind in {"ios_app"}

    def health(self) -> EngineHealth:
        return EngineHealth(ok=True, detail="static iOS .ipa analysis (offline; no device)")

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        ipa = self._locate_ipa(ctx)
        if ipa is None:
            raise IosInputError(
                "no .ipa was provided (expected asset_config['ipa_path'] or a .ipa in the "
                "workspace)")
        try:
            zf = zipfile.ZipFile(ipa)
        except (zipfile.BadZipFile, OSError) as exc:
            raise IosInputError(f"the uploaded file is not a readable .ipa/zip: {exc}") from exc
        with zf:
            try:
                bundle = read_bundle(zf)
            except IpaError as exc:
                raise IosInputError(str(exc)) from exc
            emitted = 0
            for raw in self._plist_findings(bundle):
                if emitted >= _MAX_FINDINGS:
                    return
                emitted += 1
                yield raw
            for raw in self._entitlement_findings(bundle):
                if emitted >= _MAX_FINDINGS:
                    return
                emitted += 1
                yield raw
            for raw in self._content_findings(zf, bundle):
                if emitted >= _MAX_FINDINGS:
                    return
                emitted += 1
                yield raw

    def _locate_ipa(self, ctx: ScanContext) -> str | None:
        cfg = ctx.asset_config or {}
        for key in ("ipa_path", "local_path", "artifact_path"):
            if cfg.get(key) and Path(str(cfg[key])).is_file():
                return str(cfg[key])
        if ctx.workspace_path:
            root = Path(ctx.workspace_path)
            if root.is_file() and root.suffix.lower() == ".ipa":
                return str(root)
            if root.is_dir():
                ipas = sorted(root.glob("*.ipa"))
                if ipas:
                    return str(ipas[0])
        return None

    # ── Info.plist analysis ─────────────────────────────────────────────────────────────────────
    def _plist_findings(self, b: IpaBundle) -> Iterable[RawFinding]:
        info = b.info_plist
        app = str(info.get("CFBundleIdentifier") or "the app")

        ats = info.get(_ATS) if isinstance(info.get(_ATS), dict) else {}
        if ats.get("NSAllowsArbitraryLoads") is True:
            yield _f("App Transport Security disabled globally", "ios-network", Severity.HIGH,
                     "CWE-319",
                     f"{app} sets NSAllowsArbitraryLoads=true, disabling App Transport Security "
                     "for all domains, so the app may use plaintext HTTP and weak TLS. Remove the "
                     "global exception and scope any exception to specific domains.",
                     {"key": "NSAllowsArbitraryLoads"})
        for soft_key, label in (("NSAllowsArbitraryLoadsInWebContent", "web content"),
                                ("NSAllowsArbitraryLoadsForMedia", "media")):
            if ats.get(soft_key) is True:
                yield _f(f"ATS exception for {label}", "ios-network", Severity.LOW, "CWE-319",
                         f"{app} sets {soft_key}=true, allowing insecure loads for {label}. "
                         "Confirm it is necessary and scoped.", {"key": soft_key})
        domains = ats.get("NSExceptionDomains")
        if isinstance(domains, dict):
            for dom, cfg in domains.items():
                if not isinstance(cfg, dict):
                    continue
                if cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                    yield _f(f"ATS insecure-HTTP exception for domain: {dom}", "ios-network",
                             Severity.MEDIUM, "CWE-319",
                             f"{app} permits insecure HTTP loads to {dom}. Use HTTPS and remove "
                             "the exception.", {"domain": dom})
                tls = cfg.get("NSExceptionMinimumTLSVersion")
                if isinstance(tls, str) and tls in ("TLSv1.0", "TLSv1.1"):
                    yield _f(f"ATS allows weak TLS ({tls}) for domain: {dom}", "ios-network",
                             Severity.MEDIUM, "CWE-326",
                             f"{app} lowers the minimum TLS version to {tls} for {dom}. Require "
                             "TLSv1.2 or higher.", {"domain": dom, "tls": tls})

        if info.get("UIFileSharingEnabled") is True:
            yield _f("iTunes file sharing enabled", "ios-config", Severity.MEDIUM, "CWE-200",
                     f"{app} sets UIFileSharingEnabled=true, exposing the app's Documents "
                     "directory over USB/Finder. Disable it unless the app is a document editor, "
                     "and never "
                     "store secrets there.", {"key": "UIFileSharingEnabled"})

        schemes = sorted({str(s) for t in (info.get("CFBundleURLTypes") or [])
                          if isinstance(t, dict)
                          for s in (t.get("CFBundleURLSchemes") or []) if s})
        if schemes:
            yield _f(f"Custom URL schemes registered: {', '.join(schemes[:8])}", "ios-exposure",
                     Severity.LOW, "CWE-939",
                     f"{app} registers custom URL scheme(s) ({', '.join(schemes)}). Custom schemes "
                     "are an unauthenticated entry point any app can invoke; validate all incoming "
                     "URL parameters and prefer Universal Links for sensitive actions.",
                     {"schemes": schemes})

        privacy = sorted({label for key, label in _PRIVACY_KEYS.items() if key in info})
        if privacy:
            yield _f(f"Sensitive data access declared ({len(privacy)})", "ios-privacy",
                     Severity.LOW, "CWE-359",
                     f"{app} declares access to: {', '.join(privacy)}. This is an inventory for "
                     "review, not a vulnerability by itself.", {"usage": privacy})

    # ── entitlements (provisioning profile) ─────────────────────────────────────────────────────
    def _entitlement_findings(self, b: IpaBundle) -> Iterable[RawFinding]:
        ent = b.entitlements
        app = str(b.info_plist.get("CFBundleIdentifier") or "the app")
        if ent.get("get-task-allow") is True:
            yield _f("Development-signed / debuggable build (get-task-allow)", "ios-config",
                     Severity.HIGH, "CWE-489",
                     f"{app} ships with get-task-allow=true, which lets a debugger attach to the "
                     "running process and read its memory. This must be false in a release "
                     "(App Store / distribution) build.", {"entitlement": "get-task-allow"})
        appid = str(ent.get("application-identifier") or "")
        if appid.endswith(".*"):
            yield _f("Wildcard application identifier", "ios-config", Severity.LOW, "CWE-284",
                     f"{app} is signed with a wildcard App ID ({appid}), which cannot use App-ID-"
                     "bound entitlements (keychain sharing, push) safely. Use an explicit App ID "
                     "for release.", {"application-identifier": appid})
        if str(ent.get("aps-environment") or "") == "development":
            yield _f("Development push (APS) environment", "ios-config", Severity.LOW, "CWE-489",
                     f"{app} is built against the development APNs environment. Release builds "
                     "should use production.", {"aps-environment": "development"})

    # ── binary + bundle content (secrets, http, indicators) ─────────────────────────────────────
    def _content_findings(self, zf: zipfile.ZipFile, b: IpaBundle) -> Iterable[RawFinding]:
        if b.encrypted:
            # Be honest: a FairPlay-encrypted store binary yields no meaningful strings.
            yield _f("Main binary is encrypted (FairPlay) — string analysis limited", "ios-info",
                     Severity.INFO, "CWE-1059",
                     "The main executable is App-Store (FairPlay) encrypted, so static string "
                     "analysis of it cannot see secrets or symbols. Submit a decrypted build for "
                     "full analysis. Info.plist and entitlement checks are unaffected.",
                     {"executable": b.executable_name})
        budget = _MAX_SCAN_BYTES
        seen_secret: set[tuple[str, str]] = set()
        seen_indicator: set[str] = set()
        seen_http: set[str] = set()
        prefix = f"{b.app_dir}/"
        for info in zf.infolist():
            if budget <= 0:
                break
            n = info.filename
            if not n.startswith(prefix) or n.endswith("/"):
                continue
            # Scan the executable, plists, and resources; skip large media/asset blobs by extension.
            if n.endswith((".png", ".jpg", ".jpeg", ".gif", ".mp4", ".mov", ".car", ".ttf",
                           ".otf", ".woff", ".woff2")):
                continue
            try:
                data = zf.read(n)[:budget]
            except (zipfile.BadZipFile, OSError):
                continue
            budget -= len(data)
            for m in _STRING_RE.finditer(data):
                s = m.group().decode("ascii", "replace")
                for pname, pattern, sev in _SECRET_PATTERNS:
                    hit = pattern.search(s)
                    if hit and (pname, s[:40]) not in seen_secret:
                        seen_secret.add((pname, s[:40]))
                        short = n[len(prefix):]
                        yield _f(f"Hardcoded secret in app package: {pname}", "secret",
                                 Severity.HIGH if sev == Severity.CRITICAL else sev, "CWE-798",
                                 f"A likely {pname} is embedded in {short}. Secrets shipped in an "
                                 ".ipa are extracted by unzipping it; rotate and move to a backend "
                                 "or the iOS keychain.", {"file": short, "match": _redact(
                                     hit.group(0))})
                hu = _HTTP_URL_RE.search(s)
                if hu and hu.group(0) not in seen_http and len(seen_http) < 50:
                    seen_http.add(hu.group(0))
                    yield _f("Cleartext HTTP endpoint referenced", "ios-network", Severity.LOW,
                             "CWE-319",
                             f"The app references a cleartext HTTP endpoint ({hu.group(0)}). "
                             "Traffic to it is unencrypted. Prefer HTTPS.",
                             {"file": n[len(prefix):], "url": hu.group(0)})
            for token, cat, sev, cwe, desc in _CODE_INDICATORS:
                if token.encode() in data and cat not in seen_indicator:
                    seen_indicator.add(cat)
                    yield _f(f"Security indicator: {token}", cat, sev, cwe,
                             desc + " (Static indicator — the symbol is present in the package; "
                             "confirm the call site in a review.)",
                             {"file": n[len(prefix):], "indicator": token})


def _f(title: str, category: str, severity: Severity, cwe: str, description: str,
       evidence: dict) -> RawFinding:
    return RawFinding(
        engine=EngineKey.IOS, title=title[:300], category=category, description=description,
        base_severity=severity, confidence="medium", cwe_id=cwe,
        location={"artifact": "ipa", **{k: v for k, v in evidence.items()
                  if k in ("file", "domain", "schemes")}},
        evidence={"detector": "ios-static", **evidence},
        references={"cwe": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"},
    )
