"""Mobile app static analysis engine — Android APK (Phase 1).

An APK is a zip: `AndroidManifest.xml` (binary AXML), `classes*.dex`, resources and assets, and a
signing block. This engine reads it **statically** — no emulator, no execution — and reports the
security posture a reviewer would check by hand: a debuggable or backup-enabled build, cleartext
traffic, exported components reachable by other apps, dangerous permissions, hardcoded secrets, and
high-signal WebView / crypto / TLS-trust indicators. Findings flow through the normal pipeline
(RawFinding → risk engine → evidence → AI analyst → report); secret detection reuses the platform's
existing patterns and redaction rather than adding a second secrets engine.

Static only, by deployment reality: dynamic Android instrumentation needs an emulator/host the cloud
container does not provide. That is documented (docs/MOBILE_SCANNER.md), not faked. iOS `.ipa` is
out of scope for this phase (documented as NOT SUPPORTED).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import zipfile
from collections.abc import Iterable
from pathlib import Path

from guardian_common.logging import get_logger
from guardian_core.enums import EngineKey, Severity
from guardian_core.findings import RawFinding

from guardian_scanner.engines.base import EngineHealth, ScanContext
from guardian_scanner.engines.secrets_engine import _PATTERNS as _SECRET_PATTERNS
from guardian_scanner.engines.secrets_engine import _redact
from guardian_scanner.mobile.axml import AxmlError, Element, parse_axml

log = get_logger("guardian.engine.mobile")

_MAX_SECRET_BYTES = 40_000_000   # cap total bytes read from the APK for string/secret scanning
_MAX_FINDINGS = 2_000
_STRING_RE = re.compile(rb"[\x20-\x7e]{6,}")
_HTTP_URL_RE = re.compile(r"http://(?!localhost|127\.0\.0\.1|10\.|192\.168\.)[a-zA-Z0-9.\-]+")

# Permissions that expose sensitive user data or powerful capabilities. Presence is inventory, not a
# vulnerability on its own; a subset is genuinely high-risk when an app requests it.
_DANGEROUS_PERMS = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CONTACTS", "WRITE_CONTACTS",
    "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO", "CAMERA",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "READ_PHONE_STATE", "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE", "GET_ACCOUNTS", "BODY_SENSORS",
}
_HIGH_RISK_PERMS = {
    "REQUEST_INSTALL_PACKAGES", "SYSTEM_ALERT_WINDOW", "WRITE_SETTINGS",
    "BIND_ACCESSIBILITY_SERVICE", "MANAGE_EXTERNAL_STORAGE", "QUERY_ALL_PACKAGES",
}

# High-signal code indicators (searched as strings in the DEX/resources — DEX stores method and
# class names as UTF-8 strings, so this is a reliable presence check, framed as an indicator).
_CODE_INDICATORS: tuple[tuple[str, str, Severity, str, str], ...] = (
    ("addJavascriptInterface", "webview-jsbridge", Severity.MEDIUM, "CWE-749",
     "WebView exposes a native JavaScript bridge (addJavascriptInterface); on old targetSdk or "
     "with untrusted content this lets page JavaScript call into the app."),
    ("setAllowUniversalAccessFromFileURLs", "webview-file-access", Severity.MEDIUM, "CWE-200",
     "WebView allows universal access from file URLs, which can let local HTML read arbitrary "
     "files."),
    ("setAllowFileAccessFromFileURLs", "webview-file-access", Severity.MEDIUM, "CWE-200",
     "WebView allows file access from file URLs, a local-file-disclosure risk."),
    ("setWebContentsDebuggingEnabled", "webview-debug", Severity.LOW, "CWE-489",
     "WebView contents debugging is enabled; ship it disabled in release builds."),
    ("ALLOW_ALL_HOSTNAME_VERIFIER", "tls-trust-all", Severity.HIGH, "CWE-295",
     "An all-hostname-verifier disables TLS hostname checking — a man-in-the-middle risk."),
    ("AllowAllHostnameVerifier", "tls-trust-all", Severity.HIGH, "CWE-295",
     "An all-hostname-verifier disables TLS hostname checking — a man-in-the-middle risk."),
    ("TrustAllX509TrustManager", "tls-trust-all", Severity.HIGH, "CWE-295",
     "A trust-all X509TrustManager accepts any certificate — TLS is not actually validated."),
    ("AES/ECB", "weak-crypto", Severity.MEDIUM, "CWE-327",
     "AES in ECB mode leaks structure of the plaintext; use an authenticated mode (GCM)."),
    ("DES/", "weak-crypto", Severity.MEDIUM, "CWE-327",
     "DES/3DES is a broken/weak cipher; use AES-GCM."),
)


class MobileInputError(RuntimeError):
    """No APK was provided, so nothing was analysed (readiness audit, Phase 4)."""


class MobileEngine:
    key = EngineKey.MOBILE
    name = "Guardian Mobile App Scanner (Android APK, static)"
    version = "1.0.0"
    requires_authorization = False  # static analysis of a customer-uploaded artifact

    def supports(self, asset_kind: str) -> bool:
        return asset_kind in {"mobile_app"}

    def health(self) -> EngineHealth:
        return EngineHealth(ok=True, detail="static Android APK analysis (offline; no emulator)")

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        apk = self._locate_apk(ctx)
        if apk is None:
            raise MobileInputError(
                "no APK was provided (expected asset_config['apk_path'] or a .apk in the "
                "workspace)")
        try:
            zf = zipfile.ZipFile(apk)
        except (zipfile.BadZipFile, OSError) as exc:
            raise MobileInputError(f"the uploaded file is not a readable APK/zip: {exc}") from exc
        with zf:
            names = set(zf.namelist())
            if "AndroidManifest.xml" not in names:
                raise MobileInputError("no AndroidManifest.xml — not an Android APK")
            manifest = self._read_manifest(zf)
            emitted = 0
            for raw in self._manifest_findings(manifest):
                if emitted >= _MAX_FINDINGS:
                    return
                emitted += 1
                yield raw
            for raw in self._content_findings(zf):
                if emitted >= _MAX_FINDINGS:
                    return
                emitted += 1
                yield raw

    def _locate_apk(self, ctx: ScanContext) -> str | None:
        cfg = ctx.asset_config or {}
        for key in ("apk_path", "local_path", "artifact_path"):
            if cfg.get(key) and Path(str(cfg[key])).is_file():
                return str(cfg[key])
        if ctx.workspace_path:
            root = Path(ctx.workspace_path)
            if root.is_file() and root.suffix.lower() == ".apk":
                return str(root)
            if root.is_dir():
                apks = sorted(root.glob("*.apk"))
                if apks:
                    return str(apks[0])
        return None

    def _read_manifest(self, zf: zipfile.ZipFile) -> Element:
        raw = zf.read("AndroidManifest.xml")
        head = raw.lstrip()[:1]
        if head == b"<":
            # Some tooling ships a plaintext manifest; normalize it to the same Element tree.
            # noqa S314: the manifest is a small in-APK artifact and ET resolves no external
            # entities (no network); billion-laughs is bounded by the manifest's size.
            return _from_etree(ET.fromstring(raw))  # noqa: S314
        try:
            return parse_axml(raw)
        except AxmlError as exc:
            raise MobileInputError(f"could not decode AndroidManifest.xml (AXML): {exc}") from exc

    # ── manifest analysis ───────────────────────────────────────────────────────────────────────
    def _manifest_findings(self, root: Element) -> Iterable[RawFinding]:
        manifest = _find(root, "manifest") or root
        package = str(manifest.attrs.get("package") or "the app")
        app = _find(manifest, "application")
        target_sdk = _int(_attr(_find(manifest, "uses-sdk"), "targetSdkVersion"))

        if app is not None:
            if _truthy(app.attrs.get("debuggable")):
                yield _f("Debuggable release build", "mobile-config", Severity.HIGH, "CWE-489",
                         f"{package} sets android:debuggable=\"true\". A debuggable app lets "
                         "anyone "
                         "attach a debugger and read memory, dump data, and manipulate the running "
                         "app. Ship release builds with debuggable disabled.",
                         {"component": "application", "attribute": "debuggable"})
            backup = app.attrs.get("allowBackup")
            if backup is None or _truthy(backup):
                yield _f("Application backup allowed", "mobile-config", Severity.MEDIUM, "CWE-530",
                         f"{package} allows ADB/cloud backup (android:allowBackup is true or "
                         "unset). "
                         "App data can be extracted via `adb backup` on many devices. Set "
                         "allowBackup=\"false\" unless backup is required and data is "
                         "non-sensitive.",
                         {"component": "application", "attribute": "allowBackup"})
            cleartext = app.attrs.get("usesCleartextTraffic")
            has_nsc = bool(app.attrs.get("networkSecurityConfig"))
            if _truthy(cleartext):
                yield _f("Cleartext (HTTP) traffic permitted", "mobile-network", Severity.HIGH,
                         "CWE-319",
                         f"{package} sets android:usesCleartextTraffic=\"true\", allowing "
                         "unencrypted "
                         "HTTP. Traffic can be read and modified on the network. Require HTTPS and "
                         "a "
                         "restrictive network security config.",
                         {"component": "application", "attribute": "usesCleartextTraffic"})
            elif cleartext is None and not has_nsc and (target_sdk is None or target_sdk < 28):
                yield _f("Cleartext traffic allowed by default", "mobile-network", Severity.MEDIUM,
                         "CWE-319",
                         f"{package} targets SDK {target_sdk or '<28'} with no network security "
                         "config, so cleartext HTTP is permitted by default. Set "
                         "usesCleartextTraffic=\"false\" or add a network security config.",
                         {"component": "application", "targetSdk": target_sdk})

        for kind in ("activity", "service", "receiver", "provider"):
            for comp in _findall(manifest, kind):
                yield from self._component_finding(package, kind, comp)

        perms = sorted({str(_attr(p, "name") or "").rsplit(".", 1)[-1]
                        for p in _findall(manifest, "uses-permission")} - {""})
        high = [p for p in perms if p in _HIGH_RISK_PERMS]
        dangerous = [p for p in perms if p in _DANGEROUS_PERMS]
        if high:
            yield _f(f"High-risk permissions requested: {', '.join(high)}", "mobile-permission",
                     Severity.MEDIUM, "CWE-250",
                     f"{package} requests powerful permissions ({', '.join(high)}) that materially "
                     "increase impact if the app is compromised. Confirm each is required.",
                     {"permissions": high})
        if dangerous:
            yield _f(f"Dangerous permissions requested ({len(dangerous)})", "mobile-permission",
                     Severity.LOW, "CWE-250",
                     f"{package} requests dangerous permissions: {', '.join(dangerous)}. This is "
                     "an "
                     "inventory for review, not a vulnerability by itself.",
                     {"permissions": dangerous})

    def _component_finding(self, package: str, kind: str, comp: Element) -> Iterable[RawFinding]:
        name = str(_attr(comp, "name") or "?")
        exported_attr = comp.attrs.get("exported")
        has_filter = _find(comp, "intent-filter") is not None
        # Explicitly exported, or (pre-Android-12 default) implicitly exported by having an
        # intent-filter with no explicit exported="false".
        exported = _truthy(exported_attr) or (exported_attr is None and has_filter)
        if not exported:
            return
        has_perm = bool(comp.attrs.get("permission"))
        if kind == "provider" and not has_perm:
            yield _f(f"Exported content provider without permission: {name}", "mobile-exposure",
                     Severity.HIGH, "CWE-926",
                     f"{package} exports the content provider {name} with no permission guard, so "
                     "any "
                     "installed app can query or modify its data. Set exported=\"false\" or "
                     "require a "
                     "signature-level permission.",
                     {"component": kind, "name": name})
        elif not has_perm:
            yield _f(f"Exported {kind} without permission: {name}", "mobile-exposure",
                     Severity.MEDIUM, "CWE-926",
                     f"{package} exports the {kind} {name} without a permission guard, so other "
                     "apps "
                     "can invoke it. Confirm it is meant to be public and validates its inputs, or "
                     "set exported=\"false\".",
                     {"component": kind, "name": name, "implicit": exported_attr is None})

    # ── content analysis (secrets + code indicators) ────────────────────────────────────────────
    def _content_findings(self, zf: zipfile.ZipFile) -> Iterable[RawFinding]:
        budget = _MAX_SECRET_BYTES
        seen_secret: set[tuple[str, str]] = set()
        seen_indicator: set[str] = set()
        seen_http: set[str] = set()
        for info in zf.infolist():
            if budget <= 0:
                break
            n = info.filename
            if not (n.endswith(".dex") or n.startswith(("assets/", "res/", "resources.arsc"))):
                continue
            try:
                data = zf.read(n)[:budget]
            except (zipfile.BadZipFile, OSError):
                continue
            budget -= len(data)
            for m in _STRING_RE.finditer(data):
                s = m.group().decode("ascii", "replace")
                # secrets — reuse the platform's patterns + redaction.
                for pname, pattern, sev in _SECRET_PATTERNS:
                    hit = pattern.search(s)
                    if hit and (pname, s[:40]) not in seen_secret:
                        seen_secret.add((pname, s[:40]))
                        yield _f(f"Hardcoded secret in app package: {pname}", "secret",
                                 Severity.HIGH if sev == Severity.CRITICAL else sev, "CWE-798",
                                 f"A likely {pname} is embedded in {n}. Secrets shipped in an APK "
                                 "are "
                                 "trivially extracted by unzipping it; rotate and move to a "
                                 "backend "
                                 "or the device keystore.",
                                 {"file": n, "match": _redact(hit.group(0))})
                # http cleartext URLs
                hu = _HTTP_URL_RE.search(s)
                if hu and hu.group(0) not in seen_http and len(seen_http) < 50:
                    seen_http.add(hu.group(0))
                    yield _f("Cleartext HTTP endpoint referenced", "mobile-network", Severity.LOW,
                             "CWE-319",
                             f"The app references a cleartext HTTP endpoint ({hu.group(0)}). "
                             "Traffic "
                             "to it is unencrypted. Prefer HTTPS.",
                             {"file": n, "url": hu.group(0)})
            for token, cat, sev, cwe, desc in _CODE_INDICATORS:
                if token.encode() in data and cat not in seen_indicator:
                    seen_indicator.add(cat)
                    yield _f(f"Security indicator: {token}", cat, sev, cwe,
                             desc + " (Static indicator — the symbol is present in the package; "
                             "confirm the call site in a review.)",
                             {"file": n, "indicator": token})


def _f(title: str, category: str, severity: Severity, cwe: str, description: str,
       evidence: dict) -> RawFinding:
    return RawFinding(
        engine=EngineKey.MOBILE, title=title[:300], category=category, description=description,
        base_severity=severity, confidence="medium", cwe_id=cwe,
        location={"artifact": "apk", **{k: v for k, v in evidence.items() if k in ("file", "name",
                  "component")}},
        evidence={"detector": "mobile-static", **evidence},
        references={"cwe": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"},
    )


# ── element helpers (work on both AXML-decoded and plaintext-XML trees) ─────────────────────────
def _from_etree(node: ET.Element) -> Element:
    tag = node.tag.split("}", 1)[-1]
    attrs = {k.split("}", 1)[-1].split(":", 1)[-1]: _coerce(v) for k, v in node.attrib.items()}
    el = Element(tag=tag, attrs=attrs)
    el.children = [_from_etree(c) for c in list(node)]
    return el


def _coerce(v: str) -> object:
    low = v.strip().lower()
    if low in ("true", "false"):
        return low == "true"
    return v


def _find(el: Element | None, tag: str) -> Element | None:
    if el is None:
        return None
    for c in el.children:
        if c.tag == tag:
            return c
    return None


def _findall(el: Element | None, tag: str) -> list[Element]:
    if el is None:
        return []
    out: list[Element] = []
    stack = list(el.children)
    while stack:
        c = stack.pop()
        if c.tag == tag:
            out.append(c)
        stack.extend(c.children)
    return out


def _attr(el: Element | None, name: str) -> object:
    return el.attrs.get(name) if el is not None else None


def _truthy(v: object) -> bool:
    return v is True or (isinstance(v, str) and v.strip().lower() == "true")


def _int(v: object) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().lstrip("-").isdigit():
        return int(v)
    return None
