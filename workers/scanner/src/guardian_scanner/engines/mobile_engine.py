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
from guardian_scanner.mobile.safezip import (
    MAX_MEMBER_BYTES,
    ArchiveMemberTooLarge,
    read_bounded,
    read_whole_capped,
)

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

# Per-permission grading (Batch: mobile Android #3). The engine used to lump every high-risk
# permission into one MEDIUM finding and every dangerous one into a LOW inventory. Where the
# permission alone carries a specific, well-understood risk that is safely derivable from the
# manifest, grade it individually: its own severity, CWE, and remediation. Permissions not listed
# here keep the LOW dangerous-permission inventory (genuinely "for review", no single verdict).
_GRADED_PERMS: dict[str, tuple[Severity, str, str]] = {
    "BIND_ACCESSIBILITY_SERVICE": (
        Severity.HIGH, "CWE-250",
        "grants an accessibility service, which can observe and act on every screen and input — a "
        "powerful capability routinely abused by overlay/credential-theft malware. Confirm the app "
        "genuinely provides an accessibility feature."),
    "REQUEST_INSTALL_PACKAGES": (
        Severity.MEDIUM, "CWE-250",
        "lets the app prompt the user to install arbitrary APKs — a sideloading / malware-delivery "
        "vector. Confirm the app legitimately needs to install packages."),
    "SYSTEM_ALERT_WINDOW": (
        Severity.MEDIUM, "CWE-1021",
        "lets the app draw windows over other apps — the basis of tapjacking and overlay-phishing "
        "attacks. Confirm the overlay is essential and non-interactive over sensitive UI."),
    "MANAGE_EXTERNAL_STORAGE": (
        Severity.MEDIUM, "CWE-250",
        "grants broad all-files access, bypassing scoped storage and exposing other apps' shared "
        "files. Prefer scoped storage or the Storage Access Framework."),
    "WRITE_SETTINGS": (
        Severity.MEDIUM, "CWE-250",
        "lets the app modify global system settings. Confirm this is required; it rarely is."),
    "QUERY_ALL_PACKAGES": (
        Severity.LOW, "CWE-200",
        "lets the app enumerate every installed package — a privacy/fingerprinting signal that "
        "Play policy restricts. Use targeted <queries> instead where possible."),
    "READ_SMS": (
        Severity.MEDIUM, "CWE-359",
        "lets the app read SMS, which can capture one-time passcodes / 2FA codes. Confirm it is "
        "required and that OTP autofill APIs are not a safer fit."),
    "RECEIVE_SMS": (
        Severity.MEDIUM, "CWE-359",
        "lets the app intercept incoming SMS, which can capture one-time passcodes / 2FA codes. "
        "Confirm it is required."),
    "ACCESS_BACKGROUND_LOCATION": (
        Severity.MEDIUM, "CWE-359",
        "grants continuous location tracking even when the app is in the background. Confirm the "
        "background need and that foreground location is not sufficient."),
}

_WEB_SCHEMES = {"http", "https"}

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

    def collect_inventory(self, ctx: ScanContext) -> list[tuple[str, str, str, str]]:
        """Bundled native libraries shipped in the APK (`lib/<abi>/*.so`), for the SBOM.

        A static APK exposes no dependency *versions*, but it does ship concrete native libraries —
        legitimate supply-chain inventory ("what is inside this app"). Reported version-less and
        deduped across ABIs. Never raises: an unreadable APK contributes nothing.
        """
        apk = self._locate_apk(ctx)
        if apk is None:
            return []
        try:
            zf = zipfile.ZipFile(apk)
        except (zipfile.BadZipFile, OSError):
            return []
        seen: dict[str, tuple[str, str, str, str]] = {}
        with zf:
            for name in zf.namelist():
                if name.startswith("lib/") and name.endswith(".so") and name.count("/") == 2:
                    lib = name.rsplit("/", 1)[-1]
                    seen.setdefault(lib, (lib, "", "android-native", name))
                    if len(seen) >= _MAX_FINDINGS:
                        break
        return sorted(seen.values())

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        apk = self._locate_apk(ctx)
        if apk is None:
            raise MobileInputError(
                "no APK was provided — upload the .apk to this asset before scanning")
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
            for source in (self._manifest_findings(manifest),
                           self._nsc_findings(zf, manifest),
                           self._content_findings(zf)):
                for raw in source:
                    if emitted >= _MAX_FINDINGS:
                        return
                    emitted += 1
                    yield raw

    def _locate_apk(self, ctx: ScanContext) -> str | None:
        # ONLY server-owned inputs. `artifact_path` is a temp file the worker wrote from a
        # validated, tenant-scoped upload (resolved by opaque id); `workspace_path` is a
        # worker-prepared dir. A path from the asset's tenant-controlled config is never trusted
        # here (AUD-P1-6).
        if ctx.artifact_path and Path(ctx.artifact_path).is_file():
            return ctx.artifact_path
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
        return self._decode_xml_member(zf, "AndroidManifest.xml")

    def _decode_xml_member(self, zf: zipfile.ZipFile, name: str) -> Element:
        """Decode an in-APK XML member (binary AXML, or plaintext XML that some tooling/tests ship).

        Used for both the manifest and `res/xml/*` resources such as a network-security-config.
        Raises MobileInputError on an oversized or undecodable member.
        """
        try:
            raw = read_whole_capped(zf, name)
        except ArchiveMemberTooLarge as exc:
            raise MobileInputError(f"{name} is implausibly large: {exc}") from exc
        if raw.lstrip()[:1] == b"<":
            # noqa S314: an in-APK artifact, ET resolves no external entities (no network); the
            # billion-laughs blow-up is bounded by the member's already-capped size.
            return _from_etree(ET.fromstring(raw))  # noqa: S314
        try:
            return parse_axml(raw)
        except AxmlError as exc:
            raise MobileInputError(f"could not decode {name} (AXML): {exc}") from exc

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

        for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
            for comp in _findall(manifest, kind):
                yield from self._component_finding(package, kind, comp)
                if kind in ("activity", "activity-alias"):
                    yield from self._deep_link_findings(package, kind, comp)

        perms = sorted({str(_attr(p, "name") or "").rsplit(".", 1)[-1]
                        for p in _findall(manifest, "uses-permission")} - {""})
        # Grade the individually-significant permissions (Batch #3): each gets its own severity/CWE
        # and specific remediation instead of being lumped. Everything else stays an inventory.
        for p in perms:
            grade = _GRADED_PERMS.get(p)
            if grade is not None:
                sev, cwe, why = grade
                yield _f(f"Sensitive permission: {p}", "mobile-permission", sev, cwe,
                         f"{package} requests {p}, which {why}", {"permission": p})
        high = [p for p in perms if p in _HIGH_RISK_PERMS and p not in _GRADED_PERMS]
        dangerous = [p for p in perms if p in _DANGEROUS_PERMS and p not in _GRADED_PERMS]
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

    # ── deep-link / intent-filter analysis (Batch #2) ───────────────────────────────────────────
    def _deep_link_findings(self, package: str, kind: str, comp: Element) -> Iterable[RawFinding]:
        """Flag hijackable deep links declared by a component's intent-filters.

        A BROWSABLE intent-filter is reachable from the browser and other apps. For an http/https
        link this is safe only when the filter carries android:autoVerify (an Android App Link the
        OS verifies against the host's assetlinks.json); without it any app can register the same
        host and intercept the link. A custom scheme (myapp://) cannot be verified at all, and a
        filter with a scheme but no host can be claimed by any app. All static — the manifest is
        read, never opened.
        """
        name = str(_attr(comp, "name") or "?")
        web_unverified: list[str] = []   # "scheme://host" the OS won't verify
        custom_schemes: set[str] = set()  # non-web browsable schemes (inherently hijackable)
        scheme_only: set[str] = set()     # scheme with no host — any app can claim it
        for flt in _findall(comp, "intent-filter"):
            cats = {str(_attr(c, "name") or "").rsplit(".", 1)[-1]
                    for c in _findall(flt, "category")}
            if "BROWSABLE" not in cats:
                continue
            autoverify = _truthy(flt.attrs.get("autoVerify"))
            schemes = {str(_attr(d, "scheme")).lower() for d in _findall(flt, "data")
                       if _attr(d, "scheme")}
            hosts = {str(_attr(d, "host")) for d in _findall(flt, "data") if _attr(d, "host")}
            for scheme in schemes:
                if scheme in _WEB_SCHEMES:
                    if not hosts:
                        scheme_only.add(scheme)
                    elif not autoverify:
                        web_unverified.extend(f"{scheme}://{h}" for h in sorted(hosts))
                elif not hosts:
                    scheme_only.add(scheme)
                else:
                    custom_schemes.add(scheme)
        if web_unverified:
            targets = sorted(set(web_unverified))[:20]
            yield _f(f"Hijackable web deep link (no autoVerify): {name}", "mobile-deeplink",
                     Severity.MEDIUM, "CWE-926",
                     f"{package} exports a BROWSABLE http/https deep link on {name} without "
                     "android:autoVerify, so the OS does not tie it to the host — another app can "
                     f"register the same host(s) ({', '.join(targets)}) and intercept the link "
                     "(link/OAuth-redirect hijacking). Add autoVerify=\"true\" and publish an "
                     "assetlinks.json, or don't route sensitive flows through the link.",
                     {"component": kind, "name": name, "links": targets})
        if custom_schemes or scheme_only:
            schemes = sorted({f"{s}://" for s in custom_schemes} | {f"{s}:(no host)" for s in
                             scheme_only})[:20]
            yield _f(f"Hijackable custom-scheme deep link: {name}", "mobile-deeplink",
                     Severity.MEDIUM, "CWE-939",
                     f"{package} exports a BROWSABLE deep link on {name} using a scheme any app "
                     f"can claim ({', '.join(schemes)}). Custom schemes can't be verified and "
                     "host-less filters match on scheme alone, so another app can register the "
                     "same handler and receive the intent. Don't pass secrets/auth callbacks "
                     "through it; prefer a verified https App Link.",
                     {"component": kind, "name": name, "schemes": schemes})

    # ── network-security-config analysis (Batch #1 — closes a false-negative) ────────────────────
    def _nsc_findings(self, zf: zipfile.ZipFile, root: Element) -> Iterable[RawFinding]:
        """Parse the app's network-security-config XML and flag settings that weaken TLS.

        Previously the manifest's ``networkSecurityConfig`` attribute was used only as a boolean to
        SUPPRESS the default-cleartext finding — so an NSC that re-enables cleartext or trusts
        user/custom CAs made the engine report clean. Here the referenced config is actually read.

        The manifest points at the config by a resources.arsc id, which this engine deliberately
        does not resolve; instead we locate the config by its structure — any ``res/xml*/*.xml``
        whose root is ``<network-security-config>`` — and analyse it only when the manifest declares
        one (so an unreferenced/dead file is never flagged). Static: the config is parsed, never
        applied.
        """
        manifest = _find(root, "manifest") or root
        app = _find(manifest, "application")
        if app is None or not app.attrs.get("networkSecurityConfig"):
            return
        package = str(manifest.attrs.get("package") or "the app")
        seen: set[str] = set()
        found = 0
        for member in zf.namelist():
            if not (member.startswith("res/xml") and member.endswith(".xml")):
                continue
            try:
                doc = self._decode_xml_member(zf, member)
            except MobileInputError:
                continue
            nsc = doc if doc.tag == "network-security-config" else _find(doc,
                  "network-security-config")
            if nsc is None:
                continue
            found += 1
            yield from self._analyse_nsc(package, member, nsc, seen)
            if found >= 8:
                break

    def _analyse_nsc(self, package: str, member: str, nsc: Element, seen: set[str]
                     ) -> Iterable[RawFinding]:
        base = _find(nsc, "base-config")
        domain_cfgs = _findall(nsc, "domain-config")
        debug = _find(nsc, "debug-overrides")

        def once(key: str) -> bool:
            if key in seen:
                return False
            seen.add(key)
            return True

        if base is not None and _truthy(base.attrs.get("cleartextTrafficPermitted")) \
                and once("nsc-base-cleartext"):
            yield _f("Network config permits cleartext traffic for all domains", "mobile-network",
                     Severity.HIGH, "CWE-319",
                     f"{package}'s network security config sets base-config "
                     "cleartextTrafficPermitted=\"true\", re-enabling unencrypted HTTP for the "
                     "whole app regardless of targetSdk. Traffic can be read and modified on the "
                     "network. Remove it (or set it false) and require HTTPS.",
                     {"file": member, "scope": "base-config"})
        if base is not None and _trusts_user(base) and once("nsc-base-user-ca"):
            yield _f("Network config trusts user-installed CAs", "mobile-network", Severity.HIGH,
                     "CWE-295",
                     f"{package}'s network security config adds user-installed CAs as trust "
                     "anchors in base-config, so any certificate a user (or malware/proxy) "
                     "installs is trusted — defeating TLS and enabling interception. Trust only "
                     "the system store (and pin where appropriate).",
                     {"file": member, "scope": "base-config"})

        cleartext_domains: list[str] = []
        user_ca_domains: list[str] = []
        for dc in domain_cfgs:
            doms = sorted({d.text.strip() for d in _findall(dc, "domain") if d.text.strip()}) \
                or ["(unnamed domain)"]
            if _truthy(dc.attrs.get("cleartextTrafficPermitted")):
                cleartext_domains += doms
            if _trusts_user(dc):
                user_ca_domains += doms
        if cleartext_domains and once("nsc-domain-cleartext"):
            doms = ", ".join(sorted(set(cleartext_domains))[:20])
            yield _f("Network config permits cleartext traffic for specific domains",
                     "mobile-network", Severity.MEDIUM, "CWE-319",
                     f"{package}'s network security config permits cleartext HTTP for: {doms}. "
                     "Traffic to those hosts is unencrypted. Require HTTPS for them.",
                     {"file": member, "domains": sorted(set(cleartext_domains))[:20]})
        if user_ca_domains and once("nsc-domain-user-ca"):
            doms = ", ".join(sorted(set(user_ca_domains))[:20])
            yield _f("Network config trusts user-installed CAs for specific domains",
                     "mobile-network", Severity.HIGH, "CWE-295",
                     f"{package}'s network security config trusts user-installed CAs for: {doms}. "
                     "A user- or malware-installed certificate is trusted for those hosts, so TLS "
                     "can be intercepted. Trust only the system store.",
                     {"file": member, "domains": sorted(set(user_ca_domains))[:20]})

        if debug is not None and _find(debug, "trust-anchors") is not None \
                and once("nsc-debug-overrides"):
            yield _f("Network config debug-overrides adds trust anchors", "mobile-network",
                     Severity.LOW, "CWE-295",
                     f"{package}'s network security config declares debug-overrides trust anchors. "
                     "These apply only to a debuggable build, so they are inert in a proper "
                     "release — but if the app is also shipped debuggable they take effect and "
                     "trust extra CAs. Confirm the release build is not debuggable and ideally "
                     "strip debug-overrides from release configs.",
                     {"file": member, "scope": "debug-overrides"})

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
                # Bounded read: never inflate more than the remaining budget (capped per member), so
                # a high-ratio DEFLATE bomb cannot blow up memory before the slice (AUD-P1-5).
                data = read_bounded(zf, n, min(budget, MAX_MEMBER_BYTES))
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
    el = Element(tag=tag, attrs=attrs, text=(node.text or "").strip())
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


def _trusts_user(cfg: Element) -> bool:
    """True if a base/domain/debug config adds user-installed CAs as a trust anchor."""
    for ta in _findall(cfg, "trust-anchors"):
        for cert in _findall(ta, "certificates"):
            if str(cert.attrs.get("src", "")).strip().lower() == "user":
                return True
    return False


def _int(v: object) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().lstrip("-").isdigit():
        return int(v)
    return None
