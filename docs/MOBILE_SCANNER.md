# Mobile app scanner (Android APK + iOS IPA)

**Status: STATIC ONLY — production-quality static analysis of Android `.apk` (`mobile` engine) and
iOS `.ipa` (`ios` engine). Dynamic instrumentation (Android or iOS) is NOT implemented (documented
deployment requirement).**

## What it does

`MobileEngine` (`guardian.scanner_plugins` → `mobile`, `EngineKey.MOBILE`) analyses an uploaded
Android APK entirely offline — an APK is a zip, so no execution is needed — and produces findings
through the **same** canonical pipeline as every other scanner (RawFinding → deterministic risk
engine → evidence → AI analyst → report → audit). No new finding model, no separate reporting.

| Area | Checks | Detection |
|---|---|---|
| Build config | debuggable release (CWE-489), backup allowed (CWE-530) | `AndroidManifest.xml` |
| Network | `usesCleartextTraffic`, default cleartext on low targetSdk, cleartext HTTP URLs in code/resources (CWE-319) | manifest + string scan |
| Exposure | exported activities/services/receivers without a permission guard; exported content providers (CWE-926); implicit export via intent-filter | manifest |
| Permissions | high-risk (SYSTEM_ALERT_WINDOW, REQUEST_INSTALL_PACKAGES, accessibility, …) and dangerous permission inventory (CWE-250) | manifest |
| Secrets | hardcoded AWS/GCP/GitHub/Slack/Stripe keys, private keys, JWTs, generic secrets — **reuses the platform's existing secret patterns and redaction**, never a second secrets engine (CWE-798) | DEX/resource string scan |
| WebView | JS bridge (`addJavascriptInterface`), file-URL access, contents debugging (CWE-749/200/489) | DEX string indicators |
| TLS trust | all-hostname-verifier / trust-all X509TrustManager (CWE-295) | DEX string indicators |
| Crypto | AES/ECB, DES/3DES (CWE-327) | DEX string indicators |

The **AXML decoder** (`guardian_scanner/mobile/axml.py`) is a dependency-free reader for Android's
binary XML manifest — required because a real APK never ships a text manifest. A plaintext manifest
(used by some tooling and by tests) is also accepted. Code-level items are labelled **indicators**:
the symbol is present in the package; a reviewer confirms the call site.

## iOS `.ipa` (the `ios` engine)

`IosEngine` (`guardian.scanner_plugins` → `ios`, `EngineKey.IOS`) analyses an uploaded iOS `.ipa`
entirely offline through the **same** canonical pipeline. An `.ipa` is a zip whose
`Payload/<App>.app/` holds `Info.plist`, the Mach-O executable, and `embedded.mobileprovision`.
Unlike Android's binary XML, no custom decoder is needed: stdlib **`plistlib` reads both binary
(`bplist00`) and XML plists** (`guardian_scanner/mobile/ipa.py`).

| Area | Checks | Detection |
|---|---|---|
| App Transport Security | global `NSAllowsArbitraryLoads` (CWE-319), per-domain insecure-HTTP exceptions, weak `NSExceptionMinimumTLSVersion` (CWE-326), web-content/media exceptions | Info.plist |
| Build config | development-signed / debuggable `get-task-allow` (CWE-489), wildcard App ID (CWE-284), development APS environment | `embedded.mobileprovision` entitlements |
| Attack surface | custom URL schemes as an unauthenticated entry point (CWE-939), iTunes file sharing exposing Documents (CWE-200) | Info.plist |
| Privacy | `NS*UsageDescription` sensitive-data inventory (CWE-359) | Info.plist |
| Secrets | hardcoded keys/tokens/private keys — **reuses the platform's secret patterns + redaction** (CWE-798) | Mach-O + bundle string scan |
| Weak APIs | deprecated `UIWebView` (CWE-477), TLS-trust-all (`allowsAnyHTTPSCertificate`, CWE-295), DES/3DES/MD5/SHA-1 (CWE-327/328) | Mach-O string indicators |
| Cleartext | `http://` endpoints referenced (CWE-319) | Mach-O + bundle string scan |

The provisioning profile is a signed CMS blob, but the entitlements plist sits in the clear inside
it; the reader extracts the `<plist>…</plist>` span (no signature verification — posture is read,
not trusted). A light Mach-O load-command scan reports **FairPlay encryption** (`cryptid`): an
App-Store binary is encrypted and yields no readable strings, so the engine says so in an `info`
finding rather than falsely reporting "no secrets".

## Security model

- Static only: the APK is never executed. Zip reads are bounded (`_MAX_SECRET_BYTES`,
  `_MAX_FINDINGS`); a malformed AXML or zip raises rather than looping.
- Secret values are redacted before entering any finding (reused `_redact`).
- The engine is passive (`requires_authorization = False`) — it analyses a customer-uploaded
  artifact, not a live system, so it needs no authorization record and no sandbox network egress.

## How to run it

**Android:**
1. Create an asset of kind `mobile_app` (`AssetKind.MOBILE_APP`).
2. Upload the `.apk`: `POST /api/v1/assets/{asset_id}/artifact` (multipart `file`). The server
   validates it statically, stores it tenant-scoped, and attaches it to the asset by opaque id. The
   console's guided New-scan flow does this for you.
3. Create a scan requesting `engines: ["mobile"]`. The scan is refused until the artifact is
   attached; the worker resolves it to a controlled temp file and reads only that.

**iOS:**
1. Create an asset of kind `ios_app` (`AssetKind.IOS_APP`).
2. Upload the `.ipa`: `POST /api/v1/assets/{asset_id}/artifact` (multipart `file`).
3. Create a scan requesting `engines: ["ios"]`.

> The worker no longer reads a filesystem path from the asset config (the former `local_path` /
> `apk_path` / `ipa_path` keys). Those let a request name any file on the worker (AUD-P1-6) and have
> been removed — an artifact is addressed only by its server-owned id. See
> [docs/ARTIFACT_UPLOADS.md](ARTIFACT_UPLOADS.md).

## Known limitations / deployment requirements

- **Dynamic analysis (runtime, Frida/emulator, traffic interception): NOT IMPLEMENTED.** It needs an
  Android emulator / device host with privileges the cloud container does not have. The engine seam
  is ready to add a dynamic worker later; until then this is static-only, and says so in every
  affected finding.
- **APK/IPA upload plumbing is implemented** (multipart upload → tenant-scoped Postgres storage →
  server-owned artifact id → worker materialization). See [docs/ARTIFACT_UPLOADS.md](ARTIFACT_UPLOADS.md)
  for storage durability, limits, and the security boundary.
- **iOS dynamic analysis: NOT IMPLEMENTED** — it needs a device/jailbroken host and macOS tooling
  the cloud does not have. iOS static analysis of `.ipa` **is** implemented (above).
- **FairPlay-encrypted App-Store binaries (iOS):** their `__TEXT` is encrypted, so string analysis
  of the main binary is limited — the engine detects this and says so; Info.plist and entitlement
  checks are unaffected. Submit a decrypted build for full binary analysis.
- **DEX bytecode dataflow (Android)** / **Mach-O symbol dataflow (iOS)** is not performed —
  code-level items are high-signal *string indicators*, deliberately labelled as such rather than
  presented as confirmed call-site findings.
- `resources.arsc` reference resolution is not performed; a `@ref` attribute is detected as present
  (enough for "a network security config is declared") but not resolved to its value.
