# Mobile app scanner (Android APK)

**Status: STATIC ONLY — production-quality static analysis of Android `.apk`. Dynamic Android
instrumentation is NOT implemented (documented deployment requirement). iOS `.ipa` is NOT SUPPORTED
in this phase.**

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

## Security model

- Static only: the APK is never executed. Zip reads are bounded (`_MAX_SECRET_BYTES`,
  `_MAX_FINDINGS`); a malformed AXML or zip raises rather than looping.
- Secret values are redacted before entering any finding (reused `_redact`).
- The engine is passive (`requires_authorization = False`) — it analyses a customer-uploaded
  artifact, not a live system, so it needs no authorization record and no sandbox network egress.

## How to run it

1. Create an asset of kind `mobile_app` (`AssetKind.MOBILE_APP`).
2. Make the APK available to the worker: set the asset config `local_path` / `apk_path` to the
   uploaded `.apk`, or place the file in the scan workspace. (The engine also accepts a workspace
   directory and picks the first `*.apk`.)
3. Create a scan requesting `engines: ["mobile"]`.

## Known limitations / deployment requirements

- **Dynamic analysis (runtime, Frida/emulator, traffic interception): NOT IMPLEMENTED.** It needs an
  Android emulator / device host with privileges the cloud container does not have. The engine seam
  is ready to add a dynamic worker later; until then this is static-only, and says so in every
  affected finding.
- **APK upload plumbing** (multipart upload → object storage → asset config `local_path`) is the one
  integration a production deployment must provide so the worker can read the file; the engine and
  orchestration are complete.
- **iOS `.ipa`: NOT SUPPORTED** this phase.
- **DEX bytecode dataflow** is not performed — code-level items are high-signal *string indicators*,
  deliberately labelled as such rather than presented as confirmed call-site findings.
- `resources.arsc` reference resolution is not performed; a `@ref` attribute is detected as present
  (enough for "a network security config is declared") but not resolved to its value.
